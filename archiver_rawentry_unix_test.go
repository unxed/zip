//go:build !windows
// +build !windows

package zip

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	zlib4go "github.com/unxed/zlib4go"
)

// rawEntryTree lays out a regular file, a symlink to it, a FIFO and a hard
// link: the entries the archiver writes whole, through CreateRaw.
func rawEntryTree(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	mustWriteFile(t, filepath.Join(src, "a.txt"), []byte("target contents\n"), 0o644)
	if err := os.Symlink("a.txt", filepath.Join(src, "lnk")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := syscall.Mkfifo(filepath.Join(src, "fifo"), 0o644); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	if err := os.Link(filepath.Join(src, "a.txt"), filepath.Join(src, "z_hard")); err != nil {
		t.Fatalf("link: %v", err)
	}
	return src
}

// TestArchiverRawEntries_EncodedAsTheHeaderSays: with a password, a symlink's
// body is a WinZip AES body, as the header written for it claims. Written as
// it came, 7-Zip refused it with a header error, and this package could not
// read it back either. A FIFO carries no bytes at all, so there is nothing
// here to encrypt: aes_link_entries_test.go pins that half of the rule on its
// own, and the check here just confirms the archiver-level path agrees.
//
// Torrentzip is not covered here any more: it now refuses a symlink, a hard
// link or a device node outright, before ever reaching this raw path, rather
// than writing one it cannot make canonical (torrentzip_canonical_test.go).
func TestArchiverRawEntries_EncodedAsTheHeaderSays(t *testing.T) {
	src := rawEntryTree(t)
	var buf bytes.Buffer
	a, err := NewArchiver(&buf, src, WithArchiverPassword("pw"))
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	if err := a.Archive(context.Background(), walkFilesFor(t, src)); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	raw := buf.Bytes()

	got := aesWinZipReadAll(t, raw, "pw")
	if string(got["lnk"]) != "a.txt" {
		t.Errorf("lnk reads %q, want the target a.txt", got["lnk"])
	}
	if len(got["fifo"]) != 0 {
		t.Errorf("fifo reads %d bytes, want none", len(got["fifo"]))
	}

	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("read the archive back: %v", err)
	}
	for _, f := range zr.File {
		switch f.Name {
		case "lnk":
			if f.Method != winzipAesMethod {
				t.Errorf("lnk: method %d, want %d", f.Method, winzipAesMethod)
			}
		case "fifo":
			if f.Method != Store {
				t.Errorf("fifo: method %d, want %d", f.Method, Store)
			}
			if f.Flags&0x1 != 0 {
				t.Errorf("fifo: flags %#04x, and there is nothing here to encrypt", f.Flags)
			}
			if f.CompressedSize64 != 0 {
				t.Errorf("fifo: body of %d bytes, want none", f.CompressedSize64)
			}
		}
	}
}

var errRawEntryNoZlib = errors.New("no zlib stream for this test")

// TestArchiverRawEntries_TorrentZipCompressorRefuses: under torrentzip a
// file's body goes through the compressor torrentzip registers, and its
// refusal comes back out rather than an entry with no body. A symlink used to
// exercise this through the raw path, but torrentzip now refuses a symlink
// before ever reaching a compressor (torrentzip_canonical_test.go), so a
// regular file exercises the same compressor here instead.
func TestArchiverRawEntries_TorrentZipCompressorRefuses(t *testing.T) {
	real := newZlibWriterLevel
	t.Cleanup(func() { newZlibWriterLevel = real })
	newZlibWriterLevel = func(io.Writer, int) (*zlib4go.Writer, error) {
		return nil, errRawEntryNoZlib
	}

	src := t.TempDir()
	mustWriteFile(t, filepath.Join(src, "a.txt"), []byte("target contents\n"), 0o644)
	var buf bytes.Buffer
	a, err := NewArchiver(&buf, src, WithArchiverTorrentZip(true), WithArchiverMethod(Deflate), WithArchiverLevel(9))
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	defer func() { _ = a.Close() }()
	if err := a.Archive(context.Background(), walkFilesFor(t, src)); !errors.Is(err, errRawEntryNoZlib) {
		t.Fatalf("archiving gave %v, want the compressor's refusal", err)
	}
}
