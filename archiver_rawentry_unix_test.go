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

// TestArchiverRawEntries_EncodedAsTheHeaderSays: with a password the body of
// a symlink, FIFO or hard link is a WinZip AES body, and under torrentzip a
// deflate stream, as the header written for it claims. Written as they came,
// 7-Zip refused the first with a header error and the second with a data
// error, and this package could not read either back.
func TestArchiverRawEntries_EncodedAsTheHeaderSays(t *testing.T) {
	src := rawEntryTree(t)
	for _, tc := range []struct {
		name      string
		opts      []ArchiverOption
		password  string
		method    uint16
		emptyBody uint64
	}{
		{"password", []ArchiverOption{WithArchiverPassword("pw")}, "pw", winzipAesMethod, 16 + 2 + 10},
		{"torrentzip", []ArchiverOption{WithArchiverTorrentZip(true)}, "", Deflate, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			a, err := NewArchiver(&buf, src, tc.opts...)
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

			got := aesWinZipReadAll(t, raw, tc.password)
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
				if f.Name != "lnk" && f.Name != "fifo" {
					continue
				}
				if f.Method != tc.method {
					t.Errorf("%s: method %d, want %d", f.Name, f.Method, tc.method)
				}
				if f.Name == "fifo" && f.CompressedSize64 != tc.emptyBody {
					t.Errorf("fifo: body of %d bytes, want %d", f.CompressedSize64, tc.emptyBody)
				}
			}
		})
	}
}

var errRawEntryNoZlib = errors.New("no zlib stream for this test")

// TestArchiverRawEntries_TorrentZipCompressorRefuses: a symlink's body goes
// through the compressor torrentzip registers, and its refusal comes back out
// rather than an entry with no body.
func TestArchiverRawEntries_TorrentZipCompressorRefuses(t *testing.T) {
	real := newZlibWriterLevel
	t.Cleanup(func() { newZlibWriterLevel = real })
	newZlibWriterLevel = func(io.Writer, int) (*zlib4go.Writer, error) {
		return nil, errRawEntryNoZlib
	}

	src := t.TempDir()
	if err := os.Symlink("elsewhere", filepath.Join(src, "lnk")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
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
