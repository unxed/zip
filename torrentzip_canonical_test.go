package zip

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A torrentzip archive is a fixed sequence of bytes for a given set of files:
// every entry deflated at the maximum level, no extra fields, no external
// attributes and no creator version, with the checksum of the whole directory
// in the archive comment. Anything that contradicts that is refused now, at
// the point the contradiction is asked for, rather than written into an
// archive that cannot be read and does not deserve its comment.
//
// What used to happen: the normalisation in CreateRaw rewrote the method of an
// entry whose bytes the caller had already handed over, so stored bytes went
// out under a header saying they were deflated -- and the same rewrite zeroed
// the attributes, so a symbolic link stopped being one as well. Found by
// fuzzing.

// TestTorrentZipCreateRawRefusesBytesItCannotCallDeflated pins the refusal on
// the writer. The caller's bytes are the caller's; a header that would not
// describe them is not written.
func TestTorrentZipCreateRawRefusesBytesItCannotCallDeflated(t *testing.T) {
	for _, method := range []uint16{Store, ZSTD} {
		var buf bytes.Buffer
		zw := NewWriter(&buf)
		zw.SetTorrentZip(true)

		fh := &FileHeader{
			Name:               "link",
			Method:             method,
			CompressedSize64:   10,
			UncompressedSize64: 10,
		}
		_, err := zw.CreateRaw(fh)
		if err == nil {
			t.Fatalf("method %d: CreateRaw accepted bytes torrentzip would relabel", method)
		}
		if !strings.Contains(err.Error(), "torrentzip") {
			t.Errorf("method %d: the refusal does not name torrentzip: %v", method, err)
		}
		if !strings.Contains(err.Error(), "link") {
			t.Errorf("method %d: the refusal does not name the entry: %v", method, err)
		}
		if fh.Method != method {
			t.Errorf("method %d: the refused entry came back as method %d", method, fh.Method)
		}
		if buf.Len() != 0 {
			t.Errorf("method %d: %d bytes were written for an entry that was refused", method, buf.Len())
		}
	}
}

// TestTorrentZipCreateRawWritesDeflatedBytes is the other half: a raw entry
// that is deflated is what torrentzip says it is, and still goes through.
func TestTorrentZipCreateRawWritesDeflatedBytes(t *testing.T) {
	var plain bytes.Buffer
	pw := NewWriter(&plain)
	w, err := pw.CreateHeader(&FileHeader{Name: "a.txt", Method: Deflate})
	if err != nil {
		t.Fatalf("create the entry to copy: %v", err)
	}
	if _, err := io.WriteString(w, "bytes that deflate"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	pr, err := NewReader(bytes.NewReader(plain.Bytes()), int64(plain.Len()))
	if err != nil {
		t.Fatalf("read the archive to copy from: %v", err)
	}

	var buf bytes.Buffer
	zw := NewWriter(&buf)
	zw.SetTorrentZip(true)
	if err := zw.Copy(pr.File[0]); err != nil {
		t.Fatalf("copying a deflated entry into a torrentzip archive: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close the torrentzip archive: %v", err)
	}

	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("the writer produced an archive the reader rejects: %v", err)
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got, err := io.ReadAll(rc)
	if cerr := rc.Close(); cerr != nil {
		t.Fatalf("close the entry: %v", cerr)
	}
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "bytes that deflate" {
		t.Errorf("the entry came back as %q", got)
	}
}

// TestTorrentZipSettlesTheMethodWhateverTheOptionOrder pins the archiver
// settling torrentzip once every option has run. A method torrentzip cannot
// honour is refused whichever order the two options were given in; before, the
// answer depended on which came last, and one of the two orders wrote an
// archive whose entries no reader could decode.
func TestTorrentZipSettlesTheMethodWhateverTheOptionOrder(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []ArchiverOption
	}{
		{"torrentzip first", []ArchiverOption{WithArchiverTorrentZip(true), WithArchiverMethod(Store)}},
		{"the method first", []ArchiverOption{WithArchiverMethod(Store), WithArchiverTorrentZip(true)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, err := NewArchiver(&buf, t.TempDir(), tc.opts...)
			if err == nil {
				t.Fatal("an archiver was built for torrentzip over stored entries")
			}
			if !strings.Contains(err.Error(), "torrentzip") {
				t.Errorf("the refusal does not name torrentzip: %v", err)
			}
			if buf.Len() != 0 {
				t.Errorf("%d bytes were written by an archiver that was refused", buf.Len())
			}
		})
	}
}

// TestTorrentZipRefusesALevelItCannotHonour is the same for the compression
// level: the canonical bytes are the ones the maximum level produces.
func TestTorrentZipRefusesALevelItCannotHonour(t *testing.T) {
	var buf bytes.Buffer
	if _, err := NewArchiver(&buf, t.TempDir(), WithArchiverTorrentZip(true), WithArchiverLevel(5)); err == nil {
		t.Fatal("an archiver was built for torrentzip at a level other than the maximum")
	} else if !strings.Contains(err.Error(), "torrentzip") {
		t.Errorf("the refusal does not name torrentzip: %v", err)
	}
}

// TestTorrentZipSettlesWhatWasNotAskedFor pins what torrentzip decides on its
// own, and that saying the same thing out loud is not a contradiction.
func TestTorrentZipSettlesWhatWasNotAskedFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []ArchiverOption
	}{
		{"nothing else asked for", nil},
		{"the same method and level asked for", []ArchiverOption{WithArchiverMethod(Deflate), WithArchiverLevel(9)}},
		// Zero is what this package means by "the compressor's own
		// default" rather than a level of its own, so asking for it
		// asks for nothing and contradicts nothing.
		{"the default level asked for", []ArchiverOption{WithArchiverLevel(0)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			a, err := NewArchiver(&buf, t.TempDir(), append([]ArchiverOption{WithArchiverTorrentZip(true)}, tc.opts...)...)
			if err != nil {
				t.Fatalf("building the archiver: %v", err)
			}
			closeAt(t, a)
			if a.options.method != Deflate {
				t.Errorf("torrentzip settled on method %d, want %d", a.options.method, Deflate)
			}
			if a.options.level != 9 {
				t.Errorf("torrentzip settled on level %d, want 9", a.options.level)
			}
			if a.options.concurrency != 1 {
				t.Errorf("torrentzip settled on %d workers, want 1", a.options.concurrency)
			}
		})
	}
}

// TestTorrentZipRefusesEntriesItCannotMakeCanonical pins the three entries
// that carry what a canonical entry has no room for. A link is a link because
// of its external attributes and its creator version, and torrentzip zeroes
// both; the archiver used to write such an entry anyway, and what came back
// was neither a link nor readable.
func TestTorrentZipRefusesEntriesItCannotMakeCanonical(t *testing.T) {
	srcDir := t.TempDir()

	for _, tc := range []struct {
		name  string
		what  string
		write func(t *testing.T, a *Archiver, hdr *FileHeader, fi os.FileInfo) error
	}{
		{"a symbolic link", "link", func(_ *testing.T, a *Archiver, hdr *FileHeader, fi os.FileInfo) error {
			return a.createSymlink(filepath.Join(srcDir, "link"), fi, hdr)
		}},
		{"a hard link", "hard", func(_ *testing.T, a *Archiver, hdr *FileHeader, fi os.FileInfo) error {
			hdr.Linkname = "target.txt"
			return a.createHardlink(fi, hdr)
		}},
		{"a device node", "node", func(_ *testing.T, a *Archiver, hdr *FileHeader, fi os.FileInfo) error {
			return a.createSpecialFile(fi, hdr)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			a := ArchiverCovNewArchiver(t, &buf, srcDir, WithArchiverTorrentZip(true))

			hdr, fi := ArchiverCovHeader(tc.what, Store, 0)
			err := tc.write(t, a, hdr, fi)
			if err == nil {
				t.Fatalf("torrentzip wrote %s", tc.name)
			}
			if !strings.Contains(err.Error(), "torrentzip") {
				t.Errorf("the refusal does not name torrentzip: %v", err)
			}
			if !strings.Contains(err.Error(), tc.what) {
				t.Errorf("the refusal does not name the entry: %v", err)
			}
			if buf.Len() != 0 {
				t.Errorf("%d bytes were written for an entry that was refused", buf.Len())
			}
		})
	}
}

// TestTorrentZipRefusesATreeWithALink is the shape the defect was found in:
// the archiver walking a directory that holds a symbolic link.
func TestTorrentZipRefusesATreeWithALink(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.Symlink("target.txt", filepath.Join(srcDir, "link")); err != nil {
		t.Skipf("symlinks cannot be created here: %v", err)
	}

	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, srcDir, WithArchiverTorrentZip(true))
	err := a.Archive(context.Background(), walkFilesFor(t, srcDir))
	if err == nil {
		t.Fatal("a tree holding a symbolic link was torrentzipped")
	}
	if !strings.Contains(err.Error(), "link") {
		t.Errorf("the refusal does not name the entry: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("%d bytes were written for an archive that was refused", buf.Len())
	}
}

// TestTorrentZipEmptyEntryIsDeflatedByName pins the empty entry the archiver
// writes by hand: it is two bytes of empty deflate block, and its header says
// so on its own rather than by being rewritten afterwards.
func TestTorrentZipEmptyEntryIsDeflatedByName(t *testing.T) {
	srcDir := t.TempDir()
	mustWriteFile(t, filepath.Join(srcDir, "empty.txt"), nil, 0o600)

	archive := ArchiverCovArchiveOne(t, srcDir, WithArchiverTorrentZip(true))
	entry, ok := findLocalEntry(t, archive, "empty.txt")
	if !ok {
		t.Fatal("the archive holds no empty.txt entry")
	}
	if entry.method != Deflate {
		t.Errorf("the empty entry uses method %d, want %d", entry.method, Deflate)
	}
	if !bytes.Equal(entry.payload, []byte{0x03, 0x00}) {
		t.Errorf("the empty entry holds %x, want the empty deflate block 0300", entry.payload)
	}
}

// TestTorrentZipRefusalsCarryTheirReason pins that every one of these refusals
// can be told apart from a failure to write by what it wraps.
func TestTorrentZipRefusalsCarryTheirReason(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	zw.SetTorrentZip(true)
	_, rawErr := zw.CreateRaw(&FileHeader{Name: "a.bin", Method: Store})
	if !errors.Is(rawErr, errTorrentZipCanonical) {
		t.Errorf("CreateRaw refused with %v, which does not carry the reason", rawErr)
	}

	_, optErr := NewArchiver(&buf, t.TempDir(), WithArchiverTorrentZip(true), WithArchiverMethod(Store))
	if !errors.Is(optErr, errTorrentZipCanonical) {
		t.Errorf("the archiver refused with %v, which does not carry the reason", optErr)
	}

	a := ArchiverCovNewArchiver(t, &buf, t.TempDir(), WithArchiverTorrentZip(true))
	hdr, fi := ArchiverCovHeader("node", Store, 0)
	if err := a.createSpecialFile(fi, hdr); !errors.Is(err, errTorrentZipLink) {
		t.Errorf("the entry was refused with %v, which does not carry the reason", err)
	}
}
