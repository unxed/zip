package zip

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// TestUpdater_DirectoryEntryHasItsOwnLocalHeader: a directory the Updater
// appends is written with a local header of its own, and the central directory
// record for every entry points at the local header of that entry. The
// directory used to be recorded in the central directory only, with the offset
// of whatever was appended next -- here the file inside it -- which 7-Zip
// reports as a header error.
func TestUpdater_DirectoryEntryHasItsOwnLocalHeader(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "update.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create the archive: %v", err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	mustWrite(t, mustCreateHeader(t, zw, &FileHeader{Name: "first.txt", Method: Deflate}), []byte("first"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	rw, err := os.OpenFile(zipPath, os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open for update: %v", err)
	}
	closeAt(t, rw)
	u, err := NewUpdater(rw)
	if err != nil {
		t.Fatalf("init updater: %v", err)
	}
	for _, name := range []string{"added/", "added/nested/"} {
		if _, err := u.AppendHeader(&FileHeader{Name: name}, APPEND_MODE_OVERWRITE); err != nil {
			t.Fatalf("append the directory %q: %v", name, err)
		}
	}
	w, err := u.AppendHeader(&FileHeader{Name: "added/nested/file.txt", Method: Deflate}, APPEND_MODE_OVERWRITE)
	if err != nil {
		t.Fatalf("append the file: %v", err)
	}
	mustWrite(t, w, []byte("contents"))
	if err := u.Close(); err != nil {
		t.Fatalf("close updater: %v", err)
	}

	raw, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatalf("read the archive: %v", err)
	}
	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("read the archive back: %v", err)
	}
	if len(zr.File) != 4 {
		t.Fatalf("the archive holds %d entries, want 4", len(zr.File))
	}
	for _, f := range zr.File {
		at := f.headerOffset
		if at+fileHeaderLen > int64(len(raw)) || !bytes.Equal(raw[at:at+4], []byte{'P', 'K', 0x03, 0x04}) {
			t.Fatalf("%s: no local file header at offset %d", f.Name, at)
		}
		nameLen := int64(binary.LittleEndian.Uint16(raw[at+26 : at+28]))
		if got := string(raw[at+fileHeaderLen : at+fileHeaderLen+nameLen]); got != f.Name {
			t.Errorf("%s: the local header at offset %d is %q's", f.Name, at, got)
		}
	}
}
