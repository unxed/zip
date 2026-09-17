package zip

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// writeSplitArchive builds a ZIP split archive the way WinZip, WinRAR and
// Info-ZIP's "zip -s" do: the bytes of one archive cut into archive.z01 and
// archive.zip, with every central directory entry naming the volume it starts
// on and its offset counted from that volume's start (APPNOTE 4.4.15, 4.4.16).
// It returns the path of the last volume, the one holding the directory.
func writeSplitArchive(t *testing.T, dir string, members map[string][]byte) string {
	t.Helper()

	var buf bytes.Buffer
	w := NewWriter(&buf)
	names := []string{"first.bin", "second.bin"}
	for _, name := range names {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(members[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()

	// Cut in front of the second entry, so one entry lands on each volume.
	split := bytes.Index(data[4:], []byte("PK\x03\x04"))
	if split < 0 {
		t.Fatal("second local header not found")
	}
	split += 4

	end := bytes.LastIndex(data, []byte("PK\x05\x06"))
	if end < 0 {
		t.Fatal("end of central directory not found")
	}
	directoryOffset := int(binary.LittleEndian.Uint32(data[end+16 : end+20]))
	binary.LittleEndian.PutUint16(data[end+4:end+6], 1) // this disk
	binary.LittleEndian.PutUint16(data[end+6:end+8], 1) // disk with the directory
	// #nosec G115 -- the archive is a few kilobytes
	binary.LittleEndian.PutUint32(data[end+16:end+20], uint32(directoryOffset-split))

	for p := directoryOffset; p < end; {
		if !bytes.Equal(data[p:p+4], []byte("PK\x01\x02")) {
			t.Fatalf("central directory entry expected at %d", p)
		}
		nameLen := int(binary.LittleEndian.Uint16(data[p+28 : p+30]))
		extraLen := int(binary.LittleEndian.Uint16(data[p+30 : p+32]))
		commentLen := int(binary.LittleEndian.Uint16(data[p+32 : p+34]))
		offset := int(binary.LittleEndian.Uint32(data[p+42 : p+46]))
		if offset >= split {
			binary.LittleEndian.PutUint16(data[p+34:p+36], 1) // disk number start
			// #nosec G115 -- see above
			binary.LittleEndian.PutUint32(data[p+42:p+46], uint32(offset-split))
		}
		p += 46 + nameLen + extraLen + commentLen
	}

	first := filepath.Join(dir, "archive.z01")
	last := filepath.Join(dir, "archive.zip")
	if err := os.WriteFile(first, data[:split], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(last, data[split:], 0o600); err != nil {
		t.Fatal(err)
	}
	return last
}

// A split archive must read the same whichever of its volumes names it: the
// entries of the earlier volumes used to come back as "not a valid zip file"
// or as garbage, because one base offset was applied to every entry.
func TestSplitArchiveReadsEveryVolume(t *testing.T) {
	dir := t.TempDir()
	members := map[string][]byte{
		"first.bin":  bytes.Repeat([]byte("first volume payload\n"), 200),
		"second.bin": bytes.Repeat([]byte("second volume payload\n"), 200),
	}
	last := writeSplitArchive(t, dir, members)

	for _, name := range []string{last, filepath.Join(dir, "archive.z01")} {
		rc, err := OpenReader(name)
		if err != nil {
			t.Fatalf("OpenReader(%s): %v", filepath.Base(name), err)
		}
		if len(rc.File) != len(members) {
			t.Fatalf("OpenReader(%s): %d entries, want %d", filepath.Base(name), len(rc.File), len(members))
		}
		for _, f := range rc.File {
			r, err := f.Open()
			if err != nil {
				t.Fatalf("%s: open %s: %v", filepath.Base(name), f.Name, err)
			}
			got, err := io.ReadAll(r)
			_ = r.Close()
			if err != nil {
				t.Fatalf("%s: read %s: %v", filepath.Base(name), f.Name, err)
			}
			if !bytes.Equal(got, members[f.Name]) {
				t.Fatalf("%s: %s read back %d bytes, want %d", filepath.Base(name), f.Name, len(got), len(members[f.Name]))
			}
		}
		_ = rc.Close()
	}
}
