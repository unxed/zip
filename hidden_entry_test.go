package zip

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// localExtraOf returns the extra field of the local header named name.
func localExtraOf(t *testing.T, archive []byte, name string) []byte {
	t.Helper()
	for i := 0; i+fileHeaderLen <= len(archive); i++ {
		if binary.LittleEndian.Uint32(archive[i:]) != fileHeaderSignature {
			continue
		}
		nameLen := int(binary.LittleEndian.Uint16(archive[i+26:]))
		extraLen := int(binary.LittleEndian.Uint16(archive[i+28:]))
		start := i + fileHeaderLen
		if start+nameLen+extraLen > len(archive) {
			continue
		}
		if string(archive[start:start+nameLen]) == name {
			return archive[start+nameLen : start+nameLen+extraLen]
		}
	}
	t.Fatalf("no local header named %q", name)
	return nil
}

// tagSize reports the payload size of the tag id in extra, or -1 without it.
func tagSize(extra []byte, id uint16) int {
	for len(extra) >= 4 {
		tag := binary.LittleEndian.Uint16(extra[0:2])
		size := int(binary.LittleEndian.Uint16(extra[2:4]))
		if tag == id {
			return size
		}
		if len(extra) < 4+size {
			break
		}
		extra = extra[4+size:]
	}
	return -1
}

// TestHiddenIndexCarriesTheHiddenEntryTag covers the empty 0x7812 tag on the
// local header of a seek index, which no central directory record names: the
// index carries it, the entry it indexes does not, and the reader still finds
// the index and lists only the entry.
func TestHiddenIndexCarriesTheHiddenEntryTag(t *testing.T) {
	for _, tt := range []struct {
		continuous bool
		hidden     string
	}{
		{false, ".chunk.txt.sozip.idx"},
		{true, ".chunk.txt.gzidx"},
	} {
		t.Run(tt.hidden, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf)
			fw, err := w.CreateHeader(&FileHeader{
				Name:           "chunk.txt",
				Method:         Deflate,
				SeekChunkSize:  4,
				SeekContinuous: tt.continuous,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fw.Write([]byte("chunked data")); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			b := buf.Bytes()

			if size := tagSize(localExtraOf(t, b, tt.hidden), hiddenEntryExtraID); size != 0 {
				t.Errorf("the index's 0x7812 tag has size %d, want an empty tag", size)
			}
			if size := tagSize(localExtraOf(t, b, "chunk.txt"), hiddenEntryExtraID); size != -1 {
				t.Error("the listed entry carries the 0x7812 tag")
			}

			r, err := NewReader(bytes.NewReader(b), int64(len(b)))
			if err != nil {
				t.Fatalf("NewReader: %v", err)
			}
			if len(r.File) != 1 || r.File[0].Name != "chunk.txt" {
				t.Fatalf("the archive lists %d entries, want chunk.txt alone", len(r.File))
			}
			rs, err := r.File[0].OpenSeekable()
			if err != nil {
				t.Fatalf("OpenSeekable: %v", err)
			}
			if _, err := rs.Seek(8, io.SeekStart); err != nil {
				t.Fatalf("Seek: %v", err)
			}
			got, err := io.ReadAll(rs)
			if err != nil {
				t.Fatalf("reading after the seek: %v", err)
			}
			if string(got) != "data" {
				t.Errorf("read %q after seeking to 8, want %q", got, "data")
			}
		})
	}
}
