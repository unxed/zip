package zip

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

// The zip64 record an entry needs is the updater's to write, and an entry read
// out of an archive usually arrives with one already in its extra field.
// Appending a second left the reader looking at the first: where the two
// disagreed the archive came back refused, and where they agreed the extra
// field simply grew by twenty eight bytes on every open and close, without
// bound, until its two byte length could no longer hold it. Found by fuzzing.
// The record is replaced now, never appended to.

// updaterStaleZip64Zip is an archive whose one entry already carries a well
// formed zip64 record holding numbers of its own.
var updaterStaleZip64Zip = []byte{
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x50, 0x4b, 0x01, 0x02, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0xff, 0xff, 0xff, 0xff, 0x08, 0x00, 0x1c, 0x00, 0x00, 0x00,
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00,
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x01, 0x00, 0x18, 0x00,
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x30, 0xff, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x50, 0x4b, 0x05, 0x06, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x01, 0x00,
	0x30, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// TestUpdaterCloseReplacesAStaleZip64Record pins the first face: an entry
// whose old record disagrees with the numbers the updater writes stays
// readable across an open and a close that changed nothing.
func TestUpdaterCloseReplacesAStaleZip64Record(t *testing.T) {
	r, err := NewReader(bytes.NewReader(updaterStaleZip64Zip), int64(len(updaterStaleZip64Zip)))
	if err != nil {
		t.Fatalf("the archive itself parses; NewReader reported %v", err)
	}
	if err := validateExtra(r.File[0].Extra); err != nil {
		t.Fatalf("the entry's extra area parses; validateExtra reported %v", err)
	}

	m := &memFile{data: append([]byte(nil), updaterStaleZip64Zip...)}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater refused an archive NewReader accepts: %v", err)
	}
	// No removal, no append, no comment: nothing at all.
	if err := u.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := NewReader(bytes.NewReader(m.data), int64(len(m.data))); err != nil {
		t.Fatalf("opening the archive and closing it with no edits turned %d readable bytes into %d the reader rejects: %v",
			len(updaterStaleZip64Zip), len(m.data), err)
	}
}

// zip64RecordZip lays out one small stored entry that uses the zip64 sizes and
// already carries a well formed zip64 record whose numbers are right.
func zip64RecordZip() []byte {
	body := []byte("hello")
	name := "a.txt"
	var buf bytes.Buffer

	lh := make([]byte, 30)
	binary.LittleEndian.PutUint32(lh[0:4], fileHeaderSignature)
	binary.LittleEndian.PutUint16(lh[4:6], 45)
	binary.LittleEndian.PutUint16(lh[8:10], Store)
	binary.LittleEndian.PutUint32(lh[14:18], crc32.ChecksumIEEE(body))
	// #nosec G115 -- the body is five bytes
	binary.LittleEndian.PutUint32(lh[18:22], uint32(len(body)))
	// #nosec G115 -- the body is five bytes
	binary.LittleEndian.PutUint32(lh[22:26], uint32(len(body)))
	// #nosec G115 -- the name is five bytes
	binary.LittleEndian.PutUint16(lh[26:28], uint16(len(name)))
	buf.Write(lh)
	buf.WriteString(name)
	buf.Write(body)

	z := make([]byte, 4+24)
	binary.LittleEndian.PutUint16(z[0:2], zip64ExtraID)
	binary.LittleEndian.PutUint16(z[2:4], 24)
	binary.LittleEndian.PutUint64(z[4:12], uint64(1)<<32)
	binary.LittleEndian.PutUint64(z[12:20], uint64(1)<<32)
	binary.LittleEndian.PutUint64(z[20:28], 0)

	cdOff := buf.Len()
	ch := make([]byte, 46)
	binary.LittleEndian.PutUint32(ch[0:4], directoryHeaderSignature)
	binary.LittleEndian.PutUint16(ch[4:6], 45)
	binary.LittleEndian.PutUint16(ch[6:8], 45)
	binary.LittleEndian.PutUint16(ch[10:12], Store)
	binary.LittleEndian.PutUint32(ch[16:20], crc32.ChecksumIEEE(body))
	binary.LittleEndian.PutUint32(ch[20:24], uint32max)
	binary.LittleEndian.PutUint32(ch[24:28], uint32max)
	// #nosec G115 -- the name is five bytes
	binary.LittleEndian.PutUint16(ch[28:30], uint16(len(name)))
	// #nosec G115 -- the record is twenty eight bytes
	binary.LittleEndian.PutUint16(ch[30:32], uint16(len(z)))
	binary.LittleEndian.PutUint32(ch[42:46], uint32max)
	buf.Write(ch)
	buf.WriteString(name)
	buf.Write(z)

	cdSize := buf.Len() - cdOff
	eocd := make([]byte, 22)
	binary.LittleEndian.PutUint32(eocd[0:4], directoryEndSignature)
	binary.LittleEndian.PutUint16(eocd[8:10], 1)
	binary.LittleEndian.PutUint16(eocd[10:12], 1)
	// #nosec G115 -- the archive is under two hundred bytes
	binary.LittleEndian.PutUint32(eocd[12:16], uint32(cdSize))
	// #nosec G115 -- the archive is under two hundred bytes
	binary.LittleEndian.PutUint32(eocd[16:20], uint32(cdOff))
	buf.Write(eocd)
	return buf.Bytes()
}

// TestUpdaterCloseDoesNotGrowTheExtraArea is the second face: an archive that
// stays readable still grew on every cycle, because the record was appended
// rather than replaced.
func TestUpdaterCloseDoesNotGrowTheExtraArea(t *testing.T) {
	cur := zip64RecordZip()
	r, err := NewReader(bytes.NewReader(cur), int64(len(cur)))
	if err != nil {
		t.Fatalf("the archive itself parses; NewReader reported %v", err)
	}
	first := len(r.File[0].Extra)

	for i := 1; i <= 4; i++ {
		m := &memFile{data: append([]byte(nil), cur...)}
		u, err := NewUpdater(m)
		if err != nil {
			t.Fatalf("cycle %d: NewUpdater: %v", i, err)
		}
		if err := u.Close(); err != nil {
			t.Fatalf("cycle %d: Close: %v", i, err)
		}
		cur = m.data
		r, err := NewReader(bytes.NewReader(cur), int64(len(cur)))
		if err != nil {
			t.Fatalf("cycle %d: the reader rejects the result: %v", i, err)
		}
		got := len(r.File[0].Extra)
		if got != first {
			t.Fatalf("cycle %d: the entry's extra area grew from %d bytes to %d across an open and close that changed nothing",
				i, first, got)
		}
	}
}

// TestUpdaterCloseKeepsOtherExtraRecords pins that only the zip64 record is
// the updater's to replace: everything else the entry carried comes through.
func TestUpdaterCloseKeepsOtherExtraRecords(t *testing.T) {
	var before bytes.Buffer
	w := NewWriter(&before)
	fw, err := w.CreateHeader(&FileHeader{
		Name:   "a.txt",
		Method: Store,
		Extra:  []byte{0x99, 0x99, 0x04, 0x00, 'k', 'e', 'e', 'p'},
	})
	if err != nil {
		t.Fatalf("CreateHeader: %v", err)
	}
	if _, err := fw.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	m := &memFile{data: before.Bytes()}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := NewReader(bytes.NewReader(m.data), int64(len(m.data)))
	if err != nil {
		t.Fatalf("the reader rejects the result: %v", err)
	}
	if !bytes.Contains(r.File[0].Extra, []byte("keep")) {
		t.Fatalf("the entry's own extra record did not survive the cycle: % x", r.File[0].Extra)
	}
	rc, err := r.File[0].Open()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got := make([]byte, 5)
	if _, err := rc.Read(got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("read close: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("the entry reads back as %q", got)
	}
}
