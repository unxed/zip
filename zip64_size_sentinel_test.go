package zip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"
)

// An uncompressed size of 0xFFFFFFFF with no zip64 record behind it is a claim
// the archive has not substantiated -- 4 GiB declared for a five byte entry.
// It is not refused at the reader, because an archive written before zip64
// existed may hold that as a real size; it is refused where a claim is weighed,
// and the archive it comes from must survive an updater that has no room to put
// the record such a size would need. Found by fuzzing.

// sentinelSizeZip writes one five byte stored entry whose central header
// claims the zip64 uncompressed-size sentinel with no zip64 record behind it.
// extra goes on the central header.
func sentinelSizeZip(extra []byte) []byte {
	body := []byte("hello")
	name := "a.txt"
	var buf bytes.Buffer

	lh := make([]byte, 30)
	binary.LittleEndian.PutUint32(lh[0:4], fileHeaderSignature)
	binary.LittleEndian.PutUint16(lh[4:6], 20)
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

	cdOff := buf.Len()
	ch := make([]byte, 46)
	binary.LittleEndian.PutUint32(ch[0:4], directoryHeaderSignature)
	binary.LittleEndian.PutUint16(ch[4:6], 20)
	binary.LittleEndian.PutUint16(ch[6:8], 20)
	binary.LittleEndian.PutUint16(ch[10:12], Store)
	binary.LittleEndian.PutUint32(ch[16:20], crc32.ChecksumIEEE(body))
	// #nosec G115 -- the body is five bytes
	binary.LittleEndian.PutUint32(ch[20:24], uint32(len(body)))
	binary.LittleEndian.PutUint32(ch[24:28], uint32max) // the marker, with nothing behind it
	// #nosec G115 -- the name is five bytes
	binary.LittleEndian.PutUint16(ch[28:30], uint16(len(name)))
	// #nosec G115 -- the caller passes a short extra
	binary.LittleEndian.PutUint16(ch[30:32], uint16(len(extra)))
	buf.Write(ch)
	buf.WriteString(name)
	buf.Write(extra)

	cdSize := buf.Len() - cdOff
	eocd := make([]byte, 22)
	binary.LittleEndian.PutUint32(eocd[0:4], directoryEndSignature)
	binary.LittleEndian.PutUint16(eocd[8:10], 1)
	binary.LittleEndian.PutUint16(eocd[10:12], 1)
	// #nosec G115 -- the archive is a hundred and change bytes
	binary.LittleEndian.PutUint32(eocd[12:16], uint32(cdSize))
	// #nosec G115 -- the archive is a hundred and change bytes
	binary.LittleEndian.PutUint32(eocd[16:20], uint32(cdOff))
	buf.Write(eocd)
	return buf.Bytes()
}

// TestUnbackedZip64SizeIsReadAsAClaim pins that the reader hands the number
// over rather than refusing it, and that the entry itself still reads: an
// uncompressed size of exactly 2^32-1 was a real size before zip64 existed,
// and only the compressed size and the local header offset could not be.
func TestUnbackedZip64SizeIsReadAsAClaim(t *testing.T) {
	data := sentinelSizeZip(nil)

	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("the entry was refused: %v", err)
	}
	f := r.File[0]
	if f.UncompressedSize64 != uint32max {
		t.Fatalf("the declared size came out as %d", f.UncompressedSize64)
	}
	rc, err := f.Open()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	got := make([]byte, 5)
	if _, err := rc.Read(got); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = rc.Close()
	if string(got) != "hello" {
		t.Fatalf("the entry reads back as %q", got)
	}
}

// TestUnbackedZip64SizeIsRefusedByBothExtractionLimits pins where the claim is
// weighed: the size limit turns the entry down on its own declaration, and with
// the size limit off the ratio does it instead. Only a caller who switches both
// off gets what the archive asked for.
func TestUnbackedZip64SizeIsRefusedByBothExtractionLimits(t *testing.T) {
	data := sentinelSizeZip(nil)

	for _, tc := range []struct {
		name string
		opts []ExtractorOption
		want error
	}{
		{"the default size limit", nil, ErrSizeLimit},
		{"the ratio with no size limit", []ExtractorOption{WithExtractorMaxFileSize(0)}, ErrRatioLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]ExtractorOption{WithExtractorConcurrency(1), WithExtractorNoTimes(true)}, tc.opts...)
			e, err := NewExtractorFromReader(bytes.NewReader(data), int64(len(data)), t.TempDir(), opts...)
			if err != nil {
				t.Fatalf("new extractor: %v", err)
			}
			defer func() { _ = e.Close() }()
			err = e.Extract(context.Background())
			if !errors.Is(err, tc.want) {
				t.Fatalf("the extraction answered %v", err)
			}
		})
	}
}

// TestUnbackedZip64SizeIsRefusedByTheUpdater pins the consequence that was a
// defect: the entry's declared size makes the directory need a zip64 record,
// its extra area cannot be walked to the end, and a record written behind such
// an area is one no reader ever reaches. The archive is turned away whole
// rather than opened and destroyed.
func TestUnbackedZip64SizeIsRefusedByTheUpdater(t *testing.T) {
	data := sentinelSizeZip(bytes.Repeat([]byte("0"), 48))
	before := append([]byte(nil), data...)

	m := &memFile{data: data}
	u, err := NewUpdater(m)
	if err == nil {
		err = u.Close()
		if err == nil {
			t.Fatalf("an open and close with no edits turned %d bytes into %d", len(before), len(m.data))
		}
	}
	if !errors.Is(err, ErrFormat) {
		t.Fatalf("the updater refused with %v, not as a malformed archive", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("a.txt")) {
		t.Errorf("the refusal does not name the entry: %v", err)
	}
	if !bytes.Equal(m.data, before) {
		t.Fatalf("the refused archive was modified: %d bytes in, %d out", len(before), len(m.data))
	}
}

// TestUnwalkableExtraSurvivesTheUpdaterWhenNoRecordIsNeeded is the control on
// the refusal above: an entry the updater has nothing to add to comes back out
// exactly as it went in, junk extra area and all.
func TestUnwalkableExtraSurvivesTheUpdaterWhenNoRecordIsNeeded(t *testing.T) {
	junk := bytes.Repeat([]byte("0"), 48)

	var built bytes.Buffer
	w := NewWriter(&built)
	fw, err := w.CreateRaw(&FileHeader{Name: "a.txt", Method: Store})
	if err != nil {
		t.Fatalf("CreateRaw: %v", err)
	}
	if _, err := fw.Write(nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Put the junk on the central header, which is where an entry read out
	// of an archive carries it.
	raw := built.Bytes()
	cd := bytes.Index(raw, []byte{'P', 'K', 0x01, 0x02})
	if cd < 0 {
		t.Fatal("the archive has no central directory")
	}
	// #nosec G115 -- the junk is forty eight bytes
	binary.LittleEndian.PutUint16(raw[cd+30:cd+32], uint16(len(junk)))
	nameLen := int(binary.LittleEndian.Uint16(raw[cd+28 : cd+30]))
	patched := append([]byte(nil), raw[:cd+46+nameLen]...)
	patched = append(patched, junk...)
	patched = append(patched, raw[cd+46+nameLen:]...)
	eocd := bytes.LastIndex(patched, []byte{'P', 'K', 0x05, 0x06})
	// #nosec G115 -- the archive is a couple of hundred bytes
	binary.LittleEndian.PutUint32(patched[eocd+12:eocd+16], uint32(len(patched)-22-cd))

	if _, err := NewReader(bytes.NewReader(patched), int64(len(patched))); err != nil {
		t.Fatalf("the archive with the junk extra area does not read: %v", err)
	}

	m := &memFile{data: append([]byte(nil), patched...)}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater refused an entry it has nothing to add to: %v", err)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r, err := NewReader(bytes.NewReader(m.data), int64(len(m.data)))
	if err != nil {
		t.Fatalf("the reader rejects the result: %v", err)
	}
	if !bytes.Equal(r.File[0].Extra, junk) {
		t.Fatalf("the entry's extra area came back as % x", r.File[0].Extra)
	}
}

// TestBackedZip64UncompressedSizeStillReads keeps everything above away from
// the case the marker exists for: the record is there and holds the size.
func TestBackedZip64UncompressedSizeStillReads(t *testing.T) {
	z := make([]byte, 4+8)
	binary.LittleEndian.PutUint16(z[0:2], zip64ExtraID)
	binary.LittleEndian.PutUint16(z[2:4], 8)
	binary.LittleEndian.PutUint64(z[4:12], 5)

	data := sentinelSizeZip(z)
	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("an entry whose zip64 record holds the size is refused: %v", err)
	}
	if got := r.File[0].UncompressedSize64; got != 5 {
		t.Fatalf("the size came out as %d, and the record says 5", got)
	}
}
