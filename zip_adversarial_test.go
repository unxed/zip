package zip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// The fixtures below are archives that lie. Nothing here writes a zip from
// scratch: a lying size is what Writer.CreateRaw stores verbatim, and
// everything else is a fixed-width field overwritten in place in an archive
// the writer produced, so the bytes around the lie stay exactly what a real
// archive holds.

// rawEntryArchive returns an archive holding a single entry written through
// CreateRaw, which stores the sizes it is handed rather than the sizes of the
// bytes that follow -- the entry can therefore claim any size at all.
func rawEntryArchive(t *testing.T, fh *FileHeader, data []byte) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	w, err := zw.CreateRaw(fh)
	if err != nil {
		t.Fatalf("CreateRaw(%q): %v", fh.Name, err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("writing the body of %q: %v", fh.Name, err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	return buf.Bytes()
}

// localHeaderOffset returns the offset of the local header of the named entry.
// The name appears in the local header and again in the central directory, and
// the local header comes first, so the first occurrence with a local header
// signature 30 bytes in front of it is the one wanted.
func localHeaderOffset(t *testing.T, raw []byte, name string) int {
	t.Helper()
	for i := 0; ; {
		p := bytes.Index(raw[i:], []byte(name))
		if p < 0 {
			break
		}
		off := i + p - fileHeaderLen
		if off >= 0 && binary.LittleEndian.Uint32(raw[off:]) == fileHeaderSignature {
			return off
		}
		i += p + 1
	}
	t.Fatalf("no local header for %q in the archive", name)
	return 0
}

// centralHeaderOffset returns the offset of the central directory entry of the
// named entry, found the same way and by its own signature.
func centralHeaderOffset(t *testing.T, raw []byte, name string) int {
	t.Helper()
	for i := 0; ; {
		p := bytes.Index(raw[i:], []byte(name))
		if p < 0 {
			break
		}
		off := i + p - directoryHeaderLen
		if off >= 0 && binary.LittleEndian.Uint32(raw[off:]) == directoryHeaderSignature {
			return off
		}
		i += p + 1
	}
	t.Fatalf("no central directory entry for %q in the archive", name)
	return 0
}

// hiddenIndexOffsets locates the seek index the writer hides after the entry it
// indexes: the offset of its local header and the offset of the payload the
// reader parses out of it.
func hiddenIndexOffsets(t *testing.T, raw []byte, entryName string, continuous bool) (header, payload int) {
	t.Helper()
	hidden := "." + entryName + ".sozip.idx"
	if continuous {
		hidden = "." + entryName + ".gzidx"
	}
	header = localHeaderOffset(t, raw, hidden)
	nameLen := int(binary.LittleEndian.Uint16(raw[header+26:]))
	extraLen := int(binary.LittleEndian.Uint16(raw[header+28:]))
	return header, header + fileHeaderLen + nameLen + extraLen
}

// seekableArchive returns an archive whose single entry carries a seek index,
// SOZip when continuous is false and GZIDX when it is true, plus the offsets
// the tests overwrite fields at.
func seekableArchive(t *testing.T, continuous bool, size int) (raw []byte, header, payload int) {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	w, err := zw.CreateHeader(&FileHeader{
		Name:           "seek.bin",
		Method:         Deflate,
		SeekChunkSize:  1024,
		SeekContinuous: continuous,
	})
	if err != nil {
		t.Fatalf("CreateHeader: %v", err)
	}
	// Something that compresses, so the index has several distinct offsets to
	// be wrong about.
	body := make([]byte, size)
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatalf("writing the body: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	raw = buf.Bytes()
	header, payload = hiddenIndexOffsets(t, raw, "seek.bin", continuous)
	return raw, header, payload
}

// openSeekableErr reads the archive and asks its first entry for a seek index.
func openSeekableErr(t *testing.T, raw []byte) error {
	t.Helper()
	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("reading the archive: %v", err)
	}
	_, err = zr.File[0].OpenSeekable()
	return err
}

// A size the archive cannot hold is a size the reader must not believe. Both
// sizes reach the public API as int64 -- Open, OpenRaw and OpenSeekable hand
// them to io.NewSectionReader, and FileInfo returns one -- where anything above
// MaxInt64 arrives negative, and a section reader of negative length reads
// without a bound from an offset the archive chose.

// The uncompressed size is also what fs.FileInfo reports, so an entry
// carrying one above MaxInt64 is an entry whose Size() is negative; rejecting
// the entry is what keeps that from reaching a caller sizing a buffer from it.
func TestReader_RejectsUncompressedSizeAboveMaxInt64(t *testing.T) {
	body := []byte("small")
	raw := rawEntryArchive(t, &FileHeader{
		Name:               "huge.bin",
		Method:             Store,
		CompressedSize64:   uint64(len(body)),
		UncompressedSize64: 1 << 63,
	}, body)

	if _, err := NewReader(bytes.NewReader(raw), int64(len(raw))); !errors.Is(err, ErrFormat) {
		t.Fatalf("reading an entry declaring 1<<63 uncompressed bytes: got %v, want ErrFormat", err)
	}
}

func TestReader_RejectsCompressedSizeAboveMaxInt64(t *testing.T) {
	body := []byte("small")
	raw := rawEntryArchive(t, &FileHeader{
		Name:               "huge.bin",
		Method:             Store,
		CompressedSize64:   1 << 63,
		UncompressedSize64: uint64(len(body)),
	}, body)

	if _, err := NewReader(bytes.NewReader(raw), int64(len(raw))); !errors.Is(err, ErrFormat) {
		t.Fatalf("reading an entry declaring 1<<63 compressed bytes: got %v, want ErrFormat", err)
	}
}

// TestReader_RejectsHeaderOffsetAboveMaxInt64 forges the third zip64 field, the
// offset of the local header, out of the two that are already there.
// readDirectoryHeader takes the fields of the zip64 extra in the order the
// central directory asks for them -- uncompressed size, compressed size, header
// offset -- so putting the real compressed size back in the 32-bit field and
// 0xFFFFFFFF in the 32-bit offset makes the extra's second quad the offset. It
// is then negative, and every read of the entry starts from wherever that
// lands.
func TestReader_RejectsHeaderOffsetAboveMaxInt64(t *testing.T) {
	const body = "small"
	raw := rawEntryArchive(t, &FileHeader{
		Name:               "offset.bin",
		Method:             Store,
		CompressedSize64:   1 << 63,
		UncompressedSize64: uint64(len(body)),
	}, []byte(body))

	cd := centralHeaderOffset(t, raw, "offset.bin")
	binary.LittleEndian.PutUint32(raw[cd+20:], uint32(len(body))) // compressed size, no longer asked of the extra
	binary.LittleEndian.PutUint32(raw[cd+42:], uint32max)         // local header offset, now asked of the extra

	if _, err := NewReader(bytes.NewReader(raw), int64(len(raw))); !errors.Is(err, ErrFormat) {
		t.Fatalf("reading an entry whose local header offset is 1<<63: got %v, want ErrFormat", err)
	}

	tmp := filepath.Join(t.TempDir(), "offset.zip")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(tmp, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	if _, err := NewUpdater(f); !errors.Is(err, ErrFormat) {
		t.Fatalf("updating an archive whose local header offset is 1<<63: got %v, want ErrFormat", err)
	}
}

// appendZip64End puts a zip64 end record and its locator between the central
// directory and the end record, and points the end record at them by setting
// the field that says a zip64 record is in use. recordSize is written as the
// record's own size field, which the reader allocates from before it has read
// a byte of the record.
func appendZip64End(t *testing.T, raw []byte, recordSize, dirSize, dirOffset uint64) []byte {
	t.Helper()
	end := bytes.LastIndex(raw, []byte{'P', 'K', 0x05, 0x06})
	if end < 0 {
		t.Fatal("no end of central directory record in the archive")
	}
	out := append([]byte(nil), raw[:end]...)

	var rec [directory64EndLen]byte
	b := writeBuf(rec[:])
	b.uint32(directory64EndSignature)
	b.uint64(recordSize)
	b.uint16(zipVersion45)
	b.uint16(zipVersion45)
	b.uint32(0)
	b.uint32(0)
	b.uint64(1)
	b.uint64(1)
	b.uint64(dirSize)
	b.uint64(dirOffset)
	recOffset := uint64(len(out))
	out = append(out, rec[:]...)

	var loc [directory64LocLen]byte
	b = writeBuf(loc[:])
	b.uint32(directory64LocSignature)
	b.uint32(0)
	b.uint64(recOffset)
	b.uint32(1)
	out = append(out, loc[:]...)

	tail := append([]byte(nil), raw[end:]...)
	binary.LittleEndian.PutUint32(tail[16:], uint32max) // the directory offset now lives in the zip64 record
	return append(out, tail...)
}

// TestReader_Zip64EndRecordSizeIsBounded: the size of the zip64 end record is
// eight bytes of the archive's choosing, and the reader made a buffer of it
// before reading anything into it. A quarter of the address space asked for
// this way is a panic rather than an archive the reader rejects, and a record
// shorter than the fields read out of it runs off the end of its own buffer.
func TestReader_Zip64EndRecordSizeIsBounded(t *testing.T) {
	body := []byte("small")
	raw := rawEntryArchive(t, &FileHeader{
		Name:               "entry.bin",
		Method:             Store,
		CompressedSize64:   uint64(len(body)),
		UncompressedSize64: uint64(len(body)),
	}, body)

	for _, tc := range []struct {
		name       string
		recordSize uint64
	}{
		{"a quarter of the address space", 1 << 63},
		{"shorter than the fields it holds", 10},
		// What follows a record is the zip64 locator and the end record,
		// and a record that claims to reach past where the locator says
		// it ends has those read as its version 2 fields -- where the end
		// record's signature carries the bit that says the central
		// directory is encrypted. Exactly the version 2 length is the
		// case that reaches them without claiming a byte the archive does
		// not have.
		{"exactly the version 2 length", 68},
		{"one past it", 69},
		{"longer than the archive", 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Everything about the record except its size is the truth,
			// so an archive that is still readable is one the record
			// was not believed about.
			end := bytes.LastIndex(raw, []byte{'P', 'K', 0x05, 0x06})
			dirSize := uint64(binary.LittleEndian.Uint32(raw[end+12:]))
			dirOffset := uint64(binary.LittleEndian.Uint32(raw[end+16:]))
			forged := appendZip64End(t, raw, tc.recordSize, dirSize, dirOffset)

			// A record the reader cannot believe at all sends it to
			// salvage(), which finds the entry by its local header, so
			// the archive is readable whichever way the record is wrong.
			zr, err := NewReader(bytes.NewReader(forged), int64(len(forged)))
			if err != nil {
				t.Fatalf("a zip64 end record claiming %d bytes: %v, want the archive still readable", tc.recordSize, err)
			}
			if len(zr.File) != 1 || zr.File[0].Name != "entry.bin" {
				t.Fatalf("the reader lists %d entries, want the archive's own entry.bin", len(zr.File))
			}
		})
	}
}

// TestReader_Zip64EndDirectoryFieldsAboveMaxInt64 pins the rejection that is
// already in readDirectoryEnd: the directory's size and offset are used as
// int64 by both Reader.init and Updater.init.
func TestReader_Zip64EndDirectoryFieldsAboveMaxInt64(t *testing.T) {
	body := []byte("small")
	raw := rawEntryArchive(t, &FileHeader{
		Name:               "entry.bin",
		Method:             Store,
		CompressedSize64:   uint64(len(body)),
		UncompressedSize64: uint64(len(body)),
	}, body)

	for _, tc := range []struct {
		name            string
		dirSize, dirOff uint64
	}{
		{"size", 1 << 63, 0},
		{"offset", 0, 1 << 63},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forged := appendZip64End(t, raw, directory64EndLen-12, tc.dirSize, tc.dirOff)
			zr, err := NewReader(bytes.NewReader(forged), int64(len(forged)))
			if err != nil && !errors.Is(err, ErrFormat) {
				t.Fatalf("central directory %s of 1<<63: got %v, want ErrFormat or a salvaged reader", tc.name, err)
			}
			if err == nil && len(zr.File) == 0 {
				t.Fatal("salvage returned a reader with no entries")
			}
		})
	}
}

// TestReadDirectory64End_VersionTwoFields covers the fields at the end of the
// record from both sides: they are read when the record is long enough to hold
// them, and not when the record only says it is.
func TestReadDirectory64End_VersionTwoFields(t *testing.T) {
	record := func(recordSize uint64) []byte {
		var buf [directory64EndLen + 24]byte
		b := writeBuf(buf[:])
		b.uint32(directory64EndSignature)
		b.uint64(recordSize)
		b.uint16(zipVersion45)
		b.uint16(zipVersion45)
		b.uint32(0)
		b.uint32(0)
		b.uint64(1)
		b.uint64(1)
		b.uint64(64)
		b.uint64(128)
		b.uint16(Store) // compression method
		b.uint64(64)    // compressed size
		b.uint64(128)   // original size
		b.uint16(sesAES256)
		b.uint16(256)
		b.uint16(1) // encrypted
		return buf[:]
	}

	for _, tc := range []struct {
		name       string
		recordSize uint64
		room       int64
		wantAlgID  uint16
	}{
		{"a record that holds them", 68, 68, sesAES256},
		// The same bytes, from a record with no room for them: what is
		// there is whatever the archive put after the record.
		{"a record that only claims them", 68, 44, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d directoryEnd
			raw := record(tc.recordSize)
			if err := readDirectory64End(bytes.NewReader(raw), 0, tc.room, &d); err != nil {
				t.Fatalf("readDirectory64End: %v", err)
			}
			if d.algId != tc.wantAlgID {
				t.Errorf("algId = %d, want %d", d.algId, tc.wantAlgID)
			}
			if d.encrypted != (tc.wantAlgID != 0) {
				t.Errorf("encrypted = %v, want %v", d.encrypted, tc.wantAlgID != 0)
			}
			if d.directorySize != 64 || d.directoryOffset != 128 {
				t.Errorf("directory size %d at offset %d, want 64 at 128", d.directorySize, d.directoryOffset)
			}
		})
	}
}

// A seek index is read out of a hidden entry nobody signed and nothing
// checksums, and every number in it is used as an offset into the entry it
// indexes. What the index says has to be true of the entry before the reader
// seeks by it.

func TestOpenSeekable_SOZipChunkSizeZero(t *testing.T) {
	raw, _, payload := seekableArchive(t, false, 4096)
	binary.LittleEndian.PutUint32(raw[payload+8:], 0)

	// A chunk size of zero is the divisor solidReadSeeker.Read divides the
	// wanted offset by, so believing it is an integer divide by zero.
	if err := openSeekableErr(t, raw); !errors.Is(err, ErrFormat) {
		t.Fatalf("SOZip index with a chunk size of zero: got %v, want ErrFormat", err)
	}
}

func TestOpenSeekable_GZIDXChunkSizeZero(t *testing.T) {
	raw, _, payload := seekableArchive(t, true, 4096)
	binary.LittleEndian.PutUint32(raw[payload+23:], 0)

	if err := openSeekableErr(t, raw); !errors.Is(err, ErrFormat) {
		t.Fatalf("GZIDX index with a chunk size of zero: got %v, want ErrFormat", err)
	}
}

func TestOpenSeekable_SOZipIndexOutsideEntry(t *testing.T) {
	raw, _, payload := seekableArchive(t, false, 4096)
	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	compressed := zr.File[0].CompressedSize64

	// An offset past the end of the entry is a negative length for the
	// section reader the chunk is read through, and a section reader of
	// negative length stops at nothing.
	binary.LittleEndian.PutUint64(raw[payload+32:], compressed+1)

	if err := openSeekableErr(t, raw); !errors.Is(err, ErrFormat) {
		t.Fatalf("SOZip index pointing past the entry: got %v, want ErrFormat", err)
	}
}

func TestOpenSeekable_SOZipIndexNotMonotonic(t *testing.T) {
	raw, _, payload := seekableArchive(t, false, 8192)
	first := binary.LittleEndian.Uint64(raw[payload+32:])
	second := binary.LittleEndian.Uint64(raw[payload+40:])
	if first == 0 || second <= first {
		t.Fatalf("the writer's own index is not increasing: %d then %d", first, second)
	}
	// Chunk n starts where chunk n-1 does not end.
	binary.LittleEndian.PutUint64(raw[payload+40:], first-1)

	if err := openSeekableErr(t, raw); !errors.Is(err, ErrFormat) {
		t.Fatalf("SOZip index that goes backwards: got %v, want ErrFormat", err)
	}
}

func TestOpenSeekable_GZIDXPointOutsideEntry(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field int // offset of the quad within the first point
	}{
		{"compressed", 0},
		{"uncompressed", 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _, payload := seekableArchive(t, true, 4096)
			zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
			if err != nil {
				t.Fatal(err)
			}
			f := zr.File[0]
			bound := f.CompressedSize64
			if tc.field == 8 {
				bound = f.UncompressedSize64
			}
			binary.LittleEndian.PutUint64(raw[payload+35+tc.field:], bound+1)

			if err := openSeekableErr(t, raw); !errors.Is(err, ErrFormat) {
				t.Fatalf("GZIDX point past the %s size of the entry: got %v, want ErrFormat", tc.name, err)
			}
		})
	}
}

// TestOpenSeekable_GZIDXPointCountOverflow: the payload has to be long enough
// for the points it claims, and the check that it is multiplied the claimed
// count by the size of a point. The count is the archive's, so on a 32-bit
// build the product wraps and the check passes for a payload that holds
// nothing of the sort.
func TestOpenSeekable_GZIDXPointCountOverflow(t *testing.T) {
	raw, _, payload := seekableArchive(t, true, 4096)
	binary.LittleEndian.PutUint32(raw[payload+31:], 1<<31)

	if err := openSeekableErr(t, raw); !errors.Is(err, ErrFormat) {
		t.Fatalf("GZIDX index claiming 1<<31 points: got %v, want ErrFormat", err)
	}
}

// TestOpenSeekable_HiddenIndexDeclaredSizeBeyondArchive: the payload is
// allocated from the size the hidden entry's own local header declares, before
// a byte of it has been read, so the size of the buffer is the archive's to
// choose and owes nothing to the archive's length.
func TestOpenSeekable_HiddenIndexDeclaredSizeBeyondArchive(t *testing.T) {
	raw, header, _ := seekableArchive(t, false, 4096)
	binary.LittleEndian.PutUint32(raw[header+18:], 1<<28)

	// Bounded by the bytes actually there, the payload is the real index
	// followed by the central directory, whose bytes are not offsets into a
	// few kilobytes of entry.
	if err := openSeekableErr(t, raw); !errors.Is(err, ErrFormat) {
		t.Fatalf("hidden index declaring 1<<28 bytes: got %v, want ErrFormat", err)
	}
}

// TestOpenSeekable_HiddenIndexDeclaredSizeAboveMaxInt64 is the same field
// spelled the way zip64 spells it, which is where the whole range of a uint64
// is available: 0xFFFFFFFF in the 32-bit size and the real size in a zip64
// extra. The extra is inserted into the hidden entry's local header, which is
// the last thing before the central directory, so the only offset that has to
// follow it is the one the end record keeps for the directory.
func TestOpenSeekable_HiddenIndexDeclaredSizeAboveMaxInt64(t *testing.T) {
	raw, header, _ := seekableArchive(t, false, 4096)

	var extra [20]byte
	b := writeBuf(extra[:])
	b.uint16(zip64ExtraID)
	b.uint16(16)
	b.uint64(1 << 63) // uncompressed size
	b.uint64(1 << 63) // compressed size, the one the payload is allocated from

	nameLen := int(binary.LittleEndian.Uint16(raw[header+26:]))
	extraLen := int(binary.LittleEndian.Uint16(raw[header+28:]))
	at := header + fileHeaderLen + nameLen + extraLen
	grownExtraLen, err := fitUint16(extraLen+len(extra), "local header extra field")
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(raw[header+18:], uint32max)
	binary.LittleEndian.PutUint16(raw[header+28:], grownExtraLen)

	forged := append([]byte(nil), raw[:at]...)
	forged = append(forged, extra[:]...)
	forged = append(forged, raw[at:]...)

	end := bytes.LastIndex(forged, []byte{'P', 'K', 0x05, 0x06})
	dirOffset := binary.LittleEndian.Uint32(forged[end+16:])
	binary.LittleEndian.PutUint32(forged[end+16:], dirOffset+uint32(len(extra)))

	if err := openSeekableErr(t, forged); !errors.Is(err, ErrFormat) {
		t.Fatalf("hidden index declaring 1<<63 bytes: got %v, want ErrFormat", err)
	}
}

// An extraction is allowed to write what its caller said it may write, and the
// archive is not a party to that decision. What follows is about the two
// limits: the size of one file and the ratio between what an entry takes up in
// the archive and what it expands into.

// storedEntry appends an entry to the writer with the sizes and the checksum
// of the bytes it actually holds. A solid archive's inner entries are read
// from their local headers as they stream past, and those headers have to
// carry the sizes: an entry that defers them to a data descriptor is refused
// and sends the extraction down the temp-file fallback instead.
func storedEntry(t *testing.T, zw *Writer, name string, data []byte) {
	t.Helper()
	fh := &FileHeader{
		Name:               name,
		Method:             Store,
		CRC32:              crc32.ChecksumIEEE(data),
		CompressedSize64:   uint64(len(data)),
		UncompressedSize64: uint64(len(data)),
	}
	fh.SetMode(0644)
	w, err := zw.CreateRaw(fh)
	if err != nil {
		t.Fatalf("CreateRaw(%q): %v", name, err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("writing %q: %v", name, err)
	}
}

// solidArchive returns an archive holding one entry named Solid.zip, which is
// itself a whole zip. The extraction unpacks it by streaming, without ever
// asking the reader about the inner entries.
func solidArchive(t *testing.T, outerMethod uint16, build func(inner *Writer)) []byte {
	t.Helper()
	var body bytes.Buffer
	inner := NewWriter(&body)
	build(inner)
	if err := inner.Close(); err != nil {
		t.Fatalf("closing the inner writer: %v", err)
	}

	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	outer := &FileHeader{Name: "Solid.zip", Method: outerMethod}
	outer.SetMode(0644)
	w, err := zw.CreateHeader(outer)
	if err != nil {
		t.Fatalf("CreateHeader(Solid.zip): %v", err)
	}
	if _, err := w.Write(body.Bytes()); err != nil {
		t.Fatalf("writing the solid entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	return buf.Bytes()
}

// extractArchiveTo extracts an in-memory archive into a fresh directory and
// returns the extractor, the directory, and whatever the extraction had to say.
func extractArchiveTo(t *testing.T, raw []byte, opts ...ExtractorOption) (*Extractor, string, error) {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "dst")
	e, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), dst, opts...)
	if err != nil {
		t.Fatalf("building the extractor: %v", err)
	}
	closeAt(t, e)
	return e, dst, e.Extract(context.Background())
}

// extractArchive is extractArchiveTo for the tests that only care what the
// extraction refused.
func extractArchive(t *testing.T, raw []byte, opts ...ExtractorOption) error {
	t.Helper()
	_, _, err := extractArchiveTo(t, raw, opts...)
	return err
}

// noLimitBudget is a budget with nothing turned on, for the tests that reach a
// write point directly and are about something other than the limits.
func noLimitBudget(name string) *entryBudget {
	return newExtractBudget(&extractorOptions{}, new(int64)).duplicate(name)
}

func TestExtractorOptions_RejectNegativeLimits(t *testing.T) {
	raw := rawEntryArchive(t, &FileHeader{Name: "entry.bin", Method: Store}, nil)
	for _, tc := range []struct {
		name string
		opt  ExtractorOption
	}{
		{"maximum file size", WithExtractorMaxFileSize(-1)},
		{"maximum ratio", WithExtractorMaxRatio(-1)},
		{"maximum total size", WithExtractorMaxTotalSize(-1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "dst")
			if _, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), dst, tc.opt); err == nil {
				t.Errorf("a negative %s was accepted", tc.name)
			}
			zipPath := filepath.Join(t.TempDir(), "entry.zip")
			if err := os.WriteFile(zipPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewExtractor(zipPath, dst, tc.opt); err == nil {
				t.Errorf("a negative %s was accepted", tc.name)
			}
		})
	}
}

// TestEntryBudget_HeaderCheck covers the rejection an entry gets on what its
// header claims, before anything is opened.
func TestEntryBudget_HeaderCheck(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		maxFileSize, maxRatio    int64
		compressed, uncompressed uint64
		want                     error
	}{
		{"no limits at all", 0, 0, 1, 1 << 40, nil},
		{"under the size limit", 1024, 0, 1, 1024, nil},
		{"over the size limit", 1024, 0, 1, 1025, ErrSizeLimit},
		{"up to the ratio limit", 0, 10, 100, 1000, nil},
		// One byte more is more bytes per byte than the limit allows, and
		// a quotient on its own does not notice until the next whole one.
		{"one byte past the ratio limit", 0, 10, 100, 1001, ErrRatioLimit},
		{"over the ratio limit", 0, 10, 100, 1100, ErrRatioLimit},
		{"nothing compressed is nothing to divide by", 0, 10, 0, 1 << 40, nil},
		// The size is the archive's word, and a word above MaxInt64 used to
		// be read as a negative number, which is below every limit there is.
		{"a size above MaxInt64 is not a small size", 0, 4000, 1, 1 << 63, ErrRatioLimit},
		// The ratio used to be checked by multiplying the limit by the
		// compressed size, which overflows for an entry this large and
		// turns an honest 2:1 into a rejection.
		{"a large honest entry is not a bomb", 0, 4000, 1 << 52, 1 << 53, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newExtractBudget(&extractorOptions{
				maxFileSize:           tc.maxFileSize,
				maxDecompressionRatio: tc.maxRatio,
			}, new(int64))
			eb := b.entry(&File{FileHeader: FileHeader{
				Name:               "entry.bin",
				CompressedSize64:   tc.compressed,
				UncompressedSize64: tc.uncompressed,
			}})
			err := eb.checkHeader(tc.uncompressed)
			if tc.want == nil && err != nil {
				t.Fatalf("got %v, want the entry accepted", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// TestEntryBudget_Charge covers what the budget does with bytes as they are
// written, which is the only account of an extraction that the archive cannot
// write itself.
func TestEntryBudget_Charge(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		maxFileSize, maxRatio int64
		compressed            uint64
		writes                []int
		want                  error
	}{
		{"no limits at all", 0, 0, 1, []int{1 << 20, 1 << 20}, nil},
		{"up to the size limit", 1024, 0, 1024, []int{512, 512}, nil},
		{"past the size limit", 1024, 0, 1024, []int{512, 513}, ErrSizeLimit},
		{"up to the ratio limit", 0, 10, 100, []int{1000}, nil},
		{"one byte past the ratio limit", 0, 10, 100, []int{1000, 1}, ErrRatioLimit},
		{"past the ratio limit", 0, 10, 100, []int{1000, 100}, ErrRatioLimit},
		{"the ratio limit turned off", 0, 0, 1, []int{1 << 20}, nil},
		{"nothing compressed produces nothing", 0, 10, 0, []int{0}, nil},
		{"nothing compressed cannot produce a byte", 0, 10, 0, []int{1}, ErrRatioLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var written int64
			b := newExtractBudget(&extractorOptions{
				maxFileSize:           tc.maxFileSize,
				maxDecompressionRatio: tc.maxRatio,
			}, &written)
			eb := b.entry(&File{FileHeader: FileHeader{Name: "entry.bin", CompressedSize64: tc.compressed}})
			var sink bytes.Buffer
			bw := eb.file(&sink)
			var err error
			var wrote int
			for _, n := range tc.writes {
				var w int
				w, err = bw.Write(make([]byte, n))
				wrote += w
				if err != nil {
					break
				}
			}
			if tc.want == nil {
				if err != nil {
					t.Fatalf("got %v, want the bytes accepted", err)
				}
				if int64(wrote) != written || sink.Len() != wrote {
					t.Fatalf("wrote %d bytes, the budget counted %d and the file holds %d", wrote, written, sink.Len())
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// TestEntryBudget_WriteError passes on what the file itself has to say.
func TestEntryBudget_WriteError(t *testing.T) {
	b := newExtractBudget(&extractorOptions{}, new(int64))
	eb := b.entry(&File{FileHeader: FileHeader{Name: "entry.bin"}})
	want := errors.New("disk went away")
	if _, err := eb.file(errWriter{want}).Write([]byte("x")); !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
}

type errWriter struct{ err error }

func (w errWriter) Write(p []byte) (int, error) { return 0, w.err }

// TestEntryBudget_PreallocSize covers how much of a declared size is worth
// reserving on disk. The declaration is the archive's own, so it is trusted
// only as far as a check has bounded it.
func TestEntryBudget_PreallocSize(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		maxFileSize, maxRatio int64
		compressed, declared  uint64
		want                  int64
	}{
		{"the size limit is the ceiling", 1 << 20, 4000, 1, 1 << 40, 1 << 20},
		{"under the size limit the declaration stands", 1 << 20, 4000, 1, 4096, 4096},
		{"with no size limit the ratio check bounded it", 0, 4000, 1, 4096, 4096},
		{"nothing compressed has been through no check at all", 0, 4000, 0, 1 << 40, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newExtractBudget(&extractorOptions{
				maxFileSize:           tc.maxFileSize,
				maxDecompressionRatio: tc.maxRatio,
			}, new(int64))
			eb := b.entry(&File{FileHeader: FileHeader{Name: "entry.bin", CompressedSize64: tc.compressed}})
			if got := eb.preallocSize(tc.declared); got != tc.want {
				t.Fatalf("preallocSize(%d) = %d, want %d", tc.declared, got, tc.want)
			}
		})
	}
}

// TestExtractor_SolidSizeLimit: a solid archive is unpacked by a path of its
// own, which used to consult neither limit, so an archive that named itself
// Solid.zip was exempt from both.
func TestExtractor_SolidSizeLimit(t *testing.T) {
	const limit = 1 << 20
	raw := solidArchive(t, Store, func(inner *Writer) {
		storedEntry(t, inner, "big.bin", make([]byte, 2*limit))
	})

	e, _, err := extractArchiveTo(t, raw, WithExtractorMaxFileSize(limit), WithExtractorMaxRatio(0))
	if !errors.Is(err, ErrSizeLimit) {
		t.Fatalf("a solid archive holding a 2 MiB file under a 1 MiB limit: got %v, want ErrSizeLimit", err)
	}
	if written, _ := e.Written(); written > limit {
		t.Fatalf("the extraction wrote %d bytes for a limit of %d: the refusal was followed by the fallback copying the entry anyway", written, limit)
	}
}

// TestExtractor_SolidFallbackScratchIsNotAnExtractedFile: the copy the
// fallback takes of a solid entry is the extraction's own scratch file, not a
// file the archive asked for. The size limit is a limit on the latter, and the
// ceiling checked a moment earlier deliberately allows an entry ten times that
// size, so charging the copy against the size limit refuses archives the
// ceiling had just let through.
func TestExtractor_SolidFallbackScratchIsNotAnExtractedFile(t *testing.T) {
	const limit = 4096
	const part = 2000
	// Compressed, so that the entry has to be copied out before it can be
	// read and the copy is the file this is about.
	raw := solidArchive(t, Deflate, func(inner *Writer) {
		w, err := inner.Create("deflated.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("deflated")); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 8; i++ {
			storedEntry(t, inner, fmt.Sprintf("part%d.bin", i), bytes.Repeat([]byte("x"), part))
		}
	})

	// Every file in it is well under the limit; only the archive holding
	// them is over.
	e, dst, err := extractArchiveTo(t, raw, WithExtractorMaxFileSize(limit), WithExtractorMaxRatio(0))
	if err != nil {
		t.Fatalf("a solid archive of files under the limit: %v", err)
	}
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("part%d.bin", i)
		fi, err := os.Stat(filepath.Join(dst, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if fi.Size() != part {
			t.Errorf("%s is %d bytes, want %d", name, fi.Size(), part)
		}
	}

	// What was extracted is what came out of the archive, not the copy of
	// the archive the fallback made on the way: the caller asked what this
	// extraction wrote, and it wrote nine files.
	written, entries := e.Written()
	if want := int64(8*part + len("deflated")); written != want {
		t.Errorf("Written() = %d bytes, want the %d that reached the disk", written, want)
	}
	if entries != 9 {
		t.Errorf("Written() counted %d entries, want the 9 files extracted", entries)
	}
}

// TestExtractor_SolidFallbackRatioNotDoubleCharged: the fallback copy is a
// second pass over the same entry rather than more of the first, so it is
// measured on its own. Charging both passes to one budget makes an honest
// archive look like it expanded twice as far as it did, and refuses it at its
// own true ratio.
func TestExtractor_SolidFallbackRatioNotDoubleCharged(t *testing.T) {
	raw := solidArchive(t, Deflate, func(inner *Writer) {
		storedEntry(t, inner, "zeros.bin", make([]byte, 64<<10))
		w, err := inner.Create("refused.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("deflated")); err != nil {
			t.Fatal(err)
		}
	})

	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	// Rounded up, since the limit is exact: the entry expands by this much
	// per byte and no more.
	u, c := zr.File[0].UncompressedSize64, zr.File[0].CompressedSize64
	ratio, err := u64toi64((u + c - 1) / c)
	if err != nil {
		t.Fatalf("ratio of the archive just written: %v", err)
	}

	_, dst, err := extractArchiveTo(t, raw, WithExtractorMaxFileSize(0), WithExtractorMaxRatio(ratio))
	if err != nil {
		t.Fatalf("an archive extracted at its own ratio of %d:1: %v", ratio, err)
	}
	if fi, err := os.Stat(filepath.Join(dst, "zeros.bin")); err != nil {
		t.Fatal(err)
	} else if fi.Size() != 64<<10 {
		t.Errorf("zeros.bin is %d bytes, want %d", fi.Size(), 64<<10)
	}
}

// TestExtractor_SparseHolesAreCounted: a hole the sparse copy seeks over is
// part of the file being extracted, and an extraction that does not count it
// has not counted the file.
func TestExtractor_SparseHolesAreCounted(t *testing.T) {
	const size = 4096
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	w, err := zw.CreateHeader(&FileHeader{Name: "zeros.bin", Method: Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	e, dst, err := extractArchiveTo(t, buf.Bytes(), WithExtractorSparse(true),
		WithExtractorChownErrorHandler(func(string, error) error { return nil }))
	if err != nil {
		t.Fatalf("extracting a file of nothing but zeros: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dst, "zeros.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != size {
		t.Fatalf("zeros.bin is %d bytes on disk, want %d", fi.Size(), size)
	}
	if written, _ := e.Written(); written != size {
		t.Fatalf("Written() = %d for a %d byte file that is all hole", written, size)
	}
}

// TestExtractBudget_FallbackTooLarge covers the ceiling the solid fallback
// checks before it copies an entry to a temp file: ten times the per-file
// limit, on what the entry says it holds.
func TestExtractBudget_FallbackTooLarge(t *testing.T) {
	for _, tc := range []struct {
		name        string
		maxFileSize int64
		declared    uint64
		want        bool
	}{
		{"ten times the limit is allowed", 5, 50, false},
		{"past ten times the limit is not", 5, 200, true},
		// Ten times a limit this size overflowed into a negative number,
		// and from there into a 100 GB ceiling nobody asked for.
		{"a limit of MaxInt64 is not a ceiling of 100 GB", math.MaxInt64, 1 << 40, false},
		{"no limit is no ceiling", 0, 1 << 40, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newExtractBudget(&extractorOptions{maxFileSize: tc.maxFileSize}, new(int64))
			if got := b.fallbackTooLarge(tc.declared); got != tc.want {
				t.Fatalf("fallbackTooLarge(%d) with a limit of %d = %v, want %v", tc.declared, tc.maxFileSize, got, tc.want)
			}
		})
	}
}

func TestExtractor_SolidRatioLimit(t *testing.T) {
	raw := solidArchive(t, Deflate, func(inner *Writer) {
		storedEntry(t, inner, "zeros.bin", make([]byte, 512<<10))
	})

	err := extractArchive(t, raw, WithExtractorMaxFileSize(1<<20), WithExtractorMaxRatio(10))
	if !errors.Is(err, ErrRatioLimit) {
		t.Fatalf("a solid archive expanding far past its own size: got %v, want ErrRatioLimit", err)
	}
}

// TestExtractor_SolidFallbackRatioLimit covers the other half of the solid
// path: a compressed solid entry goes to a temp file before it can be read at
// all, and that copy was unbounded.
func TestExtractor_SolidFallbackRatioLimit(t *testing.T) {
	raw := solidArchive(t, Deflate, func(inner *Writer) {
		w, err := inner.Create("refused.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("deflated")); err != nil {
			t.Fatal(err)
		}
		storedEntry(t, inner, "zeros.bin", make([]byte, 512<<10))
	})

	err := extractArchive(t, raw, WithExtractorMaxFileSize(0), WithExtractorMaxRatio(10))
	if !errors.Is(err, ErrRatioLimit) {
		t.Fatalf("a solid archive copied to a temp file: got %v, want ErrRatioLimit", err)
	}
}

// TestExtractor_ZeroCompressedSizeCannotProduceBytes: an entry that declares
// no compressed bytes has been through no check at all -- the ratio check has
// nothing to divide by -- so its declared uncompressed size is not something
// to reserve disk for, and anything it does produce is a header that lies.
func TestExtractor_ZeroCompressedSizeCannotProduceBytes(t *testing.T) {
	const method = 0x4242
	raw := rawEntryArchive(t, &FileHeader{
		Name:               "gen.bin",
		Method:             method,
		CompressedSize64:   0,
		UncompressedSize64: 1 << 45,
	}, nil)

	dst := filepath.Join(t.TempDir(), "dst")
	e, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), dst,
		WithExtractorMaxFileSize(0), WithExtractorMaxRatio(10))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	e.zr.RegisterDecompressor(method, func(r io.Reader) io.ReadCloser {
		return io.NopCloser(bytes.NewReader(make([]byte, 4096)))
	})

	if err := e.Extract(context.Background()); !errors.Is(err, ErrRatioLimit) {
		t.Fatalf("an entry producing bytes out of nothing: got %v, want ErrRatioLimit", err)
	}
}

// TestCopySparseZip_Budget: a hole is as much a part of the file as the bytes
// around it, and the sparse copy seeks over it rather than writing it, so it
// has to be charged to the budget by hand -- otherwise a file made of zeros is
// a file with no limit on it.
func TestCopySparseZip_Budget(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"seeked over", make([]byte, 4096)},
		{"written", bytes.Repeat([]byte("data"), 1024)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "out.bin")
			f, err := os.Create(dst)
			if err != nil {
				t.Fatal(err)
			}
			closeAt(t, f)

			var written int64
			b := newExtractBudget(&extractorOptions{maxFileSize: 1024}, &written)
			eb := b.entry(&File{FileHeader: FileHeader{Name: "out.bin", CompressedSize64: 4096}})

			err = copySparseZip(f, bytes.NewReader(tc.body), eb.file(f), context.Background())
			if !errors.Is(err, ErrSizeLimit) {
				t.Fatalf("%d bytes %s under a 1024 byte limit: got %v, want ErrSizeLimit", len(tc.body), tc.name, err)
			}
		})
	}
}
