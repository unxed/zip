package zip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ntfsTimesExtra builds the Info-ZIP NTFS extra field (0x000a) holding the
// three FILETIME values the reader parses out of attribute tag 1.
func ntfsTimesExtra(mtime, atime, ctime uint64) []byte {
	buf := make([]byte, 0, 4+32)
	buf = binary.LittleEndian.AppendUint16(buf, ntfsExtraID)
	buf = binary.LittleEndian.AppendUint16(buf, 32)
	buf = binary.LittleEndian.AppendUint32(buf, 0) // reserved
	buf = binary.LittleEndian.AppendUint16(buf, 1) // attribute tag 1
	buf = binary.LittleEndian.AppendUint16(buf, 24)
	buf = binary.LittleEndian.AppendUint64(buf, mtime)
	buf = binary.LittleEndian.AppendUint64(buf, atime)
	buf = binary.LittleEndian.AppendUint64(buf, ctime)
	return buf
}

// readSingleEntry writes one raw entry carrying extra and reads its header
// back through the central directory.
func readSingleEntry(t *testing.T, extra []byte, modified time.Time) *File {
	t.Helper()
	fh := &FileHeader{Name: "stamped.txt", Method: Store, Extra: extra}
	fh.Modified = modified
	if !modified.IsZero() {
		// CreateRaw writes the header as it is given, so the MS-DOS
		// fields have to be filled in here for the reader to have
		// anything to fall back on.
		fh.ModifiedDate, fh.ModifiedTime = timeToMsDosTime(modified)
	}
	raw := rawEntryArchive(t, fh, nil)

	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("the archive holds %d entries, want 1", len(zr.File))
	}
	return zr.File[0]
}

func TestReaderNtfsTimesAreUsedWhenTheyFit(t *testing.T) {
	// 2001-01-01T00:00:00Z as 100-nanosecond ticks since 1601.
	const ticks = uint64(126227808000000000)
	f := readSingleEntry(t, ntfsTimesExtra(ticks, ticks, ticks), time.Time{})

	want := time.Date(2001, time.January, 1, 0, 0, 0, 0, time.UTC)
	if !f.Modified.UTC().Equal(want) {
		t.Errorf("Modified is %v, want %v", f.Modified.UTC(), want)
	}
	if !f.Accessed.UTC().Equal(want) {
		t.Errorf("Accessed is %v, want %v", f.Accessed.UTC(), want)
	}
	if !f.Created.UTC().Equal(want) {
		t.Errorf("Created is %v, want %v", f.Created.UTC(), want)
	}
}

func TestReaderIgnoresAnNtfsTimeThatDoesNotFitAnInt64(t *testing.T) {
	// A FILETIME is unsigned. Read as an int64 anyway, a value above
	// MaxInt64 comes out negative and puts the entry before 1601, which is
	// a date the field cannot express and the archive did not mean. The
	// eight bytes still have to be consumed so the two times after this
	// one stay lined up, which is why all three are given absurd values
	// here and the middle one a legitimate value in the case below.
	stamped := time.Date(2020, time.June, 2, 10, 20, 30, 0, time.UTC)
	huge := uint64(1) << 63
	f := readSingleEntry(t, ntfsTimesExtra(huge, huge, huge), stamped)

	if want := msDosTimeToTime(f.ModifiedDate, f.ModifiedTime); !f.Modified.Equal(want) {
		t.Errorf("Modified is %v, want the MS-DOS time %v: the refused FILETIME was used anyway", f.Modified, want)
	}
	if f.Modified.Year() != stamped.Year() {
		t.Errorf("Modified is %v, want a time in %d", f.Modified, stamped.Year())
	}
	if !f.Accessed.IsZero() {
		t.Errorf("Accessed is %v, want it left unset", f.Accessed)
	}
	if !f.Created.IsZero() {
		t.Errorf("Created is %v, want it left unset", f.Created)
	}
}

func TestReaderKeepsTheNtfsTimesThatDoFitBesideOneThatDoesNot(t *testing.T) {
	const ticks = uint64(126227808000000000) // 2001-01-01T00:00:00Z
	f := readSingleEntry(t, ntfsTimesExtra(1<<63, ticks, 1<<63), time.Time{})

	want := time.Date(2001, time.January, 1, 0, 0, 0, 0, time.UTC)
	if !f.Accessed.UTC().Equal(want) {
		t.Errorf("Accessed is %v, want %v: the field after the refused one was not read", f.Accessed.UTC(), want)
	}
	if !f.Created.IsZero() {
		t.Errorf("Created is %v, want it left unset", f.Created)
	}
}

// zip64LocatorAt appends a zip64 end-of-central-directory locator naming
// recordOffset, followed by an end record whose fields are all saturated so
// that readDirectoryEnd goes looking for the zip64 record.
func zip64LocatorAt(recordOffset uint64) []byte {
	buf := make([]byte, 0, directory64LocLen+directoryEndLen)
	buf = binary.LittleEndian.AppendUint32(buf, directory64LocSignature)
	buf = binary.LittleEndian.AppendUint32(buf, 0) // disk holding the record
	buf = binary.LittleEndian.AppendUint64(buf, recordOffset)
	buf = binary.LittleEndian.AppendUint32(buf, 1) // number of disks

	buf = binary.LittleEndian.AppendUint32(buf, directoryEndSignature)
	buf = binary.LittleEndian.AppendUint16(buf, 0)
	buf = binary.LittleEndian.AppendUint16(buf, 0)
	buf = binary.LittleEndian.AppendUint16(buf, 0xffff)
	buf = binary.LittleEndian.AppendUint16(buf, 0xffff)
	buf = binary.LittleEndian.AppendUint32(buf, 0xffffffff)
	buf = binary.LittleEndian.AppendUint32(buf, 0xffffffff)
	buf = binary.LittleEndian.AppendUint16(buf, 0) // comment length
	return buf
}

func TestFindDirectory64EndRefusesAnOffsetAboveMaxInt64(t *testing.T) {
	// A negative return is how findDirectory64End says there is no zip64
	// record to read, so an offset above MaxInt64 narrowed into one would
	// quietly turn a record that is there into a record that is not.
	raw := append(make([]byte, 64), zip64LocatorAt(1<<63)...)
	_, err := findDirectory64End(bytes.NewReader(raw), int64(len(raw))-directoryEndLen)
	if !errors.Is(err, ErrFormat) {
		t.Fatalf("findDirectory64End returned %v, want ErrFormat", err)
	}
}

func TestReaderRefusesAZip64LocatorOffsetAboveMaxInt64(t *testing.T) {
	raw := append(make([]byte, 64), zip64LocatorAt(1<<63)...)
	if _, err := NewReader(bytes.NewReader(raw), int64(len(raw))); err == nil {
		t.Fatal("an archive whose zip64 locator points past MaxInt64 was accepted")
	}
}

func TestFindDirectory64EndAcceptsAnOffsetThatFits(t *testing.T) {
	// The same shape with an offset a file could hold: the locator is
	// found and its offset comes back as it was written.
	raw := append(make([]byte, 64), zip64LocatorAt(12)...)
	off, err := findDirectory64End(bytes.NewReader(raw), int64(len(raw))-directoryEndLen)
	if err != nil {
		t.Fatalf("findDirectory64End: %v", err)
	}
	if off != 12 {
		t.Fatalf("findDirectory64End gave %d, want 12", off)
	}
}

// salvageableArchiveWithHugeEntry returns bytes with no end record at all --
// so the reader has to salvage -- holding one sound entry and one whose zip64
// extra declares the given sizes.
func salvageableArchiveWithHugeEntry(t *testing.T, uncompressed, compressed uint64) []byte {
	t.Helper()
	good := &FileHeader{Name: "good.txt", Method: Store}
	raw := rawEntryArchive(t, good, []byte("payload"))

	extra := make([]byte, 0, 24)
	extra = binary.LittleEndian.AppendUint16(extra, zip64ExtraID)
	extra = binary.LittleEndian.AppendUint16(extra, 16)
	extra = binary.LittleEndian.AppendUint64(extra, uncompressed)
	extra = binary.LittleEndian.AppendUint64(extra, compressed)

	name := "huge.txt"
	local := make([]byte, 0, fileHeaderLen+len(name)+len(extra))
	local = binary.LittleEndian.AppendUint32(local, fileHeaderSignature)
	local = binary.LittleEndian.AppendUint16(local, zipVersion45) // reader version
	local = binary.LittleEndian.AppendUint16(local, 0)            // flags
	local = binary.LittleEndian.AppendUint16(local, Store)
	local = binary.LittleEndian.AppendUint16(local, 0) // time
	local = binary.LittleEndian.AppendUint16(local, 0) // date
	local = binary.LittleEndian.AppendUint32(local, 0) // crc
	local = binary.LittleEndian.AppendUint32(local, uint32max)
	local = binary.LittleEndian.AppendUint32(local, uint32max)
	nameLen, err := fitUint16(len(name), "the fixture's file name")
	if err != nil {
		t.Fatal(err)
	}
	extraLen, err := fitUint16(len(extra), "the fixture's extra field")
	if err != nil {
		t.Fatal(err)
	}
	local = binary.LittleEndian.AppendUint16(local, nameLen)
	local = binary.LittleEndian.AppendUint16(local, extraLen)
	local = append(local, name...)
	local = append(local, extra...)

	// The entries of the valid archive, with the hostile local header
	// wedged in front and everything from the central directory on cut
	// away.
	body := localHeaderOffset(t, raw, "good.txt")
	return append(append([]byte{}, local...), raw[body:centralHeaderOffset(t, raw, "good.txt")]...)
}

func TestSalvageRefusesAnEntryWhoseSizeIsAboveMaxInt64(t *testing.T) {
	// Salvage builds entries from local headers, so it has to hold them to
	// the same size invariant the central directory is held to: everything
	// downstream hands these sizes to io.NewSectionReader, where one above
	// MaxInt64 arrives negative and removes the bound instead of setting
	// it. Either size on its own is enough to make the entry one no reader
	// can be handed.
	for _, tc := range []struct {
		name                     string
		uncompressed, compressed uint64
	}{
		{"both sizes", 1 << 63, 1 << 63},
		{"only the uncompressed size", 1 << 63, 8},
		{"only the compressed size", 8, 1 << 63},
	} {
		t.Run(tc.name, func(t *testing.T) {
			salvaged := salvageableArchiveWithHugeEntry(t, tc.uncompressed, tc.compressed)
			zr, err := NewReader(bytes.NewReader(salvaged), int64(len(salvaged)))
			if err != nil {
				t.Fatalf("salvage refused the whole archive: %v", err)
			}
			for _, f := range zr.File {
				if f.Name == "huge.txt" {
					t.Fatalf("the entry declaring %d/%d bytes was salvaged anyway",
						f.UncompressedSize64, f.CompressedSize64)
				}
			}
			if len(zr.File) != 1 || zr.File[0].Name != "good.txt" {
				t.Fatalf("salvage gave %d entries, want just the sound one", len(zr.File))
			}
		})
	}
}

func TestSalvageKeepsAZip64EntryThatFits(t *testing.T) {
	// The same shape with sizes an int64 holds: the entry is salvaged, so
	// the check above is refusing what it says it refuses and not zip64
	// entries at large.
	salvaged := salvageableArchiveWithHugeEntry(t, 7, 7)
	zr, err := NewReader(bytes.NewReader(salvaged), int64(len(salvaged)))
	if err != nil {
		t.Fatalf("salvage refused the whole archive: %v", err)
	}
	found := false
	for _, f := range zr.File {
		if f.Name == "huge.txt" {
			found = true
			if f.UncompressedSize64 != 7 || f.CompressedSize64 != 7 {
				t.Errorf("the entry came back with sizes %d/%d, want 7/7",
					f.UncompressedSize64, f.CompressedSize64)
			}
		}
	}
	if !found {
		t.Fatal("an entry whose zip64 sizes fit an int64 was skipped")
	}
}

func TestOpenReaderReportsAnUnreadableXCryptHeader(t *testing.T) {
	// checkXCryptZip parses the crypto header before anything else is
	// decided; an archive that carries one it cannot parse is not an
	// archive whose stub should be handed over instead.
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.zip")

	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	w, err := zw.CreateHeader(&FileHeader{Name: ".zipext/xcrypt/crypto.hdr", Method: Store})
	if err != nil {
		t.Fatalf("creating the header entry: %v", err)
	}
	mustWrite(t, w, []byte("this is not an XCrypt header"))
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	mustWriteFile(t, path, buf.Bytes(), 0600)

	rc, err := OpenReaderWithPassword(path, "secret")
	if err == nil {
		closeAt(t, rc)
		t.Fatal("an archive with an unparsable XCrypt header was opened")
	}
}

func TestFindHiddenIndexReportsAnUnreadableZip64Extra(t *testing.T) {
	// When the hidden index entry's 32-bit compressed size is saturated,
	// the real size lives in its zip64 extra. A read of that extra that
	// runs off the end of the archive used to leave the buffer holding
	// zeros, and the size was then parsed out of them as if the archive
	// had said so.
	raw, header, _ := seekableArchive(t, false, 4096)

	// The hidden entry's local header: saturate the compressed size and
	// claim an extra field far longer than what follows it.
	binary.LittleEndian.PutUint32(raw[header+18:], uint32max)
	binary.LittleEndian.PutUint16(raw[header+28:], 0xffff)

	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	var target *File
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, ".") {
			target = f
		}
	}
	if target == nil {
		t.Fatal("the indexed entry is not in the archive")
	}
	if _, err := target.OpenSeekable(); err == nil {
		t.Fatal("an index whose zip64 extra runs off the end of the archive was accepted")
	}
}

func TestReaderFileSystemReportsDirectoryTimes(t *testing.T) {
	// Reader is an fs.FS, and the synthesised directory entries take their
	// time from the entry that named them.
	stamped := time.Date(2019, time.March, 4, 5, 6, 8, 0, time.UTC)
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	dirHeader := &FileHeader{Name: "sub/", Method: Store}
	dirHeader.Modified = stamped
	if _, err := zw.CreateHeader(dirHeader); err != nil {
		t.Fatalf("creating the directory entry: %v", err)
	}
	fileHeader := &FileHeader{Name: "sub/leaf.txt", Method: Store}
	fileHeader.Modified = stamped
	w, err := zw.CreateHeader(fileHeader)
	if err != nil {
		t.Fatalf("creating the file entry: %v", err)
	}
	mustWrite(t, w, []byte("leaf"))
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}

	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}

	seen := false
	err = fs.WalkDir(zr, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name != "sub" {
			return nil
		}
		seen = true
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		if !info.IsDir() {
			t.Errorf("%q is not reported as a directory", name)
		}
		if got := info.ModTime(); !got.Equal(stamped) {
			t.Errorf("%q has time %v, want %v", name, got, stamped)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the archive: %v", err)
	}
	if !seen {
		t.Fatal("the directory entry was not walked")
	}
}

func TestF4RecoveryFooterIsUnwrapped(t *testing.T) {
	// An archive with an F4 recovery footer is read as the archive proper,
	// with the footer and the recovery data after it left out.
	inner := new(bytes.Buffer)
	zw := NewWriter(inner)
	w, err := zw.Create("payload.txt")
	if err != nil {
		t.Fatalf("creating the entry: %v", err)
	}
	mustWrite(t, w, []byte("real content"))
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}

	archive := inner.Bytes()
	full := append(append([]byte{}, archive...), make([]byte, 64)...)
	footer := make([]byte, 32)
	binary.LittleEndian.PutUint64(footer[8:16], uint64(len(archive)))
	copy(footer[16:32], magicF4Recovery)
	full = append(full, footer...)

	ra, size := checkF4Recovery(bytes.NewReader(full), int64(len(full)))
	if size != int64(len(archive)) {
		t.Fatalf("the footer gave a size of %d, want %d", size, len(archive))
	}
	zr, err := NewReader(ra, size)
	if err != nil {
		t.Fatalf("reading the unwrapped archive: %v", err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "payload.txt" {
		t.Fatalf("the unwrapped archive holds %d entries", len(zr.File))
	}
}

func TestF4RecoveryFooterIsIgnoredWhenItDoesNotFitTheFile(t *testing.T) {
	full := make([]byte, 128)
	binary.LittleEndian.PutUint64(full[len(full)-24:], 1<<63)
	copy(full[len(full)-16:], magicF4Recovery)

	_, size := checkF4Recovery(bytes.NewReader(full), int64(len(full)))
	if size != int64(len(full)) {
		t.Fatalf("a footer claiming %d bytes was believed: size came back as %d", uint64(1)<<63, size)
	}
}

func TestF4RecoveryIgnoresAFileTooShortToHoldAFooter(t *testing.T) {
	short := []byte("tiny")
	ra, size := checkF4Recovery(bytes.NewReader(short), int64(len(short)))
	if size != int64(len(short)) {
		t.Fatalf("size came back as %d, want %d", size, len(short))
	}
	var buf [4]byte
	if _, err := ra.ReadAt(buf[:], 0); err != nil && err != io.EOF {
		t.Fatalf("the reader was replaced: %v", err)
	}
}

func TestOpenReaderReportsAMissingArchive(t *testing.T) {
	_, err := OpenReader(filepath.Join(t.TempDir(), "not-there.zip"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("opening a missing archive gave %v", err)
	}
}

// TestFindHiddenIndexIgnoresAListedEntry: a seek index is a local entry the
// central directory does not list, so an entry the directory does list is not
// one however it is named. An archive may hold an entry called
// ".a.txt.sozip.idx" written straight after "a.txt" -- this package's own
// writer produces one from those two names -- and taking it for a's index
// blames a valid archive for an index it does not have.
func TestFindHiddenIndexIgnoresAListedEntry(t *testing.T) {
	indexLike := ".a.txt.sozip.idx"
	listed := []byte("a listed entry that only looks like an index")

	var built bytes.Buffer
	w := NewWriter(&built)
	for _, e := range []struct {
		name   string
		body   []byte
		method uint16
	}{
		{"a.txt", bytes.Repeat([]byte("abcdefgh"), 512), Deflate},
		{indexLike, listed, Store},
	} {
		fw, err := w.CreateHeader(&FileHeader{Name: e.name, Method: e.method})
		if err != nil {
			t.Fatalf("%s: CreateHeader: %v", e.name, err)
		}
		if _, err := fw.Write(e.body); err != nil {
			t.Fatalf("%s: write: %v", e.name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	raw := built.Bytes()

	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	var target *File
	for _, f := range zr.File {
		if f.Name == "a.txt" {
			target = f
		}
	}
	if target == nil {
		t.Fatal("the entry the index-like name follows is not in the archive")
	}

	kind, payload, err := target.findHiddenIndex()
	if err != nil {
		t.Fatalf("looking for an index reported %v", err)
	}
	if kind != 0 {
		t.Fatalf("the entry the directory lists was taken for a seek index of kind %d holding %d bytes",
			kind, len(payload))
	}

	// And it is still an entry: it reads back as what was written.
	rc, err := zr.File[1].Open()
	if err != nil {
		t.Fatalf("opening the listed entry: %v", err)
	}
	got, rerr := io.ReadAll(rc)
	if cerr := rc.Close(); rerr == nil {
		rerr = cerr
	}
	if rerr != nil {
		t.Fatalf("reading the listed entry: %v", rerr)
	}
	if !bytes.Equal(got, listed) {
		t.Fatalf("the listed entry reads back as %q", got)
	}
}
