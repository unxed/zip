package zip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/flate"
)

// The fixtures here are archives that are wrong on purpose -- a truncated end
// record, a central directory that disagrees with what follows it, an extra
// field whose declared length runs past its own buffer, a compression method
// nobody registered -- plus a reader that stops answering at an offset the
// test picks. Between them they are what a reader meets in the wild, and the
// error paths they reach are the reader's answer to them.

// errReaderCovDevice is what an archive that has stopped answering reads with.
var errReaderCovDevice = errors.New("the archive could not be read")

// readerCovFailingAt serves an archive through ReadAt and refuses exactly the
// reads the test picked out. A byte slice always answers; storage does not,
// and the reader has error paths for the difference.
type readerCovFailingAt struct {
	data []byte
	fail func(off int64, n int) bool
}

func (r *readerCovFailingAt) ReadAt(p []byte, off int64) (int, error) {
	if r.fail != nil && r.fail(off, len(p)) {
		return 0, errReaderCovDevice
	}
	return bytes.NewReader(r.data).ReadAt(p, off)
}

// readerCovErrReader answers every read with an error that is neither the end
// of the stream nor a short read.
type readerCovErrReader struct{}

func (readerCovErrReader) Read([]byte) (int, error) { return 0, errReaderCovDevice }

// The fixed-width fields of a central directory record, counted from its
// signature.
const (
	readerCovFlags      = 8
	readerCovMethod     = 10
	readerCovCompSize   = 20
	readerCovUncompSize = 24
	readerCovNameLen    = 28
	readerCovExtraLen   = 30
	readerCovCommentLen = 32
	readerCovLocalOff   = 42
)

// readerCovStored returns an archive holding one stored entry.
func readerCovStored(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	w := mustCreateHeader(t, zw, &FileHeader{Name: name, Method: Store})
	mustWrite(t, w, data)
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	return buf.Bytes()
}

// readerCovOpen reads an archive back and fails the test if it will not open.
func readerCovOpen(t *testing.T, raw []byte) *Reader {
	t.Helper()
	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	return zr
}

// readerCovOpenWith is readerCovOpen for an archive that carries a password.
func readerCovOpenWith(t *testing.T, raw []byte, password string) *Reader {
	t.Helper()
	zr, err := NewReaderWithPassword(bytes.NewReader(raw), int64(len(raw)), password)
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	return zr
}

// readerCovSet16 overwrites a two-byte field of the named entry's central
// directory record.
func readerCovSet16(t *testing.T, raw []byte, name string, field int, v uint16) {
	t.Helper()
	binary.LittleEndian.PutUint16(raw[centralHeaderOffset(t, raw, name)+field:], v)
}

// readerCovSet32 overwrites a four-byte field of the same record.
func readerCovSet32(t *testing.T, raw []byte, name string, field int, v uint32) {
	t.Helper()
	binary.LittleEndian.PutUint32(raw[centralHeaderOffset(t, raw, name)+field:], v)
}

// readerCovOrFlags turns bits on in the named entry's flags without disturbing
// the ones the writer set: clearing the data-descriptor bit would move where
// the entry ends, and clearing the UTF-8 bit would change how it is named.
func readerCovOrFlags(t *testing.T, raw []byte, name string, bits uint16) {
	t.Helper()
	at := centralHeaderOffset(t, raw, name) + readerCovFlags
	binary.LittleEndian.PutUint16(raw[at:], binary.LittleEndian.Uint16(raw[at:])|bits)
}

// readerCovExtra lays out one extra field: a tag, a declared length, and the
// bytes that follow it. The two are given separately so that a field can
// declare more than it holds.
func readerCovExtra(tag, size uint16, body ...byte) []byte {
	buf := make([]byte, 0, 4+len(body))
	buf = binary.LittleEndian.AppendUint16(buf, tag)
	buf = binary.LittleEndian.AppendUint16(buf, size)
	return append(buf, body...)
}

// readerCovAesExtra builds a WinZip AES extra field (0x9901).
func readerCovAesExtra(version uint16, strength byte, method uint16) []byte {
	body := make([]byte, 0, 7)
	body = binary.LittleEndian.AppendUint16(body, version)
	body = append(body, strength)
	body = binary.LittleEndian.AppendUint16(body, 0x4541) // the vendor mark, "AE"
	body = binary.LittleEndian.AppendUint16(body, method)
	return readerCovExtra(winzipAesExtraID, 7, body...)
}

// readerCovExtraArchive returns an archive whose single entry carries extra,
// with patch given the entry's central directory record afterwards.
func readerCovExtraArchive(t *testing.T, extra []byte, patch func(cd []byte)) []byte {
	t.Helper()
	raw := rawEntryArchive(t, &FileHeader{Name: "extras.bin", Method: Store, Extra: extra}, nil)
	if patch != nil {
		patch(raw[centralHeaderOffset(t, raw, "extras.bin"):])
	}
	return raw
}

// readerCovAddCentralExtra inserts an extra field into the named entry's
// central directory record and grows the directory size the end record keeps,
// so that the archive still reads afterwards.
func readerCovAddCentralExtra(t *testing.T, raw []byte, name string, extra []byte) []byte {
	t.Helper()
	cd := centralHeaderOffset(t, raw, name)
	nameLen := int(binary.LittleEndian.Uint16(raw[cd+readerCovNameLen:]))
	extraLen := int(binary.LittleEndian.Uint16(raw[cd+readerCovExtraLen:]))
	grown, err := fitUint16(extraLen+len(extra), "the fixture's extra field")
	if err != nil {
		t.Fatal(err)
	}
	added, err := fitUint16(len(extra), "the fixture's extra field")
	if err != nil {
		t.Fatal(err)
	}
	at := cd + directoryHeaderLen + nameLen + extraLen

	out := append([]byte(nil), raw[:at]...)
	out = append(out, extra...)
	out = append(out, raw[at:]...)
	binary.LittleEndian.PutUint16(out[cd+readerCovExtraLen:], grown)

	end := bytes.LastIndex(out, []byte{'P', 'K', 0x05, 0x06})
	if end < 0 {
		t.Fatal("no end of central directory record in the archive")
	}
	binary.LittleEndian.PutUint32(out[end+12:], binary.LittleEndian.Uint32(out[end+12:])+uint32(added))
	return out
}

// readerCovLocalHeader lays out a local file header with nothing behind it, for
// the archives that have no central directory at all and have to be salvaged.
func readerCovLocalHeader(t *testing.T, name string, method, flags uint16, comp, uncomp uint32, extra []byte) []byte {
	t.Helper()
	nameLen, err := fitUint16(len(name), "the fixture's file name")
	if err != nil {
		t.Fatal(err)
	}
	extraLen, err := fitUint16(len(extra), "the fixture's extra field")
	if err != nil {
		t.Fatal(err)
	}

	var head [fileHeaderLen]byte
	b := writeBuf(head[:])
	b.uint32(fileHeaderSignature)
	b.uint16(zipVersion45)
	b.uint16(flags)
	b.uint16(method)
	b.uint16(0) // time
	b.uint16(0) // date
	b.uint32(0) // crc
	b.uint32(comp)
	b.uint32(uncomp)
	b.uint16(nameLen)
	b.uint16(extraLen)

	out := append([]byte(nil), head[:]...)
	out = append(out, name...)
	return append(out, extra...)
}

// readerCovLocator lays out a zip64 end of central directory locator followed
// by an end record whose fields are saturated, so that the reader goes looking
// for the record the locator names.
func readerCovLocator(sig, disk uint32, recordOffset uint64, disks uint32) []byte {
	buf := make([]byte, 0, directory64LocLen+directoryEndLen)
	buf = binary.LittleEndian.AppendUint32(buf, sig)
	buf = binary.LittleEndian.AppendUint32(buf, disk)
	buf = binary.LittleEndian.AppendUint64(buf, recordOffset)
	buf = binary.LittleEndian.AppendUint32(buf, disks)
	return buf
}

func TestReaderCovEncryptedDataErrorLeavesAWrappedErrorAlone(t *testing.T) {
	// The wrapper says "wrong password or corrupt data" once; wrapping an
	// error that already carries it would say it twice.
	f := &File{FileHeader: FileHeader{Flags: 0x1, Method: Store}}
	already := fmt.Errorf("reading the entry: %w", &EncryptedDataError{Err: ErrChecksum})
	if got := encryptedDataError(f, already); got != already {
		t.Fatalf("the error was wrapped a second time: %v", got)
	}
}

func TestReaderCovEncryptedDataErrorWrapsACorruptStream(t *testing.T) {
	// A compressed entry betrays a wrong password through the decompressor,
	// which meets the garbage as a corrupt stream, a stream that ends early,
	// or one the reader refuses outright.
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"a corrupt stream", flate.CorruptInputError(3)},
		{"a stream that ends early", io.ErrUnexpectedEOF},
		{"a stream the reader refuses", ErrFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &File{FileHeader: FileHeader{Flags: 0x1, Method: Deflate}}
			got := encryptedDataError(f, tc.err)
			if !errors.Is(got, ErrPassword) {
				t.Errorf("%v came back as %v, want it reported as a password failure", tc.err, got)
			}
			if !errors.Is(got, tc.err) {
				t.Errorf("the underlying %v is no longer reachable through %v", tc.err, got)
			}
		})
	}
}

func TestReaderCovNewReaderRefusesANegativeSize(t *testing.T) {
	// The size is the caller's, and everything downstream reads inside it.
	if _, err := NewReader(bytes.NewReader(nil), -1); err == nil {
		t.Fatal("an archive of negative length was accepted")
	}
}

func TestReaderCovNewReaderReportsAnUnreadableXCryptHeader(t *testing.T) {
	// The crypto header is parsed before anything else is decided, and an
	// archive carrying one that cannot be parsed is not an archive whose
	// stub should be handed over instead.
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	w := mustCreateHeader(t, zw, &FileHeader{Name: ".zipext/xcrypt/crypto.hdr", Method: Store})
	mustWrite(t, w, []byte("this is not an XCrypt header"))
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	raw := buf.Bytes()

	if _, err := NewReaderWithPassword(bytes.NewReader(raw), int64(len(raw)), "secret"); err == nil {
		t.Fatal("an archive with an unparsable XCrypt header was opened")
	}
}

func TestReaderCovSalvageStopsWhenTheArchiveStopsAnswering(t *testing.T) {
	// No end record can be read, so the reader falls back to scanning for
	// local headers -- and the scan cannot read either.
	raw := readerCovStored(t, "entry.txt", []byte("payload"))
	ra := &readerCovFailingAt{data: raw, fail: func(int64, int) bool { return true }}

	if _, err := NewReader(ra, int64(len(raw))); !errors.Is(err, ErrFormat) {
		t.Fatalf("an archive that answers nothing gave %v, want ErrFormat", err)
	}
}

func TestReaderCovSalvageStopsOnAHeaderItCannotFinish(t *testing.T) {
	// The signature is there and the rest of the header is not.
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data, fileHeaderSignature)
	ra := &readerCovFailingAt{data: data, fail: func(_ int64, n int) bool { return n > 4 }}

	if _, err := NewReader(ra, int64(len(data))); !errors.Is(err, ErrFormat) {
		t.Fatalf("an archive whose only header cannot be read gave %v, want ErrFormat", err)
	}
}

func TestReaderCovSalvageStopsAtAZip64ExtraThatOverrunsItself(t *testing.T) {
	// The 32-bit compressed size is saturated, so the real one is asked of
	// the zip64 extra -- which declares sixteen bytes and holds none. The
	// entry keeps the size it was found with rather than one read from
	// past the end of the field.
	extra := readerCovExtra(zip64ExtraID, 16)
	raw := readerCovLocalHeader(t, "huge.txt", Store, 0, uint32max, 4, extra)

	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("salvage refused the archive: %v", err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "huge.txt" {
		t.Fatalf("salvage recovered %d entries, want the one local header there is", len(zr.File))
	}
	if got := zr.File[0].CompressedSize64; got != uint32max {
		t.Fatalf("the entry came back with a compressed size of %d, want the saturated %d", got, uint64(uint32max))
	}
}

// readerCovEncryptedDirectory rewrites the archive's tail as a zip64 end
// record carrying the version 2 fields, which is where an archive says its
// central directory is encrypted and with how long a key.
func readerCovEncryptedDirectory(t *testing.T, raw []byte, bitLen uint16) []byte {
	t.Helper()
	end := bytes.LastIndex(raw, []byte{'P', 'K', 0x05, 0x06})
	if end < 0 {
		t.Fatal("no end of central directory record in the archive")
	}
	records := binary.LittleEndian.Uint16(raw[end+10:])
	dirSize := binary.LittleEndian.Uint32(raw[end+12:])
	dirOffset := binary.LittleEndian.Uint32(raw[end+16:])

	out := append([]byte(nil), raw[:end]...)
	recOffset := uint64(len(out))

	var rec [directory64EndLen + 24]byte
	b := writeBuf(rec[:])
	b.uint32(directory64EndSignature)
	b.uint64(directory64EndLen - 12 + 24)
	b.uint16(zipVersion45)
	b.uint16(zipVersion45)
	b.uint32(0)
	b.uint32(0)
	b.uint64(uint64(records))
	b.uint64(uint64(records))
	b.uint64(uint64(dirSize))
	b.uint64(uint64(dirOffset))
	b.uint16(Store)           // the method the directory is stored with
	b.uint64(uint64(dirSize)) // compressed size
	b.uint64(uint64(dirSize)) // original size
	b.uint16(sesAES256)
	b.uint16(bitLen)
	b.uint16(1) // the bit that says the directory is encrypted
	out = append(out, rec[:]...)

	var loc [directory64LocLen]byte
	b = writeBuf(loc[:])
	b.uint32(directory64LocSignature)
	b.uint32(0)
	b.uint64(recOffset)
	b.uint32(1)
	out = append(out, loc[:]...)

	tail := append([]byte(nil), raw[end:]...)
	binary.LittleEndian.PutUint32(tail[16:], uint32max) // the offset now lives in the zip64 record
	return append(out, tail...)
}

func TestReaderCovEncryptedCentralDirectoryUsesTheDeclaredKeyLength(t *testing.T) {
	// The key length comes out of the end record, and the directory is then
	// read through a stream decrypted with it. The password here is not the
	// one the (unencrypted) directory was written with, so what comes back
	// is the verifier's refusal rather than a directory.
	raw := readerCovStored(t, "entry.txt", []byte("payload"))
	for _, bitLen := range []uint16{192, 256} {
		t.Run(fmt.Sprintf("%d bit", bitLen), func(t *testing.T) {
			forged := readerCovEncryptedDirectory(t, raw, bitLen)
			_, err := NewReaderWithPassword(bytes.NewReader(forged), int64(len(forged)), "secret")
			if err == nil {
				t.Fatal("an encrypted central directory was read with the wrong password")
			}
			if !errors.Is(err, ErrPassword) {
				t.Fatalf("reading an encrypted central directory gave %v, want a password failure", err)
			}
		})
	}
}

func TestReaderCovInsecurePathsSkipsAnEntryWithNoName(t *testing.T) {
	// With the path check turned on, every name is held to being local. An
	// entry with no name at all has nothing to check and is left alone
	// rather than refused.
	raw := readerCovStored(t, "zqx", []byte("payload"))
	readerCovSet16(t, raw, "zqx", readerCovNameLen, 0)
	readerCovSet16(t, raw, "zqx", readerCovCommentLen, 3)

	saved := DisableInsecurePaths
	t.Cleanup(func() { DisableInsecurePaths = saved })
	DisableInsecurePaths = true

	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("an entry with no name was refused: %v", err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "" {
		t.Fatalf("the archive holds %d entries, want the one nameless one", len(zr.File))
	}
}

func TestReaderCovHeaderOffsetReportsTheLocalHeaderPosition(t *testing.T) {
	raw := readerCovStored(t, "entry.txt", []byte("payload"))
	zr := readerCovOpen(t, raw)

	if got, want := zr.File[0].HeaderOffset(), int64(localHeaderOffset(t, raw, "entry.txt")); got != want {
		t.Fatalf("HeaderOffset gave %d, want %d", got, want)
	}
}

func TestReaderCovDirectoryEntryWithContentIsRefused(t *testing.T) {
	// A name ending in a slash is a directory, and a directory that also
	// declares content is an entry no reader can make sense of.
	raw := readerCovStored(t, "adir/", nil)
	readerCovSet32(t, raw, "adir/", readerCovUncompSize, 5)
	zr := readerCovOpen(t, raw)

	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("opening the directory entry: %v", err)
	}
	closeAt(t, rc)
	if _, err := rc.Read(make([]byte, 4)); !errors.Is(err, ErrFormat) {
		t.Fatalf("reading a directory that declares five bytes gave %v, want ErrFormat", err)
	}
}

func TestReaderCovOpenReportsAMissingAesExtra(t *testing.T) {
	// The entry says it is WinZip AES and carries no 0x9901 field, so there
	// is nothing to say how long the key or the salt are.
	raw := readerCovStored(t, "aes.bin", bytes.Repeat([]byte("x"), 48))
	readerCovOrFlags(t, raw, "aes.bin", 0x1)
	readerCovSet16(t, raw, "aes.bin", readerCovMethod, winzipAesExtraID)
	zr := readerCovOpenWith(t, raw, "secret")

	if _, err := zr.File[0].Open(); err == nil {
		t.Fatal("an AES entry with no AES parameters was opened")
	}
}

func TestReaderCovOpenReportsAnUnreadableZipCryptoHeader(t *testing.T) {
	// Classic encryption puts a twelve-byte header in front of the data,
	// and an archive that cannot produce it is not one whose check byte
	// should be taken from an uninitialised buffer.
	raw := readerCovStored(t, "crypt.bin", []byte("0123456789abcdef"))
	readerCovOrFlags(t, raw, "crypt.bin", 0x1)

	lh := localHeaderOffset(t, raw, "crypt.bin")
	nameLen := int(binary.LittleEndian.Uint16(raw[lh+26:]))
	extraLen := int(binary.LittleEndian.Uint16(raw[lh+28:]))
	body := int64(lh + fileHeaderLen + nameLen + extraLen)

	ra := &readerCovFailingAt{data: raw, fail: func(off int64, n int) bool {
		return off == body && n == 12
	}}
	zr, err := NewReaderWithPassword(ra, int64(len(raw)), "secret")
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	if _, err := zr.File[0].Open(); !errors.Is(err, errReaderCovDevice) {
		t.Fatalf("opening an entry whose encryption header cannot be read gave %v", err)
	}
}

func TestReaderCovZipCryptoChecksAgainstTheModifiedTime(t *testing.T) {
	// An entry that defers its checksum to a data descriptor has no CRC in
	// the header to check the password against, so the format uses the high
	// byte of the modification time instead.
	raw := readerCovStored(t, "ddcrypt.bin", []byte("0123456789abcdef"))
	readerCovOrFlags(t, raw, "ddcrypt.bin", 0x1|0x8)
	zr := readerCovOpenWith(t, raw, "secret")

	if _, err := zr.File[0].Open(); !errors.Is(err, ErrPassword) {
		t.Fatalf("opening the entry gave %v, want the password refused", err)
	}
}

func TestReaderCovOpenBuildsAPPMdReader(t *testing.T) {
	// Method 98 is not in the decompressor table: it is dispatched by hand
	// because the reader has to hand it the uncompressed size as well.
	body := []byte{0x05, 0x00} // the PPMd parameters, then nothing to decode
	body = append(body, bytes.Repeat([]byte{0}, 32)...)
	raw := rawEntryArchive(t, &FileHeader{
		Name:               "ppmd.bin",
		Method:             98,
		CompressedSize64:   uint64(len(body)),
		UncompressedSize64: 16,
	}, body)
	zr := readerCovOpen(t, raw)

	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("opening a PPMd entry: %v", err)
	}
	if rc == nil {
		t.Fatal("opening a PPMd entry gave no reader and no error")
	}
	closeAt(t, rc)
}

func TestReaderCovZip64EntryReadsTheLongerDataDescriptor(t *testing.T) {
	// A zip64 entry's data descriptor carries its two sizes as eight bytes
	// each, so the reader has to look for twenty-four bytes after the data
	// rather than sixteen.
	body := []byte("data")
	raw := rawEntryArchive(t, &FileHeader{
		Name:               "dd64.bin",
		Method:             Store,
		Flags:              0x8,
		Extra:              readerCovExtra(zip64ExtraID, 0),
		CompressedSize64:   uint64(len(body)),
		UncompressedSize64: uint64(len(body)),
		CRC32:              crc32.ChecksumIEEE(body),
	}, body)
	zr := readerCovOpen(t, raw)
	if !zr.File[0].zip64 {
		t.Fatal("the zip64 extra field was not recognised")
	}

	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("opening the entry: %v", err)
	}
	closeAt(t, rc)
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading the entry: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("read %q, want %q", got, body)
	}
}

func TestReaderCovOpenRawRefusesAnEntryThatIsNotThere(t *testing.T) {
	var f *File
	if _, err := f.OpenRaw(); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("OpenRaw on no entry at all gave %v, want ErrInvalid", err)
	}
}

// readerCovMovedHeaderArchive points the entry's central directory record at a
// place in the archive where no local header is, which is what every path that
// starts by reading the local header has to answer for.
func readerCovMovedHeaderArchive(t *testing.T, name string, method uint16) []byte {
	t.Helper()
	body := bytes.Repeat([]byte("payload "), 64)
	raw := rawEntryArchive(t, &FileHeader{
		Name:               name,
		Method:             method,
		CompressedSize64:   uint64(len(body)),
		UncompressedSize64: uint64(len(body)),
	}, body)
	readerCovSet32(t, raw, name, readerCovLocalOff, 3)
	return raw
}

func TestReaderCovOpenRawReportsAMissingLocalHeader(t *testing.T) {
	raw := readerCovMovedHeaderArchive(t, "moved.bin", Store)
	zr := readerCovOpen(t, raw)

	if _, err := zr.File[0].OpenRaw(); !errors.Is(err, ErrFormat) {
		t.Fatalf("OpenRaw on an entry whose local header is not there gave %v, want ErrFormat", err)
	}
}

func TestReaderCovOpenSeekableReportsAMissingLocalHeader(t *testing.T) {
	// Both sides of the seek path start by reading the local header: the
	// stored entry to find where its data begins, and the compressed one to
	// find where its hidden index begins.
	for _, tc := range []struct {
		name   string
		method uint16
	}{
		{"a stored entry", Store},
		{"a compressed entry", Deflate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := readerCovMovedHeaderArchive(t, "moved.bin", tc.method)
			zr := readerCovOpen(t, raw)
			if _, err := zr.File[0].OpenSeekable(); !errors.Is(err, ErrFormat) {
				t.Fatalf("OpenSeekable gave %v, want ErrFormat", err)
			}
		})
	}
}

func TestReaderCovOpenReportsAMissingLocalHeaderThroughTheFileSystem(t *testing.T) {
	// Reader is an fs.FS, and opening a name through it opens the entry.
	raw := readerCovMovedHeaderArchive(t, "moved.bin", Store)
	zr := readerCovOpen(t, raw)

	if _, err := zr.Open("moved.bin"); !errors.Is(err, ErrFormat) {
		t.Fatalf("opening the entry through the file system gave %v, want ErrFormat", err)
	}
}

func TestReaderCovHiddenIndexLooksPastAZip64DataDescriptor(t *testing.T) {
	// The hidden seek index sits behind the entry's data and behind its data
	// descriptor, which is twenty-four bytes long for a zip64 entry. Here
	// the entry claims a terabyte, so the place the index would be is past
	// the end of the archive and the entry simply has no index.
	body := []byte("compressed bytes")
	raw := rawEntryArchive(t, &FileHeader{
		Name:               "big.bin",
		Method:             Deflate,
		Flags:              0x8,
		CompressedSize64:   1 << 40,
		UncompressedSize64: 1 << 40,
	}, body)
	zr := readerCovOpen(t, raw)
	if !zr.File[0].zip64 {
		t.Fatal("an entry declaring a terabyte was not written as zip64")
	}

	_, err := zr.File[0].OpenSeekable()
	if err == nil || !strings.Contains(err.Error(), "seek index missing") {
		t.Fatalf("OpenSeekable gave %v, want the index reported missing", err)
	}
}

func TestReaderCovHiddenIndexNeedsAWholeLocalHeader(t *testing.T) {
	// Four bytes of signature is not a header. What follows them has to be
	// readable too before anything is parsed out of it.
	raw, header, _ := seekableArchive(t, false, 4096)
	ra := &readerCovFailingAt{data: raw, fail: func(off int64, n int) bool {
		return off == int64(header) && n == fileHeaderLen
	}}
	zr, err := NewReader(ra, int64(len(raw)))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}

	_, err = zr.File[0].OpenSeekable()
	if err == nil || !strings.Contains(err.Error(), "seek index missing") {
		t.Fatalf("OpenSeekable gave %v, want the index reported missing", err)
	}
}

func TestReaderCovHiddenIndexIsIgnoredWhenItIsNotAsItShouldBe(t *testing.T) {
	// The index is looked for by the shape of the entry that holds it: a
	// stored entry, with an unmasked name that names the entry it indexes.
	// Anything else behind the data is somebody else's entry.
	for _, tc := range []struct {
		name  string
		forge func(t *testing.T, raw []byte, header int)
	}{
		{"a compressed index entry", func(_ *testing.T, raw []byte, header int) {
			binary.LittleEndian.PutUint16(raw[header+8:], Deflate)
		}},
		{"an index entry whose name is masked", func(_ *testing.T, raw []byte, header int) {
			binary.LittleEndian.PutUint16(raw[header+6:], 0x2000)
		}},
		{"an index entry named for another entry", func(_ *testing.T, raw []byte, header int) {
			raw[header+fileHeaderLen] = 'X'
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, header, _ := seekableArchive(t, false, 4096)
			tc.forge(t, raw, header)

			err := openSeekableErr(t, raw)
			if err == nil || !strings.Contains(err.Error(), "seek index missing") {
				t.Fatalf("OpenSeekable gave %v, want the index reported missing", err)
			}
		})
	}
}

func TestReaderCovHiddenIndexReportsAnUnreadableName(t *testing.T) {
	// The name is what says whether this entry is the index of the entry in
	// front of it, so a name that cannot be read is not a name that can be
	// treated as not matching.
	raw, header, _ := seekableArchive(t, false, 4096)
	nameLen := int(binary.LittleEndian.Uint16(raw[header+26:]))
	nameAt := int64(header + fileHeaderLen)

	ra := &readerCovFailingAt{data: raw, fail: func(off int64, n int) bool {
		return off == nameAt && n == nameLen
	}}
	zr, err := NewReader(ra, int64(len(raw)))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	if _, err := zr.File[0].OpenSeekable(); !errors.Is(err, errReaderCovDevice) {
		t.Fatalf("OpenSeekable gave %v, want the read failure reported", err)
	}
}

func TestReaderCovHiddenIndexReportsAnUnreadablePayload(t *testing.T) {
	raw, _, payload := seekableArchive(t, false, 4096)
	ra := &readerCovFailingAt{data: raw, fail: func(off int64, _ int) bool {
		return off == int64(payload)
	}}
	zr, err := NewReader(ra, int64(len(raw)))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	if _, err := zr.File[0].OpenSeekable(); !errors.Is(err, errReaderCovDevice) {
		t.Fatalf("OpenSeekable gave %v, want the read failure reported", err)
	}
}

func TestReaderCovHiddenIndexSkipsExtraFieldsItDoesNotWant(t *testing.T) {
	// When the index entry's 32-bit size is saturated, the real size is
	// asked of its zip64 extra -- and the extra field is a list, so the
	// tags in front of the one wanted have to be stepped over.
	raw, header, payload := seekableArchive(t, false, 4096)
	binary.LittleEndian.PutUint32(raw[header+18:], uint32max)
	extraLen := binary.LittleEndian.Uint16(raw[header+28:])
	binary.LittleEndian.PutUint16(raw[header+28:], extraLen+8)

	// The eight bytes now read as the end of the extra field are the first
	// eight of the payload, which is where a tag that is not the zip64 one
	// goes, behind the tags the index already carries.
	b := writeBuf(raw[payload:])
	b.uint16(0x9999)
	b.uint16(4)
	b.uint32(0)

	// With no zip64 field to be found the size stays saturated, so the
	// payload read back is the rest of the archive -- and the numbers in it
	// are not the offsets of a few kilobytes of entry.
	if err := openSeekableErr(t, raw); err == nil {
		t.Fatal("an index read out of the middle of the archive was believed")
	}
}

func TestReaderCovHiddenIndexStopsAtATruncatedExtraField(t *testing.T) {
	// A tag in the index entry's extra field that declares more bytes than
	// the field has left used to be sliced past, which panicked.
	raw, header, payload := seekableArchive(t, false, 4096)
	binary.LittleEndian.PutUint32(raw[header+18:], uint32max)
	extraLen := binary.LittleEndian.Uint16(raw[header+28:])
	binary.LittleEndian.PutUint16(raw[header+28:], extraLen+4)

	// The four bytes now ending the extra field are a tag header whose
	// declared size runs past the end of the field.
	b := writeBuf(raw[payload:])
	b.uint16(0x9999)
	b.uint16(4)

	if err := openSeekableErr(t, raw); err == nil {
		t.Fatal("an index read out of the middle of the archive was believed")
	}
}

func TestReaderCovOpenSeekableRefusesAnEncryptedEntryWithNoPassword(t *testing.T) {
	raw := readerCovStored(t, "locked.bin", []byte("payload"))
	readerCovOrFlags(t, raw, "locked.bin", 0x1)
	zr := readerCovOpen(t, raw)

	_, err := zr.File[0].OpenSeekable()
	if err == nil || !strings.Contains(err.Error(), "no password provided") {
		t.Fatalf("OpenSeekable gave %v, want the missing password reported", err)
	}
}

func TestReaderCovOpenSeekableRefusesClassicZipCrypto(t *testing.T) {
	// Classic encryption is a stream cipher whose state is the bytes before
	// the wanted one, so there is no reading it from the middle.
	raw := readerCovStored(t, "classic.bin", []byte("payload"))
	readerCovOrFlags(t, raw, "classic.bin", 0x1)
	zr := readerCovOpenWith(t, raw, "secret")

	_, err := zr.File[0].OpenSeekable()
	if err == nil || !strings.Contains(err.Error(), "classic ZipCrypto") {
		t.Fatalf("OpenSeekable gave %v, want classic encryption refused", err)
	}
}

func TestReaderCovOpenSeekableReportsUnusableAesParameters(t *testing.T) {
	// The key length is the archive's to declare, and one the format has no
	// spelling for leaves nothing to derive a key with.
	body := bytes.Repeat([]byte("x"), 64)
	raw := rawEntryArchive(t, &FileHeader{
		Name:               "aes.bin",
		Method:             winzipAesExtraID,
		Flags:              0x1,
		Extra:              readerCovAesExtra(2, 5, Store),
		CompressedSize64:   uint64(len(body)),
		UncompressedSize64: 32,
	}, body)
	zr := readerCovOpenWith(t, raw, "secret")

	_, err := zr.File[0].OpenSeekable()
	if err == nil || !strings.Contains(err.Error(), "AES strength") {
		t.Fatalf("OpenSeekable gave %v, want the key length refused", err)
	}
}

func TestReaderCovOpenSeekableReadsAStoredEntry(t *testing.T) {
	// A stored entry needs no index: its bytes are where they are.
	want := []byte("the whole payload, uncompressed")
	raw := readerCovStored(t, "plain.bin", want)
	zr := readerCovOpen(t, raw)

	rs, err := zr.File[0].OpenSeekable()
	if err != nil {
		t.Fatalf("OpenSeekable on a stored entry: %v", err)
	}
	if _, err := rs.Seek(4, io.SeekStart); err != nil {
		t.Fatalf("seeking: %v", err)
	}
	got, err := io.ReadAll(rs)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if string(got) != string(want[4:]) {
		t.Fatalf("read %q, want %q", got, want[4:])
	}
}

func TestReaderCovOpenSeekableRefusesAMalformedIndex(t *testing.T) {
	for _, tc := range []struct {
		name       string
		continuous bool
		want       string
		forge      func(raw []byte, header, payload int)
	}{
		{
			name: "a SOZip index too short for its own header",
			want: "invalid SOZip index length",
			forge: func(raw []byte, header, _ int) {
				binary.LittleEndian.PutUint32(raw[header+18:], 10)
			},
		},
		{
			name: "a SOZip index whose offsets are not eight bytes",
			want: "unsupported SOZip offset size",
			forge: func(raw []byte, _, payload int) {
				binary.LittleEndian.PutUint32(raw[payload+12:], 4)
			},
		},
		{
			name:       "a GZIDX index that does not say GZIDX",
			continuous: true,
			want:       "invalid GZIDX payload",
			forge: func(raw []byte, _, payload int) {
				copy(raw[payload:], "XZIDX")
			},
		},
		{
			name:       "a GZIDX index short of the windows it claims",
			continuous: true,
			want:       "truncated window data",
			forge: func(raw []byte, _, payload int) {
				// The first point carries no window; saying it does
				// asks for one more than the payload holds.
				raw[payload+35+17] = 1
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, header, payload := seekableArchive(t, tc.continuous, 4096)
			tc.forge(raw, header, payload)

			err := openSeekableErr(t, raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("OpenSeekable gave %v, want %q", err, tc.want)
			}
		})
	}
}

// readerCovSeeker returns a seek reader over the entry of a freshly built
// indexed archive, after handing the raw bytes to forge.
func readerCovSeeker(t *testing.T, continuous bool, size int, forge func(raw []byte, header, payload int)) io.ReadSeeker {
	t.Helper()
	raw, header, payload := seekableArchive(t, continuous, size)
	if forge != nil {
		forge(raw, header, payload)
	}
	rs, err := readerCovOpen(t, raw).File[0].OpenSeekable()
	if err != nil {
		t.Fatalf("OpenSeekable: %v", err)
	}
	return rs
}

func TestReaderCovSeekMovesRelativeToWhereItIs(t *testing.T) {
	rs := readerCovSeeker(t, false, 4096, nil)

	if _, err := rs.Read(make([]byte, 100)); err != nil {
		t.Fatalf("reading: %v", err)
	}
	at, err := rs.Seek(50, io.SeekCurrent)
	if err != nil {
		t.Fatalf("seeking from where the reader is: %v", err)
	}
	if at != 150 {
		t.Fatalf("the reader is at %d, want 150", at)
	}
	if at, err := rs.Seek(0, io.SeekEnd); err != nil || at != 4096 {
		t.Fatalf("seeking to the end gave %d, %v, want 4096", at, err)
	}
}

func TestReaderCovSeekRefusesAnOffsetOutsideTheEntry(t *testing.T) {
	rs := readerCovSeeker(t, false, 4096, nil)

	for _, tc := range []struct {
		name   string
		offset int64
		whence int
	}{
		{"before the start", -1, io.SeekStart},
		{"past the end", 4097, io.SeekStart},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rs.Seek(tc.offset, tc.whence); err == nil {
				t.Fatal("an offset outside the entry was accepted")
			}
		})
	}
}

func TestReaderCovReadStopsWhereTheIndexRunsOut(t *testing.T) {
	// The index says where each chunk begins, and an offset in a chunk the
	// index does not have is an offset there is no way to reach.
	for _, tc := range []struct {
		name       string
		continuous bool
		seek       int64
		forge      func(raw []byte, header, payload int)
	}{
		{
			name: "a SOZip index with fewer chunks than the offset needs",
			seek: 4000,
			forge: func(raw []byte, _, payload int) {
				// One byte per chunk makes the wanted chunk the
				// four-thousandth, and the index holds four.
				binary.LittleEndian.PutUint32(raw[payload+8:], 1)
			},
		},
		{
			name:       "a GZIDX index whose first point is not at the start",
			continuous: true,
			seek:       0,
			forge: func(raw []byte, _, payload int) {
				binary.LittleEndian.PutUint64(raw[payload+35+8:], 100)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rs := readerCovSeeker(t, tc.continuous, 4096, tc.forge)
			if _, err := rs.Seek(tc.seek, io.SeekStart); err != nil {
				t.Fatalf("seeking: %v", err)
			}
			if _, err := rs.Read(make([]byte, 16)); err != io.EOF {
				t.Fatalf("reading gave %v, want io.EOF", err)
			}
		})
	}
}

func TestReaderCovSeekableReadReportsALocalHeaderThatStopsAnswering(t *testing.T) {
	// The index is read when the entry is opened and the local header again
	// on the first read, so an archive that stops answering in between has
	// to be reported rather than read from wherever the offset lands.
	raw, _, _ := seekableArchive(t, false, 4096)
	lh := int64(localHeaderOffset(t, raw, "seek.bin"))

	armed := false
	ra := &readerCovFailingAt{data: raw, fail: func(off int64, n int) bool {
		return armed && off == lh && n == fileHeaderLen
	}}
	zr, err := NewReader(ra, int64(len(raw)))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	rs, err := zr.File[0].OpenSeekable()
	if err != nil {
		t.Fatalf("OpenSeekable: %v", err)
	}

	armed = true
	if _, err := rs.Read(make([]byte, 16)); !errors.Is(err, errReaderCovDevice) {
		t.Fatalf("reading gave %v, want the read failure reported", err)
	}
}

func TestReaderCovSeekableReadRefusesEncryptionItCannotSeekThrough(t *testing.T) {
	// Reading at an offset needs a cipher that can be started in the middle.
	// Only WinZip AES can, and only when its parameters make sense.
	for _, tc := range []struct {
		name     string
		password string
		want     string
		forge    func(t *testing.T, raw []byte) []byte
	}{
		{
			name: "an encrypted entry with no password",
			want: "no password provided",
			forge: func(t *testing.T, raw []byte) []byte {
				readerCovOrFlags(t, raw, "seek.bin", 0x1)
				return raw
			},
		},
		{
			name:     "classic encryption",
			password: "secret",
			want:     "classic ZipCrypto",
			forge: func(t *testing.T, raw []byte) []byte {
				readerCovOrFlags(t, raw, "seek.bin", 0x1)
				return raw
			},
		},
		{
			name:     "AES with a key length the format has no spelling for",
			password: "secret",
			want:     "AES strength",
			forge: func(t *testing.T, raw []byte) []byte {
				raw = readerCovAddCentralExtra(t, raw, "seek.bin", readerCovAesExtra(2, 5, Deflate))
				readerCovOrFlags(t, raw, "seek.bin", 0x1)
				readerCovSet16(t, raw, "seek.bin", readerCovMethod, winzipAesExtraID)
				return raw
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _, _ := seekableArchive(t, false, 4096)
			raw = tc.forge(t, raw)

			zr, err := NewReaderWithPassword(bytes.NewReader(raw), int64(len(raw)), tc.password)
			if err != nil {
				t.Fatalf("reading the archive back: %v", err)
			}
			rs, err := zr.File[0].OpenSeekable()
			if err != nil {
				t.Fatalf("OpenSeekable: %v", err)
			}
			_, err = rs.Read(make([]byte, 16))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("reading gave %v, want %q", err, tc.want)
			}
		})
	}
}

func TestReaderCovSeekableReadRefusesAnUnknownMethod(t *testing.T) {
	// The index says where the chunks are; it does not say what to do with
	// them. That is the entry's method, and nothing is registered for 77.
	for _, tc := range []struct {
		name       string
		continuous bool
	}{
		{"a chunked index", false},
		{"a continuous index", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _, _ := seekableArchive(t, tc.continuous, 4096)
			readerCovSet16(t, raw, "seek.bin", readerCovMethod, 77)

			rs, err := readerCovOpen(t, raw).File[0].OpenSeekable()
			if err != nil {
				t.Fatalf("OpenSeekable: %v", err)
			}
			if _, err := rs.Read(make([]byte, 16)); !errors.Is(err, ErrAlgorithm) {
				t.Fatalf("reading gave %v, want ErrAlgorithm", err)
			}
		})
	}
}

func TestReaderCovSeekableReadReportsAChunkThatIsNotThere(t *testing.T) {
	// Every chunk after the first is said to begin where the entry's
	// compressed data ends, so the decompressor is handed nothing and the
	// bytes to be skipped before the wanted offset cannot be skipped.
	raw, header, payload := seekableArchive(t, false, 8192)
	compressed := readerCovOpen(t, raw).File[0].CompressedSize64
	indexLen := int(binary.LittleEndian.Uint32(raw[header+18:]))
	for at := payload + 32; at+8 <= payload+indexLen; at += 8 {
		binary.LittleEndian.PutUint64(raw[at:], compressed)
	}

	rs, err := readerCovOpen(t, raw).File[0].OpenSeekable()
	if err != nil {
		t.Fatalf("OpenSeekable: %v", err)
	}
	if _, err := rs.Seek(1025, io.SeekStart); err != nil {
		t.Fatalf("seeking: %v", err)
	}
	if _, err := rs.Read(make([]byte, 16)); err == nil {
		t.Fatal("a chunk with no bytes behind it was read as sound")
	}
}

func TestReaderCovOpenedEntryDescribesItself(t *testing.T) {
	// An entry opened through the file system is an fs.File, so it answers
	// for the header it came from.
	raw := readerCovStored(t, "stat.txt", []byte("payload"))
	zr := readerCovOpen(t, raw)

	f, err := zr.Open("stat.txt")
	if err != nil {
		t.Fatalf("opening the entry: %v", err)
	}
	closeAt(t, f)
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Name() != "stat.txt" || info.Size() != 7 {
		t.Fatalf("the entry describes itself as %q of %d bytes, want stat.txt of 7", info.Name(), info.Size())
	}
}

func TestReaderCovReadAfterTheEndRepeatsTheAnswer(t *testing.T) {
	// The reader remembers how it finished, so a caller that reads on past
	// the end is told the same thing rather than a fresh read of nothing.
	raw := readerCovStored(t, "entry.txt", []byte("payload"))
	zr := readerCovOpen(t, raw)

	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("opening the entry: %v", err)
	}
	closeAt(t, rc)
	if _, err := io.ReadAll(rc); err != nil {
		t.Fatalf("reading the entry: %v", err)
	}
	if _, err := rc.Read(make([]byte, 4)); err != io.EOF {
		t.Fatalf("reading past the end gave %v, want io.EOF", err)
	}
}

// readerCovOverreader reports one more byte than the buffer it was handed
// holds. That breaks the io.Reader contract, which is the point: a
// decompressor comes from outside this package and the reader has no way to
// hold one to the contract other than checking what it says it produced.
type readerCovOverreader struct{ r io.Reader }

func (o readerCovOverreader) Read(p []byte) (int, error) {
	n, err := o.r.Read(p)
	if n > 0 {
		n++
	}
	return n, err
}

func (readerCovOverreader) Close() error { return nil }

func TestReaderCovDecompressorCannotOverrunTheDeclaredSize(t *testing.T) {
	// Decompressors are a registered extension point, so the one the reader
	// gets is not one it wrote. The io.LimitReader in front of it shortens
	// the slice it is given but hands back whatever count comes up, so a
	// decompressor that overstates its count carries the entry past the
	// size it declared -- and the checksum is then taken over bytes the
	// archive never accounted for.
	body := []byte("0123456789")
	raw := rawEntryArchive(t, &FileHeader{
		Name:               "over.bin",
		Method:             77,
		CompressedSize64:   uint64(len(body)),
		UncompressedSize64: 4,
	}, body)

	zr := readerCovOpen(t, raw)
	zr.RegisterDecompressor(77, func(r io.Reader) io.ReadCloser {
		return readerCovOverreader{r: r}
	})

	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("opening the entry: %v", err)
	}
	closeAt(t, rc)
	// A buffer larger than the entry declares, so that the overstated count
	// still lands inside it and the read reaches the size check rather than
	// running off the caller's slice.
	if _, err := rc.Read(make([]byte, 64)); !errors.Is(err, ErrFormat) {
		t.Fatalf("a decompressor claiming more than it was given room for gave %v, want ErrFormat", err)
	}
}

func TestReaderCovDecompressorThatBuildsNoReaderIsRefused(t *testing.T) {
	// The same extension point from the other side: a decompressor that
	// answers a stream it cannot handle with a nil io.ReadCloser. Nothing
	// downstream can tell that from a working one, so opening the entry has
	// to be where it stops -- otherwise the limit reader wraps the nil and
	// the first read dereferences it.
	body := []byte("0123456789")
	raw := rawEntryArchive(t, &FileHeader{
		Name:               "nothing.bin",
		Method:             77,
		CompressedSize64:   uint64(len(body)),
		UncompressedSize64: uint64(len(body)),
	}, body)

	zr := readerCovOpen(t, raw)
	zr.RegisterDecompressor(77, func(io.Reader) io.ReadCloser { return nil })

	rc, err := zr.File[0].Open()
	if err == nil {
		closeAt(t, rc)
		t.Fatal("an entry whose decompressor built no reader opened as if it held data")
	}
	if !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("opening the entry gave %v, want ErrAlgorithm", err)
	}
	if !strings.Contains(err.Error(), "method 77") {
		t.Errorf("the error is %q, want it to name the method", err)
	}
}

func TestReaderCovEntryShorterThanItDeclaresIsRefused(t *testing.T) {
	// The entry says a hundred bytes and five are there. Stopping at five
	// and calling it a file would hand the caller a truncated one.
	body := []byte("hello")
	raw := rawEntryArchive(t, &FileHeader{
		Name:               "short.bin",
		Method:             Store,
		CompressedSize64:   uint64(len(body)),
		UncompressedSize64: 100,
		CRC32:              crc32.ChecksumIEEE(body),
	}, body)
	zr := readerCovOpen(t, raw)

	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("opening the entry: %v", err)
	}
	closeAt(t, rc)
	if _, err := io.ReadAll(rc); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("reading an entry short of what it declares gave %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReaderCovDirectoryHeaderRefusesAShortZip64Field(t *testing.T) {
	// Each saturated 32-bit field defers to eight bytes of the zip64 extra,
	// and a field with fewer than eight left has no number to give.
	for _, tc := range []struct {
		name  string
		field int
	}{
		{"the uncompressed size", readerCovUncompSize},
		{"the compressed size", readerCovCompSize},
		{"the offset of the local header", readerCovLocalOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := readerCovExtraArchive(t, readerCovExtra(zip64ExtraID, 4, 0, 0, 0, 0), func(cd []byte) {
				binary.LittleEndian.PutUint32(cd[tc.field:], uint32max)
			})
			if _, err := NewReader(bytes.NewReader(raw), int64(len(raw))); !errors.Is(err, ErrFormat) {
				t.Fatalf("a zip64 field of four bytes gave %v, want ErrFormat", err)
			}
		})
	}
}

func TestReaderCovDirectoryHeaderRefusesASaturatedSizeWithNoZip64Field(t *testing.T) {
	// 0xFFFFFFFF means "the real number is in the zip64 extra", and an
	// entry that says so without carrying one has no size at all.
	raw := readerCovExtraArchive(t, nil, func(cd []byte) {
		binary.LittleEndian.PutUint32(cd[readerCovCompSize:], uint32max)
	})
	if _, err := NewReader(bytes.NewReader(raw), int64(len(raw))); !errors.Is(err, ErrFormat) {
		t.Fatalf("a saturated compressed size with no zip64 extra gave %v, want ErrFormat", err)
	}
}

func TestReaderCovDirectoryHeaderStepsOverMalformedExtraFields(t *testing.T) {
	// An extra field is a list of tagged records, and one record being
	// unreadable must not cost the records after it. Every case here is a
	// record the parser has to step over, followed by an extended timestamp
	// the entry is then expected to come back carrying.
	stamped := time.Date(2003, time.April, 5, 6, 7, 8, 0, time.UTC)
	timestamp := func() []byte {
		body := make([]byte, 0, 5)
		body = append(body, 1) // the flag that says a modification time follows
		// #nosec G115 -- the tag holds four bytes of Unix time and this is a time that fits them
		body = binary.LittleEndian.AppendUint32(body, uint32(stamped.Unix()))
		return readerCovExtra(extTimeExtraID, 5, body...)
	}

	for _, tc := range []struct {
		name   string
		broken []byte
	}{
		{"an NTFS field too short for its reserved word", readerCovExtra(ntfsExtraID, 2, 0, 0)},
		{
			"an NTFS attribute longer than the field holding it",
			readerCovExtra(ntfsExtraID, 8, 0, 0, 0, 0, 1, 0, 100, 0),
		},
		{
			"an NTFS attribute that is not a set of times",
			readerCovExtra(ntfsExtraID, 8, 0, 0, 0, 0, 2, 0, 0, 0),
		},
		{"a Unix field with no times in it", readerCovExtra(unixExtraID, 4, 0, 0, 0, 0)},
		{"an Info-ZIP Unix field with no times in it", readerCovExtra(infoZipUnixExtraID, 4, 0, 0, 0, 0)},
		{"an extended timestamp with no flags", readerCovExtra(extTimeExtraID, 0)},
		{"an AES field too short for its parameters", readerCovExtra(winzipAesExtraID, 4, 0, 0, 0, 0)},
		{
			"an extended attribute whose name runs past the field",
			readerCovExtra(xattrExtraID, 6, 100, 0, 0, 0, 0, 0),
		},
		{
			"an extended attribute whose value runs past the field",
			readerCovExtra(xattrExtraID, 6, 2, 0, 'k', 'v', 100, 0),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := readerCovExtraArchive(t, append(tc.broken, timestamp()...), nil)
			zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
			if err != nil {
				t.Fatalf("the entry was refused: %v", err)
			}
			if got := zr.File[0].Modified.UTC(); !got.Equal(stamped) {
				t.Fatalf("the entry is stamped %v, want %v: the field after the broken one was not read", got, stamped)
			}
		})
	}
}

func TestReaderCovDirectoryHeaderReadsAnInfoZipUnixTimestamp(t *testing.T) {
	// The Info-ZIP Unix field carries an access time and a modification
	// time, in that order, as four bytes each.
	stamped := time.Date(2001, time.September, 9, 1, 46, 40, 0, time.UTC)
	body := make([]byte, 0, 8)
	// #nosec G115 -- the tag holds four bytes of Unix time and this is a time that fits them
	body = binary.LittleEndian.AppendUint32(body, uint32(stamped.Unix()))
	// #nosec G115 -- the tag holds four bytes of Unix time and this is a time that fits them
	body = binary.LittleEndian.AppendUint32(body, uint32(stamped.Unix()))

	raw := readerCovExtraArchive(t, readerCovExtra(infoZipUnixExtraID, 8, body...), nil)
	zr := readerCovOpen(t, raw)

	if got := zr.File[0].Modified.UTC(); !got.Equal(stamped) {
		t.Fatalf("the entry is stamped %v, want %v", got, stamped)
	}
}

func TestReaderCovDirectoryHeaderReadsADeviceNumber(t *testing.T) {
	// A device node has no content: what it has is a major and a minor
	// number, and the Unix extra field is where they are kept.
	body := make([]byte, 0, 20)
	body = binary.LittleEndian.AppendUint32(body, 0)  // access time
	body = binary.LittleEndian.AppendUint32(body, 0)  // modification time
	body = binary.LittleEndian.AppendUint16(body, 7)  // uid
	body = binary.LittleEndian.AppendUint16(body, 9)  // gid
	body = binary.LittleEndian.AppendUint32(body, 12) // major
	body = binary.LittleEndian.AppendUint32(body, 34) // minor

	fh := &FileHeader{Name: "dev.node", Method: Store, Extra: readerCovExtra(unixExtraID, 20, body...)}
	fh.SetMode(fs.ModeDevice | 0644)
	raw := rawEntryArchive(t, fh, nil)
	zr := readerCovOpen(t, raw)

	if got := zr.File[0]; got.Devmajor != 12 || got.Devminor != 34 {
		t.Fatalf("the device is %d:%d, want 12:34", got.Devmajor, got.Devminor)
	}
}

func TestReaderCovReportsADirectoryThatCannotBeRead(t *testing.T) {
	// The end record was readable and named the directory; the directory
	// itself is not. That is neither a malformed archive nor the end of
	// one, so it is handed back as it came rather than turned into a
	// shorter list of entries.
	raw := readerCovStored(t, "entry.txt", bytes.Repeat([]byte("payload "), 25))
	end := bytes.LastIndex(raw, []byte{'P', 'K', 0x05, 0x06})
	dirOff := int64(binary.LittleEndian.Uint32(raw[end+16:]))

	ra := &readerCovFailingAt{data: raw, fail: func(off int64, _ int) bool {
		return off == dirOff
	}}
	if _, err := NewReader(ra, int64(len(raw))); !errors.Is(err, errReaderCovDevice) {
		t.Fatalf("reading an archive whose directory cannot be read gave %v", err)
	}
}

func TestReaderCovDirectoryHeaderReportsATruncatedDirectory(t *testing.T) {
	// The record says its name is sixty-five thousand bytes long and the
	// archive ends well before that.
	raw := readerCovStored(t, "entry.txt", []byte("payload"))
	readerCovSet16(t, raw, "entry.txt", readerCovNameLen, 0xffff)

	if _, err := NewReader(bytes.NewReader(raw), int64(len(raw))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a directory record naming more than the archive holds gave %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReaderCovReadDataDescriptorReportsAFailingReader(t *testing.T) {
	if err := readDataDescriptor(readerCovErrReader{}, &File{}); !errors.Is(err, errReaderCovDevice) {
		t.Fatalf("reading a descriptor from a failing reader gave %v", err)
	}
}

func TestReaderCovReadDataDescriptorRefusesATruncatedDescriptor(t *testing.T) {
	// Twelve bytes is the shortest descriptor there is: a checksum and two
	// sizes, with the signature left out.
	if err := readDataDescriptor(bytes.NewReader(make([]byte, 8)), &File{}); err != io.ErrUnexpectedEOF {
		t.Fatalf("an eight-byte data descriptor gave %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReaderCovReadDirectoryEndReportsAFailingArchive(t *testing.T) {
	raw := readerCovStored(t, "entry.txt", []byte("payload"))
	ra := &readerCovFailingAt{data: raw, fail: func(int64, int) bool { return true }}

	if _, _, err := readDirectoryEnd(ra, int64(len(raw))); !errors.Is(err, errReaderCovDevice) {
		t.Fatalf("readDirectoryEnd gave %v, want the read failure reported", err)
	}
}

func TestReaderCovReadDirectoryEndRefusesADirectoryOutsideTheArchive(t *testing.T) {
	// Where the directory begins is worked out from where the end record is
	// and what it says the directory's size and offset are. Numbers that
	// put the directory before the start of the file, or the far side of
	// its end, describe no archive.
	raw := readerCovStored(t, "entry.txt", []byte("payload"))

	t.Run("a directory larger than the archive", func(t *testing.T) {
		forged := append([]byte(nil), raw...)
		end := bytes.LastIndex(forged, []byte{'P', 'K', 0x05, 0x06})
		binary.LittleEndian.PutUint32(forged[end+12:], 0xfffffff0)

		if _, _, err := readDirectoryEnd(bytes.NewReader(forged), int64(len(forged))); !errors.Is(err, ErrFormat) {
			t.Fatalf("readDirectoryEnd gave %v, want ErrFormat", err)
		}
	})

	t.Run("a size and an offset that wrap around each other", func(t *testing.T) {
		// Each is the largest number an int64 holds. Subtracting both
		// from the end record's offset wraps back to a small positive
		// number, so the start of the directory looks sound and the
		// place the directory is then read from does not.
		forged := appendZip64End(t, raw, directory64EndLen-12, 1<<63-1, 1<<63-1)

		if _, _, err := readDirectoryEnd(bytes.NewReader(forged), int64(len(forged))); !errors.Is(err, ErrFormat) {
			t.Fatalf("readDirectoryEnd gave %v, want ErrFormat", err)
		}
	})
}

// readerCovStubbedArchive puts a copy of the archive's central directory in
// front of the archive itself. The end record's numbers then place the
// directory before the bytes the archive begins at -- the shape a
// self-extracting stub leaves behind -- while a readable directory still sits
// exactly where the end record says one does.
func readerCovStubbedArchive(t *testing.T, raw []byte) []byte {
	t.Helper()
	end := bytes.LastIndex(raw, []byte{'P', 'K', 0x05, 0x06})
	if end < 0 {
		t.Fatal("no end of central directory record in the archive")
	}
	dirOffset := int(binary.LittleEndian.Uint32(raw[end+16:]))
	directory := raw[dirOffset:end]

	stub := make([]byte, dirOffset+len(directory))
	copy(stub[dirOffset:], directory)
	return append(stub, raw...)
}

func TestReaderCovDirectoryFoundWhereTheEndRecordSaysIsBelieved(t *testing.T) {
	// An archive with something in front of it has every offset in its end
	// record short by the length of that something, and the reader makes up
	// the difference. But when a readable directory is at the offset as
	// written, the offsets were never short and adding to them would read
	// the archive from the wrong place.
	raw := readerCovStored(t, "entry.txt", []byte("payload"))
	forged := readerCovStubbedArchive(t, raw)

	zr, err := NewReader(bytes.NewReader(forged), int64(len(forged)))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "entry.txt" {
		t.Fatalf("the archive lists %d entries, want its own entry.txt", len(zr.File))
	}
}

func TestReaderCovFindDirectory64EndAnswersNoRecordIsThere(t *testing.T) {
	// A locator is twenty bytes in front of the end record and says which
	// disk holds the zip64 record, where it is, and how many disks there
	// are. Anything that is not that is not a locator, and the answer is
	// that there is no zip64 record rather than an error.
	for _, tc := range []struct {
		name string
		buf  []byte
	}{
		{"no room in front of the end record for a locator", nil},
		{"a locator with the wrong signature", readerCovLocator(0xdeadbeef, 0, 12, 1)},
		{"a locator naming a disk other than this one", readerCovLocator(directory64LocSignature, 1, 12, 1)},
		{"a locator naming more than one disk", readerCovLocator(directory64LocSignature, 0, 12, 2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := append(make([]byte, 64), tc.buf...)
			// The locator sits immediately in front of the end
			// record, so the end record's offset is where what was
			// appended ends.
			offset := int64(len(raw))
			if tc.buf == nil {
				// Too near the start of the file for a locator
				// to fit in front of the end record.
				offset = 4
			}
			got, err := findDirectory64End(bytes.NewReader(raw), offset)
			if err != nil {
				t.Fatalf("findDirectory64End: %v", err)
			}
			if got != -1 {
				t.Fatalf("findDirectory64End gave %d, want -1", got)
			}
		})
	}
}

func TestReaderCovFindDirectory64EndReportsAFailingArchive(t *testing.T) {
	ra := &readerCovFailingAt{data: make([]byte, 64), fail: func(int64, int) bool { return true }}

	if _, err := findDirectory64End(ra, 40); !errors.Is(err, errReaderCovDevice) {
		t.Fatalf("findDirectory64End gave %v, want the read failure reported", err)
	}
}

func TestReaderCovReadDirectory64EndRefusesWhatIsNotARecord(t *testing.T) {
	var d directoryEnd

	t.Run("an archive that cannot be read", func(t *testing.T) {
		ra := &readerCovFailingAt{data: make([]byte, 128), fail: func(int64, int) bool { return true }}
		if err := readDirectory64End(ra, 0, 68, &d); !errors.Is(err, errReaderCovDevice) {
			t.Fatalf("readDirectory64End gave %v, want the read failure reported", err)
		}
	})

	t.Run("a record with the wrong signature", func(t *testing.T) {
		raw := make([]byte, 128)
		binary.LittleEndian.PutUint32(raw, 0xdeadbeef)
		if err := readDirectory64End(bytes.NewReader(raw), 0, 68, &d); !errors.Is(err, ErrFormat) {
			t.Fatalf("readDirectory64End gave %v, want ErrFormat", err)
		}
	})

	t.Run("a record the archive stops short of", func(t *testing.T) {
		// The first twelve bytes are there, so the record announces
		// itself; the fields it announces are not.
		raw := make([]byte, 32)
		b := writeBuf(raw)
		b.uint32(directory64EndSignature)
		b.uint64(directory64EndLen - 12)
		if err := readDirectory64End(bytes.NewReader(raw), 0, 68, &d); err == nil {
			t.Fatal("a record that runs off the end of the archive was read")
		}
	})
}

func TestReaderCovReadBufSubRefusesALengthItDoesNotHave(t *testing.T) {
	// sub hands out a run of bytes and steps over it. A run longer than
	// what is left, or one of negative length, is not a run: the buffer is
	// emptied so that the caller's loop ends rather than reading on.
	for _, tc := range []struct {
		name string
		n    int
	}{
		{"more than is left", 4},
		{"a negative length", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := readBuf([]byte{1, 2, 3})
			if got := b.sub(tc.n); got != nil {
				t.Errorf("sub gave %v, want nothing", got)
			}
			if len(b) != 0 {
				t.Errorf("%d bytes are left in the buffer, want none", len(b))
			}
		})
	}
}

func TestReaderCovFileSystemRefusesDuplicateEntries(t *testing.T) {
	// Two entries under one name, or a name that is both a file and the
	// directory another entry is in, leave no single answer to give for it.
	for _, tc := range []struct {
		name  string
		build func(zw *Writer)
	}{
		{"two files of the same name", func(zw *Writer) {
			mustCreate(t, zw, "sub/dup.txt")
			mustCreate(t, zw, "sub/dup.txt")
		}},
		{"two directories of the same name", func(zw *Writer) {
			mustCreate(t, zw, "sub/")
			mustCreate(t, zw, "sub/")
		}},
		{"a file that another entry treats as a directory", func(zw *Writer) {
			mustCreate(t, zw, "sub")
			mustCreate(t, zw, "sub/leaf.txt")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			zw := NewWriter(buf)
			tc.build(zw)
			if err := zw.Close(); err != nil {
				t.Fatalf("closing the writer: %v", err)
			}
			zr := readerCovOpen(t, buf.Bytes())

			_, err := fs.ReadDir(zr, ".")
			if err == nil {
				_, err = fs.ReadDir(zr, "sub")
			}
			if err == nil || !strings.Contains(err.Error(), "duplicate entries") {
				t.Fatalf("listing the archive gave %v, want the duplicate reported", err)
			}
		})
	}
}

func TestReaderCovFileSystemLeavesOutANameThatIsNothing(t *testing.T) {
	// "/" normalises to the empty string, which names nothing that can be
	// listed or opened. The entry stays in the archive; it is the file
	// system view it is left out of.
	raw := readerCovStored(t, "zqx", []byte("payload"))
	readerCovSet16(t, raw, "zqx", readerCovNameLen, 1)
	readerCovSet16(t, raw, "zqx", readerCovCommentLen, 2)
	raw[centralHeaderOffset(t, raw, "zqx")+directoryHeaderLen] = '/'

	zr := readerCovOpen(t, raw)
	if zr.File[0].Name != "/" {
		t.Fatalf("the entry is named %q, want %q", zr.File[0].Name, "/")
	}
	entries, err := fs.ReadDir(zr, ".")
	if err != nil {
		t.Fatalf("listing the archive: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("the archive lists %d entries, want none", len(entries))
	}
}

func TestReaderCovFileSystemRefusesNamesItCannotHave(t *testing.T) {
	raw := readerCovStored(t, "entry.txt", []byte("payload"))
	zr := readerCovOpen(t, raw)

	if _, err := zr.Open("../escape.txt"); !errors.Is(err, fs.ErrInvalid) {
		t.Errorf("opening a name outside the archive gave %v, want ErrInvalid", err)
	}
	if _, err := zr.Open("absent.txt"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("opening a name that is not there gave %v, want ErrNotExist", err)
	}
}

func TestReaderCovSynthesisedDirectoryDescribesItself(t *testing.T) {
	// Nothing in this archive is an entry named "sub"; the directory is
	// there because an entry is inside it, and it has to answer for itself
	// as any other directory would.
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	w := mustCreateHeader(t, zw, &FileHeader{Name: "sub/leaf.txt", Method: Store})
	mustWrite(t, w, []byte("leaf"))
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	zr := readerCovOpen(t, buf.Bytes())

	d, err := zr.Open("sub")
	if err != nil {
		t.Fatalf("opening the directory: %v", err)
	}
	closeAt(t, d)

	if _, err := d.Read(make([]byte, 4)); err == nil {
		t.Error("a directory was read as a file")
	}

	info, err := d.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("the directory is %d bytes, want 0", info.Size())
	}
	if info.Mode() != fs.ModeDir|0555 {
		t.Errorf("the directory's mode is %v, want %v", info.Mode(), fs.ModeDir|0555)
	}
	if info.Sys() != nil {
		t.Errorf("the directory reports %v underneath it, want nothing", info.Sys())
	}
	if !info.ModTime().IsZero() {
		t.Errorf("a directory no entry named is stamped %v, want no time at all", info.ModTime())
	}

	entry, ok := info.(fs.DirEntry)
	if !ok {
		t.Fatalf("%T is not a directory entry", info)
	}
	if entry.Type() != fs.ModeDir {
		t.Errorf("the directory's type is %v, want %v", entry.Type(), fs.ModeDir)
	}
	if got := fmt.Sprint(entry); !strings.Contains(got, "sub") {
		t.Errorf("the directory prints as %q, want its own name in it", got)
	}
}

func TestReaderCovRootDirectoryNamesItself(t *testing.T) {
	// The root is the one entry whose name ends in a slash, which is how
	// the name splitter is told it is a directory.
	raw := readerCovStored(t, "entry.txt", []byte("payload"))
	zr := readerCovOpen(t, raw)

	d, err := zr.Open(".")
	if err != nil {
		t.Fatalf("opening the root: %v", err)
	}
	closeAt(t, d)
	info, err := d.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Name() != "." {
		t.Fatalf("the root is named %q, want %q", info.Name(), ".")
	}
}

func TestReaderCovReadDirAnswersAnExhaustedListing(t *testing.T) {
	// A caller asking for everything that is left is told there is nothing
	// left; only a caller asking for a fixed number is told the end of the
	// listing has been reached.
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	mustCreate(t, zw, "dir/leaf.txt")
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	zr := readerCovOpen(t, buf.Bytes())

	d, err := zr.Open("dir")
	if err != nil {
		t.Fatalf("opening the directory: %v", err)
	}
	closeAt(t, d)
	rd, ok := d.(fs.ReadDirFile)
	if !ok {
		t.Fatalf("%T cannot be listed", d)
	}

	if entries, err := rd.ReadDir(-1); err != nil || len(entries) != 1 {
		t.Fatalf("the first listing gave %d entries and %v, want 1 and no error", len(entries), err)
	}
	entries, err := rd.ReadDir(-1)
	if err != nil {
		t.Fatalf("listing an exhausted directory gave %v, want no error", err)
	}
	if len(entries) != 0 {
		t.Fatalf("listing an exhausted directory gave %d entries, want none", len(entries))
	}
}
