package zip

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/flate"
	"github.com/unxed/zipcharset"
)

var (
	ErrFormat       = errors.New("zip: not a valid zip file")
	ErrAlgorithm    = errors.New("zip: unsupported compression algorithm")
	ErrChecksum     = errors.New("zip: checksum error")
	ErrInsecurePath = errors.New("zip: insecure file path")
	// ErrPassword is returned when an encrypted entry rejects the password
	// up front: the ZipCrypto check byte or the WinZip AES password
	// verifier does not match.
	ErrPassword = errors.New("zip: incorrect password")
)

// EncryptedDataError is returned when the payload of an encrypted entry
// fails validation after the password passed the format's cheap check: the
// CRC does not match, the AES authentication code does not match, or the
// decrypted bytes are not a valid deflate stream. The ZipCrypto check is a
// single byte, so 1 in 256 wrong passwords reaches this point; the WinZip
// AES verifier is two bytes. The error therefore means either a wrong
// password or corrupt data, and errors.Is reports both ErrPassword and the
// underlying cause (ErrChecksum, flate.CorruptInputError, ...), so callers
// that re-prompt for a password on ErrPassword do so here as well.
type EncryptedDataError struct {
	Err error
}

func (e *EncryptedDataError) Error() string {
	return e.Err.Error() + " (encrypted entry: incorrect password or corrupt data)"
}

func (e *EncryptedDataError) Unwrap() error { return e.Err }

func (e *EncryptedDataError) Is(target error) bool { return target == ErrPassword }

// encryptedDataError wraps err when it is a wrong-password symptom of an
// encrypted entry and returns it unchanged otherwise. Store entries can only
// betray a wrong password through the CRC; compressed entries additionally
// through a corrupt or truncated compressed stream.
func encryptedDataError(f *File, err error) error {
	if err == nil || f == nil || !f.IsEncrypted() {
		return err
	}
	var already *EncryptedDataError
	if errors.As(err, &already) {
		return err
	}
	if errors.Is(err, ErrChecksum) {
		return &EncryptedDataError{Err: err}
	}
	if f.Method != Store {
		// Garbage fed to a decompressor shows up as a corrupt stream, a
		// stream that ends early, or one that inflates past the declared
		// size (ErrFormat from checksumReader).
		var corrupt flate.CorruptInputError
		if errors.As(err, &corrupt) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, ErrFormat) {
			return &EncryptedDataError{Err: err}
		}
	}
	return err
}

// DisableInsecurePaths controls whether paths containing ".." or "\" are rejected.
var DisableInsecurePaths bool

type Reader struct {
	r             io.ReaderAt
	File          []*File
	Comment       string
	decompressors map[uint16]Decompressor
	password      func() string // Callback to retrieve the password

	baseOffset int64

	fileListOnce sync.Once
	fileList     []fileListEntry
}

type ReadCloser struct {
	// volumes holds the open file handles OpenReader took, independently of
	// what ended up in Reader.r. The two are not the same thing: an archive
	// with an F4 recovery footer or an XCrypt payload gets its reader
	// replaced by a wrapper, and a wrapper has no way to close the files
	// underneath it.
	volumes *MultiVolumeReader
	Reader
}

type File struct {
	FileHeader
	zip          *Reader
	zipr         io.ReaderAt
	headerOffset int64
	zip64        bool
	aesInfo      *winzipAesInfo
}

func OpenReaderWithPassword(name string, password string) (*ReadCloser, error) {
	mvr, size, err := OpenMultiVolume(name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	ra, size := checkF4Recovery(mvr, size)

	raDec, sizeDec, err := checkXCryptZip(ra, size, password)
	if err != nil {
		// The volumes are being closed on the way out of a call that
		// is already failing; the error being returned is the one the
		// caller needs.
		_ = mvr.Close()
		return nil, err
	}

	zr := new(ReadCloser)
	zr.volumes = mvr
	if password != "" {
		zr.SetPassword(password)
	}
	if err = zr.init(raDec, sizeDec); err != nil {
		_ = mvr.Close()
		return nil, err
	}

	zr.r = raDec
	return zr, nil
}

func OpenReader(name string) (*ReadCloser, error) {
	return OpenReaderWithPassword(name, "")
}

func NewReaderWithPassword(r io.ReaderAt, size int64, password string) (*Reader, error) {
	if size < 0 {
		return nil, errors.New("zip: size cannot be negative")
	}
	r, size = checkF4Recovery(r, size)

	r, size, err := checkXCryptZip(r, size, password)
	if err != nil {
		return nil, err
	}

	zr := new(Reader)
	if password != "" {
		zr.SetPassword(password)
	}
	err = zr.init(r, size)
	if err != nil && err != ErrInsecurePath {
		return nil, err
	}
	return zr, err
}

func NewReader(r io.ReaderAt, size int64) (*Reader, error) {
	return NewReaderWithPassword(r, size, "")
}

func (r *Reader) salvage(rdr io.ReaderAt, size int64) error {
	buf := make([]byte, fileHeaderLen)
	for off := int64(0); off < size-fileHeaderLen; {
		if _, err := rdr.ReadAt(buf[:4], off); err != nil {
			break
		}
		if binary.LittleEndian.Uint32(buf[:4]) == fileHeaderSignature {
			if _, err := rdr.ReadAt(buf[4:], off+4); err != nil {
				break
			}
			b := readBuf(buf[4:])
			f := &File{zip: r, zipr: rdr, headerOffset: off}
			f.ReaderVersion = b.uint16()
			f.Flags = b.uint16()
			f.Method = b.uint16()
			f.ModifiedTime = b.uint16()
			f.ModifiedDate = b.uint16()
			f.CRC32 = b.uint32()
			f.CompressedSize = b.uint32()
			f.UncompressedSize = b.uint32()
			f.CompressedSize64 = uint64(f.CompressedSize)
			f.UncompressedSize64 = uint64(f.UncompressedSize)
			nlen := int(b.uint16())
			elen := int(b.uint16())

			data := make([]byte, nlen+elen)
			if _, err := rdr.ReadAt(data, off+fileHeaderLen); err == nil {
				f.Name = string(data[:nlen])
				f.Extra = data[nlen:]

				if f.CompressedSize == uint32max || f.UncompressedSize == uint32max {
					for extra := readBuf(f.Extra); len(extra) >= 4; {
						tag := extra.uint16()
						size := int(extra.uint16())
						if len(extra) < size {
							break
						}
						fieldBuf := extra.sub(size)
						if tag == zip64ExtraID {
							if f.UncompressedSize == uint32max && len(fieldBuf) >= 8 {
								f.UncompressedSize64 = fieldBuf.uint64()
							}
							if f.CompressedSize == uint32max && len(fieldBuf) >= 8 {
								f.CompressedSize64 = fieldBuf.uint64()
							}
						}
					}
				}

				// Salvage builds entries from local headers, so the
				// size invariant readDirectoryHeader holds the
				// central directory to has to be applied here too:
				// everything downstream hands these sizes to
				// io.NewSectionReader, where one above MaxInt64
				// arrives negative and removes the bound instead of
				// setting it. Such an entry is skipped and the scan
				// carries on looking for the next real header.
				if f.CompressedSize64 <= math.MaxInt64 && f.UncompressedSize64 <= math.MaxInt64 {
					r.File = append(r.File, f)

					// #nosec G115 -- both sizes are held to MaxInt64 by the check above, and the lengths are two-byte header fields
					skip := fileHeaderLen + int64(nlen) + int64(elen) + int64(f.CompressedSize64)
					if skip > 0 && off+skip < size {
						off += skip
						continue
					}
				}
			}
		}
		off++
	}
	if len(r.File) == 0 {
		return ErrFormat
	}
	return nil
}

func (r *Reader) init(rdr io.ReaderAt, size int64) error {
	r.r = rdr
	end, baseOffset, err := readDirectoryEnd(rdr, size)
	if err != nil {
		return r.salvage(rdr, size)
	}
	r.r = rdr
	r.baseOffset = baseOffset

	// #nosec G115 -- NewReaderWithPassword refuses a negative size, so this is the length of the archive
	if end.directorySize < uint64(size) && (uint64(size)-end.directorySize)/30 >= end.directoryRecords {
		r.File = make([]*File, 0, end.directoryRecords)
	}
	r.Comment = end.comment
	// #nosec G115 -- readDirectoryEnd rejects a directory offset above MaxInt64 and checks that baseOffset plus this one lands inside the archive
	dirOff := r.baseOffset + int64(end.directoryOffset)
	// The directory runs from dirOff to the end of the archive. A reader over
	// exactly that range says what seeking a reader over the whole file to the
	// same place said, and the offset has already been checked to be inside
	// the archive by the function that produced it.
	rs := io.NewSectionReader(rdr, dirOff, size-dirOff)

	var rd io.Reader = rs
	if end.encrypted {
		if r.password == nil {
			return errors.New("zip: central directory is encrypted but no password provided")
		}
		// In the case of CDE, the central directory is protected by SES.
		// For simplicity, we use the same AES logic if it's AES SES.
		// PKWARE SES AES uses an approach similar to WinZip for the stream.
		info := &winzipAesInfo{
			actualMethod: Store, // CD is usually Store or Deflate
			strength:     1,     // Default 128
		}
		switch end.bitLen {
		case 192:
			info.strength = 2
		case 256:
			info.strength = 3
		}
		// Skip the Archive Decryption Header (usually 12-24 bytes)
		// In practice, SES is more complex, but we are laying the foundation for stream decryption.
		// #nosec G115 -- readDirectoryEnd rejects a directory size above MaxInt64
		rd, _, err = newWinZipAesReader(rs, r.password(), info, int64(end.directorySize))
		if err != nil {
			return err
		}
	}

	buf := bufio.NewReaderSize(rd, 1024*1024)

	for {
		f := &File{zip: r, zipr: rdr}
		err = readDirectoryHeader(f, buf)
		if err == ErrFormat || err == io.ErrUnexpectedEOF || err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		f.headerOffset += r.baseOffset
		r.File = append(r.File, f)
	}
	// The end record counts its entries in two bytes, so only the low
	// sixteen bits of what was read can be compared with it; archive/zip
	// checks the count the same way.
	// #nosec G115 -- see above: both sides are deliberately taken modulo 2^16
	if uint16(len(r.File)) != uint16(end.directoryRecords) {
		return err
	}
	if DisableInsecurePaths {
		for _, f := range r.File {
			if f.Name == "" {
				continue
			}
			if !filepath.IsLocal(f.Name) || strings.Contains(f.Name, "\\") {
				return ErrInsecurePath
			}
		}
	}
	return nil
}

func (r *Reader) RegisterDecompressor(method uint16, dcomp Decompressor) {
	if r.decompressors == nil {
		r.decompressors = make(map[uint16]Decompressor)
	}
	r.decompressors[method] = dcomp
}

func (r *Reader) decompressor(method uint16) Decompressor {
	dcomp := r.decompressors[method]
	if dcomp == nil {
		dcomp = decompressor(method)
	}
	return dcomp
}

func (r *Reader) SetPassword(password string) {
	r.password = func() string { return password }
}

func (rc *ReadCloser) Close() error {
	// ReadCloser is exported, so a caller can hold one that never opened
	// anything -- a variable declared before the OpenReader that would have
	// filled it in returned an error. Closing that is not a failure, it is
	// nothing to do.
	if rc.volumes == nil {
		return nil
	}
	return rc.volumes.Close()
}

func (f *File) HeaderOffset() int64 {
	return f.headerOffset
}
func (f *File) DataOffset() (offset int64, err error) {
	bodyOffset, err := f.findBodyOffset()
	if err != nil {
		return
	}
	return f.headerOffset + bodyOffset, nil
}

func (f *File) Open() (io.ReadCloser, error) {
	if f == nil || f.zipr == nil {
		return nil, os.ErrInvalid
	}
	if strings.HasSuffix(f.Name, "/") {
		if f.UncompressedSize64 != 0 {
			return &dirReader{ErrFormat}, nil
		} else {
			return &dirReader{io.EOF}, nil
		}
	}
	bodyOffset, err := f.findBodyOffset()
	if err != nil {
		return nil, err
	}

	// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose CompressedSize64 is above MaxInt64
	size := int64(f.CompressedSize64)
	encryptionOffset := int64(0)
	var crypto *zipCrypto

	// Determine the decompression method in advance (it might change for AES)
	method := f.Method

	r := io.NewSectionReader(f.zipr, f.headerOffset+bodyOffset, size)
	var rr io.Reader = r

	if f.IsEncrypted() {
		if f.zip.password == nil {
			return nil, errors.New("zip: file is encrypted but no password provided")
		}
		pass := f.zip.password()

		if f.Method == winzipAesExtraID || f.aesInfo != nil {
			// WinZip AES (Method 99) case
			var err error
			rr, method, err = newWinZipAesReader(r, pass, f.aesInfo, size)
			if err != nil {
				return nil, err
			}
		} else {
			// Classic ZipCrypto
			crypto = newZipCrypto([]byte(pass))
			header := make([]byte, 12)
			if _, err := f.zipr.ReadAt(header, f.headerOffset+bodyOffset); err != nil {
				return nil, err
			}
			crypto.decrypt(header)
			checkByte := byte(f.CRC32 >> 24)
			if f.Flags&0x8 != 0 {
				checkByte = byte(f.ModifiedTime >> 8)
			}
			if header[11] != checkByte {
				return nil, ErrPassword
			}
			encryptionOffset = 12
			// Shift the base reader for classic encryption
			r = io.NewSectionReader(f.zipr, f.headerOffset+bodyOffset+encryptionOffset, size-12)
			rr = &cipherReader{r: r, crypto: crypto}
		}
	}

	var rc io.ReadCloser
	if method == 98 { // PPMd
		rc = newPPMdReader(rr, f.UncompressedSize64)
	} else {
		dcomp := f.zip.decompressor(method)
		if dcomp == nil {
			return nil, ErrAlgorithm
		}
		rc = dcomp(rr)
	}
	// A decompressor is a registered extension point, so the one that just
	// ran is not necessarily one this package wrote. Nothing downstream can
	// tell a nil io.ReadCloser from a working one: the limit reader wraps it,
	// and the entry then fails as a nil dereference on the first read instead
	// of as an error on the entry.
	if rc == nil {
		return nil, fmt.Errorf("zip: the decompressor for method %d built no reader for this entry: %w", method, ErrAlgorithm)
	}
	var desr io.Reader
	if f.hasDataDescriptor() {
		ddLen := int64(dataDescriptorLen)
		if f.zip64 {
			ddLen = dataDescriptor64Len
		}
		desr = io.NewSectionReader(f.zipr, f.headerOffset+bodyOffset+size, ddLen)
	}
	rc = &limitReadCloser{
		// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose UncompressedSize64 is above MaxInt64
		Reader: io.LimitReader(rc, int64(f.UncompressedSize64)),
		Closer: rc,
	}
	rc = &checksumReader{
		rc:   rc,
		rr:   rr,
		hash: crc32.NewIEEE(),
		f:    f,
		desr: desr,
	}
	return rc, nil
}

type limitReadCloser struct {
	io.Reader
	io.Closer
}

func (f *File) OpenRaw() (io.Reader, error) {
	if f == nil || f.zipr == nil {
		return nil, os.ErrInvalid
	}
	bodyOffset, err := f.findBodyOffset()
	if err != nil {
		return nil, err
	}
	// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose CompressedSize64 is above MaxInt64
	r := io.NewSectionReader(f.zipr, f.headerOffset+bodyOffset, int64(f.CompressedSize64))
	return r, nil
}

// readFullAt fills p from offset. io.ReaderAt is obliged to do that itself,
// but the updater's handle over an io.ReadWriteSeeker is one read of what is
// underneath and may answer short, so the fill is spelled out for whichever
// kind of reader is passed. A buffer that cannot be filled reports what the
// reader said, io.ErrUnexpectedEOF for an archive that stops in the middle of
// a header included.
func readFullAt(r io.ReaderAt, p []byte, offset int64) error {
	_, err := io.ReadFull(io.NewSectionReader(r, offset, int64(len(p))), p)
	return err
}

// hiddenIndexSpan says where an entry's seek index lies and which of the two
// kinds it is.
type hiddenIndexSpan struct {
	kind       int   // 1 for a SOZip index, 2 for a gzip one
	dataOffset int64 // where the index's payload begins
	dataSize   int64 // how long that payload is
}

// findHiddenIndexAt recognises the seek index belonging to the entry named
// owner, when one begins at offset. The index is a local entry of this
// package's own making -- stored, no data descriptor, named after the entry it
// belongs to and named by no central directory record -- which writeHiddenIndex
// puts directly behind the entry's data.
//
// It answers false and no error whenever what is there is not that index:
// there is no local header, or its method or its flags do not fit, or its name
// belongs to something else. A stray local entry another tool left behind
// reads exactly the same way from outside, and the point of the name check is
// that it is told apart from the index by nothing weaker.
func findHiddenIndexAt(r io.ReaderAt, offset int64, owner string) (hiddenIndexSpan, bool, error) {
	var none hiddenIndexSpan

	var headerBuf [fileHeaderLen]byte
	if err := readFullAt(r, headerBuf[:], offset); err != nil {
		// Most entries carry no index at all, and behind the last one
		// lies the central directory: nothing to read here is the
		// ordinary answer rather than a fault.
		return none, false, nil
	}
	b := readBuf(headerBuf[:])
	if sig := b.uint32(); sig != fileHeaderSignature {
		return none, false, nil
	}
	_ = b.uint16() // ReaderVersion / Version needed to extract (2 bytes)
	flags := b.uint16()
	method := b.uint16()
	_ = b.uint16() // ModifiedTime
	_ = b.uint16() // ModifiedDate
	_ = b.uint32() // CRC32
	compSize := b.uint32()
	_ = b.uint32() // UncompressedSize
	filenameLen := int(b.uint16())
	extraLen := int(b.uint16())

	if method != Store {
		return none, false, nil
	}

	nameBuf := make([]byte, filenameLen)
	if err := readFullAt(r, nameBuf, offset+fileHeaderLen); err != nil {
		return none, false, err
	}
	// Masked hidden name if CDE is used
	if flags&0x2000 != 0 {
		return none, false, nil
	}

	dir, name := path.Split(owner)
	var kind int
	switch string(nameBuf) {
	case dir + "." + name + ".sozip.idx":
		kind = 1
	case dir + "." + name + ".gzidx":
		kind = 2
	default:
		return none, false, nil
	}

	compSize64 := uint64(compSize)
	if compSize == uint32max {
		extraBuf := make([]byte, extraLen)
		// The zip64 extra is where the real size of the index lives when
		// the 32-bit field is saturated. A short or failed read used to
		// leave the buffer holding zeros, and the size was then parsed
		// out of them as if the archive had said so.
		if err := readFullAt(r, extraBuf, offset+fileHeaderLen+int64(filenameLen)); err != nil {
			return none, false, err
		}
		for eb := readBuf(extraBuf); len(eb) >= 4; {
			tag := eb.uint16()
			sz := int(eb.uint16())
			if tag == zip64ExtraID && sz >= 8 {
				_ = eb.uint64()
				compSize64 = eb.uint64()
				break
			}
			eb = eb[sz:]
		}
	}

	// The size of the payload is the hidden entry's own to declare -- a
	// uint32, or the whole range of a uint64 through its zip64 extra -- and
	// the buffer for it used to be made from that declaration before a byte
	// of the payload had been read.
	if compSize64 > math.MaxInt64 {
		return none, false, fmt.Errorf("zip: seek index declares %d bytes: %w", compSize64, ErrFormat)
	}
	return hiddenIndexSpan{
		kind:       kind,
		dataOffset: offset + fileHeaderLen + int64(filenameLen) + int64(extraLen),
		// #nosec G115 -- the check just above holds it to MaxInt64
		dataSize: int64(compSize64),
	}, true, nil
}

// hiddenIndexOffset is where an entry's seek index would begin: behind its
// data and behind the data descriptor, when it has one.
func (f *File) hiddenIndexOffset() (int64, error) {
	bodyOffset, err := f.findBodyOffset()
	if err != nil {
		return 0, err
	}
	// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose CompressedSize64 is above MaxInt64
	endOffset := f.headerOffset + bodyOffset + int64(f.CompressedSize64)
	if f.hasDataDescriptor() {
		if f.zip64 {
			endOffset += dataDescriptor64Len
		} else {
			endOffset += dataDescriptorLen
		}
	}
	return endOffset, nil
}

// claimedOffset says whether some entry of the archive has its local header at
// offset. A seek index is a local entry the central directory does not list,
// so an offset the directory does claim is another entry and not an index --
// an archive may perfectly well hold a listed entry named ".a.txt.sozip.idx"
// sitting behind "a.txt", and reading it as a's index would fail an archive
// that is entirely valid.
//
// The archive asked is the one this entry was read out of, which every entry
// that reaches here has: the only entries this package builds without a reader
// behind them are the updater's, and the updater walks the recognition itself
// and makes the same check against the directory it is assembling.
func (f *File) claimedOffset(offset int64) bool {
	for _, other := range f.zip.File {
		if other.headerOffset == offset {
			return true
		}
	}
	return false
}

func (f *File) findHiddenIndex() (int, []byte, error) {
	endOffset, err := f.hiddenIndexOffset()
	if err != nil {
		return 0, nil, err
	}
	if f.claimedOffset(endOffset) {
		return 0, nil, nil
	}
	idx, ok, err := findHiddenIndexAt(f.zipr, endOffset, f.Name)
	if err != nil || !ok {
		return 0, nil, err
	}
	// Reading through a section reader bounds the allocation by the bytes
	// the archive actually holds; anything the index is then short of is
	// caught where the payload is parsed.
	payload, err := io.ReadAll(io.NewSectionReader(f.zipr, idx.dataOffset, idx.dataSize))
	if err != nil {
		return 0, nil, err
	}
	return idx.kind, payload, nil
}

// OpenSeekable returns a ReadSeeker for the file content.
// It requires a Seek Index (Hidden SOZip or GZIDX) to be present in the archive for compressed files.
//
// For an AES-encrypted entry the authentication code the format stores over
// the whole entry is checked before any of that entry's data is handed back,
// since AE-2 leaves the CRC zero and AES-CTR is malleable, so nothing else
// would notice a flipped bit. The check is one sequential pass over the
// ciphertext, run once per open rather than once per read: for a stored entry
// it runs here, and for an entry read through a seek index when its decrypter
// is built on the first read. A mismatch is the same ErrChecksum-bearing error
// Open gives. OpenSeekableUnverified skips the pass.
func (f *File) OpenSeekable() (io.ReadSeeker, error) {
	return f.openSeekable(true)
}

// OpenSeekableUnverified is OpenSeekable without the authentication pass over
// an AES-encrypted entry. It saves one sequential read of the entry and gives
// up what that read buys: a tampered entry reads back as whatever the change
// made of it, with no ErrChecksum and nothing else to report it. Use it only
// where the entry is large enough for the pass to matter and the archive is
// trusted on other grounds.
func (f *File) OpenSeekableUnverified() (io.ReadSeeker, error) {
	return f.openSeekable(false)
}

func (f *File) openSeekable(verify bool) (io.ReadSeeker, error) {
	actualMethod := f.Method
	if f.Method == winzipAesExtraID && f.aesInfo != nil {
		actualMethod = f.aesInfo.actualMethod
	}

	if actualMethod == Store {
		bodyOffset, err := f.findBodyOffset()
		if err != nil {
			return nil, err
		}
		if f.IsEncrypted() {
			if f.zip.password == nil {
				return nil, errors.New("zip: file is encrypted but no password provided")
			}
			if f.Method == winzipAesExtraID || f.aesInfo != nil {
				// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose CompressedSize64 is above MaxInt64
				rawSection := io.NewSectionReader(f.zipr, f.headerOffset+bodyOffset, int64(f.CompressedSize64))
				// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose CompressedSize64 is above MaxInt64
				aesRA, err := newWinZipAesReaderAt(rawSection, f.zip.password(), f.aesInfo, int64(f.CompressedSize64), verify)
				if err != nil {
					return nil, err
				}
				// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose UncompressedSize64 is above MaxInt64
				return io.NewSectionReader(aesRA, 0, int64(f.UncompressedSize64)), nil
			}
			return nil, errors.New("zip: random access not supported for classic ZipCrypto")
		}
		// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose UncompressedSize64 is above MaxInt64
		return io.NewSectionReader(f.zipr, f.headerOffset+bodyOffset, int64(f.UncompressedSize64)), nil
	}

	idxType, payload, err := f.findHiddenIndex()
	if err != nil {
		return nil, err
	}

	if idxType == 0 {
		return nil, errors.New("zip: seek index missing or invalid for compressed file")
	}

	if idxType == 1 { // SOZip
		if len(payload) < 32 {
			return nil, errors.New("zip: invalid SOZip index length")
		}
		chunkSize := binary.LittleEndian.Uint32(payload[8:12])
		offsetSize := binary.LittleEndian.Uint32(payload[12:16])
		if offsetSize != 8 {
			return nil, errors.New("zip: unsupported SOZip offset size")
		}
		// The index is read out of a hidden entry nothing signs and nothing
		// checksums, and every number in it is used as an offset into the
		// entry it indexes. A chunk size of zero is the divisor the wanted
		// offset is divided by when a chunk is looked up.
		if chunkSize == 0 {
			return nil, fmt.Errorf("zip: SOZip index chunk size is zero: %w", ErrFormat)
		}

		// The first offset is this parser's own zero rather than the
		// archive's, so it is the rest that have to be true of the entry:
		// inside it, and in the order the chunks are in.
		index := []uint64{0}
		prev := uint64(0)
		for offsetData := payload[32:]; len(offsetData) >= 8; offsetData = offsetData[8:] {
			off := binary.LittleEndian.Uint64(offsetData[:8])
			if off > f.CompressedSize64 || off < prev {
				return nil, fmt.Errorf("zip: SOZip index offset %d is outside the entry: %w", off, ErrFormat)
			}
			prev = off
			index = append(index, off)
		}

		f.SeekChunkSize = chunkSize
		f.SeekIndex = index

		return &solidReadSeeker{f: f, verify: verify}, nil
	}

	// findHiddenIndex answers with 0, 1 or 2, and the first two are handled
	// above, so what is left is GZIDX.
	if len(payload) < 35 || string(payload[:5]) != "GZIDX" {
		return nil, errors.New("zip: invalid GZIDX payload")
	}
	chunkSize := binary.LittleEndian.Uint32(payload[23:27])
	numPoints := binary.LittleEndian.Uint32(payload[31:35])

	// How many points the payload can hold, rather than how long a
	// payload the claimed count would need: the count is the archive's,
	// and multiplying it by the size of a point wraps on a 32-bit build
	// -- above 119304647 points the product comes out small enough to
	// pass for a payload that holds nothing of the sort, and the loop
	// below then reads past it. The length of the payload is known to
	// be at least 35 by the check above.
	// #nosec G115 -- the payload is at least 35 bytes by the check above, so the subtraction cannot go negative
	if uint64(numPoints) > uint64(len(payload)-35)/18 {
		return nil, fmt.Errorf("zip: invalid GZIDX payload (too short for %d points): %w", numPoints, ErrFormat)
	}
	if chunkSize == 0 {
		return nil, fmt.Errorf("zip: GZIDX index chunk size is zero: %w", ErrFormat)
	}

	points := make([]gzPoint, numPoints)
	offset := 35
	for i := 0; i < int(numPoints); i++ {
		points[i].compOffset = binary.LittleEndian.Uint64(payload[offset:])
		points[i].uncompOffset = binary.LittleEndian.Uint64(payload[offset+8:])
		points[i].bits = payload[offset+16]
		points[i].hasData = payload[offset+17]
		// A point names a place in the entry on both sides of the
		// decompressor, and both of them are read from as offsets.
		if points[i].compOffset > f.CompressedSize64 || points[i].uncompOffset > f.UncompressedSize64 {
			return nil, fmt.Errorf("zip: GZIDX point %d is outside the entry: %w", i, ErrFormat)
		}
		offset += 18
	}
	for i := 0; i < int(numPoints); i++ {
		if points[i].hasData == 1 {
			if offset+32768 > len(payload) {
				return nil, errors.New("zip: invalid GZIDX payload (truncated window data)")
			}
			points[i].window = payload[offset : offset+32768]
			offset += 32768
		}
	}

	f.SeekChunkSize = chunkSize
	f.GzidxPoints = points
	return &solidReadSeeker{f: f, isContinuous: true, verify: verify}, nil
}

type solidReadSeeker struct {
	f            *File
	off          int64
	currRC       io.ReadCloser
	isContinuous bool
	// verify says whether the entry's AES authentication code is checked
	// when the decrypter below is built.
	verify bool
	// aesRA is the decrypter over the whole entry. A seek drops the
	// decompressor in front of it, and rebuilding this with it would derive
	// the key and go over the entry again on every seek, so it is built on
	// the first read and kept. It holds the password the first read saw,
	// the way the stored path holds the one its open saw.
	aesRA *winZipAesReaderAt
}

func (s *solidReadSeeker) Seek(offset int64, whence int) (int64, error) {
	var newOff int64
	switch whence {
	case io.SeekStart:
		newOff = offset
	case io.SeekCurrent:
		newOff = s.off + offset
	case io.SeekEnd:
		// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose UncompressedSize64 is above MaxInt64
		newOff = int64(s.f.UncompressedSize64) + offset
	}
	// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose UncompressedSize64 is above MaxInt64
	if newOff < 0 || newOff > int64(s.f.UncompressedSize64) {
		return 0, errors.New("zip: invalid seek offset")
	}
	if newOff != s.off && s.currRC != nil {
		// The reader being dropped is a decompressor positioned at the
		// old offset; the seek opens a new one, and nothing that was
		// read through this one is still wanted.
		_ = s.currRC.Close()
		s.currRC = nil
	}
	s.off = newOff
	return s.off, nil
}

func (s *solidReadSeeker) Read(p []byte) (int, error) {
	// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose UncompressedSize64 is above MaxInt64
	if s.off >= int64(s.f.UncompressedSize64) {
		return 0, io.EOF
	}

	if s.currRC == nil {
		var compOffset int64
		var uncompOffset int64

		if s.isContinuous {
			var best *gzPoint
			for i := range s.f.GzidxPoints {
				pt := &s.f.GzidxPoints[i]
				// #nosec G115 -- a GZIDX point is held to uncompOffset <= UncompressedSize64 <= MaxInt64 where the index is parsed
				if int64(pt.uncompOffset) <= s.off {
					if best == nil || pt.uncompOffset > best.uncompOffset {
						best = pt
					}
				}
			}
			if best == nil {
				return 0, io.EOF
			}
			// #nosec G115 -- a GZIDX point is held to compOffset <= CompressedSize64 <= MaxInt64 where the index is parsed
			compOffset = int64(best.compOffset)
			// #nosec G115 -- a GZIDX point is held to uncompOffset <= UncompressedSize64 <= MaxInt64 where the index is parsed
			uncompOffset = int64(best.uncompOffset)
		} else {
			blockIdx := s.off / int64(s.f.SeekChunkSize)
			if blockIdx >= int64(len(s.f.SeekIndex)) {
				return 0, io.EOF
			}
			// #nosec G115 -- a SOZip index entry is held to <= CompressedSize64 <= MaxInt64 where the index is parsed
			compOffset = int64(s.f.SeekIndex[blockIdx])
			uncompOffset = blockIdx * int64(s.f.SeekChunkSize)
		}

		bodyOffset, err := s.f.findBodyOffset()
		if err != nil {
			return 0, err
		}

		// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose CompressedSize64 is above MaxInt64
		totalCompSize := int64(s.f.CompressedSize64)

		var section io.Reader
		actualMethod := s.f.Method

		if s.f.IsEncrypted() {
			if s.f.zip.password == nil {
				return 0, errors.New("zip: file is encrypted but no password provided")
			}
			if s.f.Method == winzipAesExtraID || s.f.aesInfo != nil {
				if s.aesRA == nil {
					rawSection := io.NewSectionReader(s.f.zipr, s.f.headerOffset+bodyOffset, totalCompSize)
					aesRA, err := newWinZipAesReaderAt(rawSection, s.f.zip.password(), s.f.aesInfo, totalCompSize, s.verify)
					if err != nil {
						return 0, err
					}
					s.aesRA = aesRA
				}
				actualMethod = s.f.aesInfo.actualMethod

				remainingComp := s.aesRA.limit - compOffset
				section = io.NewSectionReader(s.aesRA, compOffset, remainingComp)
			} else {
				return 0, errors.New("zip: random access not supported for classic ZipCrypto")
			}
		} else {
			remainingComp := totalCompSize - compOffset
			section = io.NewSectionReader(s.f.zipr, s.f.headerOffset+bodyOffset+compOffset, remainingComp)
		}

		if s.isContinuous {
			var best *gzPoint
			for i := range s.f.GzidxPoints {
				// #nosec G115 -- a GZIDX point is held to uncompOffset <= UncompressedSize64 <= MaxInt64 where the index is parsed
				if int64(s.f.GzidxPoints[i].uncompOffset) == uncompOffset {
					best = &s.f.GzidxPoints[i]
					break
				}
			}
			if best != nil && best.hasData == 1 {
				s.currRC = flate.NewReaderDict(section, best.window)
			} else {
				dcomp := s.f.zip.decompressor(actualMethod)
				if dcomp == nil {
					return 0, ErrAlgorithm
				}
				s.currRC = dcomp(section)
			}
		} else {
			dcomp := s.f.zip.decompressor(actualMethod)
			if dcomp == nil {
				return 0, ErrAlgorithm
			}
			s.currRC = dcomp(section)
		}

		skip := s.off - uncompOffset
		if skip > 0 {
			if _, err := io.CopyN(io.Discard, s.currRC, skip); err != nil {
				return 0, err
			}
		}
	}

	n, err := s.currRC.Read(p)
	s.off += int64(n)
	return n, err
}

type cipherReader struct {
	r      io.Reader
	crypto *zipCrypto
}

func (cr *cipherReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		cr.crypto.decrypt(p[:n])
	}
	return n, err
}

type dirReader struct {
	err error
}

func (r *dirReader) Read([]byte) (int, error) {
	return 0, r.err
}

func (r *dirReader) Close() error {
	return nil
}

type checksumReader struct {
	rc    io.ReadCloser
	rr    io.Reader
	hash  hash.Hash32
	nread uint64
	f     *File
	desr  io.Reader
	err   error
}

func (r *checksumReader) Stat() (fs.FileInfo, error) {
	return headerFileInfo{&r.f.FileHeader}, nil
}

func (r *checksumReader) Read(b []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err = r.rc.Read(b)
	r.hash.Write(b[:n])
	// #nosec G115 -- n is the byte count io.Reader.Read returned, which is never negative
	r.nread += uint64(n)
	// The reader underneath is an io.LimitReader bounded by the entry's own
	// uncompressed size, which shortens the slice it passes down but hands
	// back whatever count came up. Decompressors are registered from
	// outside this package, so one of them reporting more bytes than it was
	// given room for is a count no bound here produced, and the entry would
	// otherwise run past the size it declared.
	if r.nread > r.f.UncompressedSize64 {
		return 0, encryptedDataError(r.f, ErrFormat)
	}
	if err == nil {
		return
	}
	if err == io.EOF {
		if r.nread != r.f.UncompressedSize64 {
			return 0, encryptedDataError(r.f, io.ErrUnexpectedEOF)
		}
		if r.f.Method == winzipAesExtraID {
			if _, macErr := io.Copy(io.Discard, r.rr); macErr != nil {
				err = macErr
			} else {
				err = io.EOF
			}
		} else if r.desr != nil {
			// readDataDescriptor answers a descriptor it could not read
			// in full with io.ErrUnexpectedEOF, never with io.EOF.
			if err1 := readDataDescriptor(r.desr, r.f); err1 != nil {
				err = err1
			} else if r.hash.Sum32() != r.f.CRC32 {
				err = ErrChecksum
			}
		} else {
			if r.f.CRC32 != 0 && r.hash.Sum32() != r.f.CRC32 {
				err = ErrChecksum
			}
		}
	}
	err = encryptedDataError(r.f, err)
	r.err = err
	return
}

func (r *checksumReader) Close() error {
	return r.rc.Close()
}

func (f *File) findBodyOffset() (int64, error) {
	var buf [fileHeaderLen]byte
	if _, err := f.zipr.ReadAt(buf[:], f.headerOffset); err != nil {
		return 0, err
	}
	b := readBuf(buf[:])
	if sig := b.uint32(); sig != fileHeaderSignature {
		return 0, ErrFormat
	}
	b = b[22:] // skip over most of the header
	filenameLen := int(b.uint16())
	extraLen := int(b.uint16())
	return int64(fileHeaderLen + filenameLen + extraLen), nil
}

func readDirectoryHeader(f *File, r io.Reader) error {
	var buf [directoryHeaderLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return err
	}
	b := readBuf(buf[:])
	if sig := b.uint32(); sig != directoryHeaderSignature {
		return ErrFormat
	}
	f.CreatorVersion = b.uint16()
	f.ReaderVersion = b.uint16()
	f.Flags = b.uint16()
	f.Method = b.uint16()
	f.ModifiedTime = b.uint16()
	f.ModifiedDate = b.uint16()
	f.CRC32 = b.uint32()
	f.CompressedSize = b.uint32()
	f.UncompressedSize = b.uint32()
	f.CompressedSize64 = uint64(f.CompressedSize)
	f.UncompressedSize64 = uint64(f.UncompressedSize)
	filenameLen := int(b.uint16())
	extraLen := int(b.uint16())
	commentLen := int(b.uint16())
	b = b[4:]
	f.ExternalAttrs = b.uint32()
	f.headerOffset = int64(b.uint32())
	d := make([]byte, filenameLen+extraLen+commentLen)
	if _, err := io.ReadFull(r, d); err != nil {
		return err
	}

	rawName := d[:filenameLen]
	f.Extra = d[filenameLen : filenameLen+extraLen]
	rawComment := d[filenameLen+extraLen:]

	isUTF8 := f.Flags&0x800 != 0
	packOS := byte(f.CreatorVersion >> 8)
	packVer := f.CreatorVersion & 0xFF

	// decodeUTF8OrMap makes the validity check itself and answers a valid
	// string with itself, so repeating the check here would only give it a
	// second spelling to disagree with.
	f.Name = decodeUTF8OrMap([]byte(zipcharset.DecodeText(rawName, isUTF8, packOS, packVer, f.Extra, false)))
	f.Name = strings.ReplaceAll(f.Name, "\\", "/")
	f.Comment = decodeUTF8OrMap([]byte(zipcharset.DecodeText(rawComment, isUTF8, packOS, packVer, f.Extra, true)))

	// decodeUTF8OrMap answers with valid UTF-8 whatever bytes it is handed,
	// so neither of these two can be invalid; what is left to decide is
	// whether the entry needs a flag the archive may not have set.
	_, utf8Require1 := detectUTF8(f.Name)
	_, utf8Require2 := detectUTF8(f.Comment)
	if !utf8Require1 && !utf8Require2 {
		f.NonUTF8 = false
	} else {
		f.NonUTF8 = !isUTF8
	}

	needUSize := f.UncompressedSize == ^uint32(0)
	needCSize := f.CompressedSize == ^uint32(0)
	needHeaderOffset := f.headerOffset == int64(^uint32(0))

	var modified time.Time
parseExtras:
	for extra := readBuf(f.Extra); len(extra) >= 4; {
		fieldTag := extra.uint16()
		fieldSize := int(extra.uint16())
		if len(extra) < fieldSize {
			break
		}
		fieldBuf := extra.sub(fieldSize)

		switch fieldTag {
		case zip64ExtraID:
			f.zip64 = true
			if needUSize {
				needUSize = false
				if len(fieldBuf) < 8 {
					return ErrFormat
				}
				f.UncompressedSize64 = fieldBuf.uint64()
			}
			if needCSize {
				needCSize = false
				if len(fieldBuf) < 8 {
					return ErrFormat
				}
				f.CompressedSize64 = fieldBuf.uint64()
			}
			if needHeaderOffset {
				needHeaderOffset = false
				if len(fieldBuf) < 8 {
					return ErrFormat
				}
				// #nosec G115 -- an offset above MaxInt64 arrives negative and the entry is refused by the check at the end of this function
				f.headerOffset = int64(fieldBuf.uint64())
			}
		case ntfsExtraID:
			if len(fieldBuf) < 4 {
				continue parseExtras
			}
			fieldBuf.uint32() // Reserved
			for len(fieldBuf) >= 4 {
				attrTag := fieldBuf.uint16()
				attrSize := int(fieldBuf.uint16())
				if len(fieldBuf) < attrSize {
					continue parseExtras
				}
				attrBuf := fieldBuf.sub(attrSize)
				if attrTag != 1 || attrSize != 24 {
					continue
				}

				const ticksPerSecond = 1e7
				epoch := time.Date(1601, time.January, 1, 0, 0, 0, 0, time.UTC).Unix()

				// A FILETIME counts 100-nanosecond ticks from 1601 and
				// is unsigned. One that does not fit an int64 read as
				// one anyway comes out negative, which puts the entry
				// before 1601 -- a date the field cannot express and
				// the archive did not mean. The eight bytes are still
				// consumed, so the fields after it stay lined up; the
				// time itself is left as it was.
				parseNTFS := func(b *readBuf) (time.Time, bool) {
					raw := b.uint64()
					if raw > math.MaxInt64 {
						return time.Time{}, false
					}
					t := int64(raw)
					return time.Unix(epoch+(t/ticksPerSecond), (t%ticksPerSecond)*100), true
				}

				if v, ok := parseNTFS(&attrBuf); ok {
					modified = v
				}
				if v, ok := parseNTFS(&attrBuf); ok {
					f.Accessed = v
				}
				if v, ok := parseNTFS(&attrBuf); ok {
					f.Created = v
				}
			}
		case unixExtraID:
			if len(fieldBuf) < 8 {
				continue parseExtras
			}
			fieldBuf.uint32()
			ts := int64(fieldBuf.uint32())
			modified = time.Unix(ts, 0)
			if len(fieldBuf) >= 4 {
				fieldBuf.uint16() // Uid
				fieldBuf.uint16() // Gid
				if len(fieldBuf) > 0 {
					if f.Mode()&(fs.ModeDevice|fs.ModeCharDevice) != 0 && len(fieldBuf) >= 8 {
						f.Devmajor = int64(fieldBuf.uint32())
						f.Devminor = int64(fieldBuf.uint32())
					} else {
						// The same mapping Name and Comment go through.
						// A link target is a name like any other and can
						// be just as undecodable, and leaving it raw here
						// left it the one archive-derived string with no
						// mark to say so -- after which osFileName handed
						// it straight back and the link was made to bytes
						// no file had been written under.
						f.Linkname = decodeUTF8OrMap(fieldBuf)
					}
				}
			}
		case infoZipUnixExtraID:
			if len(fieldBuf) < 8 {
				continue parseExtras
			}
			fieldBuf.uint32()
			ts := int64(fieldBuf.uint32())
			modified = time.Unix(ts, 0)
		case infoZipNewUnixExtraID:
			// Populate Uid/Gid fields from 0x7875
			if uid, gid, ok := parseUnixExtra(f.Extra); ok {
				f.Uid = uid
				f.Gid = gid
				f.OwnerSet = true
			}
		case unixOwnerNameExtraID:
			if uname, gname, ok := parseUnixOwnerNamesExtra(f.Extra); ok {
				f.Uname = uname
				f.Gname = gname
			}
		case ntfsAclExtraID:
			f.Acl = parseNtfsAcl(f.Extra)
		case extTimeExtraID:
			if len(fieldBuf) < 1 {
				continue parseExtras
			}
			flags := fieldBuf.uint8()
			if flags&1 != 0 && len(fieldBuf) >= 4 {
				modified = time.Unix(int64(fieldBuf.uint32()), 0)
			}
			if flags&2 != 0 && len(fieldBuf) >= 4 {
				f.Accessed = time.Unix(int64(fieldBuf.uint32()), 0)
			}
			if flags&4 != 0 && len(fieldBuf) >= 4 {
				f.Created = time.Unix(int64(fieldBuf.uint32()), 0)
			}
		case winzipAesExtraID:
			if len(fieldBuf) < 7 {
				continue parseExtras
			}
			f.aesInfo = &winzipAesInfo{
				version:      fieldBuf.uint16(),
				strength:     fieldBuf.uint8(), // fieldBuf.uint8() will move the pointer
				actualMethod: 0,                // will be set below
			}
			// Skip Vendor ID "AE" (2 bytes)
			fieldBuf.uint16()
			// The actual compression method
			f.aesInfo.actualMethod = fieldBuf.uint16()

		case xattrExtraID:
			if f.Xattrs == nil {
				f.Xattrs = make(map[string]string)
			}
			for len(fieldBuf) >= 4 {
				klen := int(fieldBuf.uint16())
				if len(fieldBuf) < klen+2 {
					break
				}
				k := string(fieldBuf.sub(klen))
				vlen := int(fieldBuf.uint16())
				if len(fieldBuf) < vlen {
					break
				}
				v := string(fieldBuf.sub(vlen))
				f.Xattrs[k] = v
			}
		}
	}

	msdosModified := msDosTimeToTime(f.ModifiedDate, f.ModifiedTime)
	f.Modified = msdosModified
	if !modified.IsZero() {
		f.Modified = modified.UTC()
		if f.ModifiedTime != 0 || f.ModifiedDate != 0 {
			f.Modified = modified.In(timeZone(msdosModified.Sub(modified)))
		}
	}

	// The three sentinels are not refused alike, and deliberately so. An
	// archive written before zip64 existed can hold an uncompressed size of
	// exactly 2^32-1 as a real size, with no record behind it because the
	// writer had no records to write; refusing it would turn away entries
	// that are merely large. A compressed size or a local header offset of
	// 2^32-1 could only be real in an archive of at least that many bytes,
	// which an archive carrying no zip64 record is not, so those two are
	// refused. What is left is a size the archive claims and has not
	// substantiated, which is what every declared size is: the extraction
	// weighs it against its limits before a byte is written, and nothing
	// reserves space on the strength of it alone.
	_ = needUSize

	if needCSize || needHeaderOffset {
		return ErrFormat
	}

	// Both sizes and the offset of the local header leave this package as
	// int64: Open, OpenRaw and OpenSeekable hand them to io.NewSectionReader
	// and FileInfo returns a size. Above MaxInt64 each of them arrives
	// negative there, and a section reader given a negative length reads
	// without a bound from an offset the archive picked. An archive that
	// large does not exist, so the entry is simply not a valid one.
	if f.CompressedSize64 > math.MaxInt64 || f.UncompressedSize64 > math.MaxInt64 || f.headerOffset < 0 {
		return ErrFormat
	}

	return nil
}

func readDataDescriptor(r io.Reader, f *File) error {
	ddLen := 16
	if f.zip64 {
		ddLen = 24
	}
	buf := make([]byte, ddLen)
	n, err := io.ReadFull(r, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return err
	}
	if n < 12 {
		return io.ErrUnexpectedEOF
	}

	sig := binary.LittleEndian.Uint32(buf[:4])
	var crc uint32

	if sig == dataDescriptorSignature {
		// Could be signature, could be CRC32.
		if n >= 8 {
			crcWithSig := binary.LittleEndian.Uint32(buf[4:8])
			if crcWithSig == f.CRC32 {
				return nil // It has a signature, and the next 4 bytes match the CRC32
			}
		}
		// If it didn't match, maybe the CRC32 itself is the signature value and there is no signature.
		crc = sig
	} else {
		crc = sig
	}

	if crc != f.CRC32 {
		return ErrChecksum
	}
	return nil
}

func readDirectoryEnd(r io.ReaderAt, size int64) (dir *directoryEnd, baseOffset int64, err error) {
	var buf []byte
	var directoryEndOffset int64
	for i, bLen := range []int64{1024, 65 * 1024} {
		if bLen > size {
			bLen = size
		}
		buf = make([]byte, int(bLen))
		if _, err := r.ReadAt(buf, size-bLen); err != nil && err != io.EOF {
			return nil, 0, err
		}
		if p := findSignatureInBlock(buf); p >= 0 {
			buf = buf[p:]
			directoryEndOffset = size - bLen + int64(p)
			break
		}
		if i == 1 || bLen == size {
			return nil, 0, ErrFormat
		}
	}

	b := readBuf(buf[4:])
	d := &directoryEnd{
		diskNbr:            uint32(b.uint16()),
		dirDiskNbr:         uint32(b.uint16()),
		dirRecordsThisDisk: uint64(b.uint16()),
		directoryRecords:   uint64(b.uint16()),
		directorySize:      uint64(b.uint32()),
		directoryOffset:    uint64(b.uint32()),
		commentLen:         b.uint16(),
	}
	// findSignatureInBlock answers with an offset only when the end record
	// and the comment it declares both fit inside the block that was read,
	// so what is left of the block holds the whole comment.
	d.comment = string(b[:d.commentLen])

	if d.directoryRecords == 0xffff || d.directorySize == 0xffff || d.directoryOffset == 0xffffffff {
		p, err := findDirectory64End(r, directoryEndOffset)
		if err == nil && p >= 0 {
			// The locator sits between the record and the end record,
			// so what is left between the record's first byte and the
			// locator is all the room the record has.
			room := max(directoryEndOffset-directory64LocLen-p-12, 0)
			directoryEndOffset = p
			err = readDirectory64End(r, p, room, d)
		}
		if err != nil {
			return nil, 0, err
		}
	}

	maxInt64 := uint64(1<<63 - 1)
	if d.directorySize > maxInt64 || d.directoryOffset > maxInt64 {
		return nil, 0, ErrFormat
	}

	baseOffset = directoryEndOffset - int64(d.directorySize) - int64(d.directoryOffset)

	if baseOffset < 0 {
		return nil, 0, ErrFormat
	}

	if o := baseOffset + int64(d.directoryOffset); o < 0 || o >= size {
		return nil, 0, ErrFormat
	}

	if baseOffset > 0 {
		off := int64(d.directoryOffset)
		rs := io.NewSectionReader(r, off, size-off)
		if readDirectoryHeader(&File{}, rs) == nil {
			baseOffset = 0
		}
	}

	return d, baseOffset, nil
}

func findDirectory64End(r io.ReaderAt, directoryEndOffset int64) (int64, error) {
	locOffset := directoryEndOffset - directory64LocLen
	if locOffset < 0 {
		return -1, nil
	}
	buf := make([]byte, directory64LocLen)
	if _, err := r.ReadAt(buf, locOffset); err != nil {
		return -1, err
	}
	b := readBuf(buf)
	if sig := b.uint32(); sig != directory64LocSignature {
		return -1, nil
	}
	if b.uint32() != 0 {
		return -1, nil
	}
	p := b.uint64()
	if b.uint32() != 1 {
		return -1, nil
	}
	// A negative return is how this function says there is no zip64 end
	// record to read, so an offset above MaxInt64 narrowed into one would
	// quietly turn a record that is there into a record that is not.
	off, err := u64toi64(p)
	if err != nil {
		return -1, err
	}
	return off, nil
}

// readDirectory64End reads the zip64 end record at offset. room is how many
// bytes of record content the archive has room for: the locator that named the
// record sits immediately after it, so the space between the two is the most
// the record can hold, whatever the record says about itself.
func readDirectory64End(r io.ReaderAt, offset, room int64, d *directoryEnd) (err error) {
	// 1. Read the first 12 bytes to get the actual record size
	var hbuf [12]byte
	if _, err := r.ReadAt(hbuf[:], offset); err != nil {
		return err
	}
	hb := readBuf(hbuf[:])
	if sig := hb.uint32(); sig != directory64EndSignature {
		return ErrFormat
	}
	// recordSize is the size of the record minus the first 12 bytes (sig + size)
	recordSize := hb.uint64()

	// 2. Read the rest of the record, which is as much of it as is used and
	// no more. The size of the record is eight bytes of the archive's own
	// choosing, and the buffer for it used to be made from that number
	// before a byte of the record had been read -- a quarter of the address
	// space asked for this way is a panic, not an archive the reader
	// rejects. What is read also has to be the record's own, which is what
	// room is for: a record that claims to reach past where the locator
	// says it ends has its version 2 fields read out of the locator and the
	// end record instead, and the end record's signature carries the bit
	// that says the central directory is encrypted -- so an archive that
	// reads perfectly well announces that it cannot be read. A record too
	// short for the fields below is not a record either, since readBuf
	// reads them without looking at what is left.
	const maxRecord = directory64EndLen - 12 + 24 // the fields below, plus the version 2 ones
	// #nosec G115 -- room is what the caller measured between the record and the locator and is clamped to zero there
	held := min(recordSize, uint64(room))
	if held < directory64EndLen-12 {
		return ErrFormat
	}
	buf := make([]byte, min(held, uint64(maxRecord)))
	if _, err := r.ReadAt(buf, offset+12); err != nil {
		return err
	}
	b := readBuf(buf)

	b.uint16() // version made by
	b.uint16() // version needed
	d.diskNbr = b.uint32()
	d.dirDiskNbr = b.uint32()
	d.dirRecordsThisDisk = b.uint64()
	d.directoryRecords = b.uint64()
	d.directorySize = b.uint64()
	d.directoryOffset = b.uint64()

	// 3. Check for the presence of Version 2 (SES)
	// APPNOTE 7.3.4: Version 2 fields occupy at least 24 bytes:
	// Method(2) + CSize(8) + USize(8) + AlgId(2) + BitLen(2) + Flags(2)
	if len(b) >= 24 {
		b.uint16() // Compression Method
		b.uint64() // Compressed Size
		b.uint64() // Original Size
		d.algId = b.uint16()
		d.bitLen = b.uint16()
		if b.uint16()&0x1 != 0 {
			d.encrypted = true
		}
	}

	return nil
}

func findSignatureInBlock(b []byte) int {
	for i := len(b) - directoryEndLen; i >= 0; i-- {
		if b[i] == 'P' && b[i+1] == 'K' && b[i+2] == 0x05 && b[i+3] == 0x06 {
			n := int(b[i+directoryEndLen-2]) | int(b[i+directoryEndLen-1])<<8
			if n+directoryEndLen+i > len(b) {
				return -1
			}
			return i
		}
	}
	return -1
}

type readBuf []byte

func (b *readBuf) uint8() uint8 {
	v := (*b)[0]
	*b = (*b)[1:]
	return v
}

func (b *readBuf) uint16() uint16 {
	v := binary.LittleEndian.Uint16(*b)
	*b = (*b)[2:]
	return v
}

func (b *readBuf) uint32() uint32 {
	v := binary.LittleEndian.Uint32(*b)
	*b = (*b)[4:]
	return v
}

func (b *readBuf) uint64() uint64 {
	v := binary.LittleEndian.Uint64(*b)
	*b = (*b)[8:]
	return v
}

func (b *readBuf) sub(n int) readBuf {
	if n < 0 || n > len(*b) {
		*b = (*b)[len(*b):]
		return nil
	}
	b2 := (*b)[:n]
	*b = (*b)[n:]
	return b2
}

type fileListEntry struct {
	name  string
	file  *File
	isDir bool
	isDup bool
}

type fileInfoDirEntry interface {
	fs.FileInfo
	fs.DirEntry
}

func (f *fileListEntry) stat() (fileInfoDirEntry, error) {
	if f.isDup {
		return nil, errors.New(f.name + ": duplicate entries in zip file")
	}
	if !f.isDir {
		return headerFileInfo{&f.file.FileHeader}, nil
	}
	return f, nil
}

func (f *fileListEntry) Name() string      { _, elem, _ := split(f.name); return elem }
func (f *fileListEntry) Size() int64       { return 0 }
func (f *fileListEntry) Mode() fs.FileMode { return fs.ModeDir | 0555 }
func (f *fileListEntry) Type() fs.FileMode { return fs.ModeDir }
func (f *fileListEntry) IsDir() bool       { return true }
func (f *fileListEntry) Sys() any          { return nil }

func (f *fileListEntry) ModTime() time.Time {
	if f.file == nil {
		return time.Time{}
	}
	return f.file.Modified.UTC()
}

func (f *fileListEntry) Info() (fs.FileInfo, error) { return f, nil }

func (f *fileListEntry) String() string {
	return fs.FormatDirEntry(f)
}

func toValidName(name string) string {
	name = strings.ReplaceAll(name, `\`, `/`)
	p := path.Clean(name)
	p = strings.TrimPrefix(p, "/")
	for strings.HasPrefix(p, "../") {
		p = p[len("../"):]
	}
	return p
}

func (r *Reader) initFileList() {
	r.fileListOnce.Do(func() {
		files := make(map[string]int)
		knownDirs := make(map[string]int)
		dirs := make(map[string]bool)

		for _, file := range r.File {
			isDir := len(file.Name) > 0 && file.Name[len(file.Name)-1] == '/'
			name := toValidName(file.Name)
			if name == "" {
				continue
			}

			if idx, ok := files[name]; ok {
				r.fileList[idx].isDup = true
				continue
			}
			if idx, ok := knownDirs[name]; ok {
				r.fileList[idx].isDup = true
				continue
			}

			dir := name
			for {
				if idx := strings.LastIndex(dir, "/"); idx < 0 {
					break
				} else {
					dir = dir[:idx]
				}
				if dirs[dir] {
					break
				}
				dirs[dir] = true
			}

			idx := len(r.fileList)
			entry := fileListEntry{
				name:  name,
				file:  file,
				isDir: isDir,
			}
			r.fileList = append(r.fileList, entry)
			if isDir {
				knownDirs[name] = idx
			} else {
				files[name] = idx
			}
		}
		for dir := range dirs {
			if _, ok := knownDirs[dir]; !ok {
				if idx, ok := files[dir]; ok {
					r.fileList[idx].isDup = true
				} else {
					entry := fileListEntry{
						name:  dir,
						file:  nil,
						isDir: true,
					}
					r.fileList = append(r.fileList, entry)
				}
			}
		}

		sort.Slice(r.fileList, func(i, j int) bool { return fileEntryLess(r.fileList[i].name, r.fileList[j].name) })
	})
}

func fileEntryLess(x, y string) bool {
	xdir, xelem, _ := split(x)
	ydir, yelem, _ := split(y)
	return xdir < ydir || xdir == ydir && xelem < yelem
}

func (r *Reader) Open(name string) (fs.File, error) {
	r.initFileList()

	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	e := r.openLookup(name)
	if e == nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if e.isDir {
		return &openDir{e, r.openReadDir(name), 0}, nil
	}
	rc, err := e.file.Open()
	if err != nil {
		return nil, err
	}
	return rc.(fs.File), nil
}

func split(name string) (dir, elem string, isDir bool) {
	if len(name) > 0 && name[len(name)-1] == '/' {
		isDir = true
		name = name[:len(name)-1]
	}
	i := len(name) - 1
	for i >= 0 && name[i] != '/' {
		i--
	}
	if i < 0 {
		return ".", name, isDir
	}
	return name[:i], name[i+1:], isDir
}

var dotFile = &fileListEntry{name: "./", isDir: true}

func (r *Reader) openLookup(name string) *fileListEntry {
	if name == "." {
		return dotFile
	}

	dir, elem, _ := split(name)
	files := r.fileList
	i := sort.Search(len(files), func(i int) bool {
		idir, ielem, _ := split(files[i].name)
		return idir > dir || idir == dir && ielem >= elem
	})
	if i < len(files) {
		fname := files[i].name
		if fname == name || len(fname) == len(name)+1 && fname[len(name)] == '/' && fname[:len(name)] == name {
			return &files[i]
		}
	}
	return nil
}

func (r *Reader) openReadDir(dir string) []fileListEntry {
	files := r.fileList
	i := sort.Search(len(files), func(i int) bool {
		idir, _, _ := split(files[i].name)
		return idir >= dir
	})
	j := sort.Search(len(files), func(j int) bool {
		jdir, _, _ := split(files[j].name)
		return jdir > dir
	})
	return files[i:j]
}

type openDir struct {
	e      *fileListEntry
	files  []fileListEntry
	offset int
}

func (d *openDir) Close() error               { return nil }
func (d *openDir) Stat() (fs.FileInfo, error) { return d.e.stat() }

func (d *openDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.e.name, Err: errors.New("is a directory")}
}

func (d *openDir) ReadDir(count int) ([]fs.DirEntry, error) {
	n := len(d.files) - d.offset
	if count > 0 && n > count {
		n = count
	}
	if n == 0 {
		if count <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}
	list := make([]fs.DirEntry, n)
	for i := range list {
		s, err := d.files[d.offset+i].stat()
		if err != nil {
			return nil, err
		}
		list[i] = s
	}
	d.offset += n
	return list, nil
}
