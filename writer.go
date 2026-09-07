package zip

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/unxed/par2"
	"hash"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

type Writer struct {
	cw          *countWriter
	dir         []*header
	last        *fileWriter
	closed      bool
	compressors map[uint16]Compressor
	comment     string

	testHookCloseSizeOffset func(size, offset uint64)
	encryptCD               bool
	password                string
	forceNoDescriptor       bool
	torrentZip              bool
	recoveryPct             int
	recoveryFile            *os.File
}

// SetTorrentZip enables torrentzip compatibility mode.
// It enforces predictable timestamps, clears extra fields, disables data descriptors,
// and appends a TORRENTZIPPED- CRC32 comment to the archive.
func (w *Writer) SetTorrentZip(b bool) {
	w.torrentZip = b
	if b {
		w.forceNoDescriptor = true
	}
}

type header struct {
	*FileHeader
	offset uint64
	raw    bool
	// zip64 says that the bytes already on disk for this entry were
	// written in the zip64 shape: a zip64 record in the entry read out of
	// an archive, or the choice this package made when it wrote the local
	// header and the data descriptor itself. It is not the same question as
	// isZip64, which only asks whether the sizes need more than four bytes:
	// a streaming writer emits the record and a twenty four byte descriptor
	// for an entry whose size it did not know yet, however small the entry
	// turns out to be.
	zip64      bool
	torrentZip bool
}

// needsZip64 says whether the central directory record for this entry has to
// carry a zip64 record: because a size does not fit four bytes, because the
// local header offset does not, or because the entry is already written in the
// zip64 shape and a reader sizes its data descriptor by what the directory
// says. None of the three can start being true later for an entry read out of
// an archive -- the sizes and the flag are fixed and an offset only ever moves
// down -- so the answer taken when the archive is opened still holds when it is
// written back out.
func (h *header) needsZip64() bool {
	return h.isZip64() || h.zip64 || h.offset >= uint32max
}

func NewWriter(w io.Writer) *Writer {
	// Уменьшаем буфер до 64КБ. Этого достаточно для заголовков,
	// и это не создает задержек при записи.
	return &Writer{cw: &countWriter{w: bufio.NewWriterSize(w, 64*1024)}}
}

func (w *Writer) SetOffset(n int64) {
	if w.cw.count != 0 {
		panic("zip: SetOffset called after data was written")
	}
	w.cw.count = n
}

func (w *Writer) Flush() error {
	return w.cw.w.(*bufio.Writer).Flush()
}

func (w *Writer) SetComment(comment string) error {
	if len(comment) > uint16max {
		return errors.New("zip: Writer.Comment too long")
	}
	w.comment = comment
	return nil
}

type flusher interface {
	Flush() error
}

type chunkSeekWriter struct {
	h          *header
	fw         *fileWriter
	compFac    Compressor
	sink       io.Writer
	base       *countWriter // physically writes to zip
	origMethod uint16
	chunkSize  uint32
	written    uint32
	dataStart  int64
	totalWrite int64
	continuous bool
	window     []byte
}

func (c *chunkSeekWriter) Write(p []byte) (n int, err error) {
	for len(p) > 0 {
		toWrite := int(c.chunkSize) - int(c.written)
		if toWrite > len(p) {
			toWrite = len(p)
		}

		wn, err := c.fw.comp.Write(p[:toWrite])
		if err != nil {
			return n, err
		}

		if c.continuous {
			c.window = append(c.window, p[:toWrite]...)
			if len(c.window) > 32768 {
				c.window = c.window[len(c.window)-32768:]
			}
		}

		n += wn
		// #nosec G115 -- wn is at most toWrite, which is what is left of the chunk and so below chunkSize
		c.written += uint32(wn)
		c.totalWrite += int64(wn)
		p = p[wn:]

		if c.written >= c.chunkSize {
			// Only flush and record if we are NOT at the very end of the file.
			// #nosec G115 -- the size is the caller's own declaration for the entry being written, not a number read from an archive
			if c.h.UncompressedSize64 == 0 || c.totalWrite < int64(c.h.UncompressedSize64) {
				if !c.continuous && (c.origMethod == ZSTD) {
					// Closing the compressor is what puts the
					// tail of the chunk into the stream; the
					// index entry recorded just below says the
					// next chunk starts after it.
					if cerr := c.fw.comp.Close(); cerr != nil {
						return n, cerr
					}
					newComp, cerr := c.compFac(c.sink)
					if cerr != nil {
						return n, cerr
					}
					c.fw.comp = newComp
				} else {
					if f, ok := c.fw.comp.(flusher); ok {
						if ferr := f.Flush(); ferr != nil {
							return n, ferr
						}
					}
				}

				// Record relative offset from the start of compressed data AFTER flush
				relativeOffset := c.base.count - c.dataStart

				if c.continuous {
					pt := gzPoint{
						// #nosec G115 -- both counters are byte counts this writer keeps and neither goes below zero
						compOffset:   uint64(relativeOffset),
						uncompOffset: uint64(c.totalWrite),
						bits:         0,
						hasData:      1,
						window:       make([]byte, 32768),
					}
					copy(pt.window[32768-len(c.window):], c.window)
					c.h.GzidxPoints = append(c.h.GzidxPoints, pt)
				} else {
					// Clear the dictionary to make the next chunk completely independent
					if r, ok := c.fw.comp.(interface{ ResetDict() }); ok {
						r.ResetDict()
					}
					// #nosec G115 -- relativeOffset is how far into the entry's own data the writer has got and does not go below zero
					c.h.SeekIndex = append(c.h.SeekIndex, uint64(relativeOffset))
				}
			}
			c.written = 0
		}
	}
	return n, nil
}

// SetEncryptCentralDirectory enables encryption of the central directory records.
// This hides file names and metadata from unauthorized users.
// Requires a password to be set.
func (w *Writer) SetEncryptCentralDirectory(enable bool, password string) {
	w.encryptCD = enable
	w.password = password
}

func (w *Writer) Close() error {
	// The setters answer nothing, so the two are weighed against each other
	// here, where the central directory is about to be written and the
	// question of whether it is encrypted is finally asked.
	if w.torrentZip && w.encryptCD {
		return fmt.Errorf("zip: the central directory is to be encrypted: %w", errTorrentZipEncryption)
	}
	if w.last != nil && !w.last.closed {
		if err := w.last.close(); err != nil {
			return err
		}
		w.last = nil
	}
	if w.closed {
		return errors.New("zip: writer closed twice")
	}
	w.closed = true

	start := w.cw.count

	var cdWriter io.Writer = w.cw
	var cdBuf *bytes.Buffer
	var aesW io.WriteCloser
	cdHasher := crc32.NewIEEE()

	if w.torrentZip {
		cdWriter = io.MultiWriter(w.cw, cdHasher)
	}

	if w.encryptCD && w.password != "" {
		cdBuf = new(bytes.Buffer)
		cdWriter = cdBuf
	}

	for _, h := range w.dir {
		var buf [directoryHeaderLen]byte
		b := writeBuf(buf[:])
		b.uint32(uint32(directoryHeaderSignature))
		b.uint16(h.CreatorVersion)
		b.uint16(h.ReaderVersion)
		b.uint16(h.Flags)
		b.uint16(h.Method)
		b.uint16(h.ModifiedTime)
		b.uint16(h.ModifiedDate)
		b.uint32(h.CRC32)
		if h.isZip64() || h.offset >= uint32max {
			b.uint32(uint32max)
			b.uint32(uint32max)

			var buf [28]byte
			eb := writeBuf(buf[:])
			eb.uint16(zip64ExtraID)
			eb.uint16(24)
			eb.uint64(h.UncompressedSize64)
			eb.uint64(h.CompressedSize64)
			eb.uint64(h.offset)
			h.Extra = append(h.Extra, buf[:]...)
		} else {
			b.uint32(h.CompressedSize)
			b.uint32(h.UncompressedSize)
		}

		nameLen, err := fitUint16(len(h.Name), "file name")
		if err != nil {
			return err
		}
		extraLen, err := fitUint16(len(h.Extra), "extra field")
		if err != nil {
			return err
		}
		commentLen, err := fitUint16(len(h.Comment), "file comment")
		if err != nil {
			return err
		}
		b.uint16(nameLen)
		b.uint16(extraLen)
		b.uint16(commentLen)
		b = b[4:]
		b.uint32(h.ExternalAttrs)
		if h.offset > uint32max {
			b.uint32(uint32max)
		} else {
			b.uint32(uint32(h.offset))
		}
		if _, err := cdWriter.Write(buf[:]); err != nil {
			return err
		}
		if _, err := io.WriteString(cdWriter, h.Name); err != nil {
			return err
		}
		if _, err := cdWriter.Write(h.Extra); err != nil {
			return err
		}
		if _, err := io.WriteString(cdWriter, h.Comment); err != nil {
			return err
		}
	}

	if w.torrentZip {
		w.comment = fmt.Sprintf("TORRENTZIPPED-%08X", cdHasher.Sum32())
	}

	// Интегрируем генерацию скрытого файла избыточности .recovery.par2 прямо перед CD
	if w.recoveryPct > 0 && w.recoveryFile != nil && !w.torrentZip && w.password == "" {
		// The recovery data is computed from the archive as it is on
		// disk, so everything written so far has to be there first: a
		// dropped flush produced recovery data for an earlier version
		// of the archive than the one it was stored next to.
		if ferr := w.cw.w.(*bufio.Writer).Flush(); ferr != nil {
			return ferr
		}
		if syncer, ok := interface{}(w.recoveryFile).(interface{ Sync() error }); ok {
			if serr := syncer.Sync(); serr != nil {
				return serr
			}
		}

		mvr, totalSize, err := OpenMultiVolume(w.recoveryFile.Name(), os.O_RDONLY)
		if err == nil {
			r := io.NewSectionReader(mvr, 0, totalSize)
			par2Bytes, err := par2.GeneratePAR2Stream(r, totalSize, filepath.Base(w.recoveryFile.Name()), w.recoveryPct)
			// The volumes were opened read-only to compute the
			// recovery data and are of no further use.
			_ = mvr.Close()
			if err == nil && len(par2Bytes) > 0 {
				fh := &FileHeader{
					Name:               ".recovery.par2",
					Method:             Store,
					UncompressedSize64: uint64(len(par2Bytes)),
					CompressedSize64:   uint64(len(par2Bytes)),
				}
				fh.injectAutoExtras()
				h := &header{
					FileHeader: fh,
					// #nosec G115 -- count is how many bytes this writer has written and does not go below zero
					offset: uint64(w.cw.count),
					raw:    true,
				}
				if err := writeHeader(w.cw, h); err != nil {
					return err
				}
				// The entry's header has already been written, so
				// a body that does not follow it leaves an archive
				// whose recovery entry is a header and nothing
				// else -- and the caller was told the archive was
				// closed successfully.
				if _, werr := w.cw.Write(par2Bytes); werr != nil {
					return werr
				}
			}
		}
	}

	if w.encryptCD && w.password != "" {
		// Now encrypt the accumulated central directory buffer
		// Use AES-256 (strength 3) for CDE
		var err error
		aesW, err = newWinZipAesWriter(w.cw, w.password, 3)
		if err != nil {
			return err
		}
		if _, err := aesW.Write(cdBuf.Bytes()); err != nil {
			return err
		}
		// Closing the AES writer is what appends the authentication
		// code over the encrypted central directory. Without it the
		// archive has a directory no reader can authenticate, and the
		// caller was told the archive closed cleanly.
		if cerr := aesW.Close(); cerr != nil {
			return cerr
		}
	}

	end := w.cw.count

	records := uint64(len(w.dir))
	// #nosec G115 -- end is where writing the directory left off and start is where it began, so the difference is not negative
	size := uint64(end - start)
	// #nosec G115 -- start is a count of bytes written by this writer and does not go below zero
	offset := uint64(start)

	var unencryptedSize uint64
	if w.encryptCD && cdBuf != nil {
		// #nosec G115 -- the length of a buffer is never negative
		unencryptedSize = uint64(cdBuf.Len())
	}

	if f := w.testHookCloseSizeOffset; f != nil {
		f(size, offset)
	}

	if records >= uint16max || size >= uint32max || offset >= uint32max || w.encryptCD {
		// For CDE, ZIP64 EOCD Record Version 2 is always required
		extraSize := uint64(0)
		if w.encryptCD {
			extraSize = 24 // Size of SES v2 fields
		}

		var buf [directory64EndLen + directory64LocLen + 24]byte
		b := writeBuf(buf[:])

		b.uint32(directory64EndSignature)
		b.uint64(directory64EndLen - 12 + extraSize)
		b.uint16(zipVersion45)
		b.uint16(zipVersion45)
		b.uint32(0)
		b.uint32(0)
		b.uint64(records)
		b.uint64(records)
		b.uint64(size)
		b.uint64(offset)

		if w.encryptCD {
			// SES Version 2 fields
			b.uint16(Store)           // Compression: None
			b.uint64(size)            // Compressed size (includes Salt + HMAC)
			b.uint64(unencryptedSize) // Original size (CD headers only)
			b.uint16(sesAES256)
			b.uint16(256)
			b.uint16(0x0001) // Flag: Encrypted
		}

		b.uint32(directory64LocSignature)
		b.uint32(0)
		// #nosec G115 -- end is a count of bytes written by this writer and does not go below zero
		b.uint64(uint64(end))
		b.uint32(1)

		if _, err := w.cw.Write(buf[:]); err != nil {
			return err
		}

		records = uint16max
		size = uint32max
		offset = uint32max
	}

	var buf [directoryEndLen]byte
	b := writeBuf(buf[:])
	b.uint32(uint32(directoryEndSignature))
	b = b[4:]
	b.uint16(uint16(records))
	b.uint16(uint16(records))
	b.uint32(uint32(size))
	b.uint32(uint32(offset))
	// #nosec G115 -- SetComment refuses a comment over uint16max, and the torrentzip comment is a fixed 22 bytes
	b.uint16(uint16(len(w.comment)))
	if _, err := w.cw.Write(buf[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(w.cw, w.comment); err != nil {
		return err
	}

	return w.cw.w.(*bufio.Writer).Flush()
}

func (w *Writer) Create(name string) (io.Writer, error) {
	header := &FileHeader{
		Name:   name,
		Method: Deflate,
	}
	return w.CreateHeader(header)
}

func detectUTF8(s string) (valid, require bool) {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		// 0x7e is '~', the last printable ASCII character before DEL (0x7f)
		if r < 0x20 || r > 0x7e || r == 0x5c {
			if !utf8.ValidRune(r) || (r == utf8.RuneError && size == 1) {
				return false, false
			}
			require = true
		}
	}
	return true, require
}

func (w *Writer) prepare(fh *FileHeader) error {
	if w.last != nil && !w.last.closed {
		if err := w.last.close(); err != nil {
			return err
		}
	}
	if len(w.dir) > 0 && w.dir[len(w.dir)-1].FileHeader == fh {
		return errors.New("archive/zip: invalid duplicate FileHeader")
	}
	return nil
}

// errTorrentZipEncryption is what both contradictions between torrentzip and
// encryption are refused with. Torrentzip's whole point is that the same files
// give the same bytes, which is why the normalisation below clears the extra
// field, forces method 8 and rewrites the flags -- and those three are exactly
// what WinZip AES needs to survive: the 0x9901 record naming the real method,
// method 99 in its place, and the encryption bit. An entry cannot have both,
// and an archive whose central directory is encrypted is not canonical either.
var errTorrentZipEncryption = errors.New("zip: torrentzip and encryption cannot be combined: a torrentzip archive is canonical bytes and encryption has no place to record itself in them")

func (w *Writer) CreateHeader(fh *FileHeader) (io.Writer, error) {
	// Before prepare, so that a refused entry leaves the writer exactly as
	// it was rather than with the previous entry flushed behind it.
	if w.torrentZip && fh.Password != "" {
		return nil, fmt.Errorf("zip: entry %q asks for a password: %w", fh.Name, errTorrentZipEncryption)
	}
	if err := w.prepare(fh); err != nil {
		return nil, err
	}
	if err := validateName(fh.Name); err != nil {
		return nil, err
	}
	// Everything this writer adds to the entry goes behind whatever the
	// caller put here, and a reader walks the area from the front, so an
	// area it cannot walk to the end is an entry it cannot read.
	if err := validateExtra(fh.Extra); err != nil {
		return nil, err
	}

	utf8Valid1, utf8Require1 := detectUTF8(fh.Name)
	utf8Valid2, utf8Require2 := detectUTF8(fh.Comment)
	switch {
	case fh.NonUTF8:
		fh.Flags &^= 0x800
	case (utf8Require1 || utf8Require2) && (utf8Valid1 && utf8Valid2):
		fh.Flags |= 0x800
	}

	fh.CreatorVersion = fh.CreatorVersion&0xff00 | zipVersion20
	fh.ReaderVersion = zipVersion20

	if w.torrentZip {
		fh.ModifiedTime = 48128
		fh.ModifiedDate = 8600
		fh.Extra = nil
		fh.ExternalAttrs = 0
		fh.CreatorVersion = 0
		fh.ReaderVersion = 20
		if strings.HasSuffix(fh.Name, "/") {
			fh.Method = Store
			fh.Flags = 0
		} else {
			fh.Method = Deflate
			fh.Flags = 2
		}
	}

	var originalMethod uint16
	if !w.torrentZip {
		originalMethod = fh.injectAutoExtras()
	} else {
		originalMethod = fh.Method
	}

	var (
		ow io.Writer
		fw *fileWriter
	)
	h := &header{
		FileHeader: fh,
		// #nosec G115 -- count is how many bytes this writer has written and does not go below zero
		offset:     uint64(w.cw.count),
		torrentZip: w.torrentZip,
	}

	if strings.HasSuffix(fh.Name, "/") {
		if w.torrentZip {
			fh.Method = Deflate
			fh.Flags = 2
			fh.CompressedSize = 2
			fh.CompressedSize64 = 2
			fh.UncompressedSize = 0
			fh.UncompressedSize64 = 0
			fh.CRC32 = 0

			if err := writeHeader(w.cw, h); err != nil {
				return nil, err
			}
			if _, err := w.cw.Write([]byte{0x03, 0x00}); err != nil {
				return nil, err
			}
			ow = dirWriter{}
		} else {
			fh.Method = Store
			fh.Flags &^= 0x8
			fh.CompressedSize = 0
			fh.CompressedSize64 = 0
			fh.UncompressedSize = 0
			fh.UncompressedSize64 = 0

			// A directory is an entry like any other and the record
			// written for it in the central directory says where its
			// local header is. Without one that offset lands on
			// whatever follows -- the next entry's header, or the
			// central directory itself for a directory written last.
			if err := writeHeader(w.cw, h); err != nil {
				return nil, err
			}
			ow = dirWriter{}
		}
	} else {
		if w.forceNoDescriptor {
			fh.Flags &^= 0x8
			// #nosec G115 -- zip64 sentinel: uint32max marks "size is in the zip64 extra", not a value
			fh.CompressedSize = uint32(min(fh.UncompressedSize64, uint32max))
			// #nosec G115 -- zip64 sentinel: uint32max marks "size is in the zip64 extra", not a value
			fh.UncompressedSize = uint32(min(fh.UncompressedSize64, uint32max))
			fh.CompressedSize64 = fh.UncompressedSize64
		} else {
			fh.Flags |= 0x8
		}

		fw = &fileWriter{
			zipw:      w.cw,
			compCount: &countWriter{w: w.cw},
			crc32:     crc32.NewIEEE(),
			isAES:     fh.Password != "",
		}

		// 1. Important: Write the Local File Header FIRST.
		if err := writeHeader(w.cw, h); err != nil {
			return nil, err
		}

		// 2. Initialize encryption/compression stream AFTER header.
		var sink io.Writer = fw.compCount
		if fw.isAES {
			var err error
			// This call writes Salt/Verif bytes to w.cw via compCount.
			fw.aesW, err = newWinZipAesWriter(fw.compCount, fh.Password, fh.AESStrength)
			if err != nil {
				return nil, err
			}
			sink = fw.aesW
		}

		comp := w.compressor(originalMethod)
		if originalMethod == Deflate && fh.Level != 0 {
			comp = func(w io.Writer) (io.WriteCloser, error) {
				return newFlateWriterLevel(w, fh.Level), nil
			}
		}
		if comp == nil {
			return nil, ErrAlgorithm
		}
		var err error
		fw.comp, err = comp(sink)
		if err != nil {
			return nil, err
		}

		fw.rawCount = &countWriter{w: fw.comp}
		fw.header = h
		if fh.SeekChunkSize > 0 && originalMethod != Store {
			csw := &chunkSeekWriter{
				h:          h,
				fw:         fw,
				compFac:    comp,
				sink:       sink,
				base:       fw.compCount,
				origMethod: originalMethod,
				chunkSize:  fh.SeekChunkSize,
				dataStart:  fw.compCount.count,
				continuous: fh.SeekContinuous,
			}
			if fh.SeekContinuous {
				h.GzidxPoints = []gzPoint{{compOffset: 0, uncompOffset: 0, bits: 0, hasData: 0}}
			} else {
				h.SeekIndex = []uint64{0} // SOZip explicitly skips offset 0 in the payload
			}
			fw.rawCount = &countWriter{w: csw}
			ow = fw
		} else {
			fw.rawCount = &countWriter{w: fw.comp}
			ow = fw
		}
		w.last = fw
	}
	w.dir = append(w.dir, h)
	return ow, nil
}

func writeHeader(w io.Writer, h *header) error {
	// The name and the extra field are checked below, once the extra field
	// is the one that will be written: the zip64 record this adds for a
	// large entry counts toward the same limit, and a check up here passed
	// an extra field that only went over the limit afterwards.

	var buf [fileHeaderLen]byte
	b := writeBuf(buf[:])
	b.uint32(uint32(fileHeaderSignature))
	b.uint16(h.ReaderVersion)
	b.uint16(h.Flags)
	b.uint16(h.Method)
	b.uint16(h.ModifiedTime)
	b.uint16(h.ModifiedDate)

	// In streaming mode or when forced by flags, always use Data Descriptor.
	// This ensures we never need to Seek back to the Local Header.
	// #nosec G115 -- zip64 sentinel: uint32max marks "size is in the zip64 extra", not a value
	if h.raw || !h.hasDataDescriptor() {
		b.uint32(h.CRC32)
		b.uint32(uint32(min(h.CompressedSize64, uint32max)))
		b.uint32(uint32(min(h.UncompressedSize64, uint32max)))
	} else {
		if h.Method == Store && h.UncompressedSize64 > 0 {
			b.uint32(0)
			// #nosec G115 -- zip64 sentinel: uint32max marks "size is in the zip64 extra", not a value
			b.uint32(uint32(min(h.CompressedSize64, uint32max)))
			// #nosec G115 -- zip64 sentinel: uint32max marks "size is in the zip64 extra", not a value
			b.uint32(uint32(min(h.UncompressedSize64, uint32max)))
		} else {
			b.uint32(0)
			b.uint32(0)
			b.uint32(0)
		}
		h.Flags |= 0x8
	}
	var extra []byte
	extra = append(extra, h.Extra...)
	if (h.CompressedSize64 >= uint32max || h.UncompressedSize64 >= uint32max) && (h.raw || !h.hasDataDescriptor()) {
		hasZip64 := false
		for eb := readBuf(h.Extra); len(eb) >= 4; {
			tag := eb.uint16()
			size := int(eb.uint16())
			if tag == zip64ExtraID {
				hasZip64 = true
				break
			}
			if len(eb) < size {
				break
			}
			eb = eb[size:]
		}
		if !hasZip64 {
			var z64Buf [20]byte
			eb := writeBuf(z64Buf[:])
			eb.uint16(zip64ExtraID)
			eb.uint16(16)
			eb.uint64(h.UncompressedSize64)
			eb.uint64(h.CompressedSize64)
			extra = append(extra, z64Buf[:]...)
		}
	}

	nameLen, err := fitUint16(len(h.Name), "file name")
	if err != nil {
		return err
	}
	extraLen, err := fitUint16(len(extra), "extra field")
	if err != nil {
		return err
	}
	b.uint16(nameLen)
	b.uint16(extraLen)
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, h.Name); err != nil {
		return err
	}
	_, err = w.Write(extra)
	return err
}

func (w *Writer) CreateRaw(fh *FileHeader) (io.Writer, error) {
	if err := w.prepare(fh); err != nil {
		return nil, err
	}

	// #nosec G115 -- zip64 sentinel: uint32max marks "size is in the zip64 extra", not a value
	fh.CompressedSize = uint32(min(fh.CompressedSize64, uint32max))
	// #nosec G115 -- zip64 sentinel: uint32max marks "size is in the zip64 extra", not a value
	fh.UncompressedSize = uint32(min(fh.UncompressedSize64, uint32max))

	if w.torrentZip {
		fh.Name = filepath.ToSlash(fh.Name)
		fh.ModifiedTime = 48128
		fh.ModifiedDate = 8600
		fh.Extra = nil
		fh.ExternalAttrs = 0
		fh.CreatorVersion = 0
		fh.ReaderVersion = 20
		if strings.HasSuffix(fh.Name, "/") {
			fh.Method = Deflate
			fh.Flags = 2
			fh.CompressedSize = 2
			fh.CompressedSize64 = 2
			fh.UncompressedSize = 0
			fh.UncompressedSize64 = 0
			fh.CRC32 = 0
		} else {
			fh.Method = Deflate
			fh.Flags = 2
		}
	}

	h := &header{
		FileHeader: fh,
		// #nosec G115 -- count is how many bytes this writer has written and does not go below zero
		offset:     uint64(w.cw.count),
		raw:        true,
		torrentZip: w.torrentZip,
	}
	w.dir = append(w.dir, h)
	if err := writeHeader(w.cw, h); err != nil {
		return nil, err
	}

	if strings.HasSuffix(fh.Name, "/") {
		if w.torrentZip {
			// В CreateRaw мы уже записали заголовок через writeHeader выше.
			// Для TorrentZip пустая директория должна содержать 2 байта (пустой deflate блок).
			// Обновляем структуру заголовка на правильные размеры.
			// Но так как заголовок уже записан, мы должны были обновить его ДО writeHeader.
			// К счастью, CreateRaw принимает структуру fh, которую пользователь заполняет сам.
			// Однако, если это torrentZip, мы переопределяем свойства.
			if _, err := w.cw.Write([]byte{0x03, 0x00}); err != nil {
				return nil, err
			}
		}
		w.last = nil
		return dirWriter{}, nil
	}

	fw := &fileWriter{
		header: h,
		zipw:   w.cw,
	}
	w.last = fw
	return fw, nil
}

func (w *Writer) Copy(f *File) error {
	r, err := f.OpenRaw()
	if err != nil {
		return err
	}
	fh := f.FileHeader
	fw, err := w.CreateRaw(&fh)
	if err != nil {
		return err
	}
	// Используем 1MB буфер вместо дефолтных 32KB для Raw Copy
	_, err = io.CopyBuffer(fw, r, make([]byte, 1024*1024))
	return err
}

func (w *Writer) RegisterCompressor(method uint16, comp Compressor) {
	if w.compressors == nil {
		w.compressors = make(map[uint16]Compressor)
	}
	w.compressors[method] = comp
}

func (w *Writer) AddFS(fsys fs.FS) error {
	copyBuf := make([]byte, 1024*1024) // 1MB буфер вместо дефолтных 32КБ
	return fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !d.IsDir() && !info.Mode().IsRegular() {
			return errors.New("zip: cannot add non-regular file")
		}
		h, err := FileInfoHeader(info)
		if err != nil {
			return err
		}
		h.Name = name
		if d.IsDir() {
			h.Name += "/"
		}
		h.Method = Deflate
		fw, err := w.CreateHeader(h)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := fsys.Open(name)
		if err != nil {
			return err
		}
		// A file being read into the archive; nothing is written
		// through this handle.
		defer func() { _ = f.Close() }()
		_, err = io.CopyBuffer(fw, f, copyBuf)
		return err
	})
}

func (w *Writer) compressor(method uint16) Compressor {
	comp := w.compressors[method]
	if comp == nil {
		comp = compressor(method)
	}
	return comp
}

type dirWriter struct{}

func (dirWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	return 0, errors.New("zip: write to directory")
}

type fileWriter struct {
	*header
	zipw      io.Writer
	rawCount  *countWriter
	comp      io.WriteCloser
	compCount *countWriter
	crc32     hash.Hash32
	closed    bool
	aesW      io.WriteCloser
	isAES     bool
}

func (w *fileWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("zip: write to closed file")
	}
	if w.raw {
		return w.zipw.Write(p)
	}
	w.crc32.Write(p)
	return w.rawCount.Write(p)
}

func (w *fileWriter) close() error {
	if w.closed {
		return errors.New("zip: file closed twice")
	}
	w.closed = true
	if w.raw {
		return w.writeDataDescriptor()
	}
	if err := w.comp.Close(); err != nil {
		return err
	}
	if w.aesW != nil {
		if err := w.aesW.Close(); err != nil {
			return err
		}
	}

	if !w.torrentZip {
		w.injectAutoExtras()
	} else {
		w.Extra = nil
	}

	fh := w.FileHeader
	if w.isAES {
		fh.CRC32 = 0 // AE-2 dictates that CRC is 0
	} else {
		fh.CRC32 = w.crc32.Sum32()
	}
	// #nosec G115 -- both are counts of bytes this writer produced and neither goes below zero
	fh.CompressedSize64 = uint64(w.compCount.count)
	// #nosec G115 -- both are counts of bytes this writer produced and neither goes below zero
	fh.UncompressedSize64 = uint64(w.rawCount.count)

	if fh.isZip64() {
		fh.CompressedSize = uint32max
		fh.UncompressedSize = uint32max
		fh.ReaderVersion = zipVersion45
	} else {
		// #nosec G115 -- isZip64 is false, so both sizes are below uint32max
		fh.CompressedSize = uint32(fh.CompressedSize64)
		// #nosec G115 -- isZip64 is false, so both sizes are below uint32max
		fh.UncompressedSize = uint32(fh.UncompressedSize64)
	}

	// writeDataDescriptor sizes the descriptor by isZip64, so this is the
	// shape the bytes on disk now have; recording it here is what lets an
	// entry this session wrote and an entry read out of an archive be
	// measured the same way afterwards.
	w.zip64 = w.isZip64()

	if err := w.writeDataDescriptor(); err != nil {
		return err
	}

	if w.SeekChunkSize > 0 && w.Method != Store {
		if err := w.writeHiddenIndex(); err != nil {
			return err
		}
	}

	return nil
}

func (w *fileWriter) writeHiddenIndex() error {
	var payload []byte
	var ext string

	if w.SeekContinuous {
		ext = ".gzidx"
		payload = w.buildGZIDX()
	} else {
		ext = ".sozip.idx"
		payload = w.buildSOZip()
	}

	dir, name := path.Split(w.Name)
	hiddenName := dir + "." + name + ext

	fh := &FileHeader{
		Name:               hiddenName,
		Method:             Store,
		UncompressedSize64: uint64(len(payload)),
		CompressedSize64:   uint64(len(payload)),
	}
	fh.injectAutoExtras()

	h := &header{
		FileHeader: fh,
		// #nosec G115 -- count is how many bytes this writer has written and does not go below zero
		offset: uint64(w.zipw.(*countWriter).count),
		raw:    true,
	}

	if err := writeHeader(w.zipw, h); err != nil {
		return err
	}
	if _, err := w.zipw.Write(payload); err != nil {
		return err
	}
	return nil
}

// buildSOZip lays out the SOZip index payload. Appending to a byte slice
// rather than writing into a buffer keeps the header fields as what they are,
// fixed-width little-endian numbers, and leaves no error to swallow: a
// bytes.Buffer never fails a write, but the call still returned one.
func (w *fileWriter) buildSOZip() []byte {
	buf := make([]byte, 0, 32+(len(w.SeekIndex)-1)*8)

	buf = binary.LittleEndian.AppendUint32(buf, 1)
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, w.SeekChunkSize)
	buf = binary.LittleEndian.AppendUint32(buf, 8)
	buf = binary.LittleEndian.AppendUint64(buf, w.UncompressedSize64)
	buf = binary.LittleEndian.AppendUint64(buf, w.CompressedSize64)

	for i := 1; i < len(w.SeekIndex); i++ {
		buf = binary.LittleEndian.AppendUint64(buf, w.SeekIndex[i])
	}
	return buf
}

// buildGZIDX lays out the GZIDX index payload, appending to a byte slice for
// the same reasons as buildSOZip.
func (w *fileWriter) buildGZIDX() []byte {
	const windowSize = 32768
	buf := make([]byte, 0, 35+len(w.GzidxPoints)*(18+windowSize))
	buf = append(buf, "GZIDX"...)
	buf = append(buf, 1) // version
	buf = append(buf, 0) // flags

	buf = binary.LittleEndian.AppendUint64(buf, w.CompressedSize64)
	buf = binary.LittleEndian.AppendUint64(buf, w.UncompressedSize64)
	buf = binary.LittleEndian.AppendUint32(buf, w.SeekChunkSize)
	buf = binary.LittleEndian.AppendUint32(buf, windowSize)
	// #nosec G115 -- every point carries a 32 KiB window in memory, so a count too large for this field would mean an index of some 140 TB held in this process
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(w.GzidxPoints)))

	for _, pt := range w.GzidxPoints {
		buf = binary.LittleEndian.AppendUint64(buf, pt.compOffset)
		buf = binary.LittleEndian.AppendUint64(buf, pt.uncompOffset)
		buf = append(buf, pt.bits, pt.hasData)
	}
	for _, pt := range w.GzidxPoints {
		if pt.hasData == 1 {
			if len(pt.window) == windowSize {
				buf = append(buf, pt.window...)
			} else {
				pad := make([]byte, windowSize)
				copy(pad[windowSize-len(pt.window):], pt.window)
				buf = append(buf, pad...)
			}
		}
	}
	return buf
}

func (w *fileWriter) writeDataDescriptor() error {
	if !w.hasDataDescriptor() {
		return nil
	}
	var buf []byte
	if w.isZip64() {
		buf = make([]byte, dataDescriptor64Len)
	} else {
		buf = make([]byte, dataDescriptorLen)
	}
	b := writeBuf(buf)
	b.uint32(dataDescriptorSignature)

	// For AES files, header.CRC32 is already 0
	b.uint32(w.CRC32)
	if w.isZip64() {
		b.uint64(w.CompressedSize64)
		b.uint64(w.UncompressedSize64)
	} else {
		b.uint32(w.CompressedSize)
		b.uint32(w.UncompressedSize)
	}
	_, err := w.zipw.Write(buf)
	return err
}

type countWriter struct {
	w     io.Writer
	count int64
}

func (w *countWriter) Write(p []byte) (n int, err error) {
	n, err = w.w.Write(p)
	w.count += int64(n)
	return n, err
}

type writeBuf []byte

func (b *writeBuf) uint8(v uint8) {
	(*b)[0] = v
	*b = (*b)[1:]
}

func (b *writeBuf) uint16(v uint16) {
	binary.LittleEndian.PutUint16(*b, v)
	*b = (*b)[2:]
}

func (b *writeBuf) uint32(v uint32) {
	binary.LittleEndian.PutUint32(*b, v)
	*b = (*b)[4:]
}

func (b *writeBuf) uint64(v uint64) {
	binary.LittleEndian.PutUint64(*b, v)
	*b = (*b)[8:]
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
