package zip

import (
    "os"
    "fmt"
    "path"
    "path/filepath"
	"bufio"
	"encoding/binary"
	"bytes"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"io/fs"
	"strings"
	"unicode/utf8"
    "github.com/unxed/par2"
)

var (
	errLongName  = errors.New("zip: FileHeader.Name too long")
	errLongExtra = errors.New("zip: FileHeader.Extra too long")
)

type Writer struct {
	cw          *countWriter
	dir         []*header
	last        *fileWriter
	closed      bool
	compressors map[uint16]Compressor
	comment     string

	testHookCloseSizeOffset func(size, offset uint64)
	encryptCD   bool
	password    string
	forceNoDescriptor bool
	torrentZip        bool
	recoveryPct       int
	recoveryFile      *os.File
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
	offset     uint64
	raw        bool
	torrentZip bool
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
	comp       io.WriteCloser
	base       *countWriter // physically writes to zip
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

		wn, err := c.comp.Write(p[:toWrite])
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
		c.written += uint32(wn)
		c.totalWrite += int64(wn)
		p = p[wn:]

		if c.written >= c.chunkSize {
			// Only flush and record if we are NOT at the very end of the file.
			if c.h.UncompressedSize64 == 0 || c.totalWrite < int64(c.h.UncompressedSize64) {
				if f, ok := c.comp.(flusher); ok {
					f.Flush()
				}

				// Record relative offset from the start of compressed data AFTER flush
				relativeOffset := c.base.count - c.dataStart

				if c.continuous {
					pt := gzPoint{
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
					if r, ok := c.comp.(interface{ ResetDict() }); ok {
						r.ResetDict()
					}
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

		b.uint16(uint16(len(h.Name)))
		b.uint16(uint16(len(h.Extra)))
		b.uint16(uint16(len(h.Comment)))
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
		w.cw.w.(*bufio.Writer).Flush()
		if syncer, ok := interface{}(w.recoveryFile).(interface{ Sync() error }); ok {
			syncer.Sync()
		}

		mvr, totalSize, err := OpenMultiVolume(w.recoveryFile.Name(), os.O_RDONLY)
		if err == nil {
			r := io.NewSectionReader(mvr, 0, totalSize)
			par2Bytes, err := par2.GeneratePAR2Stream(r, totalSize, filepath.Base(w.recoveryFile.Name()), w.recoveryPct)
			mvr.Close()
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
					offset:     uint64(w.cw.count),
					raw:        true,
				}
				if err := writeHeader(w.cw, h); err == nil {
					w.cw.Write(par2Bytes)
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
		aesW.Close()
	}

	end := w.cw.count

	records := uint64(len(w.dir))
	size := uint64(end - start)
	offset := uint64(start)

	var unencryptedSize uint64
	if w.encryptCD && cdBuf != nil {
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
			b.uint16(Store)  // Compression: None
			b.uint64(size)   // Compressed size (includes Salt + HMAC)
			b.uint64(unencryptedSize) // Original size (CD headers only)
			b.uint16(sesAES256)
			b.uint16(256)
			b.uint16(0x0001) // Flag: Encrypted
		}

		b.uint32(directory64LocSignature)
		b.uint32(0)
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

func (w *Writer) CreateHeader(fh *FileHeader) (io.Writer, error) {
	if err := w.prepare(fh); err != nil {
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
		fh.Flags = 2
		fh.Extra = nil
		fh.ExternalAttrs = 0
		fh.CreatorVersion = 0
		fh.ReaderVersion = 20
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
		offset:     uint64(w.cw.count),
		torrentZip: w.torrentZip,
	}

	if strings.HasSuffix(fh.Name, "/") {
		fh.Method = Store
		fh.Flags &^= 0x8
		fh.CompressedSize = 0
		fh.CompressedSize64 = 0
		fh.UncompressedSize = 0
		fh.UncompressedSize64 = 0

		ow = dirWriter{}
	} else {
		if w.forceNoDescriptor {
			fh.Flags &^= 0x8
			fh.CompressedSize = uint32(min(fh.UncompressedSize64, uint32max))
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
				comp:       fw.comp,
				base:       fw.compCount,
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
	const maxUint16 = 1<<16 - 1
	if len(h.Name) > maxUint16 {
		return errLongName
	}
	if len(h.Extra) > maxUint16 {
		return errLongExtra
	}

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
	if h.raw || !h.hasDataDescriptor() {
		b.uint32(h.CRC32)
		b.uint32(uint32(min(h.CompressedSize64, uint32max)))
		b.uint32(uint32(min(h.UncompressedSize64, uint32max)))
	} else {
		if h.Method == Store && h.UncompressedSize64 > 0 {
			b.uint32(0)
			b.uint32(uint32(min(h.CompressedSize64, uint32max)))
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

	b.uint16(uint16(len(h.Name)))
	b.uint16(uint16(len(extra)))
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, h.Name); err != nil {
		return err
	}
	_, err := w.Write(extra)
	return err
}

func (w *Writer) CreateRaw(fh *FileHeader) (io.Writer, error) {
	if err := w.prepare(fh); err != nil {
		return nil, err
	}

	fh.CompressedSize = uint32(min(fh.CompressedSize64, uint32max))
	fh.UncompressedSize = uint32(min(fh.UncompressedSize64, uint32max))

	if w.torrentZip {
		fh.ModifiedTime = 48128
		fh.ModifiedDate = 8600
		fh.Flags = 2
		fh.Extra = nil
		fh.ExternalAttrs = 0
		fh.CreatorVersion = 0
		fh.ReaderVersion = 20
	}

	h := &header{
		FileHeader: fh,
		offset:     uint64(w.cw.count),
		raw:        true,
		torrentZip: w.torrentZip,
	}
	w.dir = append(w.dir, h)
	if err := writeHeader(w.cw, h); err != nil {
		return nil, err
	}

	if strings.HasSuffix(fh.Name, "/") {
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
		defer f.Close()
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

	if !w.header.torrentZip {
		w.header.injectAutoExtras()
	} else {
		w.header.Extra = nil
	}

	fh := w.header.FileHeader
	if w.isAES {
		fh.CRC32 = 0 // AE-2 dictates that CRC is 0
	} else {
		fh.CRC32 = w.crc32.Sum32()
	}
	fh.CompressedSize64 = uint64(w.compCount.count)
	fh.UncompressedSize64 = uint64(w.rawCount.count)

	if fh.isZip64() {
		fh.CompressedSize = uint32max
		fh.UncompressedSize = uint32max
		fh.ReaderVersion = zipVersion45
	} else {
		fh.CompressedSize = uint32(fh.CompressedSize64)
		fh.UncompressedSize = uint32(fh.UncompressedSize64)
	}

	if err := w.writeDataDescriptor(); err != nil {
		return err
	}

	if w.header.SeekChunkSize > 0 && w.header.Method != Store {
		if err := w.writeHiddenIndex(); err != nil {
			return err
		}
	}

	return nil
}

func (w *fileWriter) writeHiddenIndex() error {
	var payload []byte
	var ext string

	if w.header.SeekContinuous {
		ext = ".gzidx"
		payload = w.buildGZIDX()
	} else {
		ext = ".sozip.idx"
		payload = w.buildSOZip()
	}

	dir, name := path.Split(w.header.Name)
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
		offset:     uint64(w.zipw.(*countWriter).count),
		raw:        true,
	}

	if err := writeHeader(w.zipw, h); err != nil {
		return err
	}
	if _, err := w.zipw.Write(payload); err != nil {
		return err
	}
	return nil
}

func (w *fileWriter) buildSOZip() []byte {
	buf := new(bytes.Buffer)
	buf.Grow(32 + (len(w.header.SeekIndex)-1)*8)

	binary.Write(buf, binary.LittleEndian, uint32(1))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(w.header.SeekChunkSize))
	binary.Write(buf, binary.LittleEndian, uint32(8))
	binary.Write(buf, binary.LittleEndian, uint64(w.header.UncompressedSize64))
	binary.Write(buf, binary.LittleEndian, uint64(w.header.CompressedSize64))

	for i := 1; i < len(w.header.SeekIndex); i++ {
		binary.Write(buf, binary.LittleEndian, uint64(w.header.SeekIndex[i]))
	}
	return buf.Bytes()
}

func (w *fileWriter) buildGZIDX() []byte {
	buf := new(bytes.Buffer)
	buf.Write([]byte("GZIDX"))
	buf.WriteByte(1) // version
	buf.WriteByte(0) // flags

	binary.Write(buf, binary.LittleEndian, uint64(w.header.CompressedSize64))
	binary.Write(buf, binary.LittleEndian, uint64(w.header.UncompressedSize64))
	binary.Write(buf, binary.LittleEndian, uint32(w.header.SeekChunkSize))
	binary.Write(buf, binary.LittleEndian, uint32(32768)) // windowSize
	binary.Write(buf, binary.LittleEndian, uint32(len(w.header.GzidxPoints)))

	for _, pt := range w.header.GzidxPoints {
		binary.Write(buf, binary.LittleEndian, pt.compOffset)
		binary.Write(buf, binary.LittleEndian, pt.uncompOffset)
		buf.WriteByte(pt.bits)
		buf.WriteByte(pt.hasData)
	}
	for _, pt := range w.header.GzidxPoints {
		if pt.hasData == 1 {
			if len(pt.window) == 32768 {
				buf.Write(pt.window)
			} else {
				pad := make([]byte, 32768)
				copy(pad[32768-len(pt.window):], pt.window)
				buf.Write(pad)
			}
		}
	}
	return buf.Bytes()
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
	b.uint32(w.header.CRC32)
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