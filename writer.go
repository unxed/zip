package zip

import (
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
}

type header struct {
	*FileHeader
	offset uint64
	raw    bool
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{cw: &countWriter{w: bufio.NewWriter(w)}}
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
		if r < 0x20 || r > 0x7d || r == 0x5c {
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

	originalMethod := fh.injectAutoExtras()

	var (
		ow io.Writer
		fw *fileWriter
	)
	h := &header{
		FileHeader: fh,
		offset:     uint64(w.cw.count),
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
		fh.Flags |= 0x8

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
		ow = fw
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
	if h.raw && !h.hasDataDescriptor() {
		b.uint32(h.CRC32)
		b.uint32(uint32(min(h.CompressedSize64, uint32max)))
		b.uint32(uint32(min(h.UncompressedSize64, uint32max)))
	} else {
		// Zero out sizes in header, they will be provided in the footer (Data Descriptor)
		b.uint32(0)
		b.uint32(0)
		b.uint32(0)
		h.Flags |= 0x8
	}
	b.uint16(uint16(len(h.Name)))
	b.uint16(uint16(len(h.Extra)))
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, h.Name); err != nil {
		return err
	}
	_, err := w.Write(h.Extra)
	return err
}

func (w *Writer) CreateRaw(fh *FileHeader) (io.Writer, error) {
	if err := w.prepare(fh); err != nil {
		return nil, err
	}

	fh.CompressedSize = uint32(min(fh.CompressedSize64, uint32max))
	fh.UncompressedSize = uint32(min(fh.UncompressedSize64, uint32max))

	h := &header{
		FileHeader: fh,
		offset:     uint64(w.cw.count),
		raw:        true,
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
	_, err = io.Copy(fw, r)
	return err
}

func (w *Writer) RegisterCompressor(method uint16, comp Compressor) {
	if w.compressors == nil {
		w.compressors = make(map[uint16]Compressor)
	}
	w.compressors[method] = comp
}

func (w *Writer) AddFS(fsys fs.FS) error {
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
		_, err = io.Copy(fw, f)
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

	return w.writeDataDescriptor()
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