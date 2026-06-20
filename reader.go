package zip

import (
	"bufio"
	"encoding/binary"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/klauspost/compress/flate"
	"github.com/unxed/zipcharset"
)

var (
	ErrFormat       = errors.New("zip: not a valid zip file")
	ErrAlgorithm    = errors.New("zip: unsupported compression algorithm")
	ErrChecksum     = errors.New("zip: checksum error")
	ErrInsecurePath = errors.New("zip: insecure file path")
)

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
	f *os.File
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
	ra, size, err := checkF4Recovery(mvr, size)
	if err != nil {
		mvr.Close()
		return nil, err
	}

	raDec, sizeDec, err := checkXCryptZip(ra, size, password)
	if err != nil {
		mvr.Close()
		return nil, err
	}

	zr := new(ReadCloser)
	if password != "" {
		zr.SetPassword(password)
	}
	if err = zr.init(raDec, sizeDec); err != nil {
		mvr.Close()
		return nil, err
	}

	zr.Reader.r = raDec
	return zr, nil
}

func OpenReader(name string) (*ReadCloser, error) {
	return OpenReaderWithPassword(name, "")
}

func NewReaderWithPassword(r io.ReaderAt, size int64, password string) (*Reader, error) {
	if size < 0 {
		return nil, errors.New("zip: size cannot be negative")
	}
	r, size, err := checkF4Recovery(r, size)
	if err != nil {
		return nil, err
	}

	r, size, err = checkXCryptZip(r, size, password)
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

				r.File = append(r.File, f)

				skip := fileHeaderLen + int64(nlen) + int64(elen) + int64(f.CompressedSize64)
				if skip > 0 && off+skip < size {
					off += skip
					continue
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

	if end.directorySize < uint64(size) && (uint64(size)-end.directorySize)/30 >= end.directoryRecords {
		r.File = make([]*File, 0, end.directoryRecords)
	}
	r.Comment = end.comment
	rs := io.NewSectionReader(rdr, 0, size)
	dirOff := r.baseOffset + int64(end.directoryOffset)
	if _, err = rs.Seek(dirOff, io.SeekStart); err != nil {
		return err
	}

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
	if mvr, ok := rc.Reader.r.(*MultiVolumeReader); ok {
		return mvr.Close()
	}
	return rc.f.Close()
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
				return nil, errors.New("zip: incorrect password")
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
	var desr io.Reader
	if f.hasDataDescriptor() {
		ddLen := int64(dataDescriptorLen)
		if f.zip64 {
			ddLen = dataDescriptor64Len
		}
		desr = io.NewSectionReader(f.zipr, f.headerOffset+bodyOffset+size, ddLen)
	}
	rc = &limitReadCloser{
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
	r := io.NewSectionReader(f.zipr, f.headerOffset+bodyOffset, int64(f.CompressedSize64))
	return r, nil
}

func (f *File) findHiddenIndex() (int, []byte, error) {
	bodyOffset, err := f.findBodyOffset()
	if err != nil {
		return 0, nil, err
	}

	endOffset := f.headerOffset + bodyOffset + int64(f.CompressedSize64)
	if f.hasDataDescriptor() {
		if f.zip64 {
			endOffset += dataDescriptor64Len
		} else {
			endOffset += dataDescriptorLen
		}
	}

	var sigBuf [4]byte
	if _, err := f.zipr.ReadAt(sigBuf[:], endOffset); err != nil {
		return 0, nil, nil
	}
	if binary.LittleEndian.Uint32(sigBuf[:]) != fileHeaderSignature {
		return 0, nil, nil
	}

	headerBuf := make([]byte, fileHeaderLen)
	if _, err := f.zipr.ReadAt(headerBuf, endOffset); err != nil {
		return 0, nil, nil
	}

	b := readBuf(headerBuf[4:])
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
		return 0, nil, nil
	}

	nameBuf := make([]byte, filenameLen)
	if _, err := f.zipr.ReadAt(nameBuf, endOffset+fileHeaderLen); err != nil {
		return 0, nil, err
	}
	hiddenName := string(nameBuf)
	// Masked hidden name if CDE is used
	if flags&0x2000 != 0 {
		return 0, nil, nil
	}

	dir, name := path.Split(f.Name)
	if hiddenName != dir+"."+name+".sozip.idx" && hiddenName != dir+"."+name+".gzidx" {
		return 0, nil, nil
	}

	idxType := 1
	if strings.HasSuffix(hiddenName, ".gzidx") {
		idxType = 2
	}

	compSize64 := uint64(compSize)
	if compSize == uint32max {
		extraBuf := make([]byte, extraLen)
		f.zipr.ReadAt(extraBuf, endOffset+fileHeaderLen+int64(filenameLen))
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

	dataOffset := endOffset + fileHeaderLen + int64(filenameLen) + int64(extraLen)
	payload := make([]byte, compSize64)
	if _, err := f.zipr.ReadAt(payload, dataOffset); err != nil {
		return 0, nil, err
	}

	return idxType, payload, nil
}

// OpenSeekable returns a ReadSeeker for the file content.
// It requires a Seek Index (Hidden SOZip or GZIDX) to be present in the archive for compressed files.
func (f *File) OpenSeekable() (io.ReadSeeker, error) {
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
				rawSection := io.NewSectionReader(f.zipr, f.headerOffset+bodyOffset, int64(f.CompressedSize64))
				aesRA, err := newWinZipAesReaderAt(rawSection, f.zip.password(), f.aesInfo, int64(f.CompressedSize64))
				if err != nil {
					return nil, err
				}
				return io.NewSectionReader(aesRA, 0, int64(f.UncompressedSize64)), nil
			}
			return nil, errors.New("zip: random access not supported for classic ZipCrypto")
		}
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

		f.SeekChunkSize = chunkSize
		f.SeekIndex = []uint64{0}

		offsetData := payload[32:]
		for len(offsetData) >= 8 {
			f.SeekIndex = append(f.SeekIndex, binary.LittleEndian.Uint64(offsetData[:8]))
			offsetData = offsetData[8:]
		}

		return &solidReadSeeker{f: f}, nil
	}

	if idxType == 2 { // GZIDX
		if len(payload) < 35 || string(payload[:5]) != "GZIDX" {
			return nil, errors.New("zip: invalid GZIDX payload")
		}
		chunkSize := binary.LittleEndian.Uint32(payload[23:27])
		numPoints := binary.LittleEndian.Uint32(payload[31:35])

		if 35+int(numPoints)*18 > len(payload) {
			return nil, errors.New("zip: invalid GZIDX payload (too short for points)")
		}

		f.SeekChunkSize = chunkSize
		f.GzidxPoints = make([]gzPoint, numPoints)
		offset := 35
		for i := 0; i < int(numPoints); i++ {
			f.GzidxPoints[i].compOffset = binary.LittleEndian.Uint64(payload[offset:])
			f.GzidxPoints[i].uncompOffset = binary.LittleEndian.Uint64(payload[offset+8:])
			f.GzidxPoints[i].bits = payload[offset+16]
			f.GzidxPoints[i].hasData = payload[offset+17]
			offset += 18
		}
		for i := 0; i < int(numPoints); i++ {
			if f.GzidxPoints[i].hasData == 1 {
				if offset+32768 > len(payload) {
					return nil, errors.New("zip: invalid GZIDX payload (truncated window data)")
				}
				f.GzidxPoints[i].window = payload[offset : offset+32768]
				offset += 32768
			}
		}
		return &solidReadSeeker{f: f, isContinuous: true}, nil
	}

	return nil, errors.New("zip: seek index missing")
}

type solidReadSeeker struct {
	f            *File
	off          int64
	currRC       io.ReadCloser
	isContinuous bool
}

func (s *solidReadSeeker) Seek(offset int64, whence int) (int64, error) {
	var newOff int64
	switch whence {
	case io.SeekStart:
		newOff = offset
	case io.SeekCurrent:
		newOff = s.off + offset
	case io.SeekEnd:
		newOff = int64(s.f.UncompressedSize64) + offset
	}
	if newOff < 0 || newOff > int64(s.f.UncompressedSize64) {
		return 0, errors.New("zip: invalid seek offset")
	}
	if newOff != s.off && s.currRC != nil {
		s.currRC.Close()
		s.currRC = nil
	}
	s.off = newOff
	return s.off, nil
}

func (s *solidReadSeeker) Read(p []byte) (int, error) {
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
				if int64(pt.uncompOffset) <= s.off {
					if best == nil || pt.uncompOffset > best.uncompOffset {
						best = pt
					}
				}
			}
			if best == nil {
				return 0, io.EOF
			}
			compOffset = int64(best.compOffset)
			uncompOffset = int64(best.uncompOffset)
		} else {
			blockIdx := s.off / int64(s.f.SeekChunkSize)
			if blockIdx >= int64(len(s.f.SeekIndex)) {
				return 0, io.EOF
			}
			compOffset = int64(s.f.SeekIndex[blockIdx])
			uncompOffset = blockIdx * int64(s.f.SeekChunkSize)
		}

		bodyOffset, err := s.f.findBodyOffset()
		if err != nil {
			return 0, err
		}

		totalCompSize := int64(s.f.CompressedSize64)

		var section io.Reader
		actualMethod := s.f.Method

		if s.f.IsEncrypted() {
			if s.f.zip.password == nil {
				return 0, errors.New("zip: file is encrypted but no password provided")
			}
			pass := s.f.zip.password()

			if s.f.Method == winzipAesExtraID || s.f.aesInfo != nil {
				rawSection := io.NewSectionReader(s.f.zipr, s.f.headerOffset+bodyOffset, totalCompSize)
				aesRA, err := newWinZipAesReaderAt(rawSection, pass, s.f.aesInfo, totalCompSize)
				if err != nil {
					return 0, err
				}
				actualMethod = s.f.aesInfo.actualMethod

				remainingComp := aesRA.limit - compOffset
				section = io.NewSectionReader(aesRA, compOffset, remainingComp)
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
	r.nread += uint64(n)
	if r.nread > r.f.UncompressedSize64 {
		return 0, ErrFormat
	}
	if err == nil {
		return
	}
	if err == io.EOF {
		if r.nread != r.f.UncompressedSize64 {
			return 0, io.ErrUnexpectedEOF
		}
		if r.f.Method == winzipAesExtraID {
			if _, macErr := io.Copy(io.Discard, r.rr); macErr != nil {
				err = macErr
			} else {
				err = io.EOF
			}
		} else if r.desr != nil {
			if err1 := readDataDescriptor(r.desr, r.f); err1 != nil {
				if err1 == io.EOF {
					err = io.ErrUnexpectedEOF
				} else {
					err = err1
				}
			} else if r.hash.Sum32() != r.f.CRC32 {
				err = ErrChecksum
			}
		} else {
			if r.f.CRC32 != 0 && r.hash.Sum32() != r.f.CRC32 {
				err = ErrChecksum
			}
		}
	}
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

	f.Name = zipcharset.DecodeText(rawName, isUTF8, packOS, packVer, f.Extra, false)
	if !utf8.ValidString(f.Name) {
		f.Name = decodeUTF8OrMap([]byte(f.Name))
	}
	f.Name = strings.ReplaceAll(f.Name, "\\", "/")
	f.Comment = zipcharset.DecodeText(rawComment, isUTF8, packOS, packVer, f.Extra, true)
	if !utf8.ValidString(f.Comment) {
		f.Comment = decodeUTF8OrMap([]byte(f.Comment))
	}

	utf8Valid1, utf8Require1 := detectUTF8(f.Name)
	utf8Valid2, utf8Require2 := detectUTF8(f.Comment)
	switch {
	case !utf8Valid1 || !utf8Valid2:
		f.NonUTF8 = true
	case !utf8Require1 && !utf8Require2:
		f.NonUTF8 = false
	default:
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

				parseNTFS := func(b *readBuf) time.Time {
					t := int64(b.uint64())
					return time.Unix(epoch+(t/ticksPerSecond), (t%ticksPerSecond)*100)
				}

				modified = parseNTFS(&attrBuf)
				f.Accessed = parseNTFS(&attrBuf)
				f.Created = parseNTFS(&attrBuf)
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
						f.Linkname = string(fieldBuf)
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

	_ = needUSize

	if needCSize || needHeaderOffset {
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
	l := int(d.commentLen)
	if l > len(b) {
		return nil, 0, errors.New("zip: invalid comment length")
	}
	d.comment = string(b[:l])

	if d.directoryRecords == 0xffff || d.directorySize == 0xffff || d.directoryOffset == 0xffffffff {
		p, err := findDirectory64End(r, directoryEndOffset)
		if err == nil && p >= 0 {
			directoryEndOffset = p
			err = readDirectory64End(r, p, d)
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
	return int64(p), nil
}

func readDirectory64End(r io.ReaderAt, offset int64, d *directoryEnd) (err error) {
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

	// 2. Read the rest of the record
	buf := make([]byte, recordSize)
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
	return f.file.FileHeader.Modified.UTC()
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
