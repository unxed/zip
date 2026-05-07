package zip

import (
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

const bufferSize int64 = 1 << 20 // 1M

// AppendMode specifies the way to append new file to existing zip archive.
type AppendMode int

const (
	// APPEND_MODE_OVERWRITE removes the existing file data and append the new
	// data to the end of the zip archive.
	APPEND_MODE_OVERWRITE AppendMode = iota

	// APPEND_MODE_KEEP_ORIGINAL will keep the original file data and only
	// write the new file data at the end of the existing zip archive file.
	// This mode will keep multiple file with same name into one archive file.
	APPEND_MODE_KEEP_ORIGINAL
)

// sectionReaderWriter implements [io.Reader], [io.Writer], [io.Seeker],
// [io.ReaderAt], [io.WriterAt] interfaces based on [io.ReadWriteSeeker].
type sectionReaderWriter struct {
	rws io.ReadWriteSeeker
}

func newSectionReaderWriter(rws io.ReadWriteSeeker) *sectionReaderWriter {
	return &sectionReaderWriter{
		rws: rws,
	}
}

func (s *sectionReaderWriter) ReadAt(p []byte, offset int64) (int, error) {
	currOffset, err := s.rws.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	defer s.rws.Seek(currOffset, io.SeekStart)
	_, err = s.rws.Seek(offset, io.SeekStart)
	if err != nil {
		return 0, err
	}
	return s.rws.Read(p)
}

func (s *sectionReaderWriter) WriteAt(p []byte, offset int64) (n int, err error) {
	currOffset, err := s.rws.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	defer s.rws.Seek(currOffset, io.SeekStart)
	_, err = s.rws.Seek(offset, io.SeekStart)
	if err != nil {
		return 0, err
	}
	return s.rws.Write(p)
}

func (s *sectionReaderWriter) Seek(offset int64, whence int) (int64, error) {
	return s.rws.Seek(offset, whence)
}

func (s *sectionReaderWriter) Read(p []byte) (n int, err error) {
	return s.rws.Read(p)
}

func (s *sectionReaderWriter) Write(p []byte) (n int, err error) {
	return s.rws.Write(p)
}

func (s *sectionReaderWriter) offset() (int64, error) {
	return s.rws.Seek(0, io.SeekCurrent)
}

type Directory struct {
	FileHeader
	offset int64 // header offset
}

func (d *Directory) HeaderOffset() int64 {
	return d.offset
}

// Updater allows to modify & append files into an existing zip archive without
// decompress the whole file.
type Updater struct {
	rw          *sectionReaderWriter
	rws         io.ReadWriteSeeker
	offset      int64
	dir         []*header
	last        *fileWriter
	closed      bool
	compressors map[uint16]Compressor
	comment     string

	// Some JAR files are zip files with a prefix that is a bash script.
	// The baseOffset field is the start of the zip file proper.
	baseOffset int64
	// dirOffset is the offset to write the directory record.
	// Note that the dirOffset may not equal to the last file data end offset.
	dirOffset int64
}

// NewUpdater returns a new Updater from [io.ReadWriteSeeker], which is
// assumed to have the given size in bytes.
func NewUpdater(rws io.ReadWriteSeeker) (*Updater, error) {
	size, err := rws.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	zu := &Updater{
		rw:  newSectionReaderWriter(rws),
		rws: rws,
	}
	if err = zu.init(size); err != nil && err != ErrInsecurePath {
		return nil, err
	}
	return zu, nil
}

func (u *Updater) init(size int64) error {
	end, baseOffset, err := readDirectoryEnd(u.rw, size)
	if err != nil {
		return err
	}
	u.baseOffset = baseOffset
	u.dirOffset = int64(end.directoryOffset)
	if end.directorySize < uint64(size) && (uint64(size)-end.directorySize)/30 >= end.directoryRecords {
		u.dir = make([]*header, 0, end.directoryRecords)
	}
	u.comment = end.comment
	if _, err = u.rw.Seek(u.baseOffset+int64(end.directoryOffset), io.SeekStart); err != nil {
		return err
	}

	for {
		f := &File{zip: nil, zipr: u.rw}
		err = readDirectoryHeader(f, u.rw)
		if err == ErrFormat || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}
		f.headerOffset += u.baseOffset
		h := &header{
			FileHeader: &f.FileHeader,
			offset:     uint64(f.headerOffset),
		}
		u.dir = append(u.dir, h)
	}
	if uint16(len(u.dir)) != uint16(end.directoryRecords) {
		return err
	}

	sort.Slice(u.dir, func(i, j int) bool {
		return u.dir[i].offset < u.dir[j].offset
	})

	for _, d := range u.dir {
		if d.Name == "" {
			continue
		}
		if !filepath.IsLocal(d.Name) || strings.Contains(d.Name, "\\") {
			return ErrInsecurePath
		}
	}
	return nil
}

func (u *Updater) Append(name string, mode AppendMode) (io.Writer, error) {
	h := &FileHeader{
		Name:   name,
		Method: Deflate,
	}
	return u.AppendHeader(h, mode)
}

func (u *Updater) prepare(fh *FileHeader) error {
	if u.last != nil && !u.last.closed {
		if err := u.last.close(); err != nil {
			return err
		}
		offset, err := u.rw.offset()
		if err != nil {
			return err
		}
		if u.dirOffset < offset {
			u.dirOffset = offset
		}
	}
	if len(u.dir) > 0 && u.dir[len(u.dir)-1].FileHeader == fh {
		return errors.New("archive/zip: invalid duplicate FileHeader")
	}
	return nil
}

func (u *Updater) AppendHeader(fh *FileHeader, mode AppendMode) (io.Writer, error) {
	if err := u.prepare(fh); err != nil {
		return nil, err
	}

	var err error
	var offset int64 = -1
	var existingDirIndex int = -1
	if mode == APPEND_MODE_OVERWRITE {
		for i, d := range u.dir {
			if d.Name == fh.Name {
				offset = int64(d.offset)
				existingDirIndex = i
				break
			}
		}
	}
	if offset < 0 {
		offset = u.dirOffset
	}
	if existingDirIndex >= 0 {
		if offset, err = u.RemoveFile(existingDirIndex); err != nil {
			return nil, err
		}
		u.dirOffset = offset
	}

	if _, err := u.rw.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	u.offset = offset

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
		offset:     uint64(u.offset),
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
			zipw:      u.rw,
			compCount: &countWriter{w: u.rw},
			crc32:     crc32.NewIEEE(),
			isAES:     fh.Password != "",
		}

		// 1. Write Header FIRST
		if err := writeHeader(u.rw, h); err != nil {
			return nil, err
		}

		// 2. Init AES/Comp AFTER header
		var sink io.Writer = fw.compCount
		if fw.isAES {
			var err error
			fw.aesW, err = newWinZipAesWriter(fw.compCount, fh.Password, fh.AESStrength)
			if err != nil {
				return nil, err
			}
			sink = fw.aesW
		}

		comp := u.compressor(originalMethod)
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
		u.last = fw
	}
	u.dir = append(u.dir, h)
	offset, err = u.rw.offset()
	if err != nil {
		return nil, err
	}
	if u.dirOffset < offset {
		u.dirOffset = offset
	}

	return ow, nil
}

func (u *Updater) RemoveFile(dirIndex int) (int64, error) {
	var start = int64(u.dir[dirIndex].offset)
	var end int64
	if dirIndex == len(u.dir)-1 {
		end = u.dirOffset
	} else {
		end = int64(u.dir[dirIndex+1].offset)
	}
	var size = end - start

	var buffer = make([]byte, bufferSize)
	var rp int64 = end
	var wp int64 = start
	for rp < u.dirOffset-bufferSize {
		n, err := u.rw.ReadAt(buffer, rp)
		if err != nil {
			return 0, fmt.Errorf("zip: rewind data: ReadAt: %w", err)
		}
		_, err = u.rw.WriteAt(buffer[:n], wp)
		if err != nil {
			return 0, fmt.Errorf("zip: rewind data: WriteAt: %w", err)
		}
		rp += int64(n)
		wp += int64(n)
	}
	if rp < u.dirOffset {
		n, err := u.rw.ReadAt(buffer[:u.dirOffset-rp], rp)
		if err != nil {
			return 0, fmt.Errorf("zip: rewind data: ReadAt: %w", err)
		}
		_, err = u.rw.WriteAt(buffer[:n], wp)
		if err != nil {
			return 0, fmt.Errorf("zip: rewind data: ReadAt: %w", err)
		}
		rp += int64(n)
		wp += int64(n)
		if rp != u.dirOffset {
			return 0, errors.New("zip: rewind data: read data before directory failed")
		}
	}
	u.dir = append(u.dir[:dirIndex], u.dir[dirIndex+1:len(u.dir)]...)
	for i := dirIndex; i < len(u.dir); i++ {
		u.dir[i].offset -= uint64(size)
	}
	return wp, nil
}

func (u *Updater) Entries() []*FileHeader {
	res := make([]*FileHeader, len(u.dir))
	for i, h := range u.dir {
		res[i] = h.FileHeader
	}
	return res
}

func (u *Updater) compressor(method uint16) Compressor {
	comp := u.compressors[method]
	if comp == nil {
		comp = compressor(method)
	}
	return comp
}

func (u *Updater) SetComment(comment string) error {
	if len(comment) > uint16max {
		return errors.New("zip: Writer.Comment too long")
	}
	u.comment = comment
	return nil
}

func (u *Updater) GetComment() string {
	return u.comment
}

func (u *Updater) Close() error {
	if u.last != nil && !u.last.closed {
		if err := u.last.close(); err != nil {
			return err
		}
		offset, err := u.rw.offset()
		if err != nil {
			return err
		}
		u.dirOffset = offset
		u.last = nil
	}
	if u.closed {
		return errors.New("zip: updater closed twice")
	}
	u.closed = true

	// Центральный каталог должен начинаться сразу после последнего файла
	start := u.dirOffset
	if u.last != nil {
		// Если мы что-то писали, актуальный конец данных в u.dirOffset
	}

	if _, err := u.rw.Seek(start, io.SeekStart); err != nil {
		return err
	}

	if err := u.writeDirectory(start); err != nil {
		return fmt.Errorf("zip: write directory: %w", err)
	}

	// Физически обрезаем файл до текущей позиции (конца EOCD)
	if t, ok := u.rws.(interface{ Truncate(int64) error }); ok {
		curr, _ := u.rw.offset()
		return t.Truncate(curr)
	}

	return nil
}

func (u *Updater) writeDirectory(start int64) error {
	for _, h := range u.dir {
		var buf []byte = make([]byte, directoryHeaderLen)
		b := writeBuf(buf)
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
			eb.uint64(uint64(h.offset))
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
		if _, err := u.rw.Write(buf); err != nil {
			return err
		}
		if _, err := io.WriteString(u.rw, h.Name); err != nil {
			return err
		}
		if _, err := u.rw.Write(h.Extra); err != nil {
			return err
		}
		if _, err := io.WriteString(u.rw, h.Comment); err != nil {
			return err
		}
	}
	end, err := u.rw.offset()
	if err != nil {
		return err
	}

	records := uint64(len(u.dir))
	size := uint64(end - start)
	offset := uint64(start)

	if records >= uint16max || size >= uint32max || offset >= uint32max {
		var buf [directory64EndLen + directory64LocLen]byte
		b := writeBuf(buf[:])

		b.uint32(directory64EndSignature)
		b.uint64(directory64EndLen - 12)
		b.uint16(zipVersion45)
		b.uint16(zipVersion45)
		b.uint32(0)
		b.uint32(0)
		b.uint64(records)
		b.uint64(records)
		b.uint64(size)
		b.uint64(offset)

		b.uint32(directory64LocSignature)
		b.uint32(0)
		b.uint64(uint64(end))
		b.uint32(1)

		if _, err := u.rw.Write(buf[:]); err != nil {
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
	b.uint16(uint16(len(u.comment)))
	if _, err := u.rw.Write(buf[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(u.rw, u.comment); err != nil {
		return err
	}
	return nil
}