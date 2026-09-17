package zip

import (
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

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

func (s *sectionReaderWriter) ReadAt(p []byte, offset int64) (n int, err error) {
	currOffset, err := s.rws.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	defer func() {
		// The updater keeps writing at wherever the handle was left,
		// so a restore that did not happen sends the next write to the
		// offset this call read from instead.
		if _, serr := s.rws.Seek(currOffset, io.SeekStart); serr != nil && err == nil {
			err = serr
		}
	}()
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
	defer func() {
		// As in ReadAt: everything after this call writes at the
		// position the handle is left at.
		if _, serr := s.rws.Seek(currOffset, io.SeekStart); serr != nil && err == nil {
			err = serr
		}
	}()
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
//
// WARNING: In-place updates modify the underlying file directly. If the process
// crashes, is killed, or encounters a power failure during an operation
// (especially APPEND_MODE_OVERWRITE or RemoveFile), the archive may be left in
// a corrupted and unrecoverable state. For mission-critical data, it is
// recommended to backup the archive before updating.
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

var ErrArchiveLocked = errors.New("zip: cannot modify archive, it is locked")

// NewUpdater returns a new Updater from [io.ReadWriteSeeker], which is
// assumed to have the given size in bytes.
func NewUpdater(rws io.ReadWriteSeeker) (*Updater, error) {
	size, err := rws.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, err
	}
	// Everything below measures against this: the offsets the central
	// directory gives are checked against it, and a buffer for the end
	// record is made from it.
	if size < 0 {
		return nil, errors.New("zip: size cannot be negative")
	}
	zu := &Updater{
		rw:  newSectionReaderWriter(rws),
		rws: rws,
	}
	if err = zu.init(size); err != nil && err != ErrInsecurePath {
		return nil, err
	}
	if strings.Contains(zu.comment, "[F4LOCKED]") {
		return nil, ErrArchiveLocked
	}

	// Prevent accidental corruption of F4Crypt encapsulated ZIP archives
	if size >= 24 {
		var footer [8]byte
		if _, err := zu.rw.ReadAt(footer[:], size-8); err == nil {
			if string(footer[:]) == "F4IDX\x00\x00\x00" {
				return nil, errors.New("zip: in-place updating of F4Crypt encapsulated archives is not supported")
			}
		}
	}

	return zu, nil
}

func (u *Updater) init(size int64) error {
	end, baseOffset, err := readDirectoryEnd(u.rw, size)
	if err != nil {
		return err
	}
	if end.encrypted {
		return errors.New("zip: updating archives with encrypted central directory is not supported")
	}
	u.baseOffset = baseOffset
	// #nosec G115 -- readDirectoryEnd rejects a directory offset above MaxInt64 and checks that baseOffset plus this one lands inside the archive
	u.dirOffset = int64(end.directoryOffset) + baseOffset
	// #nosec G115 -- NewUpdater refuses a negative size, so this is the length of the archive
	if end.directorySize < uint64(size) && (uint64(size)-end.directorySize)/30 >= end.directoryRecords {
		u.dir = make([]*header, 0, end.directoryRecords)
	}
	u.comment = end.comment
	if _, err = u.rw.Seek(u.dirOffset, io.SeekStart); err != nil {
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
		// RemoveFile shifts the bytes between two entries down and
		// writes them at the offset the central directory gave for the
		// first of them, and AppendHeader overwrites an entry in place
		// at that same offset. An entry that claims to start after the
		// central directory, or before the archive, would send those
		// writes somewhere in the middle of the file the user handed
		// over -- so the offsets are checked once here rather than at
		// each of the writes.
		if f.headerOffset < 0 || f.headerOffset > u.dirOffset {
			return fmt.Errorf("zip: entry %q has its local header at %d, outside the %d bytes before the central directory: %w",
				f.Name, f.headerOffset, u.dirOffset, ErrFormat)
		}
		h := &header{
			FileHeader: &f.FileHeader,
			// #nosec G115 -- the check above holds headerOffset to 0 <= offset <= dirOffset
			offset: uint64(f.headerOffset),
		}
		u.dir = append(u.dir, h)
	}
	// The end record counts its entries in two bytes, so only the low
	// sixteen bits of what was read can be compared with it.
	// #nosec G115 -- see above: both sides are deliberately taken modulo 2^16
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
	if err := validateName(fh.Name); err != nil {
		return nil, err
	}
	// As in Writer.CreateHeader: the records this appends to the entry go
	// behind the caller's bytes, and a reader stops at the first one it
	// cannot walk past.
	if err := validateExtra(fh.Extra); err != nil {
		return nil, err
	}

	var err error
	var offset int64 = -1
	var existingDirIndex = -1
	if mode == APPEND_MODE_OVERWRITE {
		for i, d := range u.dir {
			if d.Name == fh.Name {
				// #nosec G115 -- init holds every entry offset to 0 <= offset <= dirOffset
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
		// #nosec G115 -- u.offset is either an entry offset init checked or dirOffset, both of which are inside the archive
		offset: uint64(u.offset),
	}
	isDir := strings.HasSuffix(fh.Name, "/")
	if isDir {
		fh.Method = Store
		fh.Flags &^= 0x8

		fh.CompressedSize = 0
		fh.CompressedSize64 = 0
		fh.UncompressedSize = 0
		fh.UncompressedSize64 = 0
	} else {
		fh.Flags |= 0x8
	}

	// Every entry gets its local header, a directory as much as a file:
	// the record the central directory keeps for the entry says where that
	// header is, and a directory appended without one pointed at whatever
	// was appended after it, or at the central directory itself. 7-Zip
	// reads the local header there, finds another entry or none, and
	// reports a header error for the directory -- the defect
	// Writer.CreateHeader had and unxed/zipper#16 reported.
	if err := writeHeader(u.rw, h); err != nil {
		return nil, err
	}

	if isDir {
		ow = dirWriter{}
	} else {
		fw = &fileWriter{
			zipw:      u.rw,
			compCount: &countWriter{w: u.rw},
			crc32:     crc32.NewIEEE(),
			isAES:     fh.Password != "",
		}

		// 2. Init AES/Comp AFTER header
		var sink io.Writer = fw.compCount
		if fw.isAES {
			var err error
			fw.aesW, err = newWinZipAesWriter(fw.compCount, fh.Password, fh.AESStrength, true)
			if err != nil {
				return nil, err
			}
			sink = fw.aesW
		}

		comp := u.compressor(originalMethod)
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
	// #nosec G115 -- init holds every entry offset to 0 <= offset <= dirOffset
	var start = int64(u.dir[dirIndex].offset)
	var end int64
	if dirIndex == len(u.dir)-1 {
		end = u.dirOffset
	} else {
		// #nosec G115 -- init holds every entry offset to 0 <= offset <= dirOffset
		end = int64(u.dir[dirIndex+1].offset)
	}
	var size = end - start

	const chunkBufSize = 2 * 1024 * 1024 // 2MB для быстрого сдвига
	var buffer = make([]byte, chunkBufSize)
	var rp = end
	var wp = start
	for rp < u.dirOffset-chunkBufSize {
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
			return 0, fmt.Errorf("zip: rewind data: WriteAt: %w", err)
		}
		rp += int64(n)
		wp += int64(n)
		if rp != u.dirOffset {
			return 0, errors.New("zip: rewind data: read data before directory failed")
		}
	}
	u.dir = append(u.dir[:dirIndex], u.dir[dirIndex+1:len(u.dir)]...)
	for i := dirIndex; i < len(u.dir); i++ {
		// #nosec G115 -- u.dir is sorted by offset and every offset is at most dirOffset, so end is never before start
		u.dir[i].offset -= uint64(size)
	}

	// The data now ends at wp, and everything from there to where the
	// directory begins is what the entry left behind: the shift copied what
	// followed it down over its front and nothing has moved the end of the
	// data back, so the last entry of an archive survives there verbatim.
	//
	// Where the file can be shortened, moving the end of the data back is
	// the whole answer: Close writes the directory over the leftovers and
	// cuts the file off after it. Where it cannot, the directory has to stay
	// where it was -- a reader looks for the end record backwards from the
	// end of the file and would not find one written a whole entry earlier
	// -- so what the entry left is written over with zeros instead.
	if u.truncator() != nil {
		u.dirOffset = wp
	} else if err := u.zeroFill(wp, u.dirOffset); err != nil {
		return 0, err
	}
	return wp, nil
}

// truncator is the handle's Truncate, when it has one. An io.ReadWriteSeeker
// is not obliged to: an in-memory buffer has no way to give bytes back.
func (u *Updater) truncator() interface{ Truncate(int64) error } {
	t, ok := u.rws.(interface{ Truncate(int64) error })
	if !ok {
		return nil
	}
	return t
}

// zeroes reads as an endless run of zero bytes.
type zeroes struct{}

func (zeroes) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// zeroFill writes zeros over the archive from one offset up to another. It is
// how bytes that cannot be cut off the end of the file are unmade.
func (u *Updater) zeroFill(from, to int64) error {
	if to <= from {
		return nil
	}
	if _, err := u.rw.Seek(from, io.SeekStart); err != nil {
		return err
	}
	_, err := io.CopyN(u.rw, zeroes{}, to-from)
	return err
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

	// The central directory starts where the data ends. dirOffset is
	// already that place whichever way the last entry was finished:
	// prepare moves it past an entry when the next one starts, and the
	// block below moves it past the last one when the updater is closed.
	start := u.dirOffset

	// Physically truncate the file to the current position (end of EOCD)
	if t := u.truncator(); t != nil {
		if _, err := u.rw.Seek(start, io.SeekStart); err != nil {
			return err
		}
		curr, err := u.writeDirectory(u.rw, start)
		if err != nil {
			return fmt.Errorf("zip: write directory: %w", err)
		}
		return t.Truncate(curr)
	}

	// Nothing here can shorten the file, so the end record is put where the
	// file already ends rather than where the data now stops. A reader looks
	// for it backwards from the end of the file over a window of some tens
	// of kilobytes, and a removed entry's directory record can be larger
	// than that window all by itself -- a name, an extra field and a comment
	// of 64 KiB each are all the format allows -- so a directory written
	// straight after the data can leave more behind it than a reader will
	// ever look past. Anchored to the end there is nothing behind it at all,
	// and the gap in front of it, which the format allows, is written over
	// with zeros so that nothing of the removed entry survives in it.
	end, err := u.rws.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	// Rendered once to measure and once at the place that measurement
	// chooses. The two lengths differ only for an archive whose directory
	// sits within one entry's record of the four gigabyte line, where the
	// zip64 end record appears or disappears; the zero fill at the end
	// covers what is left over then.
	var measure bytes.Buffer
	measured, err := u.writeDirectory(&measure, start)
	if err != nil {
		return fmt.Errorf("zip: write directory: %w", err)
	}
	anchor := max(start, end-(measured-start))

	if err := u.zeroFill(start, anchor); err != nil {
		return err
	}
	if _, err := u.rw.Seek(anchor, io.SeekStart); err != nil {
		return err
	}
	curr, err := u.writeDirectory(u.rw, anchor)
	if err != nil {
		return fmt.Errorf("zip: write directory: %w", err)
	}
	return u.zeroFill(curr, end)
}

// writeDirectory renders the central directory and the end record to w as
// though they began at start, and answers the offset they end at. It writes
// through a counter rather than asking the handle where it is, so that the
// same rendering can go to a buffer, which is how Close learns how long the
// directory is before deciding where to put it.
func (u *Updater) writeDirectory(w io.Writer, start int64) (int64, error) {
	cw := &countWriter{w: w, count: start}
	for _, h := range u.dir {
		var buf = make([]byte, directoryHeaderLen)
		b := writeBuf(buf)
		b.uint32(uint32(directoryHeaderSignature))
		b.uint16(h.CreatorVersion)
		b.uint16(h.ReaderVersion)
		b.uint16(h.Flags)
		b.uint16(h.Method)
		b.uint16(h.ModifiedTime)
		b.uint16(h.ModifiedDate)
		b.uint32(h.CRC32)
		// The zip64 record goes in a copy of the entry's extra field
		// rather than on the entry itself: this rendering may run more
		// than once, and appending to the header each time would give
		// the entry one record more every time it ran.
		extra := h.Extra
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
			extra = append(append([]byte(nil), h.Extra...), buf[:]...)
		} else {
			b.uint32(h.CompressedSize)
			b.uint32(h.UncompressedSize)
		}

		nameLen, err := fitUint16(len(h.Name), "file name")
		if err != nil {
			return 0, err
		}
		extraLen, err := fitUint16(len(extra), "extra field")
		if err != nil {
			return 0, err
		}
		commentLen, err := fitUint16(len(h.Comment), "file comment")
		if err != nil {
			return 0, err
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
		if _, err := cw.Write(buf); err != nil {
			return 0, err
		}
		if _, err := io.WriteString(cw, h.Name); err != nil {
			return 0, err
		}
		if _, err := cw.Write(extra); err != nil {
			return 0, err
		}
		if _, err := io.WriteString(cw, h.Comment); err != nil {
			return 0, err
		}
	}
	end := cw.count

	records := uint64(len(u.dir))
	// #nosec G115 -- end is where writing the directory left off and start is where it began, so the difference is not negative
	size := uint64(end - start)
	// #nosec G115 -- start is dirOffset, which init holds inside the archive
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
		// #nosec G115 -- end is the offset writing the directory reached and is not negative
		b.uint64(uint64(end))
		b.uint32(1)

		if _, err := cw.Write(buf[:]); err != nil {
			return 0, err
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
	// #nosec G115 -- SetComment refuses a comment over uint16max, and one read from an archive came out of a two-byte length
	b.uint16(uint16(len(u.comment)))
	if _, err := cw.Write(buf[:]); err != nil {
		return 0, err
	}
	if _, err := io.WriteString(cw, u.comment); err != nil {
		return 0, err
	}
	return cw.count, nil
}
