package zip

import (
	"bytes"
	"encoding/binary"
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
			zip64:  f.zip64,
		}
		// Whatever this entry's extra field holds is written back out
		// verbatim, and behind it goes the zip64 record the directory
		// needs. A reader walks the area from the front and stops at
		// the first record it cannot walk past, so a record put behind
		// an area that does not walk is a record no reader reaches --
		// and the sentinels in the size fields that point at it then
		// point at nothing. An entry that needs no record of ours is
		// left alone: it comes back out exactly as it went in, and it
		// reads afterwards exactly as it read before.
		if h.needsZip64() {
			if err := validateExtra(h.Extra); err != nil {
				return fmt.Errorf("zip: entry %q needs a zip64 record and its extra field cannot be walked to the end: %w", f.Name, err)
			}
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

// entryExtent answers the offset one past the last byte the entry occupies:
// its local header, whose name and extra field are read from the header itself
// because the central directory's may differ from it, its compressed data, the
// data descriptor behind them when the entry has one, and its seek index when
// it has one of those.
//
// A descriptor is allowed to carry the 0x08074b50 signature or to begin
// straight away with the CRC, and readDataDescriptor tolerates both, so the
// four bytes at the end of the data decide which of the two lengths this is. A
// CRC that happens to equal the signature would make the answer four bytes too
// long, and four bytes too long can only reach into what lies between two
// entries: the caller weighs every extent against its neighbour before cutting
// anything, and a reach into a neighbour is refused rather than cut.
//
// Every step is held inside the archive's data as it is taken. What is over
// the line is the central directory, which nothing here may reach: an entry
// whose numbers say otherwise is describing bytes it does not own.
func (u *Updater) entryExtent(h *header) (int64, error) {
	// #nosec G115 -- init holds every entry offset to 0 <= offset <= dirOffset
	start := int64(h.offset)
	var lh [fileHeaderLen]byte
	if err := readFullAt(u.rw, lh[:], start); err != nil {
		return 0, fmt.Errorf("zip: entry %q has no readable local header at %d: %w", h.Name, start, entryReadError(err))
	}
	if binary.LittleEndian.Uint32(lh[0:4]) != fileHeaderSignature {
		return 0, fmt.Errorf("zip: entry %q has no local header at %d: %w", h.Name, start, ErrFormat)
	}
	// A name and an extra field are two bytes of length each, so a header
	// is at most a hundred and thirty odd kilobytes and start is inside the
	// archive: neither the sum nor the difference below can overflow, and a
	// difference that has gone negative is a header already over the line,
	// which the comparison then refuses for any size at all.
	body := int64(fileHeaderLen) +
		int64(binary.LittleEndian.Uint16(lh[26:28])) +
		int64(binary.LittleEndian.Uint16(lh[28:30]))
	// #nosec G115 -- readDirectoryHeader refuses an entry whose compressed size is above MaxInt64, so this is exact
	if int64(h.CompressedSize64) > u.dirOffset-start-body {
		return 0, fmt.Errorf("zip: entry %q at %d has a %d byte header and %d compressed bytes, and %d remain before the central directory: %w",
			h.Name, start, body, h.CompressedSize64, u.dirOffset-start, ErrFormat)
	}
	// #nosec G115 -- as above
	end := start + body + int64(h.CompressedSize64)

	if h.hasDataDescriptor() {
		ddLen := int64(dataDescriptorLen)
		if h.zip64 {
			ddLen = dataDescriptor64Len
		}
		var sig [4]byte
		if err := readFullAt(u.rw, sig[:], end); err != nil {
			return 0, fmt.Errorf("zip: entry %q has no readable data descriptor at %d: %w", h.Name, end, entryReadError(err))
		}
		if binary.LittleEndian.Uint32(sig[:]) != dataDescriptorSignature {
			ddLen -= 4
		}
		if ddLen > u.dirOffset-end {
			return 0, fmt.Errorf("zip: entry %q has a data descriptor at %d reaching past the central directory at %d: %w",
				h.Name, end, u.dirOffset, ErrFormat)
		}
		end += ddLen
	}

	// The entry's own seek index is part of the entry. This package writes
	// it as a local entry directly behind the data descriptor, no central
	// record names it, and findHiddenIndex looks for it exactly there --
	// so a removal that left it behind would leave the removed entry's
	// chunk offsets in an archive that says the entry is gone. What is
	// recognised is this entry's index and nothing weaker: a stray local
	// entry another tool left between two entries reads the same way from
	// outside, and bytes this package did not write are not its to cut.
	//
	// An offset the directory itself claims is the next entry rather than
	// an index, whatever it is named: an archive may hold a listed entry
	// called ".a.txt.sozip.idx" behind "a.txt", and taking that for a's
	// index would swallow an entry the caller is keeping.
	if claimed(u.dir, end) {
		return end, nil
	}
	idx, ok, err := findHiddenIndexAt(u.rw, end, h.Name)
	if err != nil {
		return 0, fmt.Errorf("zip: entry %q has an unreadable seek index at %d: %w", h.Name, end, entryReadError(err))
	}
	if !ok {
		return end, nil
	}
	if idx.dataSize > u.dirOffset-idx.dataOffset {
		return 0, fmt.Errorf("zip: entry %q has a seek index at %d reaching past the central directory at %d: %w",
			h.Name, end, u.dirOffset, ErrFormat)
	}
	return idx.dataOffset + idx.dataSize, nil
}

// claimed says whether the directory gives some entry's local header as
// beginning at offset. The directory is sorted by offset, which is what lets
// this be asked once per entry without the asking costing more than the walk
// it is part of.
func claimed(dir []*header, offset int64) bool {
	// #nosec G115 -- init holds every entry offset to 0 <= offset <= dirOffset
	i := sort.Search(len(dir), func(i int) bool { return int64(dir[i].offset) >= offset })
	// #nosec G115 -- as above
	return i < len(dir) && int64(dir[i].offset) == offset
}

// entryReadError says how a failed read of the archive's own bytes is
// reported. An archive that stops in the middle of a header it said was there
// is a malformed one, so that is what the caller is told, with what the read
// gave out kept behind it; anything else is the handle failing rather than the
// archive, and belongs to the caller unchanged.
func entryReadError(err error) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return fmt.Errorf("%w: %w", ErrFormat, err)
	}
	return err
}

// extents answers where every entry ends, and refuses an archive in which the
// entries run into one another. The directory is sorted by offset, so entries
// that do not reach their successor do not reach anything beyond it either,
// and one pass over the neighbours settles the whole file.
//
// The invariant is what makes a cut safe, and it is the whole file's rather
// than the removed entry's: the shift that follows a removal moves everything
// from the entry's end down to the central directory, so an entry anywhere
// before it whose data ran into its neighbour is written over just as surely.
func (u *Updater) extents() ([]int64, error) {
	ends := make([]int64, len(u.dir))
	for i, h := range u.dir {
		end, err := u.entryExtent(h)
		if err != nil {
			return nil, err
		}
		ends[i] = end
	}
	for i := 0; i+1 < len(u.dir); i++ {
		// #nosec G115 -- init holds every entry offset to 0 <= offset <= dirOffset
		if next := int64(u.dir[i+1].offset); ends[i] > next {
			return nil, fmt.Errorf("zip: entry %q ends at %d and entry %q begins at %d: %w",
				u.dir[i].Name, ends[i], u.dir[i+1].Name, next, ErrFormat)
		}
	}
	return ends, nil
}

func (u *Updater) RemoveFile(dirIndex int) (int64, error) {
	// What disappears is what the entry occupies, worked out from its own
	// header rather than from where the entry after it begins: a central
	// directory may name entries whose regions overlap, and cutting up to
	// the next offset then takes a neighbour's bytes with it. Padding
	// between two entries is not the entry's and stays where it is, moving
	// down with everything else.
	ends, err := u.extents()
	if err != nil {
		return 0, err
	}
	// #nosec G115 -- init holds every entry offset to 0 <= offset <= dirOffset
	var start = int64(u.dir[dirIndex].offset)
	var end = ends[dirIndex]
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

// stripZip64Extra answers a copy of an extra field area with every zip64
// record taken out of it. The records an entry arrives with were written for
// the layout the archive had; the one the directory below writes is for the
// layout it is being given, and a reader takes its fields from the first
// record it meets, so only one of them may be there.
//
// The area is walked exactly as readDirectoryHeader walks it, so what is
// dropped is what a reader would have found and no more. A record that stops
// the walk keeps everything from itself onward: those bytes are the entry's,
// not this package's to decide about.
func stripZip64Extra(extra []byte) []byte {
	out := make([]byte, 0, len(extra))
	i := 0
	for i+4 <= len(extra) {
		size := int(binary.LittleEndian.Uint16(extra[i+2 : i+4]))
		if i+4+size > len(extra) {
			break
		}
		if binary.LittleEndian.Uint16(extra[i:i+2]) != zip64ExtraID {
			out = append(out, extra[i:i+4+size]...)
		}
		i += 4 + size
	}
	return append(out, extra[i:]...)
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
		//
		// The record the entry arrived with is dropped first, always.
		// A reader takes the fields from the first zip64 record it
		// meets, so a second one behind it is never read: the entry
		// would keep the sizes and the local header offset the archive
		// had before this rewrite, and a removal has moved that offset.
		extra := stripZip64Extra(h.Extra)
		if h.needsZip64() {
			b.uint32(uint32max)
			b.uint32(uint32max)

			var buf [28]byte
			eb := writeBuf(buf[:])
			eb.uint16(zip64ExtraID)
			eb.uint16(24)
			eb.uint64(h.UncompressedSize64)
			eb.uint64(h.CompressedSize64)
			eb.uint64(uint64(h.offset))
			extra = append(extra, buf[:]...)
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
