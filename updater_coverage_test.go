package zip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

// errUpdaterCovFail is the failure a handle reports when a test has told it to
// stop cooperating.
var errUpdaterCovFail = errors.New("the handle refused")

// UpdaterCovFile is an archive held in memory behind a handle a test can make
// fail: an updater writes back into whatever it was handed, so the states the
// updater has to survive are the states of that handle.
type UpdaterCovFile struct {
	data []byte
	off  int64

	// readErr, once set, is what every Read reports.
	readErr error
	// readFailOver and readFailUnder, when positive, hold readErr to reads
	// of more, and of fewer, bytes than they name. The updater reads a
	// whole buffer at a time to move the archive down, a local header at a
	// time to work out what an entry occupies, and four bytes to see
	// whether a data descriptor carries its signature, so a threshold at
	// the length of a local header tells the three apart.
	readFailOver  int
	readFailUnder int
	// writeErr, once set, is what every Write reports.
	writeErr error
	// shortRead, when positive, caps how much a single Read hands back.
	shortRead int
	// writeFailAt, when positive, is the number of the Write that fails.
	writeFailAt int
	writes      int
	// seekCurErr, once set, is what a "where am I" seek reports.
	seekCurErr error
	// seekStartErr, once set, is what a seek to seekStartAt reports.
	seekStartErr error
	seekStartAt  int64
	// seekEndFailAt, when positive, is the number of the "how long is it"
	// seek that fails; seekEnds counts them.
	seekEndFailAt int
	seekEnds      int
}

func (f *UpdaterCovFile) Read(p []byte) (int, error) {
	if f.readErr != nil && (f.readFailOver == 0 || len(p) > f.readFailOver) &&
		(f.readFailUnder == 0 || len(p) < f.readFailUnder) {
		return 0, f.readErr
	}
	if f.off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	if f.shortRead > 0 && len(p) > f.shortRead {
		p = p[:f.shortRead]
	}
	n := copy(p, f.data[f.off:])
	f.off += int64(n)
	return n, nil
}

func (f *UpdaterCovFile) Write(p []byte) (int, error) {
	f.writes++
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.writeFailAt > 0 && f.writes == f.writeFailAt {
		return 0, errUpdaterCovFail
	}
	if need := f.off + int64(len(p)); need > int64(len(f.data)) {
		if need > int64(cap(f.data)) {
			grown := make([]byte, need, 2*need)
			copy(grown, f.data)
			f.data = grown
		}
		f.data = f.data[:need]
	}
	n := copy(f.data[f.off:], p)
	f.off += int64(n)
	return n, nil
}

func (f *UpdaterCovFile) Seek(offset int64, whence int) (int64, error) {
	if whence == io.SeekEnd {
		f.seekEnds++
		if f.seekEndFailAt > 0 && f.seekEnds == f.seekEndFailAt {
			return 0, errUpdaterCovFail
		}
	}
	if whence == io.SeekCurrent && f.seekCurErr != nil {
		return 0, f.seekCurErr
	}
	if whence == io.SeekStart && f.seekStartErr != nil && offset == f.seekStartAt {
		return 0, f.seekStartErr
	}
	switch whence {
	case io.SeekStart:
		f.off = offset
	case io.SeekCurrent:
		f.off += offset
	case io.SeekEnd:
		f.off = int64(len(f.data)) + offset
	default:
		return 0, errors.New("bad whence")
	}
	if f.off < 0 {
		return 0, errors.New("negative position")
	}
	return f.off, nil
}

func (f *UpdaterCovFile) Truncate(size int64) error {
	if size < int64(len(f.data)) {
		f.data = f.data[:size]
	}
	return nil
}

// UpdaterCovPlainFile is the same handle without a Truncate method, which is
// all an [io.ReadWriteSeeker] is obliged to be.
type UpdaterCovPlainFile struct{ file *UpdaterCovFile }

func (f *UpdaterCovPlainFile) Read(p []byte) (int, error)  { return f.file.Read(p) }
func (f *UpdaterCovPlainFile) Write(p []byte) (int, error) { return f.file.Write(p) }
func (f *UpdaterCovPlainFile) Seek(offset int64, whence int) (int64, error) {
	return f.file.Seek(offset, whence)
}

// UpdaterCovEntry describes one entry of a fixture archive.
type UpdaterCovEntry struct {
	Name string
	Data []byte
}

// UpdaterCovArchive returns an archive holding the given entries, each stored
// uncompressed so that its size on disk is the size of its contents.
func UpdaterCovArchive(t *testing.T, entries ...UpdaterCovEntry) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&FileHeader{Name: e.Name, Method: Store})
		if err != nil {
			t.Fatalf("creating %q: %v", e.Name, err)
		}
		mustWrite(t, w, e.Data)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	return buf.Bytes()
}

// UpdaterCovOpen puts raw behind a handle a test can break and opens an
// updater on it.
func UpdaterCovOpen(t *testing.T, raw []byte) (*Updater, *UpdaterCovFile) {
	t.Helper()
	mem := &UpdaterCovFile{data: append([]byte(nil), raw...)}
	u, err := NewUpdater(mem)
	if err != nil {
		t.Fatalf("opening the updater: %v", err)
	}
	return u, mem
}

// UpdaterCovNames returns the names the archive lists, in order.
func UpdaterCovNames(t *testing.T, raw []byte) []string {
	t.Helper()
	r, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	names := make([]string, 0, len(r.File))
	for _, f := range r.File {
		names = append(names, f.Name)
	}
	return names
}

// UpdaterCovContents returns the contents of the named entry.
func UpdaterCovContents(t *testing.T, raw []byte, name string) []byte {
	t.Helper()
	r, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	for _, f := range r.File {
		if f.Name != name {
			continue
		}
		rc, oerr := f.Open()
		if oerr != nil {
			t.Fatalf("opening %q: %v", name, oerr)
		}
		data, rerr := io.ReadAll(rc)
		_ = rc.Close()
		if rerr != nil {
			t.Fatalf("reading %q: %v", name, rerr)
		}
		return data
	}
	t.Fatalf("the archive has no entry named %q", name)
	return nil
}

func TestUpdaterCovSectionReaderWriterCannotFindItsPosition(t *testing.T) {
	// Reading or writing at an offset means moving the handle and putting
	// it back, so the position it is at is read first. A handle that
	// cannot say where it is can do neither: moving it anyway would leave
	// every later read and write of the updater at an offset of this
	// call's choosing.
	f := &UpdaterCovFile{data: []byte("0123456789"), seekCurErr: errUpdaterCovFail}
	s := newSectionReaderWriter(f)

	if _, err := s.ReadAt(make([]byte, 2), 0); !errors.Is(err, errUpdaterCovFail) {
		t.Errorf("ReadAt gave %v, want the failure of the handle", err)
	}
	if _, err := s.WriteAt([]byte("ab"), 0); !errors.Is(err, errUpdaterCovFail) {
		t.Errorf("WriteAt gave %v, want the failure of the handle", err)
	}
	if string(f.data) != "0123456789" {
		t.Errorf("the file was changed to %q by a write that reported an error", f.data)
	}
}

func TestUpdaterCovSectionReaderWriterCannotReachTheOffset(t *testing.T) {
	// The handle knows where it is but will not go where it was asked.
	// Nothing may then be read or written, because both would land at the
	// position the handle happens to be at instead.
	f := &UpdaterCovFile{
		data:         []byte("0123456789"),
		seekStartErr: errUpdaterCovFail,
		seekStartAt:  3,
	}
	s := newSectionReaderWriter(f)

	buf := make([]byte, 2)
	if n, err := s.ReadAt(buf, 3); !errors.Is(err, errUpdaterCovFail) || n != 0 {
		t.Errorf("ReadAt gave %d, %v, want 0 and the failure of the handle", n, err)
	}
	if n, err := s.WriteAt([]byte("ab"), 3); !errors.Is(err, errUpdaterCovFail) || n != 0 {
		t.Errorf("WriteAt gave %d, %v, want 0 and the failure of the handle", n, err)
	}
	if string(f.data) != "0123456789" {
		t.Errorf("the file was changed to %q by a write that never reached its offset", f.data)
	}
}

func TestUpdaterCovDirectoryReportsItsHeaderOffset(t *testing.T) {
	// The offset a Directory carries is where its local header begins, and
	// reading it is the only thing the type is for.
	d := Directory{offset: 4096}
	if got := d.HeaderOffset(); got != 4096 {
		t.Errorf("HeaderOffset is %d, want 4096", got)
	}
}

func TestUpdaterCovRefusesALockedArchive(t *testing.T) {
	// A marker in the archive comment says the archive is not to be
	// changed, and an updater is exactly the thing that would change it.
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	if err := zw.SetComment("kept by hand [F4LOCKED] do not touch"); err != nil {
		t.Fatalf("setting the comment: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}

	_, err := NewUpdater(&UpdaterCovFile{data: buf.Bytes()})
	if !errors.Is(err, ErrArchiveLocked) {
		t.Fatalf("a locked archive was opened for update: %v", err)
	}
}

func TestUpdaterCovRefusesAnEncapsulatedArchive(t *testing.T) {
	// An archive wrapped in the F4Crypt container ends with the container's
	// own footer. Rewriting the archive in place would leave the footer
	// describing bytes that have moved, so it is refused outright.
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	if err := zw.SetComment("F4IDX\x00\x00\x00"); err != nil {
		t.Fatalf("setting the comment: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}

	_, err := NewUpdater(&UpdaterCovFile{data: buf.Bytes()})
	if err == nil || !strings.Contains(err.Error(), "F4Crypt") {
		t.Fatalf("an encapsulated archive gave %v, want the refusal naming F4Crypt", err)
	}
}

func TestUpdaterCovReportsAHandleThatWillNotReachTheDirectory(t *testing.T) {
	// The central directory is read from the offset the end record gives,
	// so a handle that will not go there has nothing to list.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	sound, _ := UpdaterCovOpen(t, raw)
	dirOffset := sound.dirOffset

	mem := &UpdaterCovFile{
		data:         append([]byte(nil), raw...),
		seekStartErr: errUpdaterCovFail,
		seekStartAt:  dirOffset,
	}
	if _, err := NewUpdater(mem); !errors.Is(err, errUpdaterCovFail) {
		t.Fatalf("opening gave %v, want the failure of the handle", err)
	}
}

// UpdaterCovDirectoryRunsToTheEnd builds an archive whose single central
// directory entry has a name long enough to swallow the end record, so that
// the entry finishes exactly at the end of the file and the read of the next
// one starts there.
func UpdaterCovDirectoryRunsToTheEnd() []byte {
	const nameLen = directoryEndLen
	raw := make([]byte, directoryHeaderLen+nameLen)

	b := writeBuf(raw)
	b.uint32(uint32(directoryHeaderSignature))
	b.uint16(zipVersion20) // creator version
	b.uint16(zipVersion20) // reader version
	b.uint16(0)            // flags
	b.uint16(Store)        // method
	b.uint16(0)            // modified time
	b.uint16(0)            // modified date
	b.uint32(0)            // crc32
	b.uint32(0)            // compressed size
	b.uint32(0)            // uncompressed size
	b.uint16(nameLen)      // file name length
	b.uint16(0)            // extra field length
	b.uint16(0)            // file comment length
	b.uint16(0)            // disk number
	b.uint16(0)            // internal attributes
	b.uint32(0)            // external attributes
	b.uint32(0)            // offset of the local header

	// The name is the end record, which is what makes the entry reach the
	// end of the file. The directory is said to be the bytes before it.
	e := writeBuf(raw[directoryHeaderLen:])
	e.uint32(uint32(directoryEndSignature))
	e.uint16(0)                  // disk number
	e.uint16(0)                  // disk holding the directory
	e.uint16(1)                  // entries on this disk
	e.uint16(1)                  // entries in total
	e.uint32(directoryHeaderLen) // size of the directory
	e.uint32(0)                  // offset of the directory
	e.uint16(0)                  // comment length

	return raw
}

func TestUpdaterCovReportsAReadThatEndsTheDirectory(t *testing.T) {
	// A directory that runs to the last byte of the file leaves the read of
	// the entry after it with nothing at all, which is neither a malformed
	// entry nor a half-read one: the archive says it has an entry there and
	// the file has ended, so the failure is reported rather than taken for
	// the end of the directory.
	_, err := NewUpdater(&UpdaterCovFile{data: UpdaterCovDirectoryRunsToTheEnd()})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("opening gave %v, want the read failure at the end of the file", err)
	}
}

func TestUpdaterCovSkipsAnEntryWithNoName(t *testing.T) {
	// An entry with no name is not a path, so there is nothing about it to
	// judge; it is left alone rather than condemning the whole archive.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "", Data: []byte("nameless")})

	mem := &UpdaterCovFile{data: raw}
	u := &Updater{rw: newSectionReaderWriter(mem), rws: mem}
	if err := u.init(int64(len(raw))); err != nil {
		t.Fatalf("an entry with no name was refused: %v", err)
	}
	if len(u.dir) != 1 || u.dir[0].Name != "" {
		t.Fatalf("the updater holds %d entries, want the nameless one", len(u.dir))
	}
}

func TestUpdaterCovReportsAnEntryThatEscapesTheArchive(t *testing.T) {
	// An entry named out of the archive is what the caller is warned about
	// before it writes anything anywhere.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "../escapes.txt", Data: []byte("x")})

	mem := &UpdaterCovFile{data: append([]byte(nil), raw...)}
	u := &Updater{rw: newSectionReaderWriter(mem), rws: mem}
	if err := u.init(int64(len(raw))); !errors.Is(err, ErrInsecurePath) {
		t.Fatalf("init gave %v, want ErrInsecurePath", err)
	}

	// The warning does not close the archive: the entries are still
	// listed, so a caller that has looked at them can go on.
	opened, err := NewUpdater(&UpdaterCovFile{data: append([]byte(nil), raw...)})
	if err != nil {
		t.Fatalf("opening an archive with such an entry: %v", err)
	}
	if got := opened.Entries(); len(got) != 1 || got[0].Name != "../escapes.txt" {
		t.Fatalf("the updater holds %d entries", len(got))
	}
}

func TestUpdaterCovReportsAFailureFinishingThePreviousEntry(t *testing.T) {
	// Appending an entry finishes the one before it, and the compressed
	// tail of that one still has to reach the file.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	w, err := u.Append("first.txt", APPEND_MODE_KEEP_ORIGINAL)
	if err != nil {
		t.Fatalf("appending: %v", err)
	}
	mustWrite(t, w, []byte("the tail of this entry is still buffered"))

	mem.writeErr = errUpdaterCovFail
	if _, err := u.Append("second.txt", APPEND_MODE_KEEP_ORIGINAL); !errors.Is(err, errUpdaterCovFail) {
		t.Fatalf("appending gave %v, want the failure of the handle", err)
	}
}

func TestUpdaterCovReportsALostPositionAfterThePreviousEntry(t *testing.T) {
	// Where the finished entry ended is where the next one begins, so a
	// handle that cannot say where it is stops the append.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	w, err := u.Append("first.txt", APPEND_MODE_KEEP_ORIGINAL)
	if err != nil {
		t.Fatalf("appending: %v", err)
	}
	mustWrite(t, w, []byte("some contents"))

	mem.seekCurErr = errUpdaterCovFail
	if _, err := u.Append("second.txt", APPEND_MODE_KEEP_ORIGINAL); !errors.Is(err, errUpdaterCovFail) {
		t.Fatalf("appending gave %v, want the failure of the handle", err)
	}
}

func TestUpdaterCovReportsAFailedShiftWhenOverwriting(t *testing.T) {
	// Overwriting an entry removes the old one, which shifts everything
	// after it down. The bytes are read and written back one buffer at a
	// time, and a failure of either has to stop the append: the archive is
	// being rewritten under the caller.
	raw := UpdaterCovArchive(t,
		UpdaterCovEntry{Name: "first.txt", Data: []byte("replace me")},
		UpdaterCovEntry{Name: "second.txt", Data: []byte("this entry has to move down")},
	)

	t.Run("read", func(t *testing.T) {
		u, mem := UpdaterCovOpen(t, raw)
		mem.readErr = errUpdaterCovFail
		mem.readFailOver = fileHeaderLen
		_, err := u.Append("first.txt", APPEND_MODE_OVERWRITE)
		if !errors.Is(err, errUpdaterCovFail) {
			t.Fatalf("appending gave %v, want the failure of the handle", err)
		}
		if !strings.Contains(err.Error(), "rewind data") {
			t.Errorf("error %q does not say the shift was what failed", err)
		}
	})

	t.Run("write", func(t *testing.T) {
		u, mem := UpdaterCovOpen(t, raw)
		mem.writeErr = errUpdaterCovFail
		_, err := u.Append("first.txt", APPEND_MODE_OVERWRITE)
		if !errors.Is(err, errUpdaterCovFail) {
			t.Fatalf("appending gave %v, want the failure of the handle", err)
		}
		if !strings.Contains(err.Error(), "rewind data") {
			t.Errorf("error %q does not say the shift was what failed", err)
		}
	})

	t.Run("short read", func(t *testing.T) {
		// A handle that hands back less than it was asked for without
		// saying anything is wrong would leave the tail of the archive
		// where it was, with the directory then pointing into a gap.
		u, mem := UpdaterCovOpen(t, raw)
		mem.shortRead = 4
		_, err := u.Append("first.txt", APPEND_MODE_OVERWRITE)
		if err == nil {
			t.Fatal("a short read during the shift was accepted")
		}
		if !strings.Contains(err.Error(), "rewind data") {
			t.Errorf("error %q does not say the shift was what failed", err)
		}
	})
}

func TestUpdaterCovShiftsMoreThanOneBufferOfData(t *testing.T) {
	// The shift moves the archive down one buffer at a time, so an archive
	// with more than a buffer of data after the removed entry is what takes
	// the loop round more than once. A failure of either half of a round
	// has to stop the append: the archive is being rewritten under the
	// caller.
	const payload = 2<<20 + 1<<16
	raw := UpdaterCovArchive(t,
		UpdaterCovEntry{Name: "first.txt", Data: []byte("replace me")},
		UpdaterCovEntry{Name: "second.bin", Data: bytes.Repeat([]byte("abcdefgh"), payload/8)},
	)

	t.Run("the whole tail moves down", func(t *testing.T) {
		u, mem := UpdaterCovOpen(t, raw)
		w, err := u.Append("first.txt", APPEND_MODE_OVERWRITE)
		if err != nil {
			t.Fatalf("appending: %v", err)
		}
		mustWrite(t, w, []byte("replaced"))
		if err := u.Close(); err != nil {
			t.Fatalf("closing the updater: %v", err)
		}

		if got := UpdaterCovNames(t, mem.data); len(got) != 2 {
			t.Fatalf("the updated archive lists %v", got)
		}
		if got := UpdaterCovContents(t, mem.data, "first.txt"); string(got) != "replaced" {
			t.Errorf("the replaced entry holds %q", got)
		}
		moved := UpdaterCovContents(t, mem.data, "second.bin")
		if len(moved) != payload || !bytes.Equal(moved[:8], []byte("abcdefgh")) {
			t.Errorf("the entry that was shifted down holds %d bytes", len(moved))
		}
	})

	t.Run("read", func(t *testing.T) {
		u, mem := UpdaterCovOpen(t, raw)
		mem.readErr = errUpdaterCovFail
		mem.readFailOver = fileHeaderLen
		_, err := u.Append("first.txt", APPEND_MODE_OVERWRITE)
		if !errors.Is(err, errUpdaterCovFail) {
			t.Fatalf("appending gave %v, want the failure of the handle", err)
		}
		if !strings.Contains(err.Error(), "rewind data") {
			t.Errorf("error %q does not say the shift was what failed", err)
		}
	})

	t.Run("write", func(t *testing.T) {
		u, mem := UpdaterCovOpen(t, raw)
		mem.writeErr = errUpdaterCovFail
		_, err := u.Append("first.txt", APPEND_MODE_OVERWRITE)
		if !errors.Is(err, errUpdaterCovFail) {
			t.Fatalf("appending gave %v, want the failure of the handle", err)
		}
		if !strings.Contains(err.Error(), "rewind data") {
			t.Errorf("error %q does not say the shift was what failed", err)
		}
	})
}

func TestUpdaterCovReportsAHandleThatWillNotReachTheNewEntry(t *testing.T) {
	// The new entry is written where the data of the archive ends, and a
	// handle that will not go there would write it over whatever it is
	// sitting on.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	mem.seekStartErr = errUpdaterCovFail
	mem.seekStartAt = u.dirOffset
	if _, err := u.Append("new.txt", APPEND_MODE_KEEP_ORIGINAL); !errors.Is(err, errUpdaterCovFail) {
		t.Fatalf("appending gave %v, want the failure of the handle", err)
	}
}

func TestUpdaterCovSetsTheUTF8FlagFromTheName(t *testing.T) {
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})

	t.Run("name that needs it", func(t *testing.T) {
		// A name outside ASCII is written as UTF-8 and marked as such,
		// or a reader decodes it in whatever code page it assumes.
		u, _ := UpdaterCovOpen(t, raw)
		fh := &FileHeader{Name: "имя.txt", Method: Store}
		if _, err := u.AppendHeader(fh, APPEND_MODE_KEEP_ORIGINAL); err != nil {
			t.Fatalf("appending: %v", err)
		}
		if fh.Flags&0x800 == 0 {
			t.Errorf("flags are %#04x, want the UTF-8 bit set for a name outside ASCII", fh.Flags)
		}
	})

	t.Run("name the caller declares is not UTF-8", func(t *testing.T) {
		// A caller that says the name is in some other encoding is
		// taken at its word, and the bit that would claim UTF-8 is
		// cleared even if it arrived set.
		u, _ := UpdaterCovOpen(t, raw)
		fh := &FileHeader{Name: "plain.txt", Method: Store, NonUTF8: true, Flags: 0x800}
		if _, err := u.AppendHeader(fh, APPEND_MODE_KEEP_ORIGINAL); err != nil {
			t.Fatalf("appending: %v", err)
		}
		if fh.Flags&0x800 != 0 {
			t.Errorf("flags are %#04x, want the UTF-8 bit cleared", fh.Flags)
		}
	})
}

func TestUpdaterCovAppendsADirectoryEntry(t *testing.T) {
	// A name ending in a separator is a directory: it is stored, carries no
	// data descriptor and no sizes, and the writer handed back takes
	// nothing but an empty write.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	fh := &FileHeader{Name: "folder/", Method: Deflate, Flags: 0x8, UncompressedSize64: 7}
	w, err := u.AppendHeader(fh, APPEND_MODE_KEEP_ORIGINAL)
	if err != nil {
		t.Fatalf("appending a directory: %v", err)
	}
	if fh.Method != Store {
		t.Errorf("the directory entry was stored with method %d", fh.Method)
	}
	if fh.Flags&0x8 != 0 {
		t.Errorf("flags are %#04x, want no data descriptor on a directory", fh.Flags)
	}
	if fh.UncompressedSize64 != 0 || fh.CompressedSize64 != 0 {
		t.Errorf("the directory entry claims %d bytes of contents", fh.UncompressedSize64)
	}
	if n, err := w.Write(nil); n != 0 || err != nil {
		t.Errorf("an empty write to a directory gave %d, %v", n, err)
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Error("a directory took the contents it was written")
	}
	if err := u.Close(); err != nil {
		t.Fatalf("closing the updater: %v", err)
	}

	got := UpdaterCovNames(t, mem.data)
	if len(got) != 2 || got[1] != "folder/" {
		t.Fatalf("the updated archive lists %v", got)
	}
}

func TestUpdaterCovRefusesANameTooLongForItsHeader(t *testing.T) {
	// The local header holds the length of the name in two bytes. A longer
	// one used to be written under a length that had wrapped, leaving an
	// entry no reader can walk.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, _ := UpdaterCovOpen(t, raw)

	fh := &FileHeader{Name: strings.Repeat("n", uint16max+1), Method: Store}
	_, err := u.AppendHeader(fh, APPEND_MODE_KEEP_ORIGINAL)
	if err == nil {
		t.Fatalf("a name of %d bytes was written into a two-byte length", uint16max+1)
	}
	if !strings.Contains(err.Error(), "file name") {
		t.Errorf("error %q does not name the field", err)
	}
}

func TestUpdaterCovRefusesAnUnknownAESStrength(t *testing.T) {
	// The strength picks the key length, and there is no key to derive for
	// a number the format does not define.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, _ := UpdaterCovOpen(t, raw)

	fh := &FileHeader{Name: "secret.txt", Password: "hunter2", AESStrength: 9}
	_, err := u.AppendHeader(fh, APPEND_MODE_KEEP_ORIGINAL)
	if err == nil || !strings.Contains(err.Error(), "AES strength") {
		t.Fatalf("appending gave %v, want the refusal of the strength", err)
	}
}

func TestUpdaterCovHonoursTheDeflateLevel(t *testing.T) {
	// A level asks for a compressor of that level rather than the one
	// registered for the method.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	fh := &FileHeader{Name: "packed.txt", Method: Deflate, Level: 9}
	w, err := u.AppendHeader(fh, APPEND_MODE_KEEP_ORIGINAL)
	if err != nil {
		t.Fatalf("appending: %v", err)
	}
	body := bytes.Repeat([]byte("compress me well "), 512)
	mustWrite(t, w, body)
	if err := u.Close(); err != nil {
		t.Fatalf("closing the updater: %v", err)
	}

	if got := UpdaterCovContents(t, mem.data, "packed.txt"); !bytes.Equal(got, body) {
		t.Errorf("the entry holds %d bytes, want the %d written", len(got), len(body))
	}
	if fh.CompressedSize64 >= uint64(len(body)) {
		t.Errorf("the entry was not compressed: %d bytes for %d", fh.CompressedSize64, len(body))
	}
}

func TestUpdaterCovRefusesAMethodItCannotWrite(t *testing.T) {
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, _ := UpdaterCovOpen(t, raw)

	fh := &FileHeader{Name: "exotic.txt", Method: 42}
	if _, err := u.AppendHeader(fh, APPEND_MODE_KEEP_ORIGINAL); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("appending gave %v, want ErrAlgorithm", err)
	}
}

func TestUpdaterCovReportsACompressorThatWillNotStart(t *testing.T) {
	// A compressor is asked for a writer over the entry, and one that
	// cannot give it stops the append rather than leaving an entry whose
	// header has been written and whose contents go nowhere.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, _ := UpdaterCovOpen(t, raw)
	u.compressors = map[uint16]Compressor{
		Store: func(io.Writer) (io.WriteCloser, error) { return nil, errUpdaterCovFail },
	}

	fh := &FileHeader{Name: "new.txt", Method: Store}
	if _, err := u.AppendHeader(fh, APPEND_MODE_KEEP_ORIGINAL); !errors.Is(err, errUpdaterCovFail) {
		t.Fatalf("appending gave %v, want the failure of the compressor", err)
	}
}

func TestUpdaterCovReportsALostPositionAfterTheHeader(t *testing.T) {
	// Where the header of the new entry ended is where the directory will
	// go if nothing else is written, so a handle that cannot say where it
	// is stops the append.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	mem.seekCurErr = errUpdaterCovFail
	if _, err := u.Append("new.txt", APPEND_MODE_KEEP_ORIGINAL); !errors.Is(err, errUpdaterCovFail) {
		t.Fatalf("appending gave %v, want the failure of the handle", err)
	}
}

func TestUpdaterCovKeepsTheCommentItIsGiven(t *testing.T) {
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	if got := u.GetComment(); got != "" {
		t.Errorf("a fresh archive reports the comment %q", got)
	}
	// The end record holds the length of the comment in two bytes.
	if err := u.SetComment(strings.Repeat("c", uint16max+1)); err == nil {
		t.Fatalf("a comment of %d bytes was accepted", uint16max+1)
	}
	if got := u.GetComment(); got != "" {
		t.Errorf("the refused comment was kept as %q", got)
	}
	if err := u.SetComment("written by hand"); err != nil {
		t.Fatalf("setting the comment: %v", err)
	}
	if got := u.GetComment(); got != "written by hand" {
		t.Errorf("the comment reads back as %q", got)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("closing the updater: %v", err)
	}

	r, err := NewReader(bytes.NewReader(mem.data), int64(len(mem.data)))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	if r.Comment != "written by hand" {
		t.Errorf("the archive carries the comment %q", r.Comment)
	}
}

func TestUpdaterCovReportsAFailureFinishingTheLastEntryOnClose(t *testing.T) {
	// Closing finishes the entry still open, and its compressed tail has
	// to reach the file before the directory is written over it.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	w, err := u.Append("new.txt", APPEND_MODE_KEEP_ORIGINAL)
	if err != nil {
		t.Fatalf("appending: %v", err)
	}
	mustWrite(t, w, []byte("the tail of this entry is still buffered"))

	mem.writeErr = errUpdaterCovFail
	if err := u.Close(); !errors.Is(err, errUpdaterCovFail) {
		t.Fatalf("closing gave %v, want the failure of the handle", err)
	}
}

func TestUpdaterCovReportsALostPositionOnClose(t *testing.T) {
	// Where the last entry ended is where the directory begins, so a handle
	// that cannot say where it is has nowhere to put the directory.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	w, err := u.Append("new.txt", APPEND_MODE_KEEP_ORIGINAL)
	if err != nil {
		t.Fatalf("appending: %v", err)
	}
	mustWrite(t, w, []byte("some contents"))

	mem.seekCurErr = errUpdaterCovFail
	if err := u.Close(); !errors.Is(err, errUpdaterCovFail) {
		t.Fatalf("closing gave %v, want the failure of the handle", err)
	}
}

func TestUpdaterCovRefusesASecondClose(t *testing.T) {
	// The directory has already been written and the file truncated behind
	// it; writing a second one would append it to the archive.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	if err := u.Close(); err != nil {
		t.Fatalf("closing the updater: %v", err)
	}
	size := len(mem.data)
	if err := u.Close(); err == nil {
		t.Fatal("the updater was closed twice without complaint")
	}
	if len(mem.data) != size {
		t.Errorf("the second close changed the archive from %d to %d bytes", size, len(mem.data))
	}
}

func TestUpdaterCovReportsAHandleThatWillNotReachTheDirectoryOnClose(t *testing.T) {
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	mem.seekStartErr = errUpdaterCovFail
	mem.seekStartAt = u.dirOffset
	if err := u.Close(); !errors.Is(err, errUpdaterCovFail) {
		t.Fatalf("closing gave %v, want the failure of the handle", err)
	}
}

func TestUpdaterCovClosesOverAHandleThatCannotTruncate(t *testing.T) {
	// Truncating is what removes the tail of a shrinking archive, and a
	// handle that has no Truncate is closed without it: the directory and
	// the end record are still written, and a reader finds the end record
	// by looking backwards from the end of what it is given.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	mem := &UpdaterCovFile{data: append([]byte(nil), raw...)}
	u, err := NewUpdater(&UpdaterCovPlainFile{file: mem})
	if err != nil {
		t.Fatalf("opening the updater: %v", err)
	}
	w, err := u.Append("new.txt", APPEND_MODE_KEEP_ORIGINAL)
	if err != nil {
		t.Fatalf("appending: %v", err)
	}
	mustWrite(t, w, []byte("added"))
	if err := u.Close(); err != nil {
		t.Fatalf("closing the updater: %v", err)
	}

	if got := UpdaterCovNames(t, mem.data); len(got) != 2 {
		t.Fatalf("the updated archive lists %v", got)
	}
	if got := UpdaterCovContents(t, mem.data, "new.txt"); string(got) != "added" {
		t.Errorf("the appended entry holds %q", got)
	}
}

func TestUpdaterCovWritesAZip64ExtraForAnEntryOutOfRange(t *testing.T) {
	// The directory holds the sizes and the offset of an entry in four
	// bytes each. An entry that does not fit gets the marker value there
	// and a zip64 extra field carrying the real numbers. Reaching an
	// offset of four gigabytes needs an archive of four gigabytes, so the
	// offset is set here instead of written.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)
	u.dir[0].offset = uint32max + 1
	if err := u.Close(); err != nil {
		t.Fatalf("closing the updater: %v", err)
	}

	cd := centralHeaderOffset(t, mem.data, "file.txt")
	if got := binary.LittleEndian.Uint32(mem.data[cd+20:]); got != uint32max {
		t.Errorf("the compressed size in the directory is %d, want the marker", got)
	}
	if got := binary.LittleEndian.Uint32(mem.data[cd+24:]); got != uint32max {
		t.Errorf("the uncompressed size in the directory is %d, want the marker", got)
	}
	if got := binary.LittleEndian.Uint32(mem.data[cd+42:]); got != uint32max {
		t.Errorf("the header offset in the directory is %d, want the marker", got)
	}
	extraLen := int(binary.LittleEndian.Uint16(mem.data[cd+30:]))
	nameLen := int(binary.LittleEndian.Uint16(mem.data[cd+28:]))
	extra := mem.data[cd+directoryHeaderLen+nameLen:][:extraLen]
	if len(extra) < 4 || binary.LittleEndian.Uint16(extra) != zip64ExtraID {
		t.Fatalf("the entry carries the extra field %x, want a zip64 record", extra)
	}
	if got := binary.LittleEndian.Uint64(extra[20:]); got != uint32max+1 {
		t.Errorf("the zip64 record gives the offset %d", got)
	}
}

func TestUpdaterCovReportsAFailedDirectoryWrite(t *testing.T) {
	// The directory is the last thing written and the only record of where
	// everything is. Each piece of it that does not reach the file is
	// reported rather than leaving an archive whose directory stops in the
	// middle of an entry.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	for _, tc := range []struct {
		what  string
		write int
	}{
		{"the record of the entry", 1},
		{"the name of the entry", 2},
		{"the extra field of the entry", 3},
		{"the comment of the entry", 4},
		{"the end record", 5},
		{"the comment of the archive", 6},
	} {
		t.Run(tc.what, func(t *testing.T) {
			u, mem := UpdaterCovOpen(t, raw)
			if err := u.SetComment("written by hand"); err != nil {
				t.Fatalf("setting the comment: %v", err)
			}
			mem.writes = 0
			mem.writeFailAt = tc.write
			err := u.Close()
			if !errors.Is(err, errUpdaterCovFail) {
				t.Fatalf("closing gave %v, want the failure of the handle", err)
			}
			if !strings.Contains(err.Error(), "write directory") {
				t.Errorf("error %q does not say the directory was what failed", err)
			}
		})
	}
}

func TestUpdaterCovReportsAFailedZip64EndRecordWrite(t *testing.T) {
	// The end record counts entries in two bytes, so an archive with more
	// than that carries a zip64 end record and a locator naming it, and a
	// failure to write them is reported.
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "file.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	base := u.dir[0]
	for len(u.dir) <= uint16max {
		clone := *base.FileHeader
		u.dir = append(u.dir, &header{FileHeader: &clone, offset: base.offset})
	}

	// Each entry takes four writes: its record, its name, its extra field
	// and its comment. The zip64 end record is the write after the last of
	// them.
	mem.writes = 0
	mem.writeFailAt = 4*len(u.dir) + 1
	err := u.Close()
	if !errors.Is(err, errUpdaterCovFail) {
		t.Fatalf("closing gave %v, want the failure of the handle", err)
	}
	if !strings.Contains(err.Error(), "write directory") {
		t.Errorf("error %q does not say the directory was what failed", err)
	}
}

// TestUpdaterCovRemoveLeavesNothingOfTheEntry: an entry that was removed has
// to be gone from the file, not merely absent from the listing. The removal
// shifts what follows the entry down over it and leaves the end of the data
// where it was, so the entry's name and its whole payload used to survive in
// the bytes past it -- verbatim, for the last entry, which nothing is shifted
// over at all. The end record used to survive there too, and since a reader
// looks for one backwards from the end of the file, an archive whose handle
// could not be shortened came back unreadable.
func TestUpdaterCovRemoveLeavesNothingOfTheEntry(t *testing.T) {
	secret := []byte("the contents of the entry that was removed")
	raw := UpdaterCovArchive(t,
		UpdaterCovEntry{Name: "keep.txt", Data: []byte("kept")},
		UpdaterCovEntry{Name: "secret.txt", Data: secret},
		UpdaterCovEntry{Name: "tail.txt", Data: []byte("after the removal")},
	)

	for _, tc := range []struct {
		name  string
		index int
	}{
		{"an entry with another behind it", 1},
		{"the last entry, which nothing is shifted over", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, handle := range []struct {
				name     string
				truncate bool
			}{
				{"a handle that can be shortened", true},
				{"a handle that cannot", false},
			} {
				t.Run(handle.name, func(t *testing.T) {
					mem := &UpdaterCovFile{data: append([]byte(nil), raw...)}
					var rws io.ReadWriteSeeker = mem
					if !handle.truncate {
						rws = &UpdaterCovPlainFile{file: mem}
					}
					u, err := NewUpdater(rws)
					if err != nil {
						t.Fatalf("opening the updater: %v", err)
					}

					if tc.index == 1 {
						// The entry chosen is the one holding the
						// secret; the last entry is the one after it.
						if u.dir[1].Name != "secret.txt" {
							t.Fatalf("the fixture lists %q where secret.txt was expected", u.dir[1].Name)
						}
					}
					target := u.dir[tc.index].Name
					if _, err := u.RemoveFile(tc.index); err != nil {
						t.Fatalf("removing %s: %v", target, err)
					}
					if err := u.Close(); err != nil {
						t.Fatalf("closing the updater: %v", err)
					}

					got := mem.data
					if bytes.Contains(got, []byte(target)) {
						t.Errorf("the name of the removed entry is still in the archive at offset %d", bytes.Index(got, []byte(target)))
					}
					if target == "secret.txt" && bytes.Contains(got, secret) {
						t.Errorf("the payload of the removed entry is still in the archive at offset %d", bytes.Index(got, secret))
					}

					names := UpdaterCovNames(t, got)
					for _, n := range names {
						if n == target {
							t.Errorf("the archive still lists %q", n)
						}
					}
					if len(names) != 2 {
						t.Fatalf("the archive lists %v, want the two entries that were kept", names)
					}
					if body := UpdaterCovContents(t, got, "keep.txt"); string(body) != "kept" {
						t.Errorf("keep.txt holds %q, want %q", body, "kept")
					}
					if handle.truncate && int64(len(got)) >= int64(len(raw)) {
						t.Errorf("the archive is %d bytes after the removal, was %d", len(got), len(raw))
					}
				})
			}
		})
	}
}

// TestUpdaterCovRemoveCannotReadALocalHeader: what an entry occupies is read
// from its own local header, and a handle that will not hand that over leaves
// the extent unknown, so nothing may be cut.
func TestUpdaterCovRemoveCannotReadALocalHeader(t *testing.T) {
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "gone.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	mem.readErr = errUpdaterCovFail
	if _, err := u.RemoveFile(0); !errors.Is(err, errUpdaterCovFail) {
		t.Fatalf("removing gave %v, want the failure of the handle", err)
	}
}

// TestUpdaterCovRemoveCannotReadALocalHeaderToTheEnd: a handle that stops in
// the middle of a header the archive said was there is describing a truncated
// archive rather than a fault of its own, so the removal reports a malformed
// archive with what the read gave out kept behind it.
func TestUpdaterCovRemoveCannotReadALocalHeaderToTheEnd(t *testing.T) {
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "gone.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	mem.readErr = io.ErrUnexpectedEOF
	_, err := u.RemoveFile(0)
	if !errors.Is(err, ErrFormat) {
		t.Fatalf("removing gave %v, want a malformed archive", err)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("the refusal drops what the read reported: %v", err)
	}
}

// TestUpdaterCovRemoveCannotReadADataDescriptor: how long an entry's data
// descriptor is depends on the four bytes at the end of its data, and a handle
// that will not hand those over leaves the extent unknown, so nothing may be
// cut.
func TestUpdaterCovRemoveCannotReadADataDescriptor(t *testing.T) {
	raw := UpdaterCovArchive(t, UpdaterCovEntry{Name: "gone.txt", Data: []byte("content")})
	u, mem := UpdaterCovOpen(t, raw)

	// The local header is read whole and the descriptor is looked for four
	// bytes at a time, so a threshold at the length of a header lets the
	// first through and stops the second.
	mem.readErr = errUpdaterCovFail
	mem.readFailUnder = fileHeaderLen
	if _, err := u.RemoveFile(0); !errors.Is(err, errUpdaterCovFail) {
		t.Fatalf("removing gave %v, want the failure of the handle", err)
	}
}

// TestUpdaterCovRemoveCannotOverwriteWhatItFreed: on a handle that cannot be
// shortened, the bytes a removal frees are written over with zeros, and a
// handle that will not take that write leaves the entry where it was -- so the
// removal has to fail rather than report a file it did not unmake.
func TestUpdaterCovRemoveCannotOverwriteWhatItFreed(t *testing.T) {
	raw := UpdaterCovArchive(t,
		UpdaterCovEntry{Name: "gone.txt", Data: []byte("the entry to remove")},
		UpdaterCovEntry{Name: "keep.txt", Data: []byte("kept")},
	)

	// The zero fill begins where the data ends once the entry has been cut
	// out, which is the offset the removal itself answers with and is no
	// entry's own: working out an extent reads at the entries and at their
	// tails, and a seek aimed here is the zero fill's and nothing else's.
	dry := &UpdaterCovFile{data: append([]byte(nil), raw...)}
	du, err := NewUpdater(&UpdaterCovPlainFile{file: dry})
	if err != nil {
		t.Fatalf("opening the updater: %v", err)
	}
	freed, err := du.RemoveFile(0)
	if err != nil {
		t.Fatalf("the removal this measures: %v", err)
	}

	mem := &UpdaterCovFile{data: append([]byte(nil), raw...)}
	u, err := NewUpdater(&UpdaterCovPlainFile{file: mem})
	if err != nil {
		t.Fatalf("opening the updater: %v", err)
	}
	mem.seekStartAt = freed
	mem.seekStartErr = errUpdaterCovFail

	if _, err := u.RemoveFile(0); !errors.Is(err, errUpdaterCovFail) {
		t.Fatalf("removing gave %v, want the failure of the handle", err)
	}
}

// TestUpdaterCovCloseCannotMeasureWhatItWrote: with no way to shorten the
// file, the close puts the end record where the file already ends, so it has
// to ask how long the file is. A handle that will not say is the close's
// failure.
func TestUpdaterCovCloseCannotMeasureWhatItWrote(t *testing.T) {
	raw := UpdaterCovArchive(t,
		UpdaterCovEntry{Name: "keep.txt", Data: []byte("kept")},
		UpdaterCovEntry{Name: "last.txt", Data: []byte("the entry to remove")},
	)

	// A run that works, to learn how many times a removal and a close ask
	// the handle how long the file is. The last of them is the close's own.
	counter := &UpdaterCovFile{data: append([]byte(nil), raw...)}
	cu, err := NewUpdater(&UpdaterCovPlainFile{file: counter})
	if err != nil {
		t.Fatalf("opening the updater: %v", err)
	}
	if _, err := cu.RemoveFile(len(cu.dir) - 1); err != nil {
		t.Fatalf("removing the last entry: %v", err)
	}
	if err := cu.Close(); err != nil {
		t.Fatalf("closing the updater: %v", err)
	}

	mem := &UpdaterCovFile{data: append([]byte(nil), raw...)}
	u, err := NewUpdater(&UpdaterCovPlainFile{file: mem})
	if err != nil {
		t.Fatalf("opening the updater: %v", err)
	}
	if _, err := u.RemoveFile(len(u.dir) - 1); err != nil {
		t.Fatalf("removing the last entry: %v", err)
	}
	mem.seekEndFailAt = counter.seekEnds
	if err := u.Close(); !errors.Is(err, errUpdaterCovFail) {
		t.Fatalf("closing gave %v, want the failure of the handle", err)
	}
}

// TestUpdaterCovRemoveLeavesADirectoryARaderCanFind: a reader looks for the
// end record backwards from the end of the file over a window of some tens of
// kilobytes. A removed entry's directory record can be larger than that window
// by itself -- the format allows a name, an extra field and a comment of 64
// KiB each -- so on a handle that cannot be shortened, writing the new
// directory where the data now ends leaves more behind it than a reader will
// look past, and the archive comes back unreadable however thoroughly what is
// behind it has been erased.
func TestUpdaterCovRemoveLeavesADirectoryAReaderCanFind(t *testing.T) {
	// Each field is capped at 64 KiB on its own, so the record is made
	// larger than the reader's search window out of two of them: a long
	// name and an extra field of an id nothing here claims.
	name := strings.Repeat("v", 20000) + ".txt"
	extra := make([]byte, 4, 4+60000)
	binary.LittleEndian.PutUint16(extra[0:2], 0xFFFF)
	binary.LittleEndian.PutUint16(extra[2:4], 60000)
	extra = append(extra, bytes.Repeat([]byte{0x2a}, 60000)...)

	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	mustWrite(t, mustCreateHeader(t, zw, &FileHeader{Name: "keep.txt", Method: Store}), []byte("kept"))
	mustWrite(t, mustCreateHeader(t, zw, &FileHeader{
		Name:   name,
		Method: Store,
		Extra:  extra,
	}), []byte("the entry to remove"))
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	raw := buf.Bytes()

	mem := &UpdaterCovFile{data: append([]byte(nil), raw...)}
	u, err := NewUpdater(&UpdaterCovPlainFile{file: mem})
	if err != nil {
		t.Fatalf("opening the updater: %v", err)
	}
	if u.dir[1].Name != name {
		t.Fatalf("the fixture lists %q where the long name was expected", u.dir[1].Name)
	}
	if _, err := u.RemoveFile(1); err != nil {
		t.Fatalf("removing the entry: %v", err)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("closing the updater: %v", err)
	}

	got := mem.data
	if bytes.Contains(got, []byte(name)) {
		t.Errorf("the name of the removed entry is still in the archive at offset %d", bytes.Index(got, []byte(name)))
	}
	if names := UpdaterCovNames(t, got); len(names) != 1 || names[0] != "keep.txt" {
		t.Fatalf("the archive lists %v, want just keep.txt", names)
	}
	if body := UpdaterCovContents(t, got, "keep.txt"); string(body) != "kept" {
		t.Errorf("keep.txt holds %q, want %q", body, "kept")
	}
}

// TestUpdaterCovCloseOnAHandleThatCannotBeShortened: with no way to shorten
// the file, the close renders the directory once to measure it, writes over
// the gap that measurement leaves in front of it, seeks there and writes it
// out. Each of those is the close's failure when the handle refuses it.
func TestUpdaterCovCloseOnAHandleThatCannotBeShortened(t *testing.T) {
	raw := UpdaterCovArchive(t,
		UpdaterCovEntry{Name: "keep.txt", Data: []byte("kept")},
		UpdaterCovEntry{Name: "last.txt", Data: []byte("the entry to remove")},
	)

	open := func(t *testing.T) (*Updater, *UpdaterCovFile) {
		t.Helper()
		mem := &UpdaterCovFile{data: append([]byte(nil), raw...)}
		u, err := NewUpdater(&UpdaterCovPlainFile{file: mem})
		if err != nil {
			t.Fatalf("opening the updater: %v", err)
		}
		return u, mem
	}
	removeLast := func(t *testing.T, u *Updater) {
		t.Helper()
		if _, err := u.RemoveFile(len(u.dir) - 1); err != nil {
			t.Fatalf("removing the last entry: %v", err)
		}
	}

	t.Run("the directory cannot be rendered", func(t *testing.T) {
		u, _ := open(t)
		removeLast(t, u)
		// A name past what the two-byte field can hold, so the render
		// that measures the directory refuses it.
		u.dir[0].Name = strings.Repeat("n", uint16max+1)
		err := u.Close()
		if err == nil {
			t.Fatal("a directory that cannot be rendered was written anyway")
		}
		if !strings.Contains(err.Error(), "write directory") {
			t.Errorf("error %q does not say the directory was what failed", err)
		}
	})

	t.Run("the gap in front of it cannot be written over", func(t *testing.T) {
		u, mem := open(t)
		removeLast(t, u)
		mem.writeErr = errUpdaterCovFail
		if err := u.Close(); !errors.Is(err, errUpdaterCovFail) {
			t.Fatalf("closing gave %v, want the failure of the handle", err)
		}
	})

	t.Run("the place it goes cannot be reached", func(t *testing.T) {
		// Nothing removed, so the directory goes back exactly where it
		// was and the offset the seek asks for is the one it started at.
		u, mem := open(t)
		mem.seekStartAt = u.dirOffset
		mem.seekStartErr = errUpdaterCovFail
		if err := u.Close(); !errors.Is(err, errUpdaterCovFail) {
			t.Fatalf("closing gave %v, want the failure of the handle", err)
		}
	})

	t.Run("the directory cannot be written out", func(t *testing.T) {
		u, mem := open(t)
		removeLast(t, u)
		// Two writes go over the bytes the removal freed, one where it
		// happened and one where the close puts the directory; the
		// third is the directory's first record.
		mem.writeFailAt = 3
		err := u.Close()
		if !errors.Is(err, errUpdaterCovFail) {
			t.Fatalf("closing gave %v, want the failure of the handle", err)
		}
		if !strings.Contains(err.Error(), "write directory") {
			t.Errorf("error %q does not say the directory was what failed", err)
		}
	})
}

// TestUpdaterCovRemoveCompactsWhereItCan: where the file can be shortened, a
// removal is a compaction. The directory moves back to where the removed entry
// began and the file ends after it, so the bytes are gone rather than blanked
// -- an archive of the same length with a hole in it is not what the caller
// asked for, and every later entry's offset was shifted on the understanding
// that the data now ends there.
func TestUpdaterCovRemoveCompactsWhereItCan(t *testing.T) {
	raw := UpdaterCovArchive(t,
		UpdaterCovEntry{Name: "keep.txt", Data: []byte("kept")},
		UpdaterCovEntry{Name: "last.txt", Data: []byte("the entry to remove")},
	)
	u, mem := UpdaterCovOpen(t, raw)

	// #nosec G115 -- init holds every entry offset to 0 <= offset <= dirOffset
	start := int64(u.dir[len(u.dir)-1].offset)
	if _, err := u.RemoveFile(len(u.dir) - 1); err != nil {
		t.Fatalf("removing the last entry: %v", err)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("closing the updater: %v", err)
	}

	got := mem.data
	end, _, err := readDirectoryEnd(bytes.NewReader(got), int64(len(got)))
	if err != nil {
		t.Fatalf("reading the end record back: %v", err)
	}
	// #nosec G115 -- the fixture is a few hundred bytes
	if dirOffset := int64(end.directoryOffset); dirOffset != start {
		t.Errorf("the directory begins at %d, want %d, where the removed entry did", dirOffset, start)
	}
	// #nosec G115 -- the fixture is a few hundred bytes
	if want := int64(end.directoryOffset) + int64(end.directorySize) + directoryEndLen; int64(len(got)) != want {
		t.Errorf("the archive is %d bytes, want %d: the end record is not the last thing in it", len(got), want)
	}
}
