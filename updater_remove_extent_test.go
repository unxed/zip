package zip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"path"
	"testing"
)

// A central directory may name two entries whose regions run into each other,
// and the reader accepts such an archive and reads both. Removing one of them
// used to cut everything from its offset up to where the next entry begins,
// which is right only for entries laid out end to end: the cut swallowed the
// bytes of a neighbour the caller was keeping, and every call on the way
// reported success. Found by fuzzing. The extent to cut comes from the entry's
// own header now, and an archive whose entries overlap is refused rather than
// edited.

// overlappingEntriesZip lays out one real stored entry and a second directory
// record that points into the middle of it.
func overlappingEntriesZip() []byte {
	body := []byte("forty bytes of body for the good entry..")
	name := "good"
	ghost := "ghost"

	var buf bytes.Buffer

	// The one real entry, at offset 0.
	lh := make([]byte, 30)
	binary.LittleEndian.PutUint32(lh[0:4], fileHeaderSignature)
	binary.LittleEndian.PutUint16(lh[4:6], 20)
	binary.LittleEndian.PutUint16(lh[8:10], Store)
	binary.LittleEndian.PutUint32(lh[14:18], crc32.ChecksumIEEE(body))
	// #nosec G115 -- the body is forty bytes
	binary.LittleEndian.PutUint32(lh[18:22], uint32(len(body)))
	// #nosec G115 -- the body is forty bytes
	binary.LittleEndian.PutUint32(lh[22:26], uint32(len(body)))
	// #nosec G115 -- the name is four bytes
	binary.LittleEndian.PutUint16(lh[26:28], uint16(len(name)))
	buf.Write(lh)
	buf.WriteString(name)
	buf.Write(body)
	goodEnd := buf.Len() // 30 + 4 + 40 = 74

	// A second local header after it, so there is something for the removal
	// to shift down.
	tail := make([]byte, 30)
	binary.LittleEndian.PutUint32(tail[0:4], fileHeaderSignature)
	binary.LittleEndian.PutUint16(tail[4:6], 20)
	binary.LittleEndian.PutUint16(tail[8:10], Store)
	// #nosec G115 -- the name is five bytes
	binary.LittleEndian.PutUint16(tail[26:28], uint16(len(ghost)))
	buf.Write(tail)
	buf.WriteString(ghost)

	cdOffset := buf.Len()

	central := func(name string, offset uint32, size uint32, crc uint32) {
		ch := make([]byte, 46)
		binary.LittleEndian.PutUint32(ch[0:4], directoryHeaderSignature)
		binary.LittleEndian.PutUint16(ch[4:6], 20)
		binary.LittleEndian.PutUint16(ch[6:8], 20)
		binary.LittleEndian.PutUint16(ch[10:12], Store)
		binary.LittleEndian.PutUint32(ch[16:20], crc)
		binary.LittleEndian.PutUint32(ch[20:24], size)
		binary.LittleEndian.PutUint32(ch[24:28], size)
		// #nosec G115 -- the names here are a handful of bytes
		binary.LittleEndian.PutUint16(ch[28:30], uint16(len(name)))
		binary.LittleEndian.PutUint32(ch[42:46], offset)
		buf.Write(ch)
		buf.WriteString(name)
	}

	// The good entry, and a record whose offset lands inside its data.
	// #nosec G115 -- the body is forty bytes
	central(name, 0, uint32(len(body)), crc32.ChecksumIEEE(body))
	central("inside", 20, 0, 0)
	// #nosec G115 -- the archive is a couple of hundred bytes
	central(ghost, uint32(goodEnd), 0, 0)

	cdSize := buf.Len() - cdOffset

	eocd := make([]byte, 22)
	binary.LittleEndian.PutUint32(eocd[0:4], directoryEndSignature)
	binary.LittleEndian.PutUint16(eocd[8:10], 3)
	binary.LittleEndian.PutUint16(eocd[10:12], 3)
	// #nosec G115 -- the archive is a couple of hundred bytes
	binary.LittleEndian.PutUint32(eocd[12:16], uint32(cdSize))
	// #nosec G115 -- the archive is a couple of hundred bytes
	binary.LittleEndian.PutUint32(eocd[16:20], uint32(cdOffset))
	buf.Write(eocd)

	return buf.Bytes()
}

// entryBody returns what the named entry reads as, or an error.
func entryBody(archive []byte, name string) ([]byte, error) {
	r, err := NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, err
	}
	for _, f := range r.File {
		if f.Name != name {
			continue
		}
		rc, oerr := f.Open()
		if oerr != nil {
			return nil, oerr
		}
		body, rerr := io.ReadAll(io.LimitReader(rc, 1<<20))
		cerr := rc.Close()
		if rerr != nil {
			return nil, rerr
		}
		if cerr != nil {
			return nil, cerr
		}
		return body, nil
	}
	return nil, io.EOF
}

// entryIndex is where the updater lists the named entry, which is not where
// the archive listed it: the updater sorts by offset.
func entryIndex(t *testing.T, u *Updater, name string) int {
	t.Helper()
	for i, h := range u.Entries() {
		if h.Name == name {
			return i
		}
	}
	t.Fatalf("the updater does not list %q", name)
	return -1
}

// TestUpdaterRemoveKeepsOverlappingNeighbours pins that an entry which read
// cleanly before an unrelated removal still reads cleanly after it.
func TestUpdaterRemoveKeepsOverlappingNeighbours(t *testing.T) {
	archive := overlappingEntriesZip()

	before, err := entryBody(archive, "good")
	if err != nil {
		t.Fatalf("the good entry does not read before the edit: %v", err)
	}

	m := &memFile{data: append([]byte(nil), archive...)}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}

	removeErr := func() error {
		if _, err := u.RemoveFile(entryIndex(t, u, "inside")); err != nil {
			return err
		}
		return u.Close()
	}()
	if removeErr == nil {
		after, err := entryBody(m.data, "good")
		if err != nil {
			t.Fatalf("the good entry read cleanly before the edit and reports %v after it", err)
		}
		if !bytes.Equal(after, before) {
			t.Fatalf("the good entry held %d bytes before the edit and %d after it", len(before), len(after))
		}
		return
	}
	if !errors.Is(removeErr, ErrFormat) {
		t.Fatalf("the removal was refused with %v, not as a malformed archive", removeErr)
	}
	if !bytes.Equal(m.data, archive) {
		t.Fatalf("the refused removal modified the archive: %d bytes in, %d out", len(archive), len(m.data))
	}
}

// TestUpdaterRemoveCutsTheEntrysOwnExtent pins the ordinary case the cut is
// worked out for: what an entry occupies is what disappears, and the entries
// around it come through byte for byte.
func TestUpdaterRemoveCutsTheEntrysOwnExtent(t *testing.T) {
	bodies := map[string][]byte{
		"first.txt":  []byte("the first body"),
		"second.txt": []byte("the second body, which goes away"),
		"third.txt":  []byte("the third body"),
	}

	var built bytes.Buffer
	w := NewWriter(&built)
	for _, name := range []string{"first.txt", "second.txt", "third.txt"} {
		fw, err := w.CreateHeader(&FileHeader{Name: name, Method: Store})
		if err != nil {
			t.Fatalf("%s: CreateHeader: %v", name, err)
		}
		if _, err := fw.Write(bodies[name]); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	m := &memFile{data: built.Bytes()}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if _, err := u.RemoveFile(entryIndex(t, u, "second.txt")); err != nil {
		t.Fatalf("RemoveFile: %v", err)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := NewReader(bytes.NewReader(m.data), int64(len(m.data)))
	if err != nil {
		t.Fatalf("the reader rejects the result: %v", err)
	}
	if len(r.File) != 2 {
		t.Fatalf("the archive holds %d entries after one removal of three", len(r.File))
	}
	for _, name := range []string{"first.txt", "third.txt"} {
		got, err := entryBody(m.data, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, bodies[name]) {
			t.Fatalf("%s reads back as %q", name, got)
		}
	}
	if bytes.Contains(m.data, bodies["second.txt"]) {
		t.Fatal("the removed entry's body is still in the archive")
	}
}

// extentEntry describes one entry of an archive laid out by hand, so that a
// test can put together headers, descriptors and central records that no
// writer of this package would produce.
type extentEntry struct {
	name  string
	body  []byte
	flags uint16
	// tail is written behind the body exactly as given: a data
	// descriptor, a hidden seek index, or whatever else a test needs to
	// put between an entry and the one after it.
	tail []byte
	// cdExtra goes on the central record.
	cdExtra []byte
	// cdOffset and cdSize, when not negative, are what the central record
	// says instead of where the entry went and how long its body is.
	cdOffset int64
	cdSize   int64
	// sentinelSizes writes the zip64 markers into the central record's two
	// size fields, which is what makes cdExtra's record the size of record.
	sentinelSizes bool
	// inject is written over the body at injectAt, which is how a local
	// header comes to sit inside another entry's data.
	inject   []byte
	injectAt int
}

func extentFixture(entries ...extentEntry) []byte {
	var buf bytes.Buffer
	starts := make([]int64, len(entries))
	for i, e := range entries {
		starts[i] = int64(buf.Len())
		lh := make([]byte, 30)
		binary.LittleEndian.PutUint32(lh[0:4], fileHeaderSignature)
		binary.LittleEndian.PutUint16(lh[4:6], 20)
		binary.LittleEndian.PutUint16(lh[6:8], e.flags)
		binary.LittleEndian.PutUint16(lh[8:10], Store)
		binary.LittleEndian.PutUint32(lh[14:18], crc32.ChecksumIEEE(e.body))
		// #nosec G115 -- the fixtures here are a few hundred bytes
		binary.LittleEndian.PutUint32(lh[18:22], uint32(len(e.body)))
		// #nosec G115 -- the fixtures here are a few hundred bytes
		binary.LittleEndian.PutUint32(lh[22:26], uint32(len(e.body)))
		// #nosec G115 -- the names here are a handful of bytes
		binary.LittleEndian.PutUint16(lh[26:28], uint16(len(e.name)))
		buf.Write(lh)
		buf.WriteString(e.name)
		body := append([]byte(nil), e.body...)
		copy(body[e.injectAt:], e.inject)
		buf.Write(body)
		buf.Write(e.tail)
	}

	cdOff := buf.Len()
	for i, e := range entries {
		ch := make([]byte, 46)
		binary.LittleEndian.PutUint32(ch[0:4], directoryHeaderSignature)
		binary.LittleEndian.PutUint16(ch[4:6], 20)
		binary.LittleEndian.PutUint16(ch[6:8], 20)
		binary.LittleEndian.PutUint16(ch[8:10], e.flags)
		binary.LittleEndian.PutUint16(ch[10:12], Store)
		binary.LittleEndian.PutUint32(ch[16:20], crc32.ChecksumIEEE(e.body))
		size := int64(len(e.body))
		if e.cdSize >= 0 {
			size = e.cdSize
		}
		if e.sentinelSizes {
			binary.LittleEndian.PutUint32(ch[20:24], uint32max)
			binary.LittleEndian.PutUint32(ch[24:28], uint32max)
		} else {
			// #nosec G115 -- the fixtures here are a few hundred bytes
			binary.LittleEndian.PutUint32(ch[20:24], uint32(size))
			// #nosec G115 -- the fixtures here are a few hundred bytes
			binary.LittleEndian.PutUint32(ch[24:28], uint32(len(e.body)))
		}
		// #nosec G115 -- the names here are a handful of bytes
		binary.LittleEndian.PutUint16(ch[28:30], uint16(len(e.name)))
		// #nosec G115 -- the fixtures here carry one short record
		binary.LittleEndian.PutUint16(ch[30:32], uint16(len(e.cdExtra)))
		at := starts[i]
		if e.cdOffset >= 0 {
			at = e.cdOffset
		}
		// #nosec G115 -- the fixtures here are a few hundred bytes
		binary.LittleEndian.PutUint32(ch[42:46], uint32(at))
		buf.Write(ch)
		buf.WriteString(e.name)
		buf.Write(e.cdExtra)
	}
	cdSize := buf.Len() - cdOff

	eocd := make([]byte, 22)
	binary.LittleEndian.PutUint32(eocd[0:4], directoryEndSignature)
	// #nosec G115 -- the fixtures here hold a handful of entries
	binary.LittleEndian.PutUint16(eocd[8:10], uint16(len(entries)))
	// #nosec G115 -- the fixtures here hold a handful of entries
	binary.LittleEndian.PutUint16(eocd[10:12], uint16(len(entries)))
	// #nosec G115 -- the fixtures here are a few hundred bytes
	binary.LittleEndian.PutUint32(eocd[12:16], uint32(cdSize))
	// #nosec G115 -- the fixtures here are a few hundred bytes
	binary.LittleEndian.PutUint32(eocd[16:20], uint32(cdOff))
	buf.Write(eocd)
	return buf.Bytes()
}

// localHeaderFor returns a bare local header for a stored entry of no bytes.
func localHeaderFor(name string) []byte {
	lh := make([]byte, 30)
	binary.LittleEndian.PutUint32(lh[0:4], fileHeaderSignature)
	binary.LittleEndian.PutUint16(lh[4:6], 20)
	binary.LittleEndian.PutUint16(lh[8:10], Store)
	// #nosec G115 -- the names here are a handful of bytes
	binary.LittleEndian.PutUint16(lh[26:28], uint16(len(name)))
	return append(lh, name...)
}

// TestUpdaterRemoveRefusesOverlappingExtents pins the check itself: two entries
// whose local headers both parse and whose regions run into one another.
func TestUpdaterRemoveRefusesOverlappingExtents(t *testing.T) {
	inner := localHeaderFor("inner")
	raw := extentFixture(extentEntry{
		name:     "outer",
		body:     bytes.Repeat([]byte("."), 80),
		cdOffset: -1,
		cdSize:   -1,
		inject:   inner,
		injectAt: 10,
	}, extentEntry{
		// Listed as an entry of its own ten bytes into the first one's
		// data, where the header injected above sits.
		name:     "inner",
		cdOffset: int64(fileHeaderLen + len("outer") + 10),
		cdSize:   0,
	})

	m := &memFile{data: raw}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if _, err := u.RemoveFile(entryIndex(t, u, "inner")); !errors.Is(err, ErrFormat) {
		t.Fatalf("the removal answered %v, not a refusal of a malformed archive", err)
	}
}

// TestUpdaterRemoveRefusesAnEntryRunningPastTheDirectory pins one way an
// extent can be wrong: sizes the archive carries that reach beyond where the
// data ends.
func TestUpdaterRemoveRefusesAnEntryRunningPastTheDirectory(t *testing.T) {
	var built bytes.Buffer
	w := NewWriter(&built)
	fw, err := w.CreateHeader(&FileHeader{Name: "a.txt", Method: Store})
	if err != nil {
		t.Fatalf("CreateHeader: %v", err)
	}
	if _, err := fw.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw := built.Bytes()
	// Grow the entry's compressed size in the central directory so the
	// extent it describes runs past the central directory itself.
	cd := bytes.Index(raw, []byte{'P', 'K', 0x01, 0x02})
	if cd < 0 {
		t.Fatal("the archive has no central directory")
	}
	binary.LittleEndian.PutUint32(raw[cd+20:cd+24], 1<<20)

	m := &memFile{data: append([]byte(nil), raw...)}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if _, err := u.RemoveFile(0); !errors.Is(err, ErrFormat) {
		t.Fatalf("the removal answered %v, not a refusal of a malformed archive", err)
	}
	if !bytes.Equal(m.data, raw) {
		t.Fatal("the refused removal modified the archive")
	}
}

// TestUpdaterRemoveRefusesADescriptorPastTheDirectory pins the same for the
// descriptor behind the data.
func TestUpdaterRemoveRefusesADescriptorPastTheDirectory(t *testing.T) {
	// Eight bytes of descriptor where sixteen are declared: the four at the
	// front are the signature, so a whole one is looked for and does not
	// fit before the central directory.
	dd := make([]byte, 8)
	binary.LittleEndian.PutUint32(dd[0:4], dataDescriptorSignature)
	binary.LittleEndian.PutUint32(dd[4:8], crc32.ChecksumIEEE([]byte("hello")))

	raw := extentFixture(extentEntry{
		name:     "a.txt",
		body:     []byte("hello"),
		flags:    0x8,
		tail:     dd,
		cdOffset: -1,
		cdSize:   -1,
	})

	m := &memFile{data: raw}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if _, err := u.RemoveFile(0); !errors.Is(err, ErrFormat) {
		t.Fatalf("the removal answered %v, not a refusal of a malformed archive", err)
	}
}

// TestUpdaterRemoveReadsADescriptorWithoutItsSignature pins the length the
// four bytes at the end of the data decide: a descriptor is allowed to begin
// with the CRC and no signature, and is four bytes shorter when it does.
func TestUpdaterRemoveReadsADescriptorWithoutItsSignature(t *testing.T) {
	kept := []byte("the entry that stays")
	dd := make([]byte, 12)
	binary.LittleEndian.PutUint32(dd[0:4], crc32.ChecksumIEEE([]byte("hello")))
	binary.LittleEndian.PutUint32(dd[4:8], 5)
	binary.LittleEndian.PutUint32(dd[8:12], 5)

	raw := extentFixture(extentEntry{
		name:     "gone.txt",
		body:     []byte("hello"),
		flags:    0x8,
		tail:     dd,
		cdOffset: -1,
		cdSize:   -1,
	}, extentEntry{
		name:     "kept.txt",
		body:     kept,
		cdOffset: -1,
		cdSize:   -1,
	})

	m := &memFile{data: raw}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if _, err := u.RemoveFile(entryIndex(t, u, "gone.txt")); err != nil {
		t.Fatalf("RemoveFile: %v", err)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got, err := entryBody(m.data, "kept.txt")
	if err != nil {
		t.Fatalf("the surviving entry: %v", err)
	}
	if !bytes.Equal(got, kept) {
		t.Fatalf("the surviving entry reads back as %q", got)
	}
	if bytes.Contains(m.data, []byte("hello")) {
		t.Fatal("the removed entry's body is still in the archive")
	}
}

// TestUpdaterRemoveSizesAZip64Descriptor pins the other length: an entry
// written in the zip64 shape carries a descriptor eight bytes longer, and
// whether it did is what the archive's own zip64 record says rather than what
// its sizes turn out to be.
func TestUpdaterRemoveSizesAZip64Descriptor(t *testing.T) {
	body := []byte("hello")
	kept := []byte("the entry that stays")

	z := make([]byte, 4+24)
	binary.LittleEndian.PutUint16(z[0:2], zip64ExtraID)
	binary.LittleEndian.PutUint16(z[2:4], 24)
	// #nosec G115 -- the body is five bytes
	binary.LittleEndian.PutUint64(z[4:12], uint64(len(body)))
	// #nosec G115 -- the body is five bytes
	binary.LittleEndian.PutUint64(z[12:20], uint64(len(body)))

	dd := make([]byte, 24)
	binary.LittleEndian.PutUint32(dd[0:4], dataDescriptorSignature)
	binary.LittleEndian.PutUint32(dd[4:8], crc32.ChecksumIEEE(body))
	// #nosec G115 -- the body is five bytes
	binary.LittleEndian.PutUint64(dd[8:16], uint64(len(body)))
	// #nosec G115 -- the body is five bytes
	binary.LittleEndian.PutUint64(dd[16:24], uint64(len(body)))

	raw := extentFixture(extentEntry{
		name:          "gone.txt",
		body:          body,
		flags:         0x8,
		tail:          dd,
		cdExtra:       z,
		sentinelSizes: true,
		cdOffset:      -1,
		cdSize:        -1,
	}, extentEntry{
		name:     "kept.txt",
		body:     kept,
		cdOffset: -1,
		cdSize:   -1,
	})

	m := &memFile{data: raw}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if _, err := u.RemoveFile(entryIndex(t, u, "gone.txt")); err != nil {
		t.Fatalf("RemoveFile: %v", err)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got, err := entryBody(m.data, "kept.txt")
	if err != nil {
		t.Fatalf("the surviving entry: %v", err)
	}
	if !bytes.Equal(got, kept) {
		t.Fatalf("the surviving entry reads back as %q", got)
	}
}

// TestUpdaterRemoveRefusesAnUnreadableLocalHeader pins the case where the
// extent cannot be worked out at all.
func TestUpdaterRemoveRefusesAnUnreadableLocalHeader(t *testing.T) {
	var built bytes.Buffer
	w := NewWriter(&built)
	for _, name := range []string{"a.txt", "b.txt"} {
		fw, err := w.CreateHeader(&FileHeader{Name: name, Method: Store})
		if err != nil {
			t.Fatalf("%s: CreateHeader: %v", name, err)
		}
		if _, err := fw.Write([]byte("hello")); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw := built.Bytes()
	// Break the first entry's local header signature.
	raw[0] = 'Q'

	m := &memFile{data: append([]byte(nil), raw...)}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if _, err := u.RemoveFile(1); !errors.Is(err, ErrFormat) {
		t.Fatalf("the removal answered %v, not a refusal of a malformed archive", err)
	}
}

// seekIndexedArchive writes one entry carrying a seek index, with a plain
// entry on either side of it, and answers the archive and the index's hidden
// name.
func seekIndexedArchive(t *testing.T, indexed string) ([]byte, string) {
	t.Helper()
	body := make([]byte, 8192)
	for i := range body {
		body[i] = byte('a' + i%26)
	}

	var buf bytes.Buffer
	w := NewWriter(&buf)
	for _, name := range []string{"before.txt", indexed, "after.txt"} {
		fh := &FileHeader{Name: name, Method: Store}
		content := []byte("the body of " + name)
		if name == indexed {
			fh.Method = Deflate
			fh.SeekChunkSize = 1024
			content = body
		}
		fw, err := w.CreateHeader(fh)
		if err != nil {
			t.Fatalf("%s: CreateHeader: %v", name, err)
		}
		if _, err := fw.Write(content); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	dir, name := path.Split(indexed)
	hidden := dir + "." + name + ".sozip.idx"
	if !bytes.Contains(buf.Bytes(), []byte(hidden)) {
		t.Fatalf("the writer produced no seek index named %q", hidden)
	}
	return buf.Bytes(), hidden
}

// TestUpdaterRemoveTakesTheEntrysSeekIndexWithIt pins that the index this
// package hides behind an entry goes when the entry goes: it is the entry's
// own tail, and leaving it behind would leave the removed entry's chunk
// offsets in an archive that says the entry is gone.
func TestUpdaterRemoveTakesTheEntrysSeekIndexWithIt(t *testing.T) {
	raw, hidden := seekIndexedArchive(t, "indexed.bin")

	m := &memFile{data: append([]byte(nil), raw...)}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if _, err := u.RemoveFile(entryIndex(t, u, "indexed.bin")); err != nil {
		t.Fatalf("RemoveFile: %v", err)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if bytes.Contains(m.data, []byte(hidden)) {
		t.Errorf("the removed entry's seek index %q is still in the archive", hidden)
	}
	r, err := NewReader(bytes.NewReader(m.data), int64(len(m.data)))
	if err != nil {
		t.Fatalf("the reader rejects the result: %v", err)
	}
	if len(r.File) != 2 {
		t.Fatalf("the archive holds %d entries after one removal of three", len(r.File))
	}
	for _, name := range []string{"before.txt", "after.txt"} {
		got, err := entryBody(m.data, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(got) != "the body of "+name {
			t.Fatalf("%s reads back as %q", name, got)
		}
	}
}

// TestUpdaterRemoveKeepsASeekIndexItShiftsDown pins the other side: an index
// belonging to an entry that stays comes down with it and still works.
func TestUpdaterRemoveKeepsASeekIndexItShiftsDown(t *testing.T) {
	raw, _ := seekIndexedArchive(t, "indexed.bin")

	before, err := entryBody(raw, "indexed.bin")
	if err != nil {
		t.Fatalf("the indexed entry does not read before the edit: %v", err)
	}

	m := &memFile{data: append([]byte(nil), raw...)}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if _, err := u.RemoveFile(entryIndex(t, u, "before.txt")); err != nil {
		t.Fatalf("RemoveFile: %v", err)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r, err := NewReader(bytes.NewReader(m.data), int64(len(m.data)))
	if err != nil {
		t.Fatalf("the reader rejects the result: %v", err)
	}
	var indexed *File
	for _, f := range r.File {
		if f.Name == "indexed.bin" {
			indexed = f
		}
	}
	if indexed == nil {
		t.Fatal("the indexed entry is gone")
	}
	rs, err := indexed.OpenSeekable()
	if err != nil {
		t.Fatalf("the entry's seek index did not survive the shift: %v", err)
	}
	got, err := io.ReadAll(rs)
	if err != nil {
		t.Fatalf("reading through the index: %v", err)
	}
	if !bytes.Equal(got, before) {
		t.Fatalf("the entry reads back as %d bytes through its index and held %d", len(got), len(before))
	}
}

// TestUpdaterRemoveLeavesAStrayLocalEntryAlone pins the limit of the rule
// above: a local entry no central record claims, whose name is not this
// entry's index, was written by something else and stays where it is.
func TestUpdaterRemoveLeavesAStrayLocalEntryAlone(t *testing.T) {
	stray := localHeaderFor("stranger.txt")
	stray = append(stray, "bytes another tool left behind"...)
	// #nosec G115 -- the payload is thirty bytes
	binary.LittleEndian.PutUint32(stray[18:22], uint32(len(stray)-fileHeaderLen-len("stranger.txt")))
	// #nosec G115 -- the payload is thirty bytes
	binary.LittleEndian.PutUint32(stray[22:26], uint32(len(stray)-fileHeaderLen-len("stranger.txt")))

	raw := extentFixture(extentEntry{
		name:     "gone.txt",
		body:     []byte("the entry to remove"),
		cdOffset: -1,
		cdSize:   -1,
	}, extentEntry{
		// The stray sits between the two, as a body no central record
		// describes: the fixture writes a header of its own for it and
		// then never names it, which is the shape an orphan has.
		name:     "kept.txt",
		body:     []byte("the entry that stays"),
		cdOffset: -1,
		cdSize:   -1,
	})
	// Splice the stray in behind the first entry, and move the second
	// entry's record and the directory itself along by its length.
	at := fileHeaderLen + len("gone.txt") + len("the entry to remove")
	spliced := append([]byte(nil), raw[:at]...)
	spliced = append(spliced, stray...)
	spliced = append(spliced, raw[at:]...)
	cd := bytes.Index(spliced, []byte{'P', 'K', 0x01, 0x02})
	second := bytes.Index(spliced[cd+46:], []byte{'P', 'K', 0x01, 0x02}) + cd + 46
	// #nosec G115 -- the fixture is a few hundred bytes
	binary.LittleEndian.PutUint32(spliced[second+42:second+46],
		binary.LittleEndian.Uint32(spliced[second+42:second+46])+uint32(len(stray)))
	eocd := bytes.LastIndex(spliced, []byte{'P', 'K', 0x05, 0x06})
	// #nosec G115 -- the fixture is a few hundred bytes
	binary.LittleEndian.PutUint32(spliced[eocd+16:eocd+20], uint32(cd))

	if _, err := NewReader(bytes.NewReader(spliced), int64(len(spliced))); err != nil {
		t.Fatalf("the archive with the stray entry does not read: %v", err)
	}

	m := &memFile{data: append([]byte(nil), spliced...)}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if _, err := u.RemoveFile(entryIndex(t, u, "gone.txt")); err != nil {
		t.Fatalf("RemoveFile: %v", err)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !bytes.Contains(m.data, []byte("bytes another tool left behind")) {
		t.Error("a local entry this package did not write was cut with the entry before it")
	}
	got, err := entryBody(m.data, "kept.txt")
	if err != nil {
		t.Fatalf("the surviving entry: %v", err)
	}
	if string(got) != "the entry that stays" {
		t.Fatalf("the surviving entry reads back as %q", got)
	}
}

// TestUpdaterRemoveRefusesAnUnreadableSeekIndex pins that an index whose own
// header cannot be read through leaves the extent unknown, so nothing is cut.
func TestUpdaterRemoveRefusesAnUnreadableSeekIndex(t *testing.T) {
	// A local header behind the entry, stored, claiming a name longer than
	// the archive: whatever it is, its length cannot be worked out.
	tail := make([]byte, fileHeaderLen)
	binary.LittleEndian.PutUint32(tail[0:4], fileHeaderSignature)
	binary.LittleEndian.PutUint16(tail[4:6], 20)
	binary.LittleEndian.PutUint16(tail[8:10], Store)
	binary.LittleEndian.PutUint16(tail[26:28], 0xffff)

	raw := extentFixture(extentEntry{
		name:     "gone.txt",
		body:     []byte("the entry to remove"),
		tail:     tail,
		cdOffset: -1,
		cdSize:   -1,
	})

	m := &memFile{data: raw}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if _, err := u.RemoveFile(0); !errors.Is(err, ErrFormat) {
		t.Fatalf("the removal answered %v, not a refusal of a malformed archive", err)
	}
}

// TestUpdaterRemoveRefusesASeekIndexPastTheDirectory pins the bound on the
// index, as on everything else the extent is made of.
func TestUpdaterRemoveRefusesASeekIndexPastTheDirectory(t *testing.T) {
	hidden := ".gone.txt.sozip.idx"
	tail := make([]byte, fileHeaderLen)
	binary.LittleEndian.PutUint32(tail[0:4], fileHeaderSignature)
	binary.LittleEndian.PutUint16(tail[4:6], 20)
	binary.LittleEndian.PutUint16(tail[8:10], Store)
	binary.LittleEndian.PutUint32(tail[18:22], 1<<20)
	binary.LittleEndian.PutUint32(tail[22:26], 1<<20)
	// #nosec G115 -- the hidden name is nineteen bytes
	binary.LittleEndian.PutUint16(tail[26:28], uint16(len(hidden)))
	tail = append(tail, hidden...)

	raw := extentFixture(extentEntry{
		name:     "gone.txt",
		body:     []byte("the entry to remove"),
		tail:     tail,
		cdOffset: -1,
		cdSize:   -1,
	})

	m := &memFile{data: raw}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if _, err := u.RemoveFile(0); !errors.Is(err, ErrFormat) {
		t.Fatalf("the removal answered %v, not a refusal of a malformed archive", err)
	}
}

// TestUpdaterRemoveKeepsAListedIndexLikeEntry pins the limit on the other
// side: an archive may perfectly well hold an entry of its own named the way
// this package names a seek index, sitting right behind the entry it is named
// after. The central directory lists it, so it is an entry and not an index,
// and removing its neighbour leaves it whole.
func TestUpdaterRemoveKeepsAListedIndexLikeEntry(t *testing.T) {
	indexLike := ".gone.txt.sozip.idx"
	kept := []byte("what the listed index-like entry holds")

	var built bytes.Buffer
	w := NewWriter(&built)
	for _, e := range []struct {
		name string
		body []byte
	}{
		{"gone.txt", []byte("the entry to remove")},
		{indexLike, kept},
		{"after.txt", []byte("the entry after it")},
	} {
		fw, err := w.CreateHeader(&FileHeader{Name: e.name, Method: Store})
		if err != nil {
			t.Fatalf("%s: CreateHeader: %v", e.name, err)
		}
		if _, err := fw.Write(e.body); err != nil {
			t.Fatalf("%s: write: %v", e.name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	raw := built.Bytes()

	m := &memFile{data: append([]byte(nil), raw...)}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if _, err := u.RemoveFile(entryIndex(t, u, "gone.txt")); err != nil {
		t.Fatalf("RemoveFile: %v", err)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got, err := entryBody(m.data, indexLike)
	if err != nil {
		t.Fatalf("the listed index-like entry: %v", err)
	}
	if !bytes.Equal(got, kept) {
		t.Fatalf("the listed index-like entry reads back as %q", got)
	}
	if _, err := entryBody(m.data, "after.txt"); err != nil {
		t.Fatalf("the entry after it: %v", err)
	}
}

// TestUpdaterRemoveRefusesALocalHeaderPastTheDirectory pins the sub-case where
// the header alone is already over the line, before any size is weighed.
func TestUpdaterRemoveRefusesALocalHeaderPastTheDirectory(t *testing.T) {
	raw := extentFixture(extentEntry{
		name:     "a.txt",
		body:     []byte("hello"),
		cdOffset: -1,
		cdSize:   -1,
	})
	// Claim a name far longer than the entry has, so the local header runs
	// past where the central directory begins.
	binary.LittleEndian.PutUint16(raw[26:28], 0xffff)

	m := &memFile{data: raw}
	u, err := NewUpdater(m)
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	if _, err := u.RemoveFile(0); !errors.Is(err, ErrFormat) {
		t.Fatalf("the removal answered %v, not a refusal of a malformed archive", err)
	}
}
