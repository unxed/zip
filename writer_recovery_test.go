package zip

// The tests here cover the hidden .recovery.par2 entry Writer.Close appends
// when the caller asked for PAR2 redundancy, the conditions that switch that
// entry off, and the write errors on the way to it. Nothing in the central
// directory points at the entry -- that is what "hidden" means here -- so a
// test that wants to look at one has to walk the local headers the way a
// repair tool would.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unxed/par2"
)

// recoveryEntry is the name Writer.Close gives the hidden PAR2 entry.
const recoveryEntry = ".recovery.par2"

// par2Magic starts every packet of a PAR2 stream.
const par2Magic = "PAR 2\x00PK"

// recoveryStamp is the modification time every fixture entry carries. The
// error tests build the same archive twice -- once to find where the recovery
// entry lands, once over a sink that fails there -- so the bytes have to come
// out the same both times, and a timestamp taken from the clock would not.
var recoveryStamp = time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)

// localHeaderEntry is one local file header found by scanning an archive.
type localHeaderEntry struct {
	headerOffset int
	dataOffset   int
	method       uint16
	payload      []byte
}

// findLocalEntry returns the entry named name, found by walking the local file
// headers rather than the central directory: the entries this writer hides --
// the PAR2 blob and the seek indexes -- are in neither the directory nor the
// list a reader hands back.
func findLocalEntry(t *testing.T, raw []byte, name string) (localHeaderEntry, bool) {
	t.Helper()
	sig := []byte{'P', 'K', 0x03, 0x04}
	for off := 0; off+fileHeaderLen <= len(raw); {
		rel := bytes.Index(raw[off:], sig)
		if rel < 0 {
			return localHeaderEntry{}, false
		}
		h := off + rel
		off = h + len(sig)
		if h+fileHeaderLen > len(raw) {
			continue
		}
		nameLen := int(binary.LittleEndian.Uint16(raw[h+26 : h+28]))
		extraLen := int(binary.LittleEndian.Uint16(raw[h+28 : h+30]))
		data := h + fileHeaderLen + nameLen + extraLen
		if data > len(raw) || string(raw[h+fileHeaderLen:h+fileHeaderLen+nameLen]) != name {
			continue
		}
		size := int(binary.LittleEndian.Uint32(raw[h+18 : h+22]))
		if data+size > len(raw) {
			t.Fatalf("entry %q says its %d bytes of data start at %d, past the end of the %d byte archive", name, size, data, len(raw))
		}
		return localHeaderEntry{
			headerOffset: h,
			dataOffset:   data,
			method:       binary.LittleEndian.Uint16(raw[h+8 : h+10]),
			payload:      raw[data : data+size],
		}, true
	}
	return localHeaderEntry{}, false
}

// writerWithBufferSize is NewWriter with a buffer of the caller's choosing. A
// Writer buffers 64 KiB, so nothing a small archive writes reaches the sink
// until Close flushes it; a one byte buffer puts every write straight through,
// which is what lets a test fail the one write it means to.
func writerWithBufferSize(w io.Writer, size int) *Writer {
	zw := NewWriter(w)
	zw.cw.w = bufio.NewWriterSize(w, size)
	return zw
}

// fillRecoveryArchive writes the same two entries into zw and closes it,
// returning what Close said. Every test below builds its archive through this
// so that the layout on disk and the layout a failing sink sees are the same
// bytes in the same order.
func fillRecoveryArchive(t *testing.T, zw *Writer) error {
	t.Helper()
	for _, e := range []struct {
		name string
		body []byte
	}{
		{"alpha.txt", bytes.Repeat([]byte("alpha "), 200)},
		{"beta.bin", bytes.Repeat([]byte{0x1f, 0x2e, 0x3d}, 300)},
	} {
		w := mustCreateHeader(t, zw, &FileHeader{
			Name:     e.name,
			Method:   Deflate,
			Modified: recoveryStamp,
		})
		mustWrite(t, w, e.body)
	}
	return zw.Close()
}

// openRecoverySource opens path for reading and writing. The recovery file is
// the archive itself: Writer.Close syncs it before reading it back, and on
// Windows a handle without write access cannot be synced.
func openRecoverySource(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	closeAt(t, f)
	return f
}

// TestWriterRecovery_Par2EntryCoversTheArchive is the feature itself: an
// archiver told to keep 10% redundancy has to finish with a stored
// .recovery.par2 entry whose contents are PAR2 recovery data for the archive
// as it stood on disk at that moment -- not for some earlier state of it, and
// not for nothing at all. The entry stays out of the central directory, and
// the archive around it still reads.
func TestWriterRecovery_Par2EntryCoversTheArchive(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	mustMkdirAll(t, src)
	contents := map[string]string{
		"notes.txt": strings.Repeat("recovery data covers the archive as it stands\n", 40),
		"data.bin":  strings.Repeat("0123456789abcdef", 120),
	}
	for name, body := range contents {
		mustWriteFile(t, filepath.Join(src, name), []byte(body), 0600)
	}

	archivePath := filepath.Join(tmp, "archive.zip")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create %s: %v", archivePath, err)
	}
	closeAt(t, f)

	a, err := NewArchiver(f, src, WithArchiverRecovery(10, f))
	if err != nil {
		t.Fatalf("new archiver: %v", err)
	}
	closeAt(t, a)

	files := make(map[string]os.FileInfo)
	if err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path != src {
			files[path] = info
		}
		return nil
	}); err != nil {
		t.Fatalf("walk %s: %v", src, err)
	}

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", archivePath, err)
	}

	raw, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("read %s: %v", archivePath, err)
	}

	entry, ok := findLocalEntry(t, raw, recoveryEntry)
	if !ok {
		t.Fatalf("the archive holds no %s entry although 10%% recovery was asked for", recoveryEntry)
	}
	if entry.method != Store {
		t.Errorf("the recovery entry is method %d, want %d (Store): recovery data must not need a decompressor to be usable", entry.method, Store)
	}
	if len(entry.payload) == 0 {
		t.Fatal("the recovery entry is empty")
	}
	if !strings.HasPrefix(string(entry.payload), par2Magic) {
		t.Fatalf("the recovery entry does not start with the PAR2 magic, got %q", string(entry.payload[:len(par2Magic)]))
	}

	mainPkt, fileDesc, ifsc, slices, err := par2.ParsePackets(entry.payload)
	if err != nil {
		t.Fatalf("the recovery entry is not a PAR2 stream: %v", err)
	}
	if mainPkt == nil || fileDesc == nil || ifsc == nil {
		t.Fatalf("the PAR2 stream is missing a packet: main=%v filedesc=%v ifsc=%v", mainPkt != nil, fileDesc != nil, ifsc != nil)
	}
	if len(slices) == 0 {
		t.Error("the PAR2 stream carries no recovery slices, so it can repair nothing")
	}
	if fileDesc.Name != filepath.Base(archivePath) {
		t.Errorf("the PAR2 stream names %q, want the archive %q", fileDesc.Name, filepath.Base(archivePath))
	}

	// The recovery entry sits between the last entry and the central
	// directory, and its data covers the archive up to its own local header
	// followed by the directory, which starts right after its body and ends
	// at the end of central directory record.
	cdStart := entry.dataOffset + len(entry.payload)
	eocd := bytes.LastIndex(raw, []byte("PK\x05\x06"))
	if eocd < 0 || string(raw[cdStart:cdStart+4]) != "PK\x01\x02" {
		t.Fatalf("the recovery entry is not followed by the central directory")
	}
	if got := int(binary.LittleEndian.Uint32(raw[eocd+16 : eocd+20])); got != cdStart {
		t.Errorf("the end of central directory record puts the directory at %d, it starts at %d", got, cdStart)
	}
	if got := int(binary.LittleEndian.Uint32(raw[eocd+12 : eocd+16])); got != eocd-cdStart {
		t.Errorf("the end of central directory record says the directory is %d bytes, it is %d: a reader walking it would reach something else", got, eocd-cdStart)
	}
	covered := append(append([]byte{}, raw[:entry.headerOffset]...), raw[cdStart:eocd]...)
	descLen, err := u64toi64(fileDesc.Length)
	if err != nil {
		t.Fatalf("PAR2 file length: %v", err)
	}
	if descLen != int64(len(covered)) {
		t.Errorf("the PAR2 stream covers %d bytes, want %d: the archive up to the recovery entry and the central directory", descLen, len(covered))
	}

	// A checksum out of the index, recomputed here, is what says the bytes
	// covered are these bytes. The first slice is zero padded to the slice
	// size, which is how the generator hashed it.
	sliceSize, err := u64toi64(mainPkt.SliceSize)
	if err != nil {
		t.Fatalf("PAR2 slice size: %v", err)
	}
	if sliceSize <= 0 || len(ifsc.Checksums) == 0 {
		t.Fatalf("the PAR2 stream has slice size %d and %d checksums", sliceSize, len(ifsc.Checksums))
	}
	first := make([]byte, sliceSize)
	copy(first, covered)
	if got, want := crc32.ChecksumIEEE(first), binary.LittleEndian.Uint32(ifsc.Checksums[0].CRC32[:]); got != want {
		t.Errorf("the first slice of the archive checksums to %08x, the index says %08x", got, want)
	}

	zr, err := OpenReader(archivePath)
	if err != nil {
		t.Fatalf("reopen %s: %v", archivePath, err)
	}
	closeAt(t, zr)

	seen := make(map[string]string, len(zr.File))
	for _, e := range zr.File {
		if e.Name == recoveryEntry {
			t.Errorf("the recovery entry is listed in the central directory; it is meant to stay out of the file list")
			continue
		}
		rc, err := e.Open()
		if err != nil {
			t.Fatalf("open entry %q: %v", e.Name, err)
		}
		body, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read entry %q: %v", e.Name, err)
		}
		if err := rc.Close(); err != nil {
			t.Fatalf("close entry %q: %v", e.Name, err)
		}
		seen[e.Name] = string(body)
	}
	for name, body := range contents {
		if seen[name] != body {
			t.Errorf("entry %q reads back as %d bytes, want %d: appending the recovery entry damaged the archive", name, len(seen[name]), len(body))
		}
	}
}

// TestWriterRecovery_Off pins the four conditions that keep the recovery entry
// out of the archive. Each of them is a reason the entry would be wrong or
// unreadable: no redundancy was asked for, there is no file to compute it
// from, torrentzip fixes the layout byte for byte, and an encrypted directory
// would leave a plain entry sitting behind it.
func TestWriterRecovery_Off(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, zw *Writer, f *os.File)
	}{
		{"no redundancy asked for", func(_ *testing.T, zw *Writer, f *os.File) {
			zw.recoveryPct = 0
			zw.recoveryFile = f
		}},
		{"no file to compute it from", func(_ *testing.T, zw *Writer, _ *os.File) {
			zw.recoveryPct = 10
			zw.recoveryFile = nil
		}},
		{"torrentzip", func(_ *testing.T, zw *Writer, f *os.File) {
			zw.recoveryPct = 10
			zw.recoveryFile = f
			zw.SetTorrentZip(true)
		}},
		{"encrypted central directory", func(_ *testing.T, zw *Writer, f *os.File) {
			zw.recoveryPct = 10
			zw.recoveryFile = f
			zw.SetEncryptCentralDirectory(true, "secret")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "archive.zip")
			f, err := os.Create(path)
			if err != nil {
				t.Fatalf("create %s: %v", path, err)
			}
			closeAt(t, f)

			zw := NewWriter(f)
			tc.setup(t, zw, f)
			if err := fillRecoveryArchive(t, zw); err != nil {
				t.Fatalf("close writer: %v", err)
			}
			if err := f.Close(); err != nil {
				t.Fatalf("close %s: %v", path, err)
			}

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if bytes.Contains(raw, []byte(recoveryEntry)) {
				t.Errorf("the archive holds a %s entry, which this setting is supposed to switch off", recoveryEntry)
			}
		})
	}
}

// TestWriterRecovery_WriteErrors walks the failures on the way to the recovery
// entry. Each one used to be dropped, and dropping any of them ends the same
// way: Close reports success over an archive that is short of the entry it
// says it wrote, or short of the bytes the entry was computed from.
func TestWriterRecovery_WriteErrors(t *testing.T) {
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "archive.zip")

	// One good run says where the recovery entry lands, so the runs below
	// can put a failing sink exactly there.
	good, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create %s: %v", archivePath, err)
	}
	closeAt(t, good)
	zw := NewWriter(good)
	zw.recoveryPct = 10
	zw.recoveryFile = good
	if err := fillRecoveryArchive(t, zw); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := good.Close(); err != nil {
		t.Fatalf("close %s: %v", archivePath, err)
	}
	raw, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("read %s: %v", archivePath, err)
	}
	entry, ok := findLocalEntry(t, raw, recoveryEntry)
	if !ok {
		t.Fatalf("the reference archive holds no %s entry", recoveryEntry)
	}
	if entry.headerOffset >= 64*1024 {
		t.Fatalf("the fixture archive is %d bytes, too big for the flush case to be the first write to the sink", entry.headerOffset)
	}

	for _, tc := range []struct {
		name string
		// bufSize is the writer's buffer: 64 KiB keeps the whole
		// archive out of the sink until the recovery step flushes it,
		// one byte puts every write through as it is made.
		bufSize  int
		limit    int
		accepted int
	}{
		{"the buffered archive has to reach the disk before it is read back", 64 * 1024, entry.headerOffset - 1, entry.headerOffset - 1},
		{"the recovery entry's header", 1, entry.headerOffset, entry.headerOffset},
		{"the recovery entry's name", 1, entry.headerOffset + fileHeaderLen, entry.headerOffset + fileHeaderLen},
		{"the recovery entry's body", 1, entry.dataOffset, entry.dataOffset},
		{"the central directory behind it", 1, entry.dataOffset + len(entry.payload), entry.dataOffset + len(entry.payload)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errSink := errors.New("the sink stopped taking bytes")
			sink := &cutoffWriter{limit: tc.limit, err: errSink}
			source := openRecoverySource(t, archivePath)

			zw := writerWithBufferSize(sink, tc.bufSize)
			zw.recoveryPct = 10
			zw.recoveryFile = source
			if err := fillRecoveryArchive(t, zw); !errors.Is(err, errSink) {
				t.Fatalf("Close returned %v, want the sink's error: the failure was swallowed and the caller told the archive was written", err)
			}
			if sink.written != tc.accepted {
				t.Errorf("the sink took %d bytes, expected the failure at %d", sink.written, tc.accepted)
			}
		})
	}

	t.Run("the archive on disk has to be in sync", func(t *testing.T) {
		// The recovery data is read back off the disk, so a Sync that
		// failed means it would be computed over whatever the operating
		// system had got around to writing.
		stale, err := os.Create(filepath.Join(t.TempDir(), "stale.zip"))
		if err != nil {
			t.Fatalf("create the stale file: %v", err)
		}
		if err := stale.Close(); err != nil {
			t.Fatalf("close the stale file: %v", err)
		}

		zw := NewWriter(new(bytes.Buffer))
		zw.recoveryPct = 10
		zw.recoveryFile = stale
		if err := fillRecoveryArchive(t, zw); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("Close returned %v, want the sync error on a closed file", err)
		}
	})
}

// TestWriterEncryptCD_WriteErrors covers the writes that lay down an encrypted
// central directory. The last of them is the authentication code, appended by
// closing the AES writer: without it the directory is one no reader can
// authenticate, and the caller was told the archive closed cleanly.
func TestWriterEncryptCD_WriteErrors(t *testing.T) {
	const password = "directory-secret"

	// A good run reports where the encrypted directory starts and how long
	// it is, so each case below can stop the sink at one of its writes.
	var start, size int64
	cal := NewWriter(new(bytes.Buffer))
	cal.SetEncryptCentralDirectory(true, password)
	cal.testHookCloseSizeOffset = func(sz, off uint64) {
		var err error
		if size, err = u64toi64(sz); err != nil {
			t.Errorf("central directory size: %v", err)
		}
		if start, err = u64toi64(off); err != nil {
			t.Errorf("central directory offset: %v", err)
		}
	}
	if err := fillRecoveryArchive(t, cal); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if start <= 0 || size <= 0 {
		t.Fatalf("the reference run reported directory offset %d and size %d", start, size)
	}

	for _, tc := range []struct {
		name  string
		limit int64
	}{
		// The salt and the password verifier open the stream, the
		// directory itself follows, and the last ten bytes are the
		// authentication code.
		{"the salt that opens the encrypted directory", start},
		{"the directory ciphertext", start + 18},
		{"the authentication code over it", start + size - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errSink := errors.New("the sink stopped taking bytes")
			sink := &cutoffWriter{limit: int(tc.limit), err: errSink}

			zw := writerWithBufferSize(sink, 1)
			zw.SetEncryptCentralDirectory(true, password)
			if err := fillRecoveryArchive(t, zw); !errors.Is(err, errSink) {
				t.Fatalf("Close returned %v, want the sink's error", err)
			}
			if int64(sink.written) != tc.limit {
				t.Errorf("the sink took %d bytes, expected the failure at %d", sink.written, tc.limit)
			}
		})
	}
}
