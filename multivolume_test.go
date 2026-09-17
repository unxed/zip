package zip

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// mvPattern returns n bytes that differ from every other pattern with a
// different seed, so that a read landing in the wrong volume or at the wrong
// offset shows up as a content mismatch and not as a coincidence.
func mvPattern(n, seed int) []byte {
	b := make([]byte, n)
	v := byte(1)
	for i := 0; i < seed; i++ {
		v += 7
	}
	for i := range b {
		b[i] = v
		v += 31
	}
	return b
}

// mvWriteVolumes lays a volume set out in dir: the first parts become
// base.z01, base.z02 and so on, and the last one becomes base.zip. It returns
// the path of that main volume, which is the name the reader is opened by.
func mvWriteVolumes(t *testing.T, dir, base string, parts ...[]byte) string {
	t.Helper()
	if len(parts) == 0 {
		t.Fatal("a volume set needs at least the main volume")
	}
	for i, p := range parts[:len(parts)-1] {
		name := fmt.Sprintf("%s.z%02d", base, i+1)
		mustWriteFile(t, filepath.Join(dir, name), p, 0o600)
	}
	main := filepath.Join(dir, base+".zip")
	mustWriteFile(t, main, parts[len(parts)-1], 0o600)
	return main
}

// mvOpen opens a volume set and registers the handles for release.
func mvOpen(t *testing.T, main string, flag int) (*MultiVolumeReader, int64) {
	t.Helper()
	mvr, size, err := OpenMultiVolume(main, flag)
	if err != nil {
		t.Fatalf("open %s: %v", main, err)
	}
	closeAt(t, mvr)
	return mvr, size
}

func TestMultiVolumeReader_ReadAt(t *testing.T) {
	tmp := t.TempDir()

	// Create two volumes: .z01 (5 bytes) and .zip (5 bytes)
	vol1Path := filepath.Join(tmp, "test.z01")
	zipPath := filepath.Join(tmp, "test.zip")

	mustWriteFile(t, vol1Path, []byte("12345"), 0644)
	mustWriteFile(t, zipPath, []byte("67890"), 0644)

	ra, size, err := OpenMultiVolume(zipPath, os.O_RDONLY)
	if err != nil {
		t.Fatalf("failed to open multivolume: %v", err)
	}
	closeAt(t, ra)

	if size != 10 {
		t.Errorf("expected size 10, got %d", size)
	}

	// Test reading at the volume boundary
	buf := make([]byte, 4)
	n, err := ra.ReadAt(buf, 3) // Should read '45' from the first and '67' from the second
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt error: %v", err)
	}
	if n != 4 || string(buf) != "4567" {
		t.Errorf("boundary read failed: got %q", string(buf))
	}
}

func TestMultiVolumeReader_Casing(t *testing.T) {
	tmp := t.TempDir()

	// Create uppercase volumes: .Z01 (5 bytes) and .ZIP (5 bytes)
	vol1Path := filepath.Join(tmp, "test_case.Z01")
	zipPath := filepath.Join(tmp, "test_case.ZIP")

	mustWriteFile(t, vol1Path, []byte("ABCDE"), 0644)
	mustWriteFile(t, zipPath, []byte("FGHIJ"), 0644)

	ra, size, err := OpenMultiVolume(zipPath, os.O_RDONLY)
	if err != nil {
		t.Fatalf("failed to open multivolume: %v", err)
	}
	closeAt(t, ra)

	if size != 10 {
		t.Errorf("expected size 10, got %d", size)
	}

	buf := make([]byte, 10)
	n, err := ra.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt error: %v", err)
	}
	if n != 10 || string(buf) != "ABCDEFGHIJ" {
		t.Errorf("casing read failed: got %q", string(buf))
	}
}
func TestMultiVolumeWriter_Roundtrip(t *testing.T) {
	tmp := t.TempDir()
	mainPath := filepath.Join(tmp, "test_write.zip")
	splitSize := int64(10) // 10 bytes per volume

	mvw, err := NewMultiVolumeWriter(mainPath, splitSize)
	if err != nil {
		t.Fatalf("failed to create MultiVolumeWriter: %v", err)
	}
	closeAt(t, mvw)

	data := []byte("abcdefghijklmnopqrstuvwxyz") // 26 bytes -> .001(10), .002(10), .003(6)
	if _, err := mvw.Write(data); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := mvw.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	for _, part := range []string{".001", ".002", ".003"} {
		if _, err := os.Stat(mainPath + part); err != nil {
			t.Errorf("missing volume %s", part)
		}
	}
	if _, err := os.Stat(mainPath); !os.IsNotExist(err) {
		t.Errorf("a file was written under the archive name itself: %v", err)
	}

	mvr, totalSize, err := OpenMultiVolume(mainPath, os.O_RDONLY)
	if err != nil {
		t.Fatalf("failed to open multi-volume reader: %v", err)
	}
	closeAt(t, mvr)

	if totalSize != int64(len(data)) {
		t.Errorf("expected size %d, got %d", len(data), totalSize)
	}

	buf := make([]byte, len(data))
	if _, err := mvr.ReadAt(buf, 0); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(buf) != string(data) {
		t.Errorf("content mismatch: got %q, want %q", string(buf), string(data))
	}
}

// TestMultiVolumeWriterSplitsOnDisk pins down what the writer leaves on disk:
// every volume but the last holds exactly splitSize bytes, the parts are
// numbered after the archive's name from .001 upwards, the last one holds the
// tail, and volumes past it and a file under the archive's own name, left by
// an earlier archive of that name, are gone. Without this a writer that
// started numbering at .000, or left a stale part to be read back, would still
// pass a round trip through OpenMultiVolume, because the reader would follow
// the same wrong rule.
func TestMultiVolumeWriterSplitsOnDisk(t *testing.T) {
	tmp := t.TempDir()
	main := filepath.Join(tmp, "split.zip")
	const volSize = 1024

	mustWriteFile(t, main, []byte("an archive written here before"), 0o600)
	mustWriteFile(t, main+".004", []byte("a volume of an archive written here before"), 0o600)

	mvw, err := NewMultiVolumeWriter(main, volSize)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	closeAt(t, mvw)

	// 2560 bytes at 1024 per volume: .001, .002 and 512 bytes left for
	// .003. The data goes out in chunks that do not line up with the
	// volume size, so a chunk has to be split across a boundary.
	var want []byte
	for i := 0; i < 5; i++ {
		chunk := mvPattern(512, i)
		mustWrite(t, mvw, chunk)
		want = append(want, chunk...)
	}
	// An empty write must not start a volume of its own, which is what a
	// splitter that decided on the next volume before looking at the data
	// would do.
	if n, err := mvw.Write(nil); err != nil || n != 0 {
		t.Errorf("empty write returned %d, %v, want 0 and no error", n, err)
	}
	if err := mvw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	for _, part := range []struct {
		path string
		size int64
	}{
		{main + ".001", volSize},
		{main + ".002", volSize},
		{main + ".003", 512},
	} {
		fi, err := os.Stat(part.path)
		if err != nil {
			t.Fatalf("stat %s: %v", part.path, err)
		}
		if fi.Size() != part.size {
			t.Errorf("%s holds %d bytes, want %d", part.path, fi.Size(), part.size)
		}
	}
	for _, stale := range []string{main, main + ".004"} {
		if _, err := os.Stat(stale); !os.IsNotExist(err) {
			t.Errorf("%s from the archive written before is still there: %v", stale, err)
		}
	}

	// By the archive's name and by the name of the first volume alike.
	first, _ := mvOpen(t, main+".001", os.O_RDONLY)
	if first.size != int64(len(want)) {
		t.Errorf("opened by the first volume, the set is %d bytes, want %d", first.size, len(want))
	}
	mvr, size := mvOpen(t, main, os.O_RDONLY)
	if size != int64(len(want)) {
		t.Fatalf("reopened size %d, want %d", size, len(want))
	}
	got := make([]byte, len(want))
	if _, err := mvr.ReadAt(got, 0); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Error("the concatenated volumes differ from what was written")
	}
}

// TestMultiVolumeArchiveRoundTrip writes a real archive through the splitting
// writer and reads it back through the public OpenReader, which is the way the
// feature is actually used. The entries are stored uncompressed so that they
// are certain to outgrow one volume; what this pins down is that a central
// directory written at the end of the last volume still describes offsets that
// resolve inside the earlier ones.
func TestMultiVolumeArchiveRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	main := filepath.Join(tmp, "archive.zip")

	mvw, err := NewMultiVolumeWriter(main, 4096)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	closeAt(t, mvw)

	zw := NewWriter(mvw)
	closeAt(t, zw)
	want := make(map[string][]byte, 3)
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("part%d.bin", i)
		body := mvPattern(4000, i)
		w := mustCreateHeader(t, zw, &FileHeader{Name: name, Method: Store})
		mustWrite(t, w, body)
		want[name] = body
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	if err := mvw.Close(); err != nil {
		t.Fatalf("close volumes: %v", err)
	}

	if _, err := os.Stat(main + ".002"); err != nil {
		t.Fatalf("the archive did not span more than one volume: %v", err)
	}

	rc, err := OpenReader(main)
	if err != nil {
		t.Fatalf("open the archive back: %v", err)
	}
	closeAt(t, rc)
	if len(rc.File) != len(want) {
		t.Fatalf("read back %d entries, want %d", len(rc.File), len(want))
	}
	for _, f := range rc.File {
		rd, err := f.Open()
		if err != nil {
			t.Fatalf("open entry %q: %v", f.Name, err)
		}
		got, err := io.ReadAll(rd)
		if err != nil {
			t.Fatalf("read entry %q: %v", f.Name, err)
		}
		if err := rd.Close(); err != nil {
			t.Fatalf("close entry %q: %v", f.Name, err)
		}
		if !bytes.Equal(got, want[f.Name]) {
			t.Errorf("entry %q came back with %d bytes of different content", f.Name, len(got))
		}
	}
}

// TestMultiVolumeReaderReadAtRanges walks the cases ReadAt has to tell apart:
// a range inside one volume, one that crosses into the next, the tail of the
// set, and offsets outside it. The tail read is the interesting one -- it has
// to report the bytes it did get together with io.EOF, because a caller that
// sees only the error would treat a good archive as truncated.
func TestMultiVolumeReaderReadAtRanges(t *testing.T) {
	tmp := t.TempDir()
	main := mvWriteVolumes(t, tmp, "ranges",
		[]byte("AAAAA"), []byte("BBBBB"), []byte("CC"))

	mvr, size := mvOpen(t, main, os.O_RDONLY)
	if size != 12 {
		t.Fatalf("size %d, want 12", size)
	}

	tests := []struct {
		name    string
		off     int64
		bufLen  int
		wantN   int
		wantStr string
		wantErr error
	}{
		{"inside the first volume", 1, 3, 3, "AAA", nil},
		{"exactly one whole volume", 5, 5, 5, "BBBBB", nil},
		{"across one boundary", 3, 4, 4, "AABB", nil},
		{"across two boundaries", 4, 7, 7, "ABBBBBC", nil},
		{"tail shorter than the buffer", 10, 5, 2, "CC", io.EOF},
		{"first byte past the end", 12, 4, 0, "", io.EOF},
		{"far past the end", 400, 4, 0, "", io.EOF},
		{"negative offset", -1, 4, 0, "", io.EOF},
		{"empty buffer inside the set", 6, 0, 0, "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, tc.bufLen)
			n, err := mvr.ReadAt(buf, tc.off)
			if err != tc.wantErr {
				t.Errorf("error %v, want %v", err, tc.wantErr)
			}
			if n != tc.wantN {
				t.Errorf("read %d bytes, want %d", n, tc.wantN)
			}
			if got := string(buf[:n]); got != tc.wantStr {
				t.Errorf("read %q, want %q", got, tc.wantStr)
			}
		})
	}
}

// TestMultiVolumeReaderWriteAt patches bytes in place through the joined
// stream and checks the volumes on disk afterwards, because a write that
// landed in the right volume at the wrong offset, or that spilled the whole
// buffer into the first volume, would still read back correctly through the
// same wrong offset arithmetic.
func TestMultiVolumeReaderWriteAt(t *testing.T) {
	tmp := t.TempDir()
	main := mvWriteVolumes(t, tmp, "patch",
		[]byte("12345"), []byte("67890"))

	mvr, size := mvOpen(t, main, os.O_RDWR)
	if size != 10 {
		t.Fatalf("size %d, want 10", size)
	}

	// A write that stays inside the first volume.
	n, err := mvr.WriteAt([]byte("ab"), 1)
	if err != nil {
		t.Fatalf("write inside a volume: %v", err)
	}
	if n != 2 {
		t.Errorf("wrote %d bytes inside a volume, want 2", n)
	}

	// A write that starts in the first volume and ends in the second.
	n, err = mvr.WriteAt([]byte("cdef"), 3)
	if err != nil {
		t.Fatalf("write across the boundary: %v", err)
	}
	if n != 4 {
		t.Errorf("wrote %d bytes across the boundary, want 4", n)
	}

	// The set does not grow: a write running off the end stores what fits
	// and reports the rest as out of bounds rather than extending the last
	// volume, which would move every offset in the archive behind it.
	n, err = mvr.WriteAt([]byte("XYZ"), 9)
	if err == nil {
		t.Error("a write past the end of the last volume was accepted")
	}
	if n != 1 {
		t.Errorf("a write past the end stored %d bytes, want 1", n)
	}

	if _, err := mvr.WriteAt([]byte("Q"), -1); err == nil {
		t.Error("a write at a negative offset was accepted")
	}
	if _, err := mvr.WriteAt([]byte("Q"), 10); err == nil {
		t.Error("a write starting past the end was accepted")
	}

	if err := mvr.Close(); err != nil {
		t.Fatalf("close the volumes: %v", err)
	}

	prefix := main[:len(main)-len(".zip")]
	for _, part := range []struct {
		path string
		want string
	}{
		{prefix + ".z01", "1abcd"},
		{main, "ef89X"},
	} {
		got, err := os.ReadFile(part.path)
		if err != nil {
			t.Fatalf("read %s: %v", part.path, err)
		}
		if string(got) != part.want {
			t.Errorf("%s holds %q, want %q", part.path, got, part.want)
		}
	}
}

// TestMultiVolumeReaderAppend pins down that Append lands at the end of the
// last volume and not at the end of the first, and that the joined size grows
// by what was appended so the new bytes are readable through ReadAt straight
// away.
func TestMultiVolumeReaderAppend(t *testing.T) {
	tmp := t.TempDir()
	main := mvWriteVolumes(t, tmp, "append",
		[]byte("12345"), []byte("67890"))

	mvr, size := mvOpen(t, main, os.O_RDWR)
	if size != 10 {
		t.Fatalf("size %d, want 10", size)
	}

	if err := mvr.Append([]byte("XY")); err != nil {
		t.Fatalf("append: %v", err)
	}

	buf := make([]byte, 4)
	n, err := mvr.ReadAt(buf, 8)
	if err != nil {
		t.Fatalf("read the appended bytes: %v", err)
	}
	if n != 4 || string(buf) != "90XY" {
		t.Errorf("read %q after appending, want %q", string(buf[:n]), "90XY")
	}

	if err := mvr.Close(); err != nil {
		t.Fatalf("close the volumes: %v", err)
	}
	got, err := os.ReadFile(main)
	if err != nil {
		t.Fatalf("read %s: %v", main, err)
	}
	if string(got) != "67890XY" {
		t.Errorf("the main volume holds %q, want %q", got, "67890XY")
	}
	prefix := main[:len(main)-len(".zip")]
	first, err := os.ReadFile(prefix + ".z01")
	if err != nil {
		t.Fatalf("read the first volume: %v", err)
	}
	if string(first) != "12345" {
		t.Errorf("appending changed the first volume to %q", first)
	}
}

// TestOpenMultiVolumeShapes covers the sets OpenMultiVolume has to recognise
// from the main name alone: a lone .zip with no parts beside it, a .zipx, a
// name that is not an archive extension at all, and a set whose numbering
// stops before the parts on disk do.
func TestOpenMultiVolumeShapes(t *testing.T) {
	t.Run("a single zip with no parts", func(t *testing.T) {
		tmp := t.TempDir()
		main := mvWriteVolumes(t, tmp, "alone", []byte("0123456789"))
		mvr, size := mvOpen(t, main, os.O_RDONLY)
		if size != 10 {
			t.Fatalf("size %d, want 10", size)
		}
		if len(mvr.files) != 1 {
			t.Errorf("opened %d handles for a single file", len(mvr.files))
		}
		buf := make([]byte, 10)
		if _, err := mvr.ReadAt(buf, 0); err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf) != "0123456789" {
			t.Errorf("read %q", buf)
		}
	})

	t.Run("a zipx with parts", func(t *testing.T) {
		tmp := t.TempDir()
		mustWriteFile(t, filepath.Join(tmp, "wide.z01"), []byte("AAAA"), 0o600)
		main := filepath.Join(tmp, "wide.zipx")
		mustWriteFile(t, main, []byte("BB"), 0o600)

		mvr, size := mvOpen(t, main, os.O_RDONLY)
		if size != 6 {
			t.Fatalf("size %d, want 6", size)
		}
		buf := make([]byte, 6)
		if _, err := mvr.ReadAt(buf, 0); err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf) != "AAAABB" {
			t.Errorf("read %q, want %q", buf, "AAAABB")
		}
	})

	t.Run("a name that is not an archive extension", func(t *testing.T) {
		tmp := t.TempDir()
		// A part named .z01 next to it must be ignored: the caller asked
		// for one file by name and gets exactly that file.
		mustWriteFile(t, filepath.Join(tmp, "plain.z01"), []byte("AAAA"), 0o600)
		plain := filepath.Join(tmp, "plain.dat")
		mustWriteFile(t, plain, []byte("BB"), 0o600)

		mvr, size := mvOpen(t, plain, os.O_RDONLY)
		if size != 2 {
			t.Fatalf("size %d, want 2", size)
		}
		buf := make([]byte, 2)
		if _, err := mvr.ReadAt(buf, 0); err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf) != "BB" {
			t.Errorf("read %q, want %q", buf, "BB")
		}
	})

	t.Run("a gap in the numbering ends the set", func(t *testing.T) {
		tmp := t.TempDir()
		main := mvWriteVolumes(t, tmp, "gap", []byte("AAAA"), []byte("CC"))
		// .z03 exists but .z02 does not, so the set is .z01 plus the main
		// name and the stray part stays out of it.
		mustWriteFile(t, filepath.Join(tmp, "gap.z03"), []byte("ZZZZZZ"), 0o600)

		mvr, size := mvOpen(t, main, os.O_RDONLY)
		if size != 6 {
			t.Fatalf("size %d, want 6", size)
		}
		buf := make([]byte, 6)
		if _, err := mvr.ReadAt(buf, 0); err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf) != "AAAACC" {
			t.Errorf("read %q, want %q", buf, "AAAACC")
		}
	})
}

// TestMultiVolumeWriterSyncAndName checks the two accessors the archiver calls
// on a writer it cannot see inside: Name gives back the main archive name even
// while the bytes are still going into a numbered part, and Sync is safe both
// before and after the volumes are closed.
func TestMultiVolumeWriterSyncAndName(t *testing.T) {
	tmp := t.TempDir()
	main := filepath.Join(tmp, "sync.zip")

	mvw, err := NewMultiVolumeWriter(main, 8)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	closeAt(t, mvw)

	if got := mvw.Name(); got != main {
		t.Errorf("Name is %q, want the main archive name %q", got, main)
	}
	mustWrite(t, mvw, []byte("0123456789"))
	if err := mvw.Sync(); err != nil {
		t.Fatalf("sync an open volume: %v", err)
	}
	if err := mvw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// After Close there is no open volume left, and Sync has to say so by
	// succeeding rather than by dereferencing the handle it no longer has.
	if err := mvw.Sync(); err != nil {
		t.Fatalf("sync after close: %v", err)
	}
	if got := mvw.Name(); got != main {
		t.Errorf("Name after close is %q, want %q", got, main)
	}
}
