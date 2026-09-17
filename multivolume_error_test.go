package zip

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// The multivolume code reaches the file system on every operation, so most of
// its error handling only runs when a volume misbehaves. The two ways of
// arranging that here are portable: a handle that has already been closed
// fails every later operation with "file already closed" on both Windows and
// Linux, and a handle opened for reading rejects every write. Neither depends
// on file modes, which Windows does not enforce the way Unix does.

// mvClosedHandle creates a file under dir and hands back its handle already
// closed, which is the stand-in for a volume whose device is no longer there.
func mvClosedHandle(t *testing.T, dir, name string) *os.File {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
	return f
}

// mvReadOnlyHandle writes data to a file under dir and opens it for reading
// only, so that a write through the returned handle fails.
func mvReadOnlyHandle(t *testing.T, dir, name string, data []byte) *os.File {
	t.Helper()
	path := filepath.Join(dir, name)
	mustWriteFile(t, path, data, 0o600)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	closeAt(t, f)
	return f
}

// TestMultiVolumeReaderReadAtFailures covers what ReadAt does when a volume
// does not hand over the bytes the offset table says it holds. The failure has
// to travel back to the caller together with the count already read: a reader
// that swallowed the error and reported a short read would look to the archive
// code exactly like a truncated archive, and one that reported the error
// without the count would lose bytes it had already copied into the buffer.
func TestMultiVolumeReaderReadAtFailures(t *testing.T) {
	t.Run("a volume that cannot be read", func(t *testing.T) {
		tmp := t.TempDir()
		mvr := &MultiVolumeReader{
			files:   []*os.File{mvClosedHandle(t, tmp, "dead.z01")},
			offsets: []int64{0},
			size:    8,
		}
		n, err := mvr.ReadAt(make([]byte, 4), 0)
		if err == nil {
			t.Fatal("a read from an unusable volume reported success")
		}
		if err == io.EOF {
			t.Error("an unusable volume was reported as the end of the archive")
		}
		if n != 0 {
			t.Errorf("read %d bytes from an unusable volume", n)
		}
	})

	t.Run("a volume shorter than the recorded size", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "short.zip")
		mustWriteFile(t, path, []byte("12345"), 0o600)
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		closeAt(t, f)

		// The recorded size is larger than the volume, which is what a
		// set looks like when a part was truncated after it was opened.
		mvr := &MultiVolumeReader{files: []*os.File{f}, offsets: []int64{0}, size: 10}
		buf := make([]byte, 8)
		n, err := mvr.ReadAt(buf, 0)
		if err != io.EOF {
			t.Errorf("error %v, want io.EOF", err)
		}
		if n != 5 || string(buf[:n]) != "12345" {
			t.Errorf("read %q, want the 5 bytes the volume really holds", buf[:n])
		}
	})

	t.Run("an offset no volume covers", func(t *testing.T) {
		tmp := t.TempDir()
		f := mvReadOnlyHandle(t, tmp, "gap.zip", []byte("12345"))
		// A table whose first volume does not start at zero leaves a
		// hole below it. Nothing in this package builds such a table,
		// and the point of the case is that a hole reads as the end of
		// the archive instead of silently reading the wrong volume.
		mvr := &MultiVolumeReader{files: []*os.File{f}, offsets: []int64{4}, size: 9}
		if n, err := mvr.ReadAt(make([]byte, 2), 0); err != io.EOF || n != 0 {
			t.Errorf("read %d bytes with error %v, want 0 and io.EOF", n, err)
		}
	})
}

// TestMultiVolumeReaderWriteAtFailures is the same for WriteAt: a volume that
// refuses the write and an offset the table does not cover both have to come
// back as errors, because the caller is patching a header in place and a write
// reported as done but dropped would leave the archive quietly inconsistent.
func TestMultiVolumeReaderWriteAtFailures(t *testing.T) {
	t.Run("a volume that cannot be written", func(t *testing.T) {
		tmp := t.TempDir()
		f := mvReadOnlyHandle(t, tmp, "ro.zip", []byte("12345"))
		mvr := &MultiVolumeReader{files: []*os.File{f}, offsets: []int64{0}, size: 5}
		n, err := mvr.WriteAt([]byte("ab"), 0)
		if err == nil {
			t.Fatal("a write to a read-only volume reported success")
		}
		if n != 0 {
			t.Errorf("wrote %d bytes to a read-only volume", n)
		}
	})

	t.Run("an offset no volume covers", func(t *testing.T) {
		tmp := t.TempDir()
		f := mvReadOnlyHandle(t, tmp, "gap.zip", []byte("12345"))
		mvr := &MultiVolumeReader{files: []*os.File{f}, offsets: []int64{4}, size: 9}
		if n, err := mvr.WriteAt([]byte("ab"), 0); err == nil || n != 0 {
			t.Errorf("wrote %d bytes with error %v, want 0 and an error", n, err)
		}
	})
}

// TestMultiVolumeReaderAppendFailures covers the two ways Append can fail. In
// both the joined size has to stay where it was: counting bytes that never
// reached the disk would put every later offset past the real end of the set.
func TestMultiVolumeReaderAppendFailures(t *testing.T) {
	t.Run("a volume that cannot be sought", func(t *testing.T) {
		tmp := t.TempDir()
		mvr := &MultiVolumeReader{
			files:   []*os.File{mvClosedHandle(t, tmp, "dead.zip")},
			offsets: []int64{0},
			size:    0,
		}
		if err := mvr.Append([]byte("XY")); err == nil {
			t.Fatal("appending to an unusable volume reported success")
		}
		if mvr.size != 0 {
			t.Errorf("the joined size grew to %d after a failed append", mvr.size)
		}
	})

	t.Run("a volume that cannot be written", func(t *testing.T) {
		tmp := t.TempDir()
		f := mvReadOnlyHandle(t, tmp, "ro.zip", []byte("12345"))
		mvr := &MultiVolumeReader{files: []*os.File{f}, offsets: []int64{0}, size: 5}
		if err := mvr.Append([]byte("XY")); err == nil {
			t.Fatal("appending to a read-only volume reported success")
		}
		if mvr.size != 5 {
			t.Errorf("the joined size moved to %d after a failed append", mvr.size)
		}
	})
}

// TestOpenMultiVolumeFailures covers the openings that cannot produce a
// reader. The handles opened before the failure have to be closed on the way
// out: on Windows a leaked handle keeps the volume locked, so each case
// removes the part it opened, which only succeeds once nothing holds it.
func TestOpenMultiVolumeFailures(t *testing.T) {
	t.Run("a missing name that is not an archive extension", func(t *testing.T) {
		tmp := t.TempDir()
		if _, _, err := OpenMultiVolume(filepath.Join(tmp, "absent.dat"), os.O_RDONLY); !os.IsNotExist(err) {
			t.Errorf("error %v, want a does-not-exist error", err)
		}
	})

	t.Run("a missing archive with no parts", func(t *testing.T) {
		tmp := t.TempDir()
		if _, _, err := OpenMultiVolume(filepath.Join(tmp, "absent.zip"), os.O_RDONLY); !os.IsNotExist(err) {
			t.Errorf("error %v, want a does-not-exist error", err)
		}
	})

	t.Run("parts without the main volume", func(t *testing.T) {
		tmp := t.TempDir()
		part := filepath.Join(tmp, "orphan.z01")
		mustWriteFile(t, part, []byte("AAAA"), 0o600)

		_, _, err := OpenMultiVolume(filepath.Join(tmp, "orphan.zip"), os.O_RDONLY)
		if !os.IsNotExist(err) {
			t.Fatalf("error %v, want a does-not-exist error", err)
		}
		if err := os.Remove(part); err != nil {
			t.Errorf("the opened part was still held after the failure: %v", err)
		}
	})

	t.Run("a part that cannot be opened", func(t *testing.T) {
		tmp := t.TempDir()
		first := filepath.Join(tmp, "blocked.z01")
		mustWriteFile(t, first, []byte("AAAA"), 0o600)
		// A directory where the second part belongs cannot be opened for
		// writing on either Windows or Linux, which is the portable way
		// to fail a part that is not simply missing.
		mustMkdir(t, filepath.Join(tmp, "blocked.z02"))
		main := filepath.Join(tmp, "blocked.zip")
		mustWriteFile(t, main, []byte("BB"), 0o600)

		_, _, err := OpenMultiVolume(main, os.O_RDWR)
		if err == nil {
			t.Fatal("a set with an unopenable part was opened")
		}
		if os.IsNotExist(err) {
			t.Errorf("error %v, want the failure of the part and not a missing part", err)
		}
		if err := os.Remove(first); err != nil {
			t.Errorf("the part opened before the failure was still held: %v", err)
		}
	})

	t.Run("the first part cannot be opened", func(t *testing.T) {
		tmp := t.TempDir()
		// Nothing has been opened yet when this one fails, so the error
		// has to come back on its own rather than through the cleanup
		// that the later parts go through.
		mustMkdir(t, filepath.Join(tmp, "first.z01"))
		main := filepath.Join(tmp, "first.zip")
		mustWriteFile(t, main, []byte("BB"), 0o600)

		_, _, err := OpenMultiVolume(main, os.O_RDWR)
		if err == nil {
			t.Fatal("a set whose first part is a directory was opened")
		}
		if os.IsNotExist(err) {
			t.Errorf("error %v, want the failure of the part and not a missing part", err)
		}
	})

	t.Run("a main volume that cannot be opened", func(t *testing.T) {
		tmp := t.TempDir()
		first := filepath.Join(tmp, "locked.z01")
		mustWriteFile(t, first, []byte("AAAA"), 0o600)
		mustMkdir(t, filepath.Join(tmp, "locked.zip"))

		_, _, err := OpenMultiVolume(filepath.Join(tmp, "locked.zip"), os.O_RDWR)
		if err == nil {
			t.Fatal("a set whose main volume is a directory was opened")
		}
		if err := os.Remove(first); err != nil {
			t.Errorf("the parts opened before the failure were still held: %v", err)
		}
	})
}

// TestNewMultiVolumeWriterCreateFailure pins down that a writer which cannot
// create its first volume reports that instead of handing back a writer whose
// every later call would fail on a nil handle.
func TestNewMultiVolumeWriterStaleArchiveInTheWay(t *testing.T) {
	tmp := t.TempDir()
	main := filepath.Join(tmp, "taken.zip")
	mustMkdir(t, main)
	mustWriteFile(t, filepath.Join(main, "keep.txt"), []byte("k"), 0o600)
	if mvw, err := NewMultiVolumeWriter(main, 16); err == nil {
		_ = mvw.Close()
		t.Fatal("a writer was made although what holds the archive's name cannot be removed, and would be opened by that name instead of the volumes")
	}
}

func TestNewMultiVolumeWriterCreateFailure(t *testing.T) {
	tmp := t.TempDir()
	mvw, err := NewMultiVolumeWriter(filepath.Join(tmp, "absent", "a.zip"), 16)
	if err == nil {
		t.Fatal("a writer was created below a directory that does not exist")
	}
	if mvw != nil {
		t.Error("a writer was returned together with the error")
	}
}

// TestMultiVolumeWriterWriteFailures covers the two failures Write has to pass
// on: the volume being closed at a split boundary, and the current volume
// refusing the bytes. Both must return the count actually written so far, so
// that a caller cannot mistake a partly written volume for an untouched one.
func TestMultiVolumeWriterWriteFailures(t *testing.T) {
	t.Run("the finished volume cannot be closed", func(t *testing.T) {
		tmp := t.TempDir()
		mvw := &MultiVolumeWriter{
			mainPath:    filepath.Join(tmp, "roll.zip"),
			splitSize:   4,
			currentFile: mvClosedHandle(t, tmp, "roll.z01"),
			volumeIndex: 1,
			written:     4, // full, so the next byte starts a new volume
		}
		n, err := mvw.Write([]byte("x"))
		if err == nil {
			t.Fatal("the split reported success although the volume did not close")
		}
		if n != 0 {
			t.Errorf("reported %d bytes written, want 0", n)
		}
	})

	t.Run("the current volume refuses the write", func(t *testing.T) {
		tmp := t.TempDir()
		mvw := &MultiVolumeWriter{
			mainPath:    filepath.Join(tmp, "ro.zip"),
			splitSize:   1024,
			currentFile: mvReadOnlyHandle(t, tmp, "ro.z01", []byte("AAAA")),
			volumeIndex: 1,
		}
		n, err := mvw.Write([]byte("abc"))
		if err == nil {
			t.Fatal("a write to a read-only volume reported success")
		}
		if n != 0 {
			t.Errorf("reported %d bytes written, want 0", n)
		}
	})
}

// TestMultiVolumeWriterCloseFailures covers the finishing step. Close both
// closes the last volume and removes volumes an earlier archive of the same
// name left past it, and neither may be reported as done when it did not
// happen: a stale volume is read back as the rest of the archive.
func TestMultiVolumeWriterCloseFailures(t *testing.T) {
	t.Run("the last volume cannot be closed", func(t *testing.T) {
		tmp := t.TempDir()
		main := filepath.Join(tmp, "unclosable.zip")
		mvw := &MultiVolumeWriter{
			mainPath:    main,
			splitSize:   16,
			currentFile: mvClosedHandle(t, tmp, "unclosable.zip.001"),
			volumeIndex: 1,
		}
		if err := mvw.Close(); err == nil {
			t.Fatal("closing an already closed volume reported success")
		}
		if _, err := os.Stat(main); !os.IsNotExist(err) {
			t.Error("the volume was renamed to the main name although closing it failed")
		}
	})

	t.Run("a volume left past the last one cannot be removed", func(t *testing.T) {
		tmp := t.TempDir()
		main := filepath.Join(tmp, "occupied.zip")

		mvw, err := NewMultiVolumeWriter(main, 8)
		if err != nil {
			t.Fatalf("new writer: %v", err)
		}
		closeAt(t, mvw)
		mustWrite(t, mvw, []byte("0123456789"))

		// A non-empty directory under the next volume's name can be
		// removed on neither system, and a reader would take it for the
		// rest of the archive.
		stale := main + ".003"
		mustMkdir(t, stale)
		mustWriteFile(t, filepath.Join(stale, "keep.txt"), []byte("k"), 0o600)

		if err := mvw.Close(); err == nil {
			t.Fatal("closing reported success with a stale volume left behind")
		}
		last := main + ".002"
		fi, err := os.Stat(last)
		if err != nil {
			t.Fatalf("stat %s: %v", last, err)
		}
		if fi.Size() != 2 {
			t.Errorf("%s holds %d bytes, want the 2 that did not fit in the first volume", last, fi.Size())
		}
	})
}
