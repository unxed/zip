package zip

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenMultiVolumeNumbered covers the numbered volume names: the set is
// found from the first volume and from the archive's name when no file has
// it, it stops at the first missing number, and a volume that cannot be
// opened fails the whole set.
func TestOpenMultiVolumeNumbered(t *testing.T) {
	t.Run("by either name", func(t *testing.T) {
		tmp := t.TempDir()
		main := filepath.Join(tmp, "set.zip")
		mustWriteFile(t, main+".001", []byte("AAAA"), 0o600)
		mustWriteFile(t, main+".002", []byte("BB"), 0o600)
		mustWriteFile(t, main+".004", []byte("not part of the set"), 0o600)
		for _, name := range []string{main, main + ".001"} {
			mvr, size := mvOpen(t, name, os.O_RDONLY)
			buf := make([]byte, size)
			if _, err := mvr.ReadAt(buf, 0); err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			if string(buf) != "AAAABB" {
				t.Errorf("opened by %s the set reads %q, want AAAABB", name, buf)
			}
		}
	})

	t.Run("a file under the archive's name wins", func(t *testing.T) {
		tmp := t.TempDir()
		main := filepath.Join(tmp, "one.zip")
		mustWriteFile(t, main, []byte("whole"), 0o600)
		mustWriteFile(t, main+".001", []byte("AAAA"), 0o600)
		if _, size := mvOpen(t, main, os.O_RDONLY); size != 5 {
			t.Errorf("opened %d bytes, want the 5 of the file named %s", size, main)
		}
	})

	t.Run("the first volume is missing", func(t *testing.T) {
		if _, _, err := OpenMultiVolume(filepath.Join(t.TempDir(), "none.zip.001"), os.O_RDONLY); !os.IsNotExist(err) {
			t.Errorf("got %v, want a missing file", err)
		}
	})

	t.Run("a later volume cannot be opened", func(t *testing.T) {
		tmp := t.TempDir()
		main := filepath.Join(tmp, "blocked.zip")
		mustWriteFile(t, main+".001", []byte("AAAA"), 0o600)
		mustMkdir(t, main+".002")
		if _, _, err := OpenMultiVolume(main+".001", os.O_RDWR); err == nil {
			t.Error("a set whose second volume is a directory opened for writing")
		}
	})
}

// TestMultiVolumeArchiveCarriesRecoveryRecord: an archive split into volumes
// gets the recovery record it is asked for, which WithArchiverRecovery used to
// drop for anything but an *os.File, and reads back whole.
func TestMultiVolumeArchiveCarriesRecoveryRecord(t *testing.T) {
	src := t.TempDir()
	body := mvPattern(20000, 3)
	mustWriteFile(t, filepath.Join(src, "data.bin"), body, 0o600)
	main := filepath.Join(t.TempDir(), "rr.zip")

	mvw, err := NewMultiVolumeWriter(main, 4096)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	closeAt(t, mvw)
	a, err := NewArchiver(mvw, src, WithArchiverRecovery(10, mvw), WithArchiverMethod(Store))
	if err != nil {
		t.Fatalf("new archiver: %v", err)
	}
	if err := a.Archive(context.Background(), walkFilesFor(t, src)); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := mvw.Close(); err != nil {
		t.Fatalf("close volumes: %v", err)
	}

	mvr, size := mvOpen(t, main, os.O_RDONLY)
	raw := make([]byte, size)
	if _, err := mvr.ReadAt(raw, 0); err != nil {
		t.Fatalf("read the volumes: %v", err)
	}
	if !bytes.Contains(raw, []byte(recoveryEntry)) {
		t.Fatalf("the split archive holds no %s entry", recoveryEntry)
	}
	rc, err := OpenReader(main)
	if err != nil {
		t.Fatalf("open the archive: %v", err)
	}
	closeAt(t, rc)
	if len(rc.File) != 1 {
		t.Fatalf("the archive lists %d entries, want 1", len(rc.File))
	}
	r, err := rc.File[0].Open()
	if err != nil {
		t.Fatalf("open data.bin: %v", err)
	}
	got, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("data.bin did not read back: %v", err)
	}
}
