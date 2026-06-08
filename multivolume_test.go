package zip

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestMultiVolumeReader_ReadAt(t *testing.T) {
	tmp := t.TempDir()

	// Create two volumes: .z01 (5 bytes) and .zip (5 bytes)
	vol1Path := filepath.Join(tmp, "test.z01")
	zipPath := filepath.Join(tmp, "test.zip")

	os.WriteFile(vol1Path, []byte("12345"), 0644)
	os.WriteFile(zipPath, []byte("67890"), 0644)

	ra, size, err := OpenMultiVolume(zipPath, os.O_RDONLY)
	if err != nil {
		t.Fatalf("failed to open multivolume: %v", err)
	}
	defer ra.Close()

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

	os.WriteFile(vol1Path, []byte("ABCDE"), 0644)
	os.WriteFile(zipPath, []byte("FGHIJ"), 0644)

	ra, size, err := OpenMultiVolume(zipPath, os.O_RDONLY)
	if err != nil {
		t.Fatalf("failed to open multivolume: %v", err)
	}
	defer ra.Close()

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

	data := []byte("abcdefghijklmnopqrstuvwxyz") // 26 bytes -> z01(10), z02(10), zip(6)
	if _, err := mvw.Write(data); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := mvw.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	prefix := mainPath[:len(mainPath)-len(".zip")]
	if _, err := os.Stat(prefix + ".z01"); err != nil {
		t.Errorf("missing volume .z01")
	}
	if _, err := os.Stat(prefix + ".z02"); err != nil {
		t.Errorf("missing volume .z02")
	}
	if _, err := os.Stat(mainPath); err != nil {
		t.Errorf("missing main volume .zip")
	}

	mvr, totalSize, err := OpenMultiVolume(mainPath, os.O_RDONLY)
	if err != nil {
		t.Fatalf("failed to open multi-volume reader: %v", err)
	}
	defer mvr.Close()

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
