package zip

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestMultiVolumeReader_ReadAt(t *testing.T) {
	tmp := t.TempDir()

	// Создаем два тома: .z01 (5 байт) и .zip (5 байт)
	vol1Path := filepath.Join(tmp, "test.z01")
	zipPath := filepath.Join(tmp, "test.zip")

	os.WriteFile(vol1Path, []byte("12345"), 0644)
	os.WriteFile(zipPath, []byte("67890"), 0644)

	ra, size, closer, err := openMultiVolume(zipPath)
	if err != nil {
		t.Fatalf("failed to open multivolume: %v", err)
	}
	defer closer.Close()

	if size != 10 {
		t.Errorf("expected size 10, got %d", size)
	}

	// Тест чтения на границе томов
	buf := make([]byte, 4)
	n, err := ra.ReadAt(buf, 3) // Должен прочитать '45' из первого и '67' из второго
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt error: %v", err)
	}
	if n != 4 || string(buf) != "4567" {
		t.Errorf("boundary read failed: got %q", string(buf))
	}
}