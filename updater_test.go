package zip

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdater(t *testing.T) {
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, "test.zip")

	// 1. Create a basic zip archive
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip: %v", err)
	}
	zw := NewWriter(f)
	w, err := zw.Create("file1.txt")
	if err != nil {
		t.Fatalf("failed to create file1.txt: %v", err)
	}
	w.Write([]byte("version1"))
	zw.Close()
	f.Close()

	// 2. Open with Updater and APPEND file2.txt
	fRW, err := os.OpenFile(zipPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open zip for update: %v", err)
	}
	updater, err := NewUpdater(fRW)
	if err != nil {
		t.Fatalf("failed to init updater: %v", err)
	}

	w2, err := updater.Append("file2.txt", APPEND_MODE_KEEP_ORIGINAL)
	if err != nil {
		t.Fatalf("failed to append file2.txt: %v", err)
	}
	w2.Write([]byte("file2-content"))

	updater.SetComment("Test comment")
	if err := updater.Close(); err != nil {
		t.Fatalf("failed to close updater: %v", err)
	}
	fRW.Close()

	// 3. Verify content
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open reader: %v", err)
	}
	if len(zr.File) != 2 {
		t.Fatalf("expected 2 files, got %d", len(zr.File))
	}
	if zr.Comment != "Test comment" {
		t.Errorf("expected comment 'Test comment', got %q", zr.Comment)
	}
	zr.Close()

	// 4. Open with Updater and OVERWRITE file1.txt
	fRW, err = os.OpenFile(zipPath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open zip for overwrite: %v", err)
	}
	updater, err = NewUpdater(fRW)
	if err != nil {
		t.Fatalf("failed to init updater: %v", err)
	}

	w1, err := updater.Append("file1.txt", APPEND_MODE_OVERWRITE)
	if err != nil {
		t.Fatalf("failed to overwrite file1.txt: %v", err)
	}
	w1.Write([]byte("version2-overwritten"))

	if err := updater.Close(); err != nil {
		t.Fatalf("failed to close updater after overwrite: %v", err)
	}
	fRW.Close()

	// 5. Verify overwritten content
	zr, err = OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open reader: %v", err)
	}
	defer zr.Close()

	if len(zr.File) != 2 {
		t.Fatalf("expected 2 files after overwrite, got %d", len(zr.File))
	}

	for _, f := range zr.File {
		if f.Name == "file1.txt" {
			rc, _ := f.Open()
			content, _ := io.ReadAll(rc)
			rc.Close()
			if !bytes.Equal(content, []byte("version2-overwritten")) {
				t.Errorf("file1.txt was not overwritten properly, got %q", string(content))
			}
		}
	}
}

func TestUpdater_RemoveFirstFile(t *testing.T) {
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, "remove.zip")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	zw.Create("file1.txt") // will be removed
	w, _ := zw.Create("file2.txt")
	w.Write([]byte("keep-me"))
	zw.Close()
	f.Close()

	fRW, _ := os.OpenFile(zipPath, os.O_RDWR, 0644)
	u, _ := NewUpdater(fRW)
	// Overwrite file1.txt to trigger removal and shift of file2.txt
	w1, _ := u.Append("file1.txt", APPEND_MODE_OVERWRITE)
	w1.Write([]byte("new-file1-is-shorter"))
	u.Close()
	fRW.Close()

	zr, _ := OpenReader(zipPath)
	defer zr.Close()
	if len(zr.File) != 2 {
		t.Fatalf("expected 2 files, got %d", len(zr.File))
	}
}
func TestUpdater_LargeDataShift(t *testing.T) {
	// bufferSize in updater.go is 1MB. Let's create a 2MB file and replace a small file before it.
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, "largeshift.zip")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)

	// File 1: small
	w1, _ := zw.Create("small.txt")
	w1.Write([]byte("small"))

	// File 2: > 1MB
	w2, _ := zw.Create("large.bin")
	largeData := make([]byte, 1024*1024*2) // 2MB
	w2.Write(largeData)

	zw.Close()
	f.Close()

	// Replace "small.txt" with something else of different size to force shift of 2MB
	fRW, _ := os.OpenFile(zipPath, os.O_RDWR, 0644)
	u, _ := NewUpdater(fRW)
	w, _ := u.Append("small.txt", APPEND_MODE_OVERWRITE)
	w.Write([]byte("now-larger-than-before"))
	u.Close()
	fRW.Close()

	// Verify
	zr, _ := OpenReader(zipPath)
	defer zr.Close()
	if len(zr.File) != 2 {
		t.Errorf("expected 2 files, got %d", len(zr.File))
	}
}
func TestUpdater_SameSize(t *testing.T) {
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, "samesize.zip")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	w, _ := zw.Create("data.txt")
	w.Write([]byte("12345"))
	zw.Close()
	f.Close()

	fRW, _ := os.OpenFile(zipPath, os.O_RDWR, 0644)
	u, _ := NewUpdater(fRW)
	w, _ = u.Append("data.txt", APPEND_MODE_OVERWRITE)
	w.Write([]byte("abcde")) // Same size
	u.Close()
	fRW.Close()

	zr, _ := OpenReader(zipPath)
	defer zr.Close()
	rc, _ := zr.File[0].Open()
	b, _ := io.ReadAll(rc)
	if string(b) != "abcde" {
		t.Errorf("expected 'abcde', got %q", string(b))
	}
}

func TestUpdater_ReplaceLastFile(t *testing.T) {
	tempDir := t.TempDir()
	zipPath := filepath.Join(tempDir, "last.zip")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	zw.Create("file1.txt")
	w, _ := zw.Create("file2.txt")
	w.Write([]byte("old"))
	zw.Close()
	f.Close()

	fRW, _ := os.OpenFile(zipPath, os.O_RDWR, 0644)
	u, _ := NewUpdater(fRW)
	w, _ = u.Append("file2.txt", APPEND_MODE_OVERWRITE)
	w.Write([]byte("new-much-longer-content"))
	u.Close()
	fRW.Close()

	zr, _ := OpenReader(zipPath)
	defer zr.Close()
	if len(zr.File) != 2 {
		t.Fatalf("expected 2 files, got %d", len(zr.File))
	}
}

func TestUpdater_DuplicateHeaderError(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "dup.zip")
	
	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	zw.Create("file.txt")
	zw.Close()
	f.Close()

	fRW, _ := os.OpenFile(zipPath, os.O_RDWR, 0644)
	u, _ := NewUpdater(fRW)
	defer fRW.Close()

	fh := &FileHeader{Name: "new.txt"}
	u.AppendHeader(fh, APPEND_MODE_KEEP_ORIGINAL)
	
	// Попытка добавить ТОТ ЖЕ заголовок второй раз без закрытия стрима
	_, err := u.AppendHeader(fh, APPEND_MODE_KEEP_ORIGINAL)
	if err == nil {
		t.Error("expected error when appending duplicate FileHeader object, got nil")
	}
}
