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