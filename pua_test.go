package zip

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPUA_Zip_EncodingPreservation(t *testing.T) {
	tmpDir := t.TempDir()
	rawName := "bad_utf8_\xff\xfe_name.txt"
	zipPath := filepath.Join(tmpDir, "pua.zip")
	dstDir := filepath.Join(tmpDir, "extract")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	fh := &FileHeader{Name: rawName, Method: Store}
	fh.SetMode(0644)
	w, _ := zw.CreateHeader(fh)
	w.Write([]byte("pua-data"))
	zw.Close()
	f.Close()

	e, _ := NewExtractor(zipPath, dstDir)
	err := e.Extract(context.Background())
	if err != nil {
		t.Fatalf("Extraction failed: %v", err)
	}

	expectedPath := filepath.Join(dstDir, rawName)
	if _, err := os.Stat(expectedPath); err != nil {
		t.Errorf("PUA Filename not restored correctly to raw bytes: %v", err)
	}
}
