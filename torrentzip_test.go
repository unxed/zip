package zip

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchiver_TorrentZip(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	os.MkdirAll(filepath.Join(src, "dir2"), 0755)
	os.MkdirAll(filepath.Join(src, "dir1"), 0755) // This one will have a file
	os.WriteFile(filepath.Join(src, "dir1", "file.txt"), []byte("file data"), 0644)
	os.WriteFile(filepath.Join(src, "Z_file.txt"), []byte("data Z"), 0644)
	os.WriteFile(filepath.Join(src, "a_file.txt"), []byte("data a"), 0644)

	zipPath := filepath.Join(tmp, "tz.zip")
	f, _ := os.Create(zipPath)

	a, err := NewArchiver(f, src, WithArchiverTorrentZip(true))
	if err != nil {
		t.Fatal(err)
	}

	files := make(map[string]os.FileInfo)
	filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if path != src {
			files[path] = info
		}
		return nil
	})

	err = a.Archive(context.Background(), files)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	f.Close()

	// Check properties
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	if !strings.HasPrefix(zr.Comment, "TORRENTZIPPED-") {
		t.Errorf("expected TORRENTZIPPED- comment, got %q", zr.Comment)
	}

	expectedOrder := []string{
		"a_file.txt",
		"dir1/file.txt",
		"dir2/",
		"Z_file.txt",
	}
	if len(zr.File) != len(expectedOrder) {
		t.Fatalf("expected %d files, got %d", len(expectedOrder), len(zr.File))
	}

	for i, f := range zr.File {
		if f.Name != expectedOrder[i] {
			t.Errorf("expected file %d to be %q, got %q", i, expectedOrder[i], f.Name)
		}
		if f.ModifiedTime != 48128 || f.ModifiedDate != 8600 {
			t.Errorf("timestamps not overridden for %s", f.Name)
		}
		if f.Flags != 2 {
			t.Errorf("flags not overridden for %s: got %d", f.Name, f.Flags)
		}
		if len(f.Extra) != 0 {
			t.Errorf("extra fields not cleared for %s", f.Name)
		}
		if f.CreatorVersion != 0 || f.ReaderVersion != 20 {
			t.Errorf("versions not set correctly for %s", f.Name)
		}
	}
}