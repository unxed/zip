package zip

import (
	"context"
	"time"
	"os"
	"bytes"
	"strings"
	"path/filepath"
	"runtime"
	"testing"
)

func TestArchiverAndExtractor(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	zipPath := filepath.Join(t.TempDir(), "fast.zip")

	// 1. Prepare source structure
	filesToCreate := map[string]string{
		"file1.txt":      "hello parallel world",
		"dir1/file2.txt": "inside a directory",
	}

	for path, content := range filesToCreate {
		fullPath := filepath.Join(srcDir, path)
		os.MkdirAll(filepath.Dir(fullPath), 0755)
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	// Create symlink (skip on Windows unless running with admin privileges)
	if runtime.GOOS != "windows" {
		symlinkTarget := "file1.txt"
		symlinkPath := filepath.Join(srcDir, "symlink.txt")
		if err := os.Symlink(symlinkTarget, symlinkPath); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}
	}

	// 2. Gather files for Archiver
	filesMap := make(map[string]os.FileInfo)
	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == srcDir {
			return nil // skip root
		}
		filesMap[path] = info
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	// 3. Archive files (Testing multi-threading)
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip file: %v", err)
	}
	archiver, err := NewArchiver(f, srcDir, WithArchiverConcurrency(4), WithArchiverMethod(Deflate))
	if err != nil {
		t.Fatalf("failed to init archiver: %v", err)
	}

	if err := archiver.Archive(context.Background(), filesMap); err != nil {
		t.Fatalf("archive failed: %v", err)
	}
	archiver.Close()
	f.Close()

	// 4. Extract files (Testing multi-threading)
	extractor, err := NewExtractor(zipPath, dstDir, WithExtractorConcurrency(4))
	if err != nil {
		t.Fatalf("failed to init extractor: %v", err)
	}
	if err := extractor.Extract(context.Background()); err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	extractor.Close()

	// 5. Verify extracted content
	for path, expectedContent := range filesToCreate {
		fullPath := filepath.Join(dstDir, path)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			t.Errorf("extracted file %s is missing: %v", path, err)
			continue
		}
		if !bytes.Equal(content, []byte(expectedContent)) {
			t.Errorf("extracted file %s content mismatch. Expected %q, got %q", path, expectedContent, string(content))
		}
	}

	if runtime.GOOS != "windows" {
		symlinkPath := filepath.Join(dstDir, "symlink.txt")
		target, err := os.Readlink(symlinkPath)
		if err != nil {
			t.Errorf("symlink was not extracted properly: %v", err)
		} else if target != "file1.txt" {
			t.Errorf("symlink target mismatch. Expected 'file1.txt', got %q", target)
		}
	}
}

func TestArchiver_ChrootViolation(t *testing.T) {
	tmp := t.TempDir()
	chroot := filepath.Join(tmp, "inside")
	os.Mkdir(chroot, 0755)

	outsideFile := filepath.Join(tmp, "outside.txt")
	os.WriteFile(outsideFile, []byte("danger"), 0644)

	f, _ := os.Create(filepath.Join(tmp, "test.zip"))
	defer f.Close()

	a, _ := NewArchiver(f, chroot)
	files := map[string]os.FileInfo{
		outsideFile: nil, // This should trigger the prefix check
	}

	// We need a real FileInfo for the check
	info, _ := os.Stat(outsideFile)
	files[outsideFile] = info

	err := a.Archive(context.Background(), files)
	if err == nil || !strings.Contains(err.Error(), "outside of chroot") {
		t.Errorf("expected chroot violation error, got: %v", err)
	}
}
func TestArchiver_SkipIrregularFiles(t *testing.T) {
	tmp := t.TempDir()
	fPath := filepath.Join(tmp, "normal.txt")
	os.WriteFile(fPath, []byte("data"), 0644)

	zipF, _ := os.Create(filepath.Join(tmp, "out.zip"))
	defer zipF.Close()

	a, _ := NewArchiver(zipF, tmp)

	// Симулируем FileInfo для сокета (нерегулярный файл)
	files := make(map[string]os.FileInfo)
	info, _ := os.Stat(fPath)
	files[fPath] = info

	// Добавляем файл с модом сокета вручную (FileInfo это интерфейс)
	files["/tmp/socket"] = mockFileInfo{name: "socket", mode: os.ModeSocket}

	err := a.Archive(context.Background(), files)
	if err != nil {
		t.Fatalf("archiver failed: %v", err)
	}

	// Проверяем, что в архиве только 1 файл (сокет пропущен)
	a.Close()
	zr, _ := OpenReader(zipF.Name())
	if len(zr.File) != 1 {
		t.Errorf("expected 1 file (socket should be skipped), got %d", len(zr.File))
	}
}
func TestArchiver_EmptyEntries(t *testing.T) {
	tmp := t.TempDir()

	// Создаем пустую папку и пустой файл
	os.Mkdir(filepath.Join(tmp, "empty_dir"), 0755)
	os.WriteFile(filepath.Join(tmp, "empty_file.txt"), []byte{}, 0644)

	zipF, _ := os.Create(filepath.Join(tmp, "empty.zip"))
	defer zipF.Close()

	a, _ := NewArchiver(zipF, tmp)

	files := make(map[string]os.FileInfo)
	filepath.Walk(tmp, func(p string, info os.FileInfo, err error) error {
		if p != tmp && p != zipF.Name() {
			files[p] = info
		}
		return nil
	})

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatalf("failed to archive empty entries: %v", err)
	}
	a.Close()

	zr, _ := OpenReader(zipF.Name())
	defer zr.Close()

	foundFile := false
	foundDir := false
	for _, f := range zr.File {
		if f.Name == "empty_file.txt" && f.UncompressedSize64 == 0 {
			foundFile = true
		}
		if f.Name == "empty_dir/" {
			foundDir = true
		}
	}
	if !foundFile || !foundDir {
		t.Errorf("archiver missed empty entries: file=%v, dir=%v", foundFile, foundDir)
	}
}

type mockFileInfo struct {
	name string
	mode os.FileMode
}
func (m mockFileInfo) Name() string { return m.name }
func (m mockFileInfo) Size() int64 { return 0 }
func (m mockFileInfo) Mode() os.FileMode { return m.mode }
func (m mockFileInfo) ModTime() time.Time { return time.Now() }
func (m mockFileInfo) IsDir() bool { return m.mode.IsDir() }
func (m mockFileInfo) Sys() interface{} { return nil }
