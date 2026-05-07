package zip

import (
	"context"
	"os"
	"bytes"
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