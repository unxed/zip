package zip

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestZipIndexingOptimization_Threshold(t *testing.T) {
	// Временно подменяем os.Args, чтобы убрать "-test." и активировать порог 4МБ
	oldArgs := os.Args
	os.Args = []string{"zipper"}
	defer func() { os.Args = oldArgs }()

	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	os.MkdirAll(srcDir, 0755)

	// 1. Тест: Маленький файл (1МБ) -> Скрытого индекса быть НЕ должно
	smallFile := filepath.Join(srcDir, "small.bin")
	os.WriteFile(smallFile, bytes.Repeat([]byte("A"), 1024*1024), 0644)

	arcSmall := filepath.Join(tmpDir, "small.zip")
	f1, _ := os.Create(arcSmall)
	a1, _ := NewArchiver(f1, tmpDir, WithArchiverMethod(Deflate), WithArchiverSeekIndex(1024*1024, false))
	fi1, _ := os.Stat(smallFile)
	a1.Archive(context.Background(), map[string]os.FileInfo{smallFile: fi1})
	a1.Close()
	f1.Close()

	zr1, _ := OpenReader(arcSmall)
	idxType1, _, _ := zr1.File[0].findHiddenIndex()
	zr1.Close()
	if idxType1 != 0 {
		t.Errorf("Expected no hidden index for 1MB file, but found index type %d", idxType1)
	}

	// 2. Тест: Большой файл (5МБ) -> Скрытый индекс ДОЛЖЕН быть
	largeFile := filepath.Join(srcDir, "large.bin")
	os.WriteFile(largeFile, bytes.Repeat([]byte("B"), 5*1024*1024), 0644)

	arcLarge := filepath.Join(tmpDir, "large.zip")
	f2, _ := os.Create(arcLarge)
	a2, _ := NewArchiver(f2, tmpDir, WithArchiverMethod(Deflate), WithArchiverSeekIndex(1024*1024, false))
	fi2, _ := os.Stat(largeFile)
	a2.Archive(context.Background(), map[string]os.FileInfo{largeFile: fi2})
	a2.Close()
	f2.Close()

	zr2, _ := OpenReader(arcLarge)
	idxType, payload, err2 := zr2.File[0].findHiddenIndex()
	zr2.Close()
	if err2 != nil || idxType == 0 || len(payload) == 0 {
		t.Errorf("Expected hidden index for 5MB file, but it was missing: %v", err2)
	}
}