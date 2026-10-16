package zip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/unxed/zip/internal/filepool"
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
		mustMkdirAll(t, filepath.Dir(fullPath))
		if err := os.WriteFile(fullPath, []byte(content), 0600); err != nil {
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
	closeAt(t, f)
	archiver, err := NewArchiver(f, srcDir, WithArchiverConcurrency(4), WithArchiverMethod(Deflate))
	if err != nil {
		t.Fatalf("failed to init archiver: %v", err)
	}
	closeAt(t, archiver)

	if err := archiver.Archive(context.Background(), filesMap); err != nil {
		t.Fatalf("archive failed: %v", err)
	}
	if err := archiver.Close(); err != nil {
		t.Fatalf("failed to close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close %s: %v", zipPath, err)
	}

	// 4. Extract files (Testing multi-threading)
	extractor, err := NewExtractor(zipPath, dstDir, WithExtractorConcurrency(4))
	if err != nil {
		t.Fatalf("failed to init extractor: %v", err)
	}
	closeAt(t, extractor)
	if err := extractor.Extract(context.Background()); err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if err := extractor.Close(); err != nil {
		t.Fatalf("failed to close extractor: %v", err)
	}

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

func TestArchiver_OutsideChrootNormalization(t *testing.T) {
	tmp := t.TempDir()
	chroot := filepath.Join(tmp, "inside")
	mustMkdir(t, chroot)

	outsideFile := filepath.Join(tmp, "outside.txt")
	mustWriteFile(t, outsideFile, []byte("safe"), 0644)

	zipPath := filepath.Join(tmp, "test.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

	a, err := NewArchiver(f, chroot)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)
	info, _ := os.Stat(outsideFile)
	files := map[string]os.FileInfo{
		outsideFile: info,
	}

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatalf("expected successful archive with normalized path, got: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)

	if len(zr.File) != 1 {
		t.Fatalf("expected 1 file, got %d", len(zr.File))
	}

	if filepath.IsAbs(zr.File[0].Name) || strings.HasPrefix(zr.File[0].Name, "../") {
		t.Errorf("path was not safely normalized: %s", zr.File[0].Name)
	}
}
func TestArchiver_SkipIrregularFiles(t *testing.T) {
	tmp := t.TempDir()
	fPath := filepath.Join(tmp, "normal.txt")
	mustWriteFile(t, fPath, []byte("data"), 0644)

	zipPath := filepath.Join(tmp, "out.zip")
	zipF, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zipF)

	a, err := NewArchiver(zipF, tmp)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	// Simulate FileInfo for a socket (irregular file)
	files := make(map[string]os.FileInfo)
	info, _ := os.Stat(fPath)
	files[fPath] = info

	// Manually add a file with socket mode (FileInfo is an interface)
	files["/tmp/socket"] = mockFileInfo{name: "socket", mode: os.ModeSocket}

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatalf("archiver failed: %v", err)
	}

	// Verify that the archive contains only 1 file (the socket was skipped)
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := zipF.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)
	if len(zr.File) != 1 {
		t.Errorf("expected 1 file (socket should be skipped), got %d", len(zr.File))
	}
}
func TestArchiver_EmptyEntries(t *testing.T) {
	tmp := t.TempDir()

	// Create an empty directory and an empty file
	mustMkdir(t, filepath.Join(tmp, "empty_dir"))
	mustWriteFile(t, filepath.Join(tmp, "empty_file.txt"), []byte{}, 0644)

	zipPath := filepath.Join(tmp, "empty.zip")
	zipF, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zipF)

	a, err := NewArchiver(zipF, tmp)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	files := make(map[string]os.FileInfo)
	if err := filepath.Walk(tmp, func(p string, info os.FileInfo, err error) error {
		if p != tmp && p != zipPath {
			files[p] = info
		}
		return nil
	}); err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatalf("failed to archive empty entries: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := zipF.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)

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
func TestArchiver_MetadataPreservation(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	mustMkdir(t, srcDir)

	filePath := filepath.Join(srcDir, "meta.txt")
	mustWriteFile(t, filePath, []byte("metadata preservation"), 0644)

	now := time.Now().Truncate(time.Second)
	if err := os.Chtimes(filePath, now.Add(-time.Hour), now); err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(tmp, "meta.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

	// Enable metadata support via Archiver option
	a, err := NewArchiver(f, srcDir, WithArchiverPlatformMetadata(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)
	info, _ := os.Stat(filePath)

	// Manually add OwnerSet to simulate a successful pull (since tests might not run as root)
	fh := &FileHeader{
		Name:     "meta.txt",
		Uid:      123,
		Gid:      456,
		Uname:    "testuser",
		Gname:    "testgroup",
		OwnerSet: true,
		Modified: now,
	}

	if err := a.createFile(context.Background(), filePath, info, fh, nil); err != nil {
		t.Fatalf("createFile failed: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)
	file := zr.File[0]

	uid, gid, ok := parseUnixExtra(file.Extra)
	if !ok || uid != 123 || gid != 456 {
		t.Errorf("Unix metadata not preserved in Archiver: %d:%d (ok=%v)", uid, gid, ok)
	}
	if file.Uname != "testuser" || file.Gname != "testgroup" {
		t.Errorf("Unix owner name strings not preserved in Archiver: %q:%q", file.Uname, file.Gname)
	}
}
func TestArchiver_ZstdParallel(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	mustMkdir(t, srcDir)

	// Generate multiple files for parallel processing
	filesMap := make(map[string]os.FileInfo)
	for i := 0; i < 20; i++ {
		p := filepath.Join(srcDir, fmt.Sprintf("file_%d.bin", i))
		mustWriteFile(t, p, make([]byte, 1024), 0644)
		info, _ := os.Stat(p)
		filesMap[p] = info
	}

	zipPath := filepath.Join(tmp, "zstd_para.zip")
	zipF, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zipF)

	// Use ZSTD in parallel mode
	a, err := NewArchiver(zipF, srcDir, WithArchiverMethod(ZSTD), WithArchiverConcurrency(4))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)
	if err := a.Archive(context.Background(), filesMap); err != nil {
		t.Fatalf("parallel ZSTD archive failed: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := zipF.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	// Verify that files are readable
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)
	if len(zr.File) != 20 || zr.File[0].Method != ZSTD {
		t.Errorf("ZSTD parallel archive error: count=%d, method=%d", len(zr.File), zr.File[0].Method)
	}
}

func TestArchiver_ContextCancellation(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	mustMkdir(t, srcDir)

	p := filepath.Join(srcDir, "large.bin")
	mustWriteFile(t, p, make([]byte, 1024*1024), 0644)
	info, _ := os.Stat(p)

	zipF, err := os.Create(filepath.Join(tmp, "cancel.zip"))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zipF)

	ctx, cancel := context.WithCancel(context.Background())
	a, err := NewArchiver(zipF, srcDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	// Cancel immediately
	cancel()

	err = a.Archive(ctx, map[string]os.FileInfo{p: info})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
func TestArchiver_InvalidStageDir(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	mustMkdirAll(t, srcDir)
	// Create two files to force the Archiver to use FilePool (since concurrency=2)
	mustWriteFile(t, filepath.Join(srcDir, "test1.txt"), make([]byte, 5*1024*1024), 0644)
	mustWriteFile(t, filepath.Join(srcDir, "test2.txt"), make([]byte, 5*1024*1024), 0644)

	zipF, err := os.Create(filepath.Join(tmp, "test.zip"))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zipF)

	// Provide a non-existent path as the directory for buffers.
	// Set BufferSize(0) so that data does not stay in memory,
	// but goes directly to the file system (triggering a path error).
	a, err := NewArchiver(zipF, srcDir,
		WithArchiverConcurrency(2),
		WithArchiverBufferSize(0),
		WithStageDirectory(filepath.Join(tmp, "non-existent-path")))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	files := make(map[string]os.FileInfo)
	i1, _ := os.Stat(filepath.Join(srcDir, "test1.txt"))
	i2, _ := os.Stat(filepath.Join(srcDir, "test2.txt"))
	files[filepath.Join(srcDir, "test1.txt")] = i1
	files[filepath.Join(srcDir, "test2.txt")] = i2

	err = a.Archive(context.Background(), files)
	if err == nil {
		t.Error("expected error due to invalid stage directory, got nil")
	}
}
func TestArchiver_WrittenStats(t *testing.T) {
	srcDir := t.TempDir()
	zipPath := filepath.Join(t.TempDir(), "stats.zip")

	// Create multiple files
	mustWriteFile(t, filepath.Join(srcDir, "f1.txt"), []byte("data1"), 0644)
	mustWriteFile(t, filepath.Join(srcDir, "f2.txt"), []byte("data22"), 0644)

	filesMap := make(map[string]os.FileInfo)
	if err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if path != srcDir {
			filesMap[path] = info
		}
		return nil
	}); err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	archiver, err := NewArchiver(f, srcDir, WithArchiverSolid(true), WithArchiverMethod(Deflate))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, archiver)
	if err := archiver.Archive(context.Background(), filesMap); err != nil {
		t.Fatalf("solid archiving failed: %v", err)
	}
	if err := archiver.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	bytes, entries := archiver.Written()
	// 2 entries (f1.txt and f2.txt) + 1 outer Solid.zip entry = 3 entries total
	if entries != 3 {
		t.Errorf("expected 3 entries total (2 inner + 1 outer), got %d", entries)
	}
	if bytes <= 0 {
		t.Errorf("expected positive bytes written, got %d", bytes)
	}
}

type mockFileInfo struct {
	name string
	mode os.FileMode
}

func (m mockFileInfo) Name() string       { return m.name }
func (m mockFileInfo) Size() int64        { return 0 }
func (m mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m mockFileInfo) ModTime() time.Time { return time.Now() }
func (m mockFileInfo) IsDir() bool        { return m.mode.IsDir() }
func (m mockFileInfo) Sys() interface{}   { return nil }

func TestArchiver_SolidSeekIndex(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	mustMkdirAll(t, srcDir)
	mustWriteFile(t, filepath.Join(srcDir, "test.txt"), []byte("solid seek index test data"), 0644)

	archivePath := filepath.Join(tmpDir, "solid.zip")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

	a, err := NewArchiver(f, srcDir,
		WithArchiverSolid(true),
		WithArchiverMethod(Deflate),
		WithArchiverSeekIndex(1024, true),
	)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	files := make(map[string]os.FileInfo)
	if err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if path != srcDir {
			files[path] = info
		}
		return nil
	}); err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", archivePath, err)
	}

	zr, err := OpenReader(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)

	if len(zr.File) != 1 || zr.File[0].Name != "Solid.zip" {
		t.Fatalf("Expected Solid.zip, got %v", zr.File[0].Name)
	}

	rs, err := zr.File[0].OpenSeekable()
	if err != nil {
		t.Fatalf("OpenSeekable failed on Solid archive: %v", err)
	}

	buf := make([]byte, 5)
	n, _ := rs.Read(buf)
	if n == 0 {
		t.Fatalf("Read from seekable stream failed")
	}
}
func TestArchiver_DifferentDrivesWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "different_drives.zip")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

	a, err := NewArchiver(f, tmp)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	currentDrive := filepath.VolumeName(tmp)
	targetDrive := "D:"
	if currentDrive == "D:" || currentDrive == "d:" {
		targetDrive = "C:"
	}

	targetPath := targetDrive + `\dummy_dir`

	files := map[string]os.FileInfo{
		targetPath: mockFileInfo{name: "dummy_dir", mode: os.ModeDir | 0755},
	}

	err = a.Archive(context.Background(), files)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}
func TestArchiver_CompressionHeuristics(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	mustMkdirAll(t, srcDir)

	// 1. Тест на эффективность сжатия мелкого текста (раньше было 104%, теперь должно быть < 100%)
	// Генерируем текст с высокой энтропией Хаффмана, но плохим LZ77 (короткий, без повторов строк)
	textPath := filepath.Join(srcDir, "small_text.txt")
	var textBuf bytes.Buffer
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&textBuf, "line %d: some unique text content here\n", i)
	}
	mustWriteFile(t, textPath, textBuf.Bytes(), 0644)

	// 2. Тест на защиту нулей (не должны сжиматься через HuffmanOnly, иначе ratio будет ~12%)
	zeroPath := filepath.Join(srcDir, "zeros.bin")
	mustWriteFile(t, zeroPath, make([]byte, 1024*10), 0644)

	zipPath := filepath.Join(tmpDir, "heuristics.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

	// Используем уровень 1 (BestSpeed), на котором раньше были аномалии
	a, err := NewArchiver(f, srcDir, WithArchiverLevel(1), WithArchiverMethod(Deflate))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	files := make(map[string]os.FileInfo)
	if err := filepath.Walk(srcDir, func(p string, info os.FileInfo, err error) error {
		if p != srcDir {
			files[p] = info
		}
		return nil
	}); err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatalf("Archive failed: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)

	for _, file := range zr.File {
		ratio := float64(file.CompressedSize64) / float64(file.UncompressedSize64) * 100
		if file.Name == "small_text.txt" {
			if ratio >= 100 {
				t.Errorf("Small text anomaly: ratio is %.2f%%, expected < 100%%", ratio)
			}
			t.Logf("Small text ratio: %.2f%% (OK)", ratio)
		}
		if file.Name == "zeros.bin" {
			// LZ77 сожмет 10КБ нулей почти в ноль (десятки байт).
			// Хаффман сожмет 10КБ нулей до ~1.2КБ (12.5%).
			if ratio > 5 {
				t.Errorf("Zeros bloat anomaly: ratio is %.2f%%, expected < 5%% (LZ77 should be used)", ratio)
			}
			t.Logf("Zeros ratio: %.2f%% (OK)", ratio)
		}
	}
}

func TestArchiver_TorrentZipConsistencyWithHeuristics(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	mustMkdirAll(t, srcDir)

	// Создаем "идеальный" файл для Хаффмана (много уникальных символов, мало повторов)
	// Эвристика analyzeBlock захотела бы включить HuffmanOnly (Level -2)
	path := filepath.Join(srcDir, "huffman_bait.txt")
	data := make([]byte, 8192)
	for i := range data {
		data[i] = byte(i % 256)
	}
	mustWriteFile(t, path, data, 0644)

	zipPath := filepath.Join(tmpDir, "tz_test.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

	// В режиме TorrentZip уровень ВСЕГДА должен оставаться 9 (LZ77)
	a, err := NewArchiver(f, srcDir, WithArchiverTorrentZip(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)
	info, _ := os.Stat(path)
	if err := a.Archive(context.Background(), map[string]os.FileInfo{path: info}); err != nil {
		t.Fatalf("archive failed: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)

	// На уровне 9 LZ77 на таком паттерне (0..255 повторяется) сработает идеально.
	// Если бы включился HuffmanOnly, размер был бы точно 8192 + оверхед Хаффмана.
	if zr.File[0].CompressedSize64 > 500 {
		t.Errorf("TorrentZip likely used HuffmanOnly instead of Level 9 LZ77: comp size %d", zr.File[0].CompressedSize64)
	}
}
func TestArchiver_ParallelEncryption(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	dstDir := filepath.Join(tmpDir, "dst")
	mustMkdirAll(t, srcDir)

	password := "parallel-password-123"

	// Create multiple files to force concurrency > 1
	filesToCreate := map[string]string{
		"file1.txt": "parallel encrypted content 1",
		"file2.txt": "parallel encrypted content 2",
		"file3.txt": "parallel encrypted content 3",
		"file4.txt": "parallel encrypted content 4",
		"file5.txt": "parallel encrypted content 5",
	}

	for path, content := range filesToCreate {
		fullPath := filepath.Join(srcDir, path)
		mustMkdirAll(t, filepath.Dir(fullPath))
		if err := os.WriteFile(fullPath, []byte(content), 0600); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	zipPath := filepath.Join(tmpDir, "parallel_enc.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("failed to create zip file: %v", err)
	}
	closeAt(t, f)

	// Use WithArchiverConcurrency(4) to ensure multiple goroutines process files in parallel
	a, err := NewArchiver(f, srcDir, WithArchiverConcurrency(4), WithArchiverPassword(password))
	if err != nil {
		t.Fatalf("failed to init archiver: %v", err)
	}
	closeAt(t, a)

	filesMap := make(map[string]os.FileInfo)
	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path != srcDir {
			filesMap[path] = info
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk failed: %v", err)
	}

	if err := a.Archive(context.Background(), filesMap); err != nil {
		t.Fatalf("archive failed: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("failed to close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close %s: %v", zipPath, err)
	}

	// Extract and verify using multiple goroutines as well
	mustMkdirAll(t, dstDir)
	e, err := NewExtractor(zipPath, dstDir, WithExtractorPassword(password), WithExtractorConcurrency(4))
	if err != nil {
		t.Fatalf("failed to init extractor: %v", err)
	}
	closeAt(t, e)

	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("failed to close extractor: %v", err)
	}

	// Verify the extracted files contents
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
}

// symlinkModeInfo is a real file's FileInfo with the symlink bit set on top.
//
// Archive is handed the FileInfo along with the path, so an entry can claim to
// be a symlink while the path names an ordinary file. That is exactly what a
// caller does when the tree changed under it between the walk and the archive,
// and it makes os.Readlink fail for a reason no platform disagrees about --
// EINVAL on Unix, "the file or directory is not a reparse point" on Windows --
// without needing the privilege that creating a real symlink on Windows wants.
type symlinkModeInfo struct{ os.FileInfo }

func (s symlinkModeInfo) Mode() os.FileMode { return s.FileInfo.Mode() | os.ModeSymlink }

// TestArchiver_ErrorWithIdleWorkersReturns pins every exit from Archive
// against the worker channel being left open.
//
// The workers sit in `for task := range taskCh`, so only the close lets them
// out, and the errgroup is waited on in a deferred call. Any return from the
// middle of the submit loop therefore hangs that wait on every worker that has
// nothing left to do, unless the channel is closed on the path actually taken.
//
// The window is forced rather than raced for. The eight regular entries sort
// ahead of the ninth and all succeed, so by the time the loop reaches the
// symlink entry the pool is idle by construction; the symlink is archived
// inline, on the loop's own goroutine, and its Readlink failure returns
// straight out of the loop -- without cancelling the context, so no worker
// notices anything and all four stay parked. Against a close that happens at
// the bottom of the function this hangs every time, not one run in four.
func TestArchiver_ErrorWithIdleWorkersReturns(t *testing.T) {
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}

	files := make(map[string]os.FileInfo)
	add := func(name string, wrap bool) {
		p := filepath.Join(srcDir, name)
		if err := os.WriteFile(p, []byte("payload"), 0600); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if wrap {
			fi = symlinkModeInfo{fi}
		}
		files[p] = fi
	}
	for i := 0; i < 8; i++ {
		add(fmt.Sprintf("a%02d.txt", i), false)
	}
	// Sorts last, so every worker has drained its task and gone idle before
	// the loop gets here.
	add("zz_link", true)

	zipF, err := os.Create(filepath.Join(tmp, "out.zip"))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zipF)

	a, err := NewArchiver(zipF, srcDir, WithArchiverConcurrency(4))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	done := make(chan error, 1)
	go func() { done <- a.Archive(context.Background(), files) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected the unreadable link to be reported")
		}
	case <-time.After(30 * time.Second):
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		t.Fatalf("Archive did not return within 30s, workers are still waiting on the task channel:\n%s", buf[:n])
	}
}

// seekFailReader is a ReadSeeker whose seeks stop working from the nth one on,
// the way a file whose disk has gone away does. The reads keep working, so the
// failure is the rewind and nothing else.
type seekFailReader struct {
	r      *bytes.Reader
	failAt int
	seeks  int
	err    error
}

func (s *seekFailReader) Read(p []byte) (int, error) { return s.r.Read(p) }

func (s *seekFailReader) Seek(offset int64, whence int) (int64, error) {
	s.seeks++
	if s.seeks >= s.failAt {
		return 0, s.err
	}
	return s.r.Seek(offset, whence)
}

// expandingCompressor is a compressor that makes an entry twice the size it
// was, which is the case the fall back to Store exists for. A real compressor
// expands incompressible data by a fraction of a percent, so a file large
// enough to cross the archiver's threshold that way would be tens of
// megabytes of test fixture.
type expandingCompressor struct{ w io.Writer }

func (e expandingCompressor) Write(p []byte) (int, error) {
	for i := 0; i < 2; i++ {
		if _, err := e.w.Write(p); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (e expandingCompressor) Close() error { return nil }

// mixedEntropyBytes returns n bytes over 200 distinct values, which is what
// the archiver's heuristic reads as "worth deflating": too many distinct bytes
// to be worth Huffman coding alone, too few to look like data that is already
// compressed.
func mixedEntropyBytes(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i % 200)
	}
	return data
}

// highEntropyBytes returns n bytes over all 256 values, evenly enough spread
// that the archiver's heuristic reads them as data that is already compressed
// and not worth deflating a second time. The generator is a plain xorshift so
// that the fixture is the same on every run.
func highEntropyBytes(n int) []byte {
	data := make([]byte, 0, n+4)
	x := uint32(2463534242)
	var word [4]byte
	for len(data) < n {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		binary.LittleEndian.PutUint32(word[:], x)
		data = append(data, word[:]...)
	}
	return data[:n]
}

// TestArchiver_CompressFileStoresWhatIsAlreadyCompressed covers the other
// answer the peek can give: a file the heuristic reads as incompressible is
// stored, and the compressor is never asked about it.
func TestArchiver_CompressFileStoresWhatIsAlreadyCompressed(t *testing.T) {
	var buf bytes.Buffer
	a, err := NewArchiver(&buf, t.TempDir())
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	closeAt(t, a)

	fp, err := filepool.New(t.TempDir(), 1, -1)
	if err != nil {
		t.Fatalf("building the file pool: %v", err)
	}
	closeAt(t, fp)

	data := highEntropyBytes(8192)
	hdr := &FileHeader{Name: "entry.bin", Method: Deflate, UncompressedSize64: uint64(len(data))}
	hdr.SetMode(0644)
	fi := mockFileInfo{name: "entry.bin", mode: 0644}

	if err := a.compressFile(context.Background(), bytes.NewReader(data), fi, hdr, fp.Get()); err != nil {
		t.Fatalf("compressFile: %v", err)
	}
	if hdr.Method != Store {
		t.Errorf("the entry was written with method %d, want Store", hdr.Method)
	}
}

// TestArchiver_CompressFileReturnsAFailedPeekRewind covers the rewind after
// the archiver peeks at the head of a file to decide how to compress it. The
// peek has to be given back before the file is read for real: a rewind that
// did not happen puts the first 64 KiB into the entry twice over, under the
// checksum of a file that has neither.
func TestArchiver_CompressFileReturnsAFailedPeekRewind(t *testing.T) {
	var buf bytes.Buffer
	a, err := NewArchiver(&buf, t.TempDir())
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	closeAt(t, a)

	data := mixedEntropyBytes(8192)
	hdr := &FileHeader{Name: "entry.bin", Method: Deflate, UncompressedSize64: uint64(len(data))}
	hdr.SetMode(0644)

	gone := errors.New("the file went away")
	r := &seekFailReader{r: bytes.NewReader(data), failAt: 1, err: gone}
	fi := mockFileInfo{name: "entry.bin", mode: 0644}

	if err := a.compressFile(context.Background(), r, fi, hdr, nil); !errors.Is(err, gone) {
		t.Fatalf("compressFile returned %v, want %v", err, gone)
	}
}

// TestArchiver_CompressFileFallsBackToStore covers an entry that came out of
// the compressor larger than it went in. The file is read a second time and
// stored instead, and the rewind between the two passes is what makes the
// second pass see the whole file rather than what was left after the first.
func TestArchiver_CompressFileFallsBackToStore(t *testing.T) {
	var buf bytes.Buffer
	a, err := NewArchiver(&buf, t.TempDir())
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	closeAt(t, a)
	a.zw.RegisterCompressor(Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return expandingCompressor{w}, nil
	})

	fp, err := filepool.New(t.TempDir(), 1, -1)
	if err != nil {
		t.Fatalf("building the file pool: %v", err)
	}
	closeAt(t, fp)

	data := mixedEntropyBytes(8192)
	hdr := &FileHeader{Name: "entry.bin", Method: Deflate, UncompressedSize64: uint64(len(data))}
	hdr.SetMode(0644)
	fi := mockFileInfo{name: "entry.bin", mode: 0644}

	if err := a.compressFile(context.Background(), bytes.NewReader(data), fi, hdr, fp.Get()); err != nil {
		t.Fatalf("compressFile: %v", err)
	}
	if hdr.Method != Store {
		t.Errorf("the entry was written with method %d, want Store", hdr.Method)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("closing the archiver: %v", err)
	}

	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("the archive holds %d entries, want 1", len(zr.File))
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("opening the entry: %v", err)
	}
	closeAt(t, rc)
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading the entry: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("the stored entry is %d bytes, want the %d that went in", len(got), len(data))
	}
}

// TestArchiver_CompressFileReturnsAFailedStoreRewind covers the second rewind
// failing. Without it the entry would be written from wherever the compressed
// pass left the file, which is the end of it.
func TestArchiver_CompressFileReturnsAFailedStoreRewind(t *testing.T) {
	var buf bytes.Buffer
	a, err := NewArchiver(&buf, t.TempDir())
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	closeAt(t, a)
	a.zw.RegisterCompressor(Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return expandingCompressor{w}, nil
	})

	fp, err := filepool.New(t.TempDir(), 1, -1)
	if err != nil {
		t.Fatalf("building the file pool: %v", err)
	}
	closeAt(t, fp)

	data := mixedEntropyBytes(8192)
	hdr := &FileHeader{Name: "entry.bin", Method: Deflate, UncompressedSize64: uint64(len(data))}
	hdr.SetMode(0644)
	fi := mockFileInfo{name: "entry.bin", mode: 0644}

	gone := errors.New("the file went away")
	// The first seek is the peek's rewind and still works; the second is
	// the one before the file is stored.
	r := &seekFailReader{r: bytes.NewReader(data), failAt: 2, err: gone}

	if err := a.compressFile(context.Background(), r, fi, hdr, fp.Get()); !errors.Is(err, gone) {
		t.Fatalf("compressFile returned %v, want %v", err, gone)
	}
}

// TestArchiver_XattrsOnLinksAndSpecialFiles covers reading extended attributes
// for the entries that are not ordinary files: a hard link, and a named pipe
// on both the archiver's serial path and its worker path. Reading them is best
// effort whatever the archiver is set to -- it fails on what the source
// filesystem holds rather than on the file, so FAT, exFAT, SMB shares and
// tmpfs would each turn archiving into a failure for carrying no attributes at
// all -- so what is pinned here is that the entries come out whole with the
// option on.
func TestArchiver_XattrsOnLinksAndSpecialFiles(t *testing.T) {
	srcDir := t.TempDir()

	pipeHdr := &FileHeader{Name: "pipe"}
	pipeHdr.SetMode(os.ModeNamedPipe | 0644)
	pipePath := filepath.Join(srcDir, "pipe")
	if err := extractSpecialFile(pipePath, pipeHdr); err != nil {
		t.Skipf("named pipes are not available here: %v", err)
	}
	if fi, err := os.Lstat(pipePath); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Skip("named pipes are not available here")
	}

	target := filepath.Join(srcDir, "target.txt")
	mustWriteFile(t, target, []byte("linked"), 0o600)
	if err := os.Link(target, filepath.Join(srcDir, "hard.txt")); err != nil {
		t.Skipf("hard links are not available here: %v", err)
	}

	for _, tc := range []struct {
		name        string
		concurrency int
	}{
		// One worker means the archiver writes the special file on the
		// loop's own goroutine; more than one sends it to a worker, and
		// the attributes are read on each path separately.
		{"serial", 1},
		{"parallel", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := walkFilesFor(t, srcDir)
			var buf bytes.Buffer
			a, err := NewArchiver(&buf, srcDir,
				WithArchiverXattrs(true),
				WithArchiverConcurrency(tc.concurrency))
			if err != nil {
				t.Fatalf("building the archiver: %v", err)
			}
			closeAt(t, a)
			if err := a.Archive(context.Background(), files); err != nil {
				t.Fatalf("archiving: %v", err)
			}
			if err := a.Close(); err != nil {
				t.Fatalf("closing the archiver: %v", err)
			}

			zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			if err != nil {
				t.Fatalf("reading the archive back: %v", err)
			}
			var sawPipe, sawLink bool
			for _, f := range zr.File {
				if f.Name == "pipe" && f.Mode()&os.ModeNamedPipe != 0 {
					sawPipe = true
				}
				if f.Linkname != "" {
					sawLink = true
				}
			}
			if !sawPipe {
				t.Error("the named pipe did not come out as a named pipe")
			}
			if !sawLink {
				t.Error("neither of the two names came out as a hard link to the other")
			}
		})
	}
}

// skewedBinaryBytes returns n bytes that hold every one of the 256 values but
// are dominated by zeros, which is what the start of an executable, a library
// or a database looks like: all values present, far from random. The order-0
// entropy is about 5 bits per byte.
func skewedBinaryBytes(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		if i%2 == 1 {
			data[i] = byte(i / 2)
		}
	}
	return data
}

// TestAnalyzeBlock_StoreDecisionFollowsEntropy pins the rule the peek goes by:
// a block is stored when its entropy is close to 8 bits per byte, and not
// merely because every byte value occurs in it (f4 #1753: DLL, EXE and DB
// files were stored uncompressed).
func TestAnalyzeBlock_StoreDecisionFollowsEntropy(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"random-like data is stored", highEntropyBytes(8192), true},
		{"all 256 values but skewed is deflated", skewedBinaryBytes(65536), false},
		{"200 even values is deflated", mixedEntropyBytes(8192), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if store, _ := analyzeBlock(tc.data); store != tc.want {
				t.Errorf("analyzeBlock stored=%v, want %v", store, tc.want)
			}
		})
	}
}

// TestArchiver_CompressFileDeflatesSkewedBinary is the end-to-end side of the
// rule above: a binary with all 256 byte values keeps the Deflate method.
func TestArchiver_CompressFileDeflatesSkewedBinary(t *testing.T) {
	var buf bytes.Buffer
	a, err := NewArchiver(&buf, t.TempDir())
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	closeAt(t, a)

	fp, err := filepool.New(t.TempDir(), 1, -1)
	if err != nil {
		t.Fatalf("building the file pool: %v", err)
	}
	closeAt(t, fp)

	data := skewedBinaryBytes(65536)
	hdr := &FileHeader{Name: "entry.dll", Method: Deflate, UncompressedSize64: uint64(len(data))}
	hdr.SetMode(0644)
	fi := mockFileInfo{name: "entry.dll", mode: 0644}

	if err := a.compressFile(context.Background(), bytes.NewReader(data), fi, hdr, fp.Get()); err != nil {
		t.Fatalf("compressFile: %v", err)
	}
	if hdr.Method != Deflate {
		t.Errorf("the entry was written with method %d, want Deflate", hdr.Method)
	}
	if hdr.CompressedSize64 >= hdr.UncompressedSize64 {
		t.Errorf("compressed %d bytes to %d: the entry was not shrunk", hdr.UncompressedSize64, hdr.CompressedSize64)
	}
}
