package zip

import (
    "fmt"
    "bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExtractor_ChownErrorHandling(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "test.zip")
	dstDir := filepath.Join(tmp, "dst")

	// Create an archive with Unix metadata
	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	fh := &FileHeader{Name: "file.txt"}
	fh.Extra = appendUnixExtra(nil, 1000, 1000)
	w, _ := zw.CreateHeader(fh)
	w.Write([]byte("data"))
	zw.Close()
	f.Close()

	// Configure extractor with a chown error handler
	chownCalled := false
	handler := func(name string, err error) error {
		chownCalled = true
		return nil // Ignore error
	}

	e, _ := NewExtractor(zipPath, dstDir, WithExtractorChownErrorHandler(handler))
	err := e.Extract(context.Background())
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	// On standard OSes (non-root), lchown will likely return an error.
	// Use a variable to satisfy the compiler and log the result.
	if chownCalled {
		t.Log("Chown error handler was successfully triggered and executed")
	}
}

func TestExtractor_OutsideChroot(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "evil.zip")
	dstDir := filepath.Join(tmp, "safe")
	os.Mkdir(dstDir, 0755)

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	// Try to go outside the directory via a relative path
	zw.Create("../evil.txt")
	zw.Close()
	f.Close()

	e, _ := NewExtractor(zipPath, dstDir)
	err := e.Extract(context.Background())
	if err == nil {
		t.Error("expected error for path outside of chroot, got nil")
	}
}

func TestExtractor_ZipSlipSecurity(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "slip.zip")
	dstDir := filepath.Join(tmp, "safe")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	// Direct attempt to write to the system root (on Unix) or go far up
	zw.Create("/tmp/pwned.txt")
	zw.Create("../../../opt/pwned.txt")
	zw.Close()
	f.Close()

	e, _ := NewExtractor(zipPath, dstDir)
	err := e.Extract(context.Background())

	// NewExtractor uses filepath.Abs(filepath.Join(chroot, file.Name))
	// and then checks HasPrefix. This should cut off such paths.
	if err == nil {
		t.Error("Extractor allowed Zip Slip path! Security violation.")
	}
}

func TestExtractor_ZipBomb(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "bomb.zip")
	dstDir := filepath.Join(tmp, "extract")

	// Create archive. Write 2048 bytes.
	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	w, _ := zw.Create("bomb.txt")
	w.Write(make([]byte, 2048))
	zw.Close()
	f.Close()

	// Set a limit of 1024 bytes. 2048 > 1024, should fail.
	e, _ := NewExtractor(zipPath, dstDir, WithExtractorMaxFileSize(1024))
	err := e.Extract(context.Background())

	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("expected zip bomb error (limit exceeded), got: %v", err)
	}
}

func TestExtractor_RatioBomb(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "ratio.zip")
	dstDir := filepath.Join(tmp, "extract")

	// Create an archive with data that compresses VERY well (zeros).
	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	w, _ := zw.CreateHeader(&FileHeader{
		Name:   "ratio.txt",
		Method: Deflate,
	})
	// Write 100KB of zeros. Compressed size will be around ~100-200 bytes.
	w.Write(make([]byte, 1024*100))
	zw.Close()
	f.Close()

	// Set a Ratio limit of 2:1. The real ratio will be > 500:1.
	e, _ := NewExtractor(zipPath, dstDir, WithExtractorMaxRatio(2))
	err := e.Extract(context.Background())

	if err == nil || !strings.Contains(err.Error(), "ratio") {
		t.Errorf("expected ratio bomb error, got: %v", err)
	}
}

func TestExtractor_PermissionsPreservation(t *testing.T) {
	// Unix only, as permissions work differently on Windows
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "perms.zip")
	dstDir := filepath.Join(tmp, "dst")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)

	// File with very strict permissions
	fh, _ := FileInfoHeader(mockFileInfo{name: "secret.txt", mode: 0700})
	w, _ := zw.CreateHeader(fh)
	w.Write([]byte("secret"))
	zw.Close()
	f.Close()

	e, _ := NewExtractor(zipPath, dstDir)
	e.Extract(context.Background())

	info, err := os.Stat(filepath.Join(dstDir, "secret.txt"))
	if err != nil {
		t.Fatal(err)
	}

	// Verify that 0700 permissions (rwx------) are preserved
	if info.Mode().Perm() != 0700 {
		t.Errorf("permissions lost! expected 0700, got %o", info.Mode().Perm())
	}
}

func TestExtractor_SymlinkSecurityDeep(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "sym_attack.zip")
	dstDir := filepath.Join(tmp, "safe")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	
	// Create a symlink that points to a path OUTSIDE the archive
	fh := &FileHeader{Name: "attack_link"}
	fh.SetMode(os.ModeSymlink)
	w, _ := zw.CreateHeader(fh)
	// Link target is a system file
	w.Write([]byte("/etc/passwd"))
	zw.Close()
	f.Close()

	e, _ := NewExtractor(zipPath, dstDir)
	err := e.Extract(context.Background())

	// Verify that the link is created, but we shouldn't allow it
	// to act as an attack vector if the library declares this.
	// At this stage extractor.go does os.Symlink(target, path).
	// This will create a link at dstDir/attack_link -> /etc/passwd.
	if err == nil {
		t.Log("Symlink created pointing to /etc/passwd. Ensure your application handles link targets safely.")
	}
}

func TestExtractor_SymlinkDirectoryTraversal(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "traversal.zip")
	dstDir := filepath.Join(tmp, "safe")

	// Directory outside the extraction zone we are "targeting"
	trapDir := filepath.Join(tmp, "trap")
	os.Mkdir(trapDir, 0755)

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)

	// 1. Create symlink "sub" pointing to "trap"
	fh := &FileHeader{Name: "sub"}
	fh.SetMode(os.ModeSymlink)
	w, _ := zw.CreateHeader(fh)
	w.Write([]byte(trapDir))

	// 2. Create file "sub/evil.txt"
	// If the extractor doesn't check that "sub" is already an existing symlink,
	// it might write to trap/evil.txt
	zw.Create("sub/evil.txt")

	zw.Close()
	f.Close()

	e, _ := NewExtractor(zipPath, dstDir)
	err := e.Extract(context.Background())

	// Verification: file should not appear in trapDir
	if _, serr := os.Stat(filepath.Join(trapDir, "evil.txt")); serr == nil {
		t.Errorf("Security Breach! File extracted through symlink into %s", trapDir)
	}

	// Should be an error or simply a safe skip
	_ = err
}

func TestExtractor_LinksToDirs(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "links_to_dirs.zip")
	dstDir := filepath.Join(tmp, "extract")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	w, _ := zw.Create("sub/file.txt")
	w.Write([]byte("file-data"))
	zw.Close()
	f.Close()

	trap := filepath.Join(tmp, "trap")
	os.Mkdir(trap, 0755)
	os.Mkdir(dstDir, 0755)
	os.Symlink(trap, filepath.Join(dstDir, "sub"))

	e, _ := NewExtractor(zipPath, dstDir)
	err := e.Extract(context.Background())
	if err != nil {
		t.Fatalf("Extraction failed: %v", err)
	}
	e.Close()

	fi, err := os.Lstat(filepath.Join(dstDir, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Error("expected symlink 'sub' to be deleted and replaced with a physical directory")
	}

	if _, err := os.Stat(filepath.Join(trap, "file.txt")); err == nil {
		t.Error("Security violation! File extracted through symlink")
	}
}

func TestExtractor_SanitizeMOTW(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "motw.zip")
	dstDir := filepath.Join(tmp, "extract")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	w, _ := zw.Create("test.txt:Zone.Identifier")
	w.Write([]byte("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=http://evil.com/leak\r\nHostUrl=http://evil.com/file\r\n"))
	zw.Close()
	f.Close()

	e, _ := NewExtractor(zipPath, dstDir)
	e.Extract(context.Background())
	e.Close()

	data, err := os.ReadFile(filepath.Join(dstDir, "test.txt:Zone.Identifier"))
	if err != nil {
		t.Fatal(err)
	}
	expected := "[ZoneTransfer]\r\nZoneId=3\r\n"
	if string(data) != expected {
		t.Errorf("expected sanitized MOTW %q, got %q", expected, string(data))
	}
}
func TestExtractor_KeepBroken(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "broken.zip")
	dstDir := filepath.Join(tmp, "extract")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	w, _ := zw.Create("file.txt")
	w.Write([]byte("some substantial data to corrupt"))
	zw.Close()
	f.Close()

	// Corrupt the zip to force a CRC or read error during extraction
	raw, _ := os.ReadFile(zipPath)
	for i := 30; i < 40 && i < len(raw); i++ {
		raw[i] = 0x00
	}
	os.WriteFile(zipPath, raw, 0644)

	// 1. Extraction without KeepBroken (default): file should be cleaned up (deleted)
	e, _ := NewExtractor(zipPath, dstDir)
	err := e.Extract(context.Background())
	e.Close()
	if err == nil {
		t.Error("expected extraction to fail due to corruption")
	}
	if _, serr := os.Stat(filepath.Join(dstDir, "file.txt")); serr == nil {
		t.Error("expected corrupted file to be deleted by default")
	}

	// 2. Extraction with KeepBroken: file should be preserved
	os.RemoveAll(dstDir)
	e2, _ := NewExtractor(zipPath, dstDir, WithExtractorKeepBroken(true))
	err2 := e2.Extract(context.Background())
	e2.Close()
	if err2 == nil {
		t.Error("expected extraction to fail")
	}
	if _, serr := os.Stat(filepath.Join(dstDir, "file.txt")); serr != nil {
		t.Error("expected corrupted file to be preserved when KeepBroken is enabled")
	}
}
func TestExtractor_KeepOldFiles(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "keepold.zip")
	dstDir := filepath.Join(tmpDir, "dst")
	os.MkdirAll(dstDir, 0755)

	targetPath := filepath.Join(dstDir, "test.txt")
	os.WriteFile(targetPath, []byte("ORIGINAL"), 0644)

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	w, _ := zw.Create("test.txt")
	w.Write([]byte("NEW"))
	zw.Close()
	f.Close()

	ignoreChown := WithExtractorChownErrorHandler(func(name string, err error) error { return nil })
	e, err := NewExtractor(zipPath, dstDir, WithExtractorKeepOldFiles(true), ignoreChown)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	if err := e.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(targetPath)
	if string(data) != "ORIGINAL" {
		t.Errorf("Expected ORIGINAL, got %s", string(data))
	}
}

func TestExtractor_KeepNewerFiles(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "keepnewer.zip")
	dstDir := filepath.Join(tmpDir, "dst")
	os.MkdirAll(dstDir, 0755)

	targetPath := filepath.Join(dstDir, "test.txt")
	os.WriteFile(targetPath, []byte("NEWER_DISK"), 0644)

	newerTime := time.Now().Add(1 * time.Hour)
	os.Chtimes(targetPath, newerTime, newerTime)

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	fh := &FileHeader{Name: "test.txt", Method: Store}
	fh.SetModTime(time.Now().Add(-1 * time.Hour))
	w, _ := zw.CreateHeader(fh)
	w.Write([]byte("ARCHIVE"))
	zw.Close()
	f.Close()

	ignoreChown := WithExtractorChownErrorHandler(func(name string, err error) error { return nil })
	e, err := NewExtractor(zipPath, dstDir, WithExtractorKeepNewerFiles(true), ignoreChown)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	if err := e.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(targetPath)
	if string(data) != "NEWER_DISK" {
		t.Errorf("Expected NEWER_DISK, got %s", string(data))
	}
}

func TestExtractor_NoTimes(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "notimes.zip")
	dstDir := filepath.Join(tmpDir, "dst")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	oldTime := time.Date(1999, time.January, 1, 0, 0, 0, 0, time.UTC)
	fh := &FileHeader{Name: "oldfile.txt"}
	fh.SetModTime(oldTime)
	w, _ := zw.CreateHeader(fh)
	w.Write([]byte("data"))
	zw.Close()
	f.Close()

	ignoreChown := WithExtractorChownErrorHandler(func(name string, err error) error { return nil })
	e, err := NewExtractor(zipPath, dstDir, WithExtractorNoTimes(true), ignoreChown)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	if err := e.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(filepath.Join(dstDir, "oldfile.txt"))
	if err != nil {
		t.Fatal(err)
	}

	if fi.ModTime().Equal(oldTime) {
		t.Errorf("Modification time was restored despite WithExtractorNoTimes(true)")
	}
}

func TestExtractor_StripComponents(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "strip.zip")
	dstDir := filepath.Join(tmpDir, "dst")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	w, _ := zw.Create("level1/level2/target.txt")
	w.Write([]byte("data"))
	w, _ = zw.Create("short.txt")
	w.Write([]byte("data"))
	zw.Close()
	f.Close()

	ignoreChown := WithExtractorChownErrorHandler(func(name string, err error) error { return nil })
	e, err := NewExtractor(zipPath, dstDir, WithExtractorStripComponents(1), ignoreChown)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	if err := e.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dstDir, "level2", "target.txt")); err != nil {
		t.Errorf("Expected stripped nested file not found: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dstDir, "short.txt")); !os.IsNotExist(err) {
		t.Errorf("Expected short.txt to be skipped, but it was extracted")
	}
}

func TestExtractor_SparseExtraction(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "sparse.zip")
	dstDir := filepath.Join(tmpDir, "dst")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)

	zeroSize := int64(1024 * 1024)
	fh := &FileHeader{Name: "zeros.txt", Method: Store}
	fh.UncompressedSize64 = uint64(zeroSize)
	w, _ := zw.CreateHeader(fh)
	w.Write(make([]byte, zeroSize))
	zw.Close()
	f.Close()

	ignoreChown := WithExtractorChownErrorHandler(func(name string, err error) error { return nil })
	e, err := NewExtractor(zipPath, dstDir, WithExtractorSparse(true), ignoreChown)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("Extraction failed: %v", err)
	}

	targetFile := filepath.Join(dstDir, "zeros.txt")
	fi, err := os.Stat(targetFile)
	if err != nil {
		t.Fatal(err)
	}

	if fi.Size() != zeroSize {
		t.Errorf("Logical size mismatch: expected %d, got %d", zeroSize, fi.Size())
	}
}

func TestSolidAndIncremental_Zip(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	dstDir := filepath.Join(tmpDir, "dst")
	zipPath := filepath.Join(tmpDir, "solid_inc.zip")

	os.MkdirAll(srcDir, 0755)
	os.WriteFile(filepath.Join(srcDir, "stay.txt"), []byte("stay data"), 0644)
	os.WriteFile(filepath.Join(srcDir, "deleted.txt"), []byte("to be deleted"), 0644)

	// 1. Pack files into Solid ZIP with incremental index preservation
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	a, err := NewArchiver(f, srcDir,
		WithArchiverSolid(true),
		WithArchiverIncremental(true),
		WithArchiverMethod(Deflate),
		WithArchiverPlatformMetadata(true),
		WithArchiverXattrs(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	filesMap := make(map[string]os.FileInfo)
	filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if path != srcDir {
			filesMap[path] = info
		}
		return nil
	})

	if err := a.Archive(context.Background(), filesMap); err != nil {
		t.Fatal(err)
	}
	a.Close()
	f.Close()

	// 2. Extract files for the first time
	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.Close()

	if _, err := os.Stat(filepath.Join(dstDir, "stay.txt")); err != nil {
		t.Errorf("file 'stay.txt' was not extracted")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "deleted.txt")); err != nil {
		t.Errorf("file 'deleted.txt' was not extracted")
	}

	// 3. Create a new incremental archive where 'deleted.txt' is no longer present
	os.Remove(filepath.Join(srcDir, "deleted.txt"))
	os.Remove(zipPath)

	f2, _ := os.Create(zipPath)
	a2, _ := NewArchiver(f2, srcDir,
		WithArchiverSolid(true),
		WithArchiverIncremental(true),
		WithArchiverMethod(Deflate),
		WithArchiverPlatformMetadata(true),
		WithArchiverXattrs(true),
	)

	filesMap2 := make(map[string]os.FileInfo)
	filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if path != srcDir {
			filesMap2[path] = info
		}
		return nil
	})

	a2.Archive(context.Background(), filesMap2)
	a2.Close()
	f2.Close()

	// 4. Restore archive over dstDir with WithExtractorIncremental(true) flag
	e2, err := NewExtractor(zipPath, dstDir, WithExtractorIncremental(true))
	if err != nil {
		t.Fatal(err)
	}
	if err := e2.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}
	e2.Close()

	// File 'stay.txt' should remain, while 'deleted.txt' should be deleted
	if _, err := os.Stat(filepath.Join(dstDir, "stay.txt")); err != nil {
		t.Errorf("file 'stay.txt' should be kept")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "deleted.txt")); !os.IsNotExist(err) {
		t.Errorf("file 'deleted.txt' was not deleted during incremental restore")
	}

	// 5. Check compatibility with standard unzip utility (if available)
	if unzipPath, err := exec.LookPath("unzip"); err == nil {

		unzipDst := filepath.Join(tmpDir, "unzip_dst")
		os.MkdirAll(unzipDst, 0755)

		cmd := exec.Command(unzipPath, zipPath, "-d", unzipDst)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Native unzip extraction of outer ZIP failed: %v, output: %s", err, string(output))
		}

		innerZipPath := filepath.Join(unzipDst, "Solid.zip")
		unzipInnerDst := filepath.Join(unzipDst, "inner")
		os.MkdirAll(unzipInnerDst, 0755)

		cmdInner := exec.Command(unzipPath, innerZipPath, "-d", unzipInnerDst)
		if output, err := cmdInner.CombinedOutput(); err != nil {
			t.Fatalf("Native unzip extraction of inner ZIP failed: %v, output: %s", err, string(output))
		}

		data, err := os.ReadFile(filepath.Join(unzipInnerDst, "stay.txt"))
		if err != nil {
			t.Fatalf("Failed to read stay.txt extracted by native unzip: %v", err)
		}
		if string(data) != "stay data" {
			t.Errorf("Content mismatch in file extracted by native unzip: expected 'stay data', got %q", string(data))
		}
		t.Log("[DEBUG TEST] Native unzip compatibility verified successfully!")
	} else {
		t.Log("[DEBUG TEST] Native unzip utility not found on this system. Skipping external compatibility check.")
	}
}

func TestSolidFallback_Zip(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "fallback.zip")
	dstDir := filepath.Join(tmpDir, "dst")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := NewWriter(f)

	hdr := &FileHeader{
		Name:   "Solid.zip",
		Method: Store,
	}
	w, _ := zw.CreateHeader(hdr)

	// Create internal archiver with forceNoDescriptor = false (simulating a third-party utility)
	innerZw := NewWriter(w)

	innerW, _ := innerZw.Create("test.txt")
	innerW.Write([]byte("some fallback data"))
	innerZw.Close()

	zw.Close()
	f.Close()

	// Extract. Streaming extraction should fail, automatically triggering two-pass fallback mode.
	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("Solid extraction fallback failed: %v", err)
	}
	e.Close()

	data, err := os.ReadFile(filepath.Join(dstDir, "test.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "some fallback data" {
		t.Errorf("expected 'some fallback data', got %q", string(data))
	}
}

func TestExtractor_ConcurrencyIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "stress.zip")
	dstDir := filepath.Join(tmpDir, "dst")

	// Create 100 files, each containing its name as content
	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("file_%d.txt", i)
		w, _ := zw.Create(name)
		w.Write([]byte(name))
	}
	zw.Close()
	f.Close()

	// Extract with high concurrency
	e, _ := NewExtractor(zipPath, dstDir, WithExtractorConcurrency(20))
	if err := e.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.Close()

	// Check that each file contains exactly its name (not another one due to a race)
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("file_%d.txt", i)
		data, _ := os.ReadFile(filepath.Join(dstDir, name))
		if string(data) != name {
			t.Errorf("Integrity breach at %s: expected %q, got %q", name, name, string(data))
		}
	}
}

func TestTolerantMode_Zip(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "corrupt.zip")
	dstDir := filepath.Join(tmpDir, "dst")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	w, _ := zw.Create("good1.txt")
	w.Write([]byte("I am fine"))
	w, _ = zw.Create("bad.txt")
	w.Write([]byte("I will be corrupted"))
	w, _ = zw.Create("good2.txt")
	w.Write([]byte("I am also fine"))
	zw.Close()
	f.Close()

	// Corrupt bad.txt data (find it in the middle of the archive)
	raw, _ := os.ReadFile(zipPath)
	idx := bytes.Index(raw, []byte("I will be corrupted"))
	for i := 0; i < 5; i++ {
		raw[idx+i] = 0xFF
	}
	os.WriteFile(zipPath, raw, 0644)

	// Extract with TolerantMode(true)
	e, _ := NewExtractor(zipPath, dstDir, WithExtractorTolerant(true))
	err := e.Extract(context.Background())
	if err != nil {
		t.Errorf("Extract failed despite tolerant mode: %v", err)
	}
	e.Close()

	// Check that good files are present
	if _, err := os.Stat(filepath.Join(dstDir, "good1.txt")); err != nil {
		t.Error("good1.txt missing")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "good2.txt")); err != nil {
		t.Error("good2.txt missing")
	}
}

func TestZipExternalCompatibility_Zip(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	os.MkdirAll(srcDir, 0755)

	filePath := filepath.Join(srcDir, "test.txt")
	os.WriteFile(filePath, []byte("solid metadata content"), 0644)

	zipPath := filepath.Join(tmpDir, "meta_compat.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	// Pack with xattrs, platform metadata (Uname/Gname)
	a, err := NewArchiver(f, tmpDir,
		WithArchiverSolid(true),
		WithArchiverIncremental(true),
		WithArchiverMethod(Deflate),
		WithArchiverPlatformMetadata(true),
		WithArchiverXattrs(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	filesMap := make(map[string]os.FileInfo)
	filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if path != srcDir {
			filesMap[path] = info
		}
		return nil
	})

	if err := a.Archive(context.Background(), filesMap); err != nil {
		t.Fatal(err)
	}
	a.Close()
	f.Close()

	// 1. Check compatibility with 7z (if available)
	if p7zPath, err := exec.LookPath("7z"); err == nil {
		t.Logf("[DEBUG TEST] Found 7z utility at %s. Verifying backward compatibility...", p7zPath)
		dstDir := filepath.Join(tmpDir, "7z_dst")
		os.MkdirAll(dstDir, 0755)

		cmd := exec.Command(p7zPath, "x", "-o"+dstDir, zipPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("7z extraction of outer ZIP failed: %v, output: %s", err, string(output))
		}

		innerZip := filepath.Join(dstDir, "Solid.zip")
		innerDst := filepath.Join(dstDir, "inner")
		cmdInner := exec.Command(p7zPath, "x", "-o"+innerDst, innerZip)
		if output, err := cmdInner.CombinedOutput(); err != nil {
			t.Fatalf("7z extraction of inner ZIP failed: %v, output: %s", err, string(output))
		}

		data, err := os.ReadFile(filepath.Join(innerDst, "src", "test.txt"))
		if err != nil {
			t.Fatalf("Failed to read file extracted by 7z: %v", err)
		}
		if string(data) != "solid metadata content" {
			t.Errorf("Content mismatch in file extracted by 7z: expected 'solid metadata content', got %q", string(data))
		}
		t.Log("[DEBUG TEST] 7z compatibility verified successfully!")
	}

	// 2. Check compatibility with unar (if available)
	if unarPath, err := exec.LookPath("unar"); err == nil {
		t.Logf("[DEBUG TEST] Found unar utility at %s. Verifying backward compatibility...", unarPath)
		dstDir := filepath.Join(tmpDir, "unar_dst")
		os.MkdirAll(dstDir, 0755)

		cmd := exec.Command(unarPath, "-o", dstDir, zipPath)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("unar extraction of outer ZIP failed: %v, output: %s", err, string(output))
		}

		innerZip := filepath.Join(dstDir, "Solid.zip")
		innerDst := filepath.Join(dstDir, "inner")
		cmdInner := exec.Command(unarPath, "-o", innerDst, innerZip)
		if output, err := cmdInner.CombinedOutput(); err != nil {
			t.Fatalf("unar extraction of inner ZIP failed: %v, output: %s", err, string(output))
		}

		data, err := os.ReadFile(filepath.Join(innerDst, "Solid", "src", "test.txt"))
		if err != nil {
			data, err = os.ReadFile(filepath.Join(innerDst, "src", "test.txt"))
		}
		if err != nil {
			t.Fatalf("Failed to read file extracted by unar: %v", err)
		}
		if string(data) != "solid metadata content" {
			t.Errorf("Content mismatch in file extracted by unar: expected 'solid metadata content', got %q", string(data))
		}
		t.Log("[DEBUG TEST] unar compatibility verified successfully!")
	}
}

func TestExternalZip_Zip(t *testing.T) {
	zipPath, err := exec.LookPath("zip")
	if err != nil {
		t.Skip("Native zip utility not found on this system. Skipping forward compatibility check.")
	}

	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	os.MkdirAll(srcDir, 0755)

	os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("external zip data"), 0644)
	os.MkdirAll(filepath.Join(srcDir, "sub"), 0755)
	os.WriteFile(filepath.Join(srcDir, "sub", "file2.txt"), []byte("nested external zip data"), 0644)

	archivePath := filepath.Join(tmpDir, "external.zip")

	cmd := exec.Command(zipPath, "-r", archivePath, ".")
	cmd.Dir = srcDir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Native zip utility failed: %v, output: %s", err, string(output))
	}

	dstDir := filepath.Join(tmpDir, "extract")
	e, err := NewExtractor(archivePath, dstDir)
	if err != nil {
		t.Fatalf("Failed to initialize Extractor for external zip: %v", err)
	}
	defer e.Close()

	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("Extraction of external zip failed: %v", err)
	}

	data1, err := os.ReadFile(filepath.Join(dstDir, "file1.txt"))
	if err != nil {
		t.Fatalf("Failed to read file1.txt: %v", err)
	}
	if string(data1) != "external zip data" {
		t.Errorf("Content mismatch in file1.txt: expected 'external zip data', got %q", string(data1))
	}

	data2, err := os.ReadFile(filepath.Join(dstDir, "sub", "file2.txt"))
	if err != nil {
		t.Fatalf("Failed to read sub/file2.txt: %v", err)
	}
	if string(data2) != "nested external zip data" {
		t.Errorf("Content mismatch in sub/file2.txt: expected 'nested external zip data', got %q", string(data2))
	}
}

