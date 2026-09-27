package zip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestExtractor_ChownErrorHandling(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "test.zip")
	dstDir := filepath.Join(tmp, "dst")

	// Create an archive with Unix metadata
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	fh := &FileHeader{Name: "file.txt"}
	fh.Extra = appendUnixExtra(nil, 1000, 1000)
	w := mustCreateHeader(t, zw, fh)
	mustWrite(t, w, []byte("data"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	// Configure extractor with a chown error handler
	chownCalled := false
	handler := func(name string, err error) error {
		chownCalled = true
		return nil // Ignore error
	}

	e, err := NewExtractor(zipPath, dstDir, WithExtractorChownErrorHandler(handler))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
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
	mustMkdir(t, dstDir)

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	// Try to go outside the directory via a relative path
	mustCreate(t, zw, "../evil.txt")
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); !errors.Is(err, ErrInsecurePath) {
		t.Errorf("expected ErrInsecurePath for path outside of chroot, got: %v", err)
	}
}

func TestExtractor_ZipSlipSecurity(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "slip.zip")
	dstDir := filepath.Join(tmp, "safe")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	// Direct attempt to write to the system root (on Unix) or go far up
	mustCreate(t, zw, "/tmp/pwned.txt")
	mustCreate(t, zw, "../../../opt/pwned.txt")
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)

	// NewExtractor uses filepath.Abs(filepath.Join(chroot, file.Name))
	// and then checks HasPrefix. This should cut off such paths.
	if err := e.Extract(context.Background()); !errors.Is(err, ErrInsecurePath) {
		t.Errorf("Extractor allowed Zip Slip path! Security violation. got: %v", err)
	}
}

func TestExtractor_ZipBomb(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "bomb.zip")
	dstDir := filepath.Join(tmp, "extract")

	// Create archive. Write 2048 bytes.
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w := mustCreate(t, zw, "bomb.txt")
	mustWrite(t, w, make([]byte, 2048))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	// Set a limit of 1024 bytes. 2048 > 1024, should fail.
	e, err := NewExtractor(zipPath, dstDir, WithExtractorMaxFileSize(1024))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)

	if err := e.Extract(context.Background()); !errors.Is(err, ErrSizeLimit) {
		t.Errorf("expected zip bomb error (ErrSizeLimit), got: %v", err)
	}
}

func TestExtractor_RatioBomb(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "ratio.zip")
	dstDir := filepath.Join(tmp, "extract")

	// Create an archive with data that compresses VERY well (zeros).
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w := mustCreateHeader(t, zw, &FileHeader{
		Name:   "ratio.txt",
		Method: Deflate,
	})
	// Write 100KB of zeros. Compressed size will be around ~100-200 bytes.
	mustWrite(t, w, make([]byte, 1024*100))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	// Set a Ratio limit of 2:1. The real ratio will be > 500:1.
	e, err := NewExtractor(zipPath, dstDir, WithExtractorMaxRatio(2))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)

	if err := e.Extract(context.Background()); !errors.Is(err, ErrRatioLimit) {
		t.Errorf("expected ratio bomb error (ErrRatioLimit), got: %v", err)
	}
}

// TestExtractor_TotalSizeLimit covers the case WithExtractorMaxFileSize and
// WithExtractorMaxRatio do not: many entries, each of them within both of
// those per-entry limits, whose sum is not. Without a limit of its own on the
// whole extraction, an archive built this way could expand to an unbounded
// total on disk.
func TestExtractor_TotalSizeLimit(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "many.zip")
	dstDir := filepath.Join(tmp, "extract")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	// Ten entries of 1000 bytes each, well under a 1024 byte per-file limit
	// and a 1:1 ratio (stored, so there is nothing to expand).
	for i := 0; i < 10; i++ {
		w := mustCreateHeader(t, zw, &FileHeader{
			Name:   fmt.Sprintf("entry-%d.bin", i),
			Method: Store,
		})
		mustWrite(t, w, make([]byte, 1000))
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	// The sum, 10000 bytes, is well past a 5000 byte total limit, even
	// though every single entry stays under the per-file and ratio limits.
	e, err := NewExtractor(zipPath, dstDir,
		WithExtractorMaxFileSize(1024), WithExtractorMaxRatio(1), WithExtractorMaxTotalSize(5000))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)

	if err := e.Extract(context.Background()); !errors.Is(err, ErrTotalSizeLimit) {
		t.Errorf("expected total size limit error (ErrTotalSizeLimit), got: %v", err)
	}
}

// TestExtractor_TotalSizeLimit_Disabled covers the zero value: a total limit
// of zero turns the check off, same as the per-file and ratio limits, so an
// archive that would trip a smaller one extracts cleanly.
func TestExtractor_TotalSizeLimit_Disabled(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "many.zip")
	dstDir := filepath.Join(tmp, "extract")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	for i := 0; i < 10; i++ {
		w := mustCreateHeader(t, zw, &FileHeader{
			Name:   fmt.Sprintf("entry-%d.bin", i),
			Method: Store,
		})
		mustWrite(t, w, make([]byte, 1000))
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	e, err := NewExtractor(zipPath, dstDir, WithExtractorMaxTotalSize(0))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)

	if err := e.Extract(context.Background()); err != nil {
		t.Errorf("a disabled total size limit refused the extraction: %v", err)
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

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)

	// File with very strict permissions
	fh, err := FileInfoHeader(mockFileInfo{name: "secret.txt", mode: 0700})
	if err != nil {
		t.Fatal(err)
	}
	w := mustCreateHeader(t, zw, fh)
	mustWrite(t, w, []byte("secret"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

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

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)

	// Create a symlink that points to a path OUTSIDE the archive
	fh := &FileHeader{Name: "attack_link"}
	fh.SetMode(os.ModeSymlink)
	w := mustCreateHeader(t, zw, fh)
	// Link target is a system file
	mustWrite(t, w, []byte("/etc/passwd"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	err = e.Extract(context.Background())

	// The extractor must reject absolute symlinks
	if err == nil || !strings.Contains(err.Error(), "absolute symlink target not allowed") {
		t.Errorf("Security Breach! Expected error rejecting absolute symlink, got: %v", err)
	}

	// Clean up and test relative escape. The extractor still holds the
	// archive open, and Windows will not unlink an open file, so close it
	// here rather than deferring to the end of the test.
	if err := e.Close(); err != nil {
		t.Fatalf("close extractor: %v", err)
	}
	if err := os.RemoveAll(dstDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(zipPath); err != nil {
		t.Fatal(err)
	}

	f2, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f2)
	zw2 := NewWriter(f2)
	fh2 := &FileHeader{Name: "sub/attack_link"}
	fh2.SetMode(os.ModeSymlink)
	w2 := mustCreateHeader(t, zw2, fh2)
	mustWrite(t, w2, []byte("../../etc/passwd"))
	if err := zw2.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f2.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	e2, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e2)
	err2 := e2.Extract(context.Background())
	if err2 == nil || !strings.Contains(err2.Error(), "escapes chroot") {
		t.Errorf("Security Breach! Expected error rejecting relative escape symlink, got: %v", err2)
	}
}

func TestExtractor_SymlinkDirectoryTraversal(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "traversal.zip")
	dstDir := filepath.Join(tmp, "safe")

	// Directory outside the extraction zone we are "targeting"
	trapDir := filepath.Join(tmp, "trap")
	mustMkdir(t, trapDir)

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)

	// 1. Create symlink "sub" pointing to "trap"
	fh := &FileHeader{Name: "sub"}
	fh.SetMode(os.ModeSymlink)
	w := mustCreateHeader(t, zw, fh)
	mustWrite(t, w, []byte(trapDir))

	// 2. Create file "sub/evil.txt"
	// If the extractor doesn't check that "sub" is already an existing symlink,
	// it might write to trap/evil.txt
	mustCreate(t, zw, "sub/evil.txt")

	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	// Should be an error or simply a safe skip, so the answer is only logged;
	// where the file ends up is what this test is about.
	if err := e.Extract(context.Background()); err != nil {
		t.Logf("extraction reported: %v", err)
	}

	// Verification: file should not appear in trapDir
	if _, serr := os.Stat(filepath.Join(trapDir, "evil.txt")); serr == nil {
		t.Errorf("Security Breach! File extracted through symlink into %s", trapDir)
	}
}

func TestExtractor_LinksToDirs(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "links_to_dirs.zip")
	dstDir := filepath.Join(tmp, "extract")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w := mustCreate(t, zw, "sub/file.txt")
	mustWrite(t, w, []byte("file-data"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	trap := filepath.Join(tmp, "trap")
	mustMkdir(t, trap)
	mustMkdir(t, dstDir)
	if err := os.Symlink(trap, filepath.Join(dstDir, "sub")); err != nil {
		// Making a symlink is a privilege the account may not hold, and
		// without one there is no traversal to attempt.
		t.Skipf("cannot create a symlink here: %v", err)
	}

	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("Extraction failed: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close extractor: %v", err)
	}

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

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w := mustCreate(t, zw, "test.txt:Zone.Identifier")
	mustWrite(t, w, []byte("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=http://evil.com/leak\r\nHostUrl=http://evil.com/file\r\n"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close extractor: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dstDir, "test.txt:Zone.Identifier"))
	if err != nil {
		t.Fatal(err)
	}
	expected := "[ZoneTransfer]\r\nZoneId=3\r\n"
	if string(data) != expected {
		t.Errorf("expected sanitized MOTW %q, got %q", expected, string(data))
	}
}
func TestExtractor_SanitizeMOTW_UTF16LE(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "motw_utf16.zip")
	dstDir := filepath.Join(tmp, "extract")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w := mustCreate(t, zw, "test.txt:Zone.Identifier")

	// UTF-16LE encoded Zone.Identifier with BOM (0xFF, 0xFE)
	rawInput := "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=http://evil.com\r\n"
	utf16Input := encodeUTF16LE(rawInput)
	mustWrite(t, w, utf16Input)
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close extractor: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dstDir, "test.txt:Zone.Identifier"))
	if err != nil {
		t.Fatal(err)
	}

	if !isUTF16LE(data) {
		t.Fatal("expected sanitized output to remain UTF-16LE encoded")
	}

	decoded := decodeUTF16LE(data)
	expected := "[ZoneTransfer]\r\nZoneId=3\r\n"
	if decoded != expected {
		t.Errorf("expected sanitized UTF-16LE content %q, got %q", expected, decoded)
	}
}
func TestExtractor_KeepBroken(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "broken.zip")
	dstDir := filepath.Join(tmp, "extract")

	// The archive is assembled in memory so that the corruption below is
	// applied to the bytes on their way to disk, rather than by writing the
	// file once and reading it back to patch it.
	var archive bytes.Buffer
	zw := NewWriter(&archive)
	w := mustCreate(t, zw, "file.txt")
	mustWrite(t, w, []byte("some substantial data to corrupt"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	// Corrupt the zip to force a CRC or read error during extraction
	raw := archive.Bytes()
	for i := 30; i < 40 && i < len(raw); i++ {
		raw[i] = 0x00
	}
	mustWriteFile(t, zipPath, raw, 0600)

	// 1. Extraction without KeepBroken (default): file should be cleaned up (deleted)
	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	err = e.Extract(context.Background())
	if cerr := e.Close(); cerr != nil {
		t.Fatalf("close extractor: %v", cerr)
	}
	if err == nil {
		t.Error("expected extraction to fail due to corruption")
	}
	if _, serr := os.Stat(filepath.Join(dstDir, "file.txt")); serr == nil {
		t.Error("expected corrupted file to be deleted by default")
	}

	// 2. Extraction with KeepBroken: file should be preserved
	if err := os.RemoveAll(dstDir); err != nil {
		t.Fatal(err)
	}
	e2, err := NewExtractor(zipPath, dstDir, WithExtractorKeepBroken(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e2)
	err2 := e2.Extract(context.Background())
	if cerr := e2.Close(); cerr != nil {
		t.Fatalf("close extractor: %v", cerr)
	}
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
	mustMkdirAll(t, dstDir)

	targetPath := filepath.Join(dstDir, "test.txt")
	mustWriteFile(t, targetPath, []byte("ORIGINAL"), 0644)

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w := mustCreate(t, zw, "test.txt")
	mustWrite(t, w, []byte("NEW"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	ignoreChown := WithExtractorChownErrorHandler(func(name string, err error) error { return nil })
	e, err := NewExtractor(zipPath, dstDir, WithExtractorKeepOldFiles(true), ignoreChown)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)

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
	mustMkdirAll(t, dstDir)

	targetPath := filepath.Join(dstDir, "test.txt")
	mustWriteFile(t, targetPath, []byte("NEWER_DISK"), 0644)

	newerTime := time.Now().Add(1 * time.Hour)
	if err := os.Chtimes(targetPath, newerTime, newerTime); err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	fh := &FileHeader{Name: "test.txt", Method: Store}
	fh.SetModTime(time.Now().Add(-1 * time.Hour))
	w := mustCreateHeader(t, zw, fh)
	mustWrite(t, w, []byte("ARCHIVE"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	ignoreChown := WithExtractorChownErrorHandler(func(name string, err error) error { return nil })
	e, err := NewExtractor(zipPath, dstDir, WithExtractorKeepNewerFiles(true), ignoreChown)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)

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

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	oldTime := time.Date(1999, time.January, 1, 0, 0, 0, 0, time.UTC)
	fh := &FileHeader{Name: "oldfile.txt"}
	fh.SetModTime(oldTime)
	w := mustCreateHeader(t, zw, fh)
	mustWrite(t, w, []byte("data"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	ignoreChown := WithExtractorChownErrorHandler(func(name string, err error) error { return nil })
	e, err := NewExtractor(zipPath, dstDir, WithExtractorNoTimes(true), ignoreChown)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)

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

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w := mustCreate(t, zw, "level1/level2/target.txt")
	mustWrite(t, w, []byte("data"))
	w = mustCreate(t, zw, "short.txt")
	mustWrite(t, w, []byte("data"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	ignoreChown := WithExtractorChownErrorHandler(func(name string, err error) error { return nil })
	e, err := NewExtractor(zipPath, dstDir, WithExtractorStripComponents(1), ignoreChown)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)

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

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)

	zeroSize := int64(1024 * 1024)
	fh := &FileHeader{Name: "zeros.txt", Method: Store}
	fh.UncompressedSize64 = uint64(zeroSize)
	w := mustCreateHeader(t, zw, fh)
	mustWrite(t, w, make([]byte, zeroSize))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	ignoreChown := WithExtractorChownErrorHandler(func(name string, err error) error { return nil })
	e, err := NewExtractor(zipPath, dstDir, WithExtractorSparse(true), ignoreChown)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)

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

	mustMkdirAll(t, srcDir)
	mustWriteFile(t, filepath.Join(srcDir, "stay.txt"), []byte("stay data"), 0644)
	mustWriteFile(t, filepath.Join(srcDir, "deleted.txt"), []byte("to be deleted"), 0644)

	// 1. Pack files into Solid ZIP with incremental index preservation
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

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
	closeAt(t, a)

	filesMap := make(map[string]os.FileInfo)
	if err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if path != srcDir {
			filesMap[path] = info
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := a.Archive(context.Background(), filesMap); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	// 2. Extract files for the first time
	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close extractor: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dstDir, "stay.txt")); err != nil {
		t.Errorf("file 'stay.txt' was not extracted")
	}
	if _, err := os.Stat(filepath.Join(dstDir, "deleted.txt")); err != nil {
		t.Errorf("file 'deleted.txt' was not extracted")
	}

	// 3. Create a new incremental archive where 'deleted.txt' is no longer present
	if err := os.Remove(filepath.Join(srcDir, "deleted.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(zipPath); err != nil {
		t.Fatal(err)
	}

	f2, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f2)
	a2, err := NewArchiver(f2, srcDir,
		WithArchiverSolid(true),
		WithArchiverIncremental(true),
		WithArchiverMethod(Deflate),
		WithArchiverPlatformMetadata(true),
		WithArchiverXattrs(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a2)

	filesMap2 := make(map[string]os.FileInfo)
	if err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if path != srcDir {
			filesMap2[path] = info
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := a2.Archive(context.Background(), filesMap2); err != nil {
		t.Fatal(err)
	}
	if err := a2.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f2.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	// 4. Restore archive over dstDir with WithExtractorIncremental(true) flag
	e2, err := NewExtractor(zipPath, dstDir, WithExtractorIncremental(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e2)
	if err := e2.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e2.Close(); err != nil {
		t.Fatalf("close extractor: %v", err)
	}

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
		mustMkdirAll(t, unzipDst)

		cmd := exec.Command(unzipPath, zipPath, "-d", unzipDst)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Native unzip extraction of outer ZIP failed: %v, output: %s", err, string(output))
		}

		innerZipPath := filepath.Join(unzipDst, "Solid.zip")
		unzipInnerDst := filepath.Join(unzipDst, "inner")
		mustMkdirAll(t, unzipInnerDst)

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

func TestSolid_CRC32Check(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "solid_crc.zip")
	dstDir := filepath.Join(tmpDir, "dst")

	// The archive is assembled in memory so that the corruption below is
	// applied to the bytes on their way to disk, rather than by writing the
	// file once and reading it back to patch it.
	var archive bytes.Buffer
	zw := NewWriter(&archive)
	hdr := &FileHeader{
		Name:   "Solid.zip",
		Method: Store,
	}
	w := mustCreateHeader(t, zw, hdr)
	innerZw := NewWriter(w)
	data := []byte("data to be corrupted")
	innerW, err := innerZw.CreateRaw(&FileHeader{
		Name:               "test.txt",
		Method:             Store,
		CompressedSize64:   uint64(len(data)),
		UncompressedSize64: uint64(len(data)),
		CRC32:              crc32.ChecksumIEEE(data),
	})
	if err != nil {
		t.Fatalf("create raw entry: %v", err)
	}
	mustWrite(t, innerW, data)
	if err := innerZw.Close(); err != nil {
		t.Fatalf("close inner writer: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	// Corrupt the data in the inner file to trigger CRC mismatch
	raw := archive.Bytes()
	// Search for "data to be"
	idx := bytes.Index(raw, []byte("data to be"))
	if idx != -1 {
		raw[idx] = 'D'
	}
	mustWriteFile(t, zipPath, raw, 0600)

	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	err = e.Extract(context.Background())
	if err == nil || err != ErrChecksum {
		t.Errorf("expected ErrChecksum for corrupted Solid archive, got: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close extractor: %v", err)
	}
}
func TestExtractor_IncrementalSafeguard(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "inc.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w := mustCreate(t, zw, ".zip_dumpdir")
	mustWrite(t, w, []byte("file.txt\n"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	trapDir := filepath.Join(tmpDir, "trap")
	mustMkdir(t, trapDir)
	mustWriteFile(t, filepath.Join(trapDir, "valuable.txt"), []byte("do not delete me"), 0644)

	e, err := NewExtractor(zipPath, trapDir, WithExtractorIncremental(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	err = e.Extract(context.Background())
	if cerr := e.Close(); cerr != nil {
		t.Fatalf("close extractor: %v", cerr)
	}

	if err == nil || !strings.Contains(err.Error(), "refusing to extract incremental archive into a non-empty directory") {
		t.Errorf("Expected safeguard error, got: %v", err)
	}

	if _, err := os.Stat(filepath.Join(trapDir, "valuable.txt")); os.IsNotExist(err) {
		t.Error("Safeguard failed: valuable file was deleted!")
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
	closeAt(t, f)
	zw := NewWriter(f)

	// A compressed solid entry is one the extraction cannot read where it
	// lies, so it goes through the scratch copy the counters below are
	// about.
	hdr := &FileHeader{
		Name:   "Solid.zip",
		Method: Deflate,
	}
	w := mustCreateHeader(t, zw, hdr)

	// Create internal archiver with forceNoDescriptor = false (simulating a third-party utility)
	innerZw := NewWriter(w)

	innerW := mustCreate(t, innerZw, "test.txt")
	mustWrite(t, innerW, []byte("some fallback data"))
	if err := innerZw.Close(); err != nil {
		t.Fatalf("close inner writer: %v", err)
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	// Extract. Streaming extraction should fail, automatically triggering two-pass fallback mode.
	mustMkdirAll(t, dstDir)
	// The real removal, counted. The wait behind it is for holders outside
	// this process; nothing outside this process has heard of the scratch
	// file here, so one attempt is the whole story and a second would mean
	// the extraction had not let go of it yet.
	stub := stubScratchRemoval(t,
		func(_ *scratchStub, name string) error { return os.Remove(name) },
		removeHeldElsewhere,
	)
	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("Solid extraction fallback failed: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close extractor: %v", err)
	}
	if stub.removals != 1 {
		t.Errorf("the scratch file took %d removal attempts, want 1", stub.removals)
	}
	if stub.sleeps != 0 {
		t.Errorf("the removal waited %d times, want 0", stub.sleeps)
	}

	data, err := os.ReadFile(filepath.Join(dstDir, "test.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "some fallback data" {
		t.Errorf("expected 'some fallback data', got %q", string(data))
	}
}
func TestSolidFallback_LimitExceeded(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "fallback_limit.zip")
	dstDir := filepath.Join(tmpDir, "dst")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	// Compressed, so that the entry has to be copied out before it can be
	// read at all and the ceiling on that copy is what answers.
	hdr := &FileHeader{
		Name:   "Solid.zip",
		Method: Deflate,
	}
	w := mustCreateHeader(t, zw, hdr)
	innerZw := NewWriter(w)
	innerW := mustCreate(t, innerZw, "test.txt")
	mustWrite(t, innerW, make([]byte, 200)) // 200 bytes uncompressed Solid.zip
	if err := innerZw.Close(); err != nil {
		t.Fatalf("close inner writer: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	mustMkdirAll(t, dstDir)
	// Limit maxFileSize to 5 bytes. maxFallback will be 50 bytes.
	// 200 > 50, so it should fail.
	e, err := NewExtractor(zipPath, dstDir, WithExtractorMaxFileSize(5))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	err = e.Extract(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Solid archive too large for temp file fallback") {
		t.Errorf("expected fallback limit error, got: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close extractor: %v", err)
	}
}

func TestExtractor_ConcurrencyIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "stress.zip")
	dstDir := filepath.Join(tmpDir, "dst")

	// Create 100 files, each containing its name as content
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("file_%d.txt", i)
		w := mustCreate(t, zw, name)
		mustWrite(t, w, []byte(name))
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	// Extract with high concurrency
	e, err := NewExtractor(zipPath, dstDir, WithExtractorConcurrency(20))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close extractor: %v", err)
	}

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

	// The archive is assembled in memory so that the corruption below is
	// applied to the bytes on their way to disk, rather than by writing the
	// file once and reading it back to patch it.
	var archive bytes.Buffer
	zw := NewWriter(&archive)
	w := mustCreate(t, zw, "good1.txt")
	mustWrite(t, w, []byte("I am fine"))
	w = mustCreate(t, zw, "bad.txt")
	mustWrite(t, w, []byte("I will be corrupted"))
	w = mustCreate(t, zw, "good2.txt")
	mustWrite(t, w, []byte("I am also fine"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	// Corrupt bad.txt data (find it in the middle of the archive)
	raw := archive.Bytes()
	idx := bytes.Index(raw, []byte("I will be corrupted"))
	if idx < 0 {
		t.Fatal("the archive does not carry the entry the test corrupts")
	}
	for i := 0; i < 5; i++ {
		raw[idx+i] = 0xFF
	}
	mustWriteFile(t, zipPath, raw, 0600)

	// Extract with TolerantMode(true)
	e, err := NewExtractor(zipPath, dstDir, WithExtractorTolerant(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Errorf("Extract failed despite tolerant mode: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close extractor: %v", err)
	}

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
	mustMkdirAll(t, srcDir)

	filePath := filepath.Join(srcDir, "test.txt")
	mustWriteFile(t, filePath, []byte("solid metadata content"), 0644)

	zipPath := filepath.Join(tmpDir, "meta_compat.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

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
	closeAt(t, a)

	filesMap := make(map[string]os.FileInfo)
	if err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if path != srcDir {
			filesMap[path] = info
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := a.Archive(context.Background(), filesMap); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	// 1. Check compatibility with 7z (if available)
	if p7zPath, err := exec.LookPath("7z"); err == nil {
		t.Logf("[DEBUG TEST] Found 7z utility at %s. Verifying backward compatibility...", p7zPath)
		dstDir := filepath.Join(tmpDir, "7z_dst")
		mustMkdirAll(t, dstDir)

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
		mustMkdirAll(t, dstDir)

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
	mustMkdirAll(t, srcDir)

	mustWriteFile(t, filepath.Join(srcDir, "file1.txt"), []byte("external zip data"), 0644)
	mustMkdirAll(t, filepath.Join(srcDir, "sub"))
	mustWriteFile(t, filepath.Join(srcDir, "sub", "file2.txt"), []byte("nested external zip data"), 0644)

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
	closeAt(t, e)

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
func TestExtractor_WorkerPool_Cancellation(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "cancel.zip")
	dstDir := filepath.Join(tmpDir, "dst")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	for i := 0; i < 10; i++ {
		w := mustCreate(t, zw, fmt.Sprintf("file_%d.txt", i))
		mustWrite(t, w, []byte("data"))
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	e, err := NewExtractor(zipPath, dstDir, WithExtractorConcurrency(4))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = e.Extract(ctx)
	if err == nil || err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestIsAbsArchiveTarget(t *testing.T) {
	tests := []struct {
		target string
		want   bool
	}{
		{"", false},
		{"target.txt", false},
		{"sub/target.txt", false},
		{`sub\target.txt`, false},
		{"..", false},
		{"../../etc/passwd", false},
		{"a", false},
		{"ab", false},
		{"1:name", false},
		{"::name", false},
		{"/etc/passwd", true},
		{"/", true},
		{`\etc\passwd`, true},
		{`\server\share\secret`, true},
		{`\?\C:\Windows`, true},
		{`C:\Windows\System32`, true},
		{"c:/Windows/System32", true},
		{"C:name", true},
		{"Z:", true},
	}

	for _, tt := range tests {
		if got := isAbsArchiveTarget(tt.target); got != tt.want {
			t.Errorf("isAbsArchiveTarget(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

// TestExtractor_AbsoluteSymlinkTargetRejected checks the rejection on every
// spelling of "absolute", not only the spelling the running OS recognises.
// An archive records the paths the machine that wrote it saw, so a Unix
// target can arrive on Windows and a drive-letter target can arrive on Unix;
// filepath.IsAbs answers only for the platform it runs on, and so waves each
// one through on exactly the platform it was aimed at.
func TestExtractor_AbsoluteSymlinkTargetRejected(t *testing.T) {
	targets := []string{
		"/etc/passwd",
		`\etc\passwd`,
		`C:\Windows\System32\drivers\etc\hosts`,
		"c:/Windows/System32",
		`\server\share\secret`,
	}

	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			tmp := t.TempDir()
			zipPath := filepath.Join(tmp, "sym.zip")
			dstDir := filepath.Join(tmp, "safe")

			f, err := os.Create(zipPath)
			if err != nil {
				t.Fatal(err)
			}
			closeAt(t, f)
			zw := NewWriter(f)
			fh := &FileHeader{Name: "attack_link"}
			fh.SetMode(os.ModeSymlink)
			w, err := zw.CreateHeader(fh)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte(target)); err != nil {
				t.Fatal(err)
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatalf("close %s: %v", zipPath, err)
			}

			e, err := NewExtractor(zipPath, dstDir)
			if err != nil {
				t.Fatal(err)
			}
			closeAt(t, e)

			err = e.Extract(context.Background())
			if err == nil || !strings.Contains(err.Error(), "absolute symlink target not allowed") {
				t.Errorf("expected %q to be rejected as absolute, got: %v", target, err)
			}
		})
	}
}

// TestExtractor_HardLink covers the hard link branch of createLink on every
// platform. An archive records a hard link as a regular entry carrying a
// Linkname in its unix extra field, and nothing about reading that back is
// Unix-specific: os.Link works on NTFS just as well, and an archive written
// on one system is routinely extracted on another.
func TestExtractor_HardLink(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "hardlink.zip")
	dstDir := filepath.Join(tmp, "out")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)

	target := &FileHeader{Name: "target.txt", Method: Store}
	target.SetMode(0644)
	w, err := zw.CreateHeader(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("shared content")); err != nil {
		t.Fatal(err)
	}

	link := &FileHeader{Name: "hard.txt", Method: Store, Linkname: "target.txt"}
	link.SetMode(0644)
	if _, err := zw.CreateHeader(link); err != nil {
		t.Fatal(err)
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	for _, name := range []string{"target.txt", "hard.txt"} {
		data, err := os.ReadFile(filepath.Join(dstDir, name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if string(data) != "shared content" {
			t.Errorf("%s = %q, want %q", name, data, "shared content")
		}
	}

	// A hard link is one file under two names, so a write through one name is
	// visible through the other. That holds on every filesystem this runs on
	// and needs no platform-specific stat fields to check.
	if err := os.WriteFile(filepath.Join(dstDir, "target.txt"), []byte("rewritten....."), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dstDir, "hard.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "rewritten....." {
		t.Errorf("hard.txt did not follow a write through target.txt: got %q", data)
	}
}

// TestExtractor_RelativeSymlinkTargetResolvesAgainstTheLink pins the anchor a
// relative link target is measured from.
//
// The chroot check resolves the target against the directory the link lives
// in, which is what a symlink means. Everything the link is then made with
// has to use that same anchor: on Windows a symlink needs a privilege the
// extraction may not hold, so createWindowsSymlink falls back to a hard link
// and then to copying the bytes, and both of those resolve a relative path
// against the process working directory instead. That is a different
// directory, chosen by whoever launched the program rather than by the check,
// so the file the link ends up carrying is not the file the check approved --
// and since the depth of the entry name is the archive's to choose, any
// number of leading ".." survives the check and still climbs out of the
// working directory.
func TestExtractor_RelativeSymlinkTargetResolvesAgainstTheLink(t *testing.T) {
	tmp := t.TempDir()

	// "../data.txt" names this one from the working directory, and the one
	// inside the destination from the link. Only the second is the archive's.
	if err := os.WriteFile(filepath.Join(tmp, "data.txt"), []byte("WRONG"), 0600); err != nil {
		t.Fatal(err)
	}
	cwd := filepath.Join(tmp, "cwd")
	if err := os.MkdirAll(cwd, 0755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)

	zipPath := filepath.Join(tmp, "link.zip")
	dstDir := filepath.Join(tmp, "out")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)

	data := &FileHeader{Name: "data.txt", Method: Store}
	data.SetMode(0644)
	w, err := zw.CreateHeader(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("RIGHT")); err != nil {
		t.Fatal(err)
	}

	dir := &FileHeader{Name: "sub/", Method: Store}
	dir.SetMode(os.ModeDir | 0755)
	if _, err := zw.CreateHeader(dir); err != nil {
		t.Fatal(err)
	}

	link := &FileHeader{Name: "sub/link", Method: Store}
	link.SetMode(os.ModeSymlink | 0777)
	w, err = zw.CreateHeader(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("../data.txt")); err != nil {
		t.Fatal(err)
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	// Whether the entry became a symlink, a hard link or a copy, reading it
	// has to hand back the file the archive pointed at.
	got, err := os.ReadFile(filepath.Join(dstDir, "sub", "link"))
	if err != nil {
		t.Fatalf("reading the extracted link: %v", err)
	}
	if string(got) != "RIGHT" {
		t.Errorf("the link carries %q, want %q -- it was resolved against the working directory", got, "RIGHT")
	}
}

// TestExtractor_HardLinkTargetRejected covers the other half of createLink.
// A hard link names its target relative to the extraction root, and nothing
// checked that the name stayed there: filepath.Join cleans, so a leading ".."
// ate the root and the link was made to a file outside it -- silently, and
// with the metadata step then going on to chmod and chown that outside file
// through the link it had just made.
func TestExtractor_HardLinkTargetRejected(t *testing.T) {
	tests := []struct {
		target string
		// wantIs is the sentinel the refusal has to carry; wantErr is the
		// message the refusals that have no sentinel are recognised by.
		wantIs  error
		wantErr string
	}{
		{target: "../outside_secret.txt", wantIs: ErrInsecurePath},
		{target: "a/../../outside_secret.txt", wantIs: ErrInsecurePath},
		// filepath.Clean answers ".." with itself, which is neither a "../"
		// prefix nor a "/" one, so a bare ".." used to resolve to the parent
		// of the extraction directory with no error at all. "." is the same
		// hole one step short: it names the extraction directory itself.
		{target: "..", wantIs: ErrInsecurePath},
		{target: "a/..", wantIs: ErrInsecurePath},
		{target: ".", wantIs: ErrInsecurePath},
		{target: "/etc/passwd", wantErr: "absolute hard link target not allowed"},
		{target: `\etc\passwd`, wantErr: "absolute hard link target not allowed"},
		{target: `C:\Windows\System32\drivers\etc\hosts`, wantErr: "absolute hard link target not allowed"},
		{target: "c:/Windows/System32/config/SAM", wantErr: "absolute hard link target not allowed"},
	}

	for _, tt := range tests {
		target := tt.target
		t.Run(target, func(t *testing.T) {
			tmp := t.TempDir()
			zipPath := filepath.Join(tmp, "hard.zip")
			dstDir := filepath.Join(tmp, "out")
			if err := os.MkdirAll(dstDir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(tmp, "outside_secret.txt"), []byte("secret"), 0600); err != nil {
				t.Fatal(err)
			}

			f, err := os.Create(zipPath)
			if err != nil {
				t.Fatal(err)
			}
			closeAt(t, f)
			zw := NewWriter(f)
			link := &FileHeader{Name: "stolen.txt", Method: Store, Linkname: target}
			link.SetMode(0644)
			if _, err := zw.CreateHeader(link); err != nil {
				t.Fatal(err)
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}

			e, err := NewExtractor(zipPath, dstDir)
			if err != nil {
				t.Fatal(err)
			}
			closeAt(t, e)

			err = e.Extract(context.Background())
			if tt.wantIs != nil {
				if !errors.Is(err, tt.wantIs) {
					t.Fatalf("extracting a hard link to %q: got %v, want %v", target, err, tt.wantIs)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("extracting a hard link to %q: got %v, want an error containing %q", target, err, tt.wantErr)
			}
			if _, err := os.Lstat(filepath.Join(dstDir, "stolen.txt")); !os.IsNotExist(err) {
				t.Errorf("a link was made anyway: Lstat says %v", err)
			}
		})
	}
}

// TestExtractor_HardLinkToMissingTarget covers the report when the entry the
// link names is not in the archive at all. A hard link cannot be dangling --
// there is no such thing -- so there is nothing to make and nothing to do but
// say so.
func TestExtractor_HardLinkToMissingTarget(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "hard.zip")
	dstDir := filepath.Join(tmp, "out")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	link := &FileHeader{Name: "hard.txt", Method: Store, Linkname: "not_in_the_archive.txt"}
	link.SetMode(0644)
	if _, err := zw.CreateHeader(link); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err == nil {
		t.Fatal("expected a hard link to a missing target to be reported")
	}
}

// TestExtractor_SymlinkCreationFailureIsReported covers the report when the
// platform refuses to make the link. The two branches are refused in two
// different ways, and neither is refused by accident.
//
// Unix takes any byte in a name and is perfectly happy with a link that points
// at nothing, so what it will not take is a target longer than a path may be.
// Windows is happy with that target too when the process holds the symlink
// privilege, so it is refused on the path instead: the second link here goes
// inside the first, which by the time the links are made is a file rather than
// the directory its name suggests, and all three of the ways
// createWindowsSymlink has of making an entry need that parent to be there.
func TestExtractor_SymlinkCreationFailureIsReported(t *testing.T) {
	type entry struct {
		name string
		body string
		mode os.FileMode
	}
	entries := []entry{{"link", strings.Repeat("a", 5000), os.ModeSymlink | 0777}}
	if runtime.GOOS == "windows" {
		entries = []entry{
			{"data.txt", "payload", 0644},
			{"d", "data.txt", os.ModeSymlink | 0777},
			{"d/link", "data.txt", os.ModeSymlink | 0777},
		}
	}

	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "sym.zip")
	dstDir := filepath.Join(tmp, "out")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	for _, ent := range entries {
		fh := &FileHeader{Name: ent.name, Method: Store}
		fh.SetMode(ent.mode)
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(ent.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err == nil {
		t.Fatal("expected the refused link to be reported")
	}
}

// TestExtractor_EntryNamingTheDestinationRejected covers the other side of the
// same hole in absPath, on an ordinary file entry rather than a link.
//
// A file entry whose name cleans to "." resolves to the extraction directory
// itself, and createFile then does to it what it does to any destination it is
// about to write: os.Remove, which takes an empty directory away, and then
// OpenFile, which puts a regular file there. A fresh destination is empty, so
// the extraction replaced the directory it was given with a file and reported
// success. A directory entry naming the root is a different matter and stays
// allowed: it goes to MkdirAll, which has nothing to do.
func TestExtractor_EntryNamingTheDestinationRejected(t *testing.T) {
	for _, name := range []string{".", "a/.."} {
		t.Run(name, func(t *testing.T) {
			tmp := t.TempDir()
			zipPath := filepath.Join(tmp, "dot.zip")
			dstDir := filepath.Join(tmp, "out")
			if err := os.MkdirAll(dstDir, 0755); err != nil {
				t.Fatal(err)
			}

			f, err := os.Create(zipPath)
			if err != nil {
				t.Fatal(err)
			}
			closeAt(t, f)
			zw := NewWriter(f)
			fh := &FileHeader{Name: name, Method: Store}
			fh.SetMode(0644)
			w, err := zw.CreateHeader(fh)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte("payload")); err != nil {
				t.Fatal(err)
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}

			e, err := NewExtractor(zipPath, dstDir)
			if err != nil {
				t.Fatal(err)
			}
			closeAt(t, e)
			if err := e.Extract(context.Background()); !errors.Is(err, ErrInsecurePath) {
				t.Fatalf("extracting an entry named %q: got %v, want ErrInsecurePath", name, err)
			}
			fi, err := os.Lstat(dstDir)
			if err != nil {
				t.Fatal(err)
			}
			if !fi.IsDir() {
				t.Errorf("the destination is now %v, not a directory", fi.Mode())
			}
		})
	}
}

// TestExtractor_RootDirectoryEntryAllowed is the case the rule above must not
// catch: an archive that carries "./" as an entry names the extraction
// directory, which already exists and is meant to.
func TestExtractor_RootDirectoryEntryAllowed(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "root.zip")
	dstDir := filepath.Join(tmp, "out")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	dir := &FileHeader{Name: "./", Method: Store}
	dir.SetMode(os.ModeDir | 0755)
	if _, err := zw.CreateHeader(dir); err != nil {
		t.Fatal(err)
	}
	fh := &FileHeader{Name: "inside.txt", Method: Store}
	fh.SetMode(0644)
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dstDir, "inside.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "payload" {
		t.Errorf("content = %q, want %q", data, "payload")
	}
}

// TestExtractor_SymlinkBodyUnreadable covers what createLink reports when the
// entry it has to read the target out of cannot be read.
//
// A symlink's target is the entry's body, so making the link means opening and
// reading it like any other entry, and both of those can fail on an archive
// that is damaged or built to be. The first case clobbers the local header
// signature the open checks; the second leaves the header intact and destroys
// the deflate stream behind it, which only the read can notice.
func TestExtractor_SymlinkBodyUnreadable(t *testing.T) {
	build := func(t *testing.T, method uint16, target string) []byte {
		t.Helper()
		var buf bytes.Buffer
		zw := NewWriter(&buf)
		fh := &FileHeader{Name: "link", Method: method}
		fh.SetMode(os.ModeSymlink | 0777)
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(target)); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	tests := []struct {
		name    string
		archive func(t *testing.T) []byte
	}{
		{
			name: "the local header is not one",
			archive: func(t *testing.T) []byte {
				raw := build(t, Store, "target.txt")
				// The first entry's local header sits at offset zero, and its
				// signature is the first thing findBodyOffset checks.
				binary.LittleEndian.PutUint32(raw[0:4], 0xDEADBEEF)
				return raw
			},
		},
		{
			name: "the body is not a deflate stream",
			archive: func(t *testing.T) []byte {
				raw := build(t, Deflate, strings.Repeat("target/", 512))
				zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
				if err != nil {
					t.Fatal(err)
				}
				off, err := zr.File[0].DataOffset()
				if err != nil {
					t.Fatal(err)
				}
				size, err := u64toi64(zr.File[0].CompressedSize64)
				if err != nil {
					t.Fatal(err)
				}
				// 0xFF opens a block whose type is the one flate has no
				// meaning for, so the very first read fails.
				for i := off; i < off+size; i++ {
					raw[i] = 0xFF
				}
				return raw
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			zipPath := filepath.Join(tmp, "broken.zip")
			if err := os.WriteFile(zipPath, tt.archive(t), 0600); err != nil {
				t.Fatal(err)
			}

			e, err := NewExtractor(zipPath, filepath.Join(tmp, "out"))
			if err != nil {
				t.Fatal(err)
			}
			closeAt(t, e)
			if err := e.Extract(context.Background()); err == nil {
				t.Fatal("expected the unreadable link body to be reported")
			}
		})
	}
}

// TestExtractor_IncrementalSweepPastAStaleDirectory pins that the sweep visits
// everything, not everything up to the first stale directory.
//
// An incremental extraction removes what the archive's listing no longer
// names. Removing a directory pulls the ground out from under the walk's own
// descent into it, and the walk then asks the callback again with the error
// that follows -- which used to be handed straight back, ending the walk. So
// one stale directory was enough to leave every later entry in place, and the
// walk's answer was discarded, so nothing said so. The directory here sorts
// ahead of the stale file on purpose: that is the order in which the second
// one used to survive.
func TestExtractor_IncrementalSweepPastAStaleDirectory(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "incr.zip")
	dstDir := filepath.Join(tmp, "out")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	for _, ent := range []struct{ name, content string }{
		{".zip_dumpdir", "keep.txt\n"},
		{"keep.txt", "kept"},
	} {
		fh := &FileHeader{Name: ent.name, Method: Store}
		fh.SetMode(0644)
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(ent.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// What an earlier run left behind. The marker is what says the directory
	// is one of ours; the other three are what the sweep has to decide on.
	if err := os.MkdirAll(filepath.Join(dstDir, "a_stale_dir"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		".zip_dumpdir":          "\n",
		"keep.txt":              "from the earlier run",
		"a_stale_dir/child.txt": "stale",
		"z_stale_file.txt":      "stale",
	} {
		if err := os.WriteFile(filepath.Join(dstDir, filepath.FromSlash(name)), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}

	e, err := NewExtractor(zipPath, dstDir, WithExtractorIncremental(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dstDir, "keep.txt"))
	if err != nil {
		t.Fatalf("the listed file did not survive: %v", err)
	}
	if string(data) != "kept" {
		t.Errorf("keep.txt = %q, want %q", data, "kept")
	}
	for _, name := range []string{"a_stale_dir", "z_stale_file.txt"} {
		if _, err := os.Lstat(filepath.Join(dstDir, name)); !os.IsNotExist(err) {
			t.Errorf("the sweep left %s behind: %v", name, err)
		}
	}
}

// solidEntry is one entry of the archive a solid entry holds.
type solidEntry struct {
	name   string
	method uint16
	data   string
}

// innerSolidArchive builds the archive that the outer Solid.zip entry holds.
func innerSolidArchive(t *testing.T, entries []solidEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	for _, e := range entries {
		w := mustCreateHeader(t, zw, &FileHeader{Name: e.name, Method: e.method})
		mustWrite(t, w, []byte(e.data))
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close inner writer: %v", err)
	}
	return buf.Bytes()
}

// writeSolidArchive writes an archive whose single entry is the Solid.zip the
// extractor recognises, and returns its path.
func writeSolidArchive(t *testing.T, dir string, inner []byte) string {
	t.Helper()
	path := filepath.Join(dir, "outer.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	w := mustCreateHeader(t, zw, &FileHeader{Name: "Solid.zip", Method: Deflate})
	mustWrite(t, w, inner)
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
	return path
}

// assertDirHolds names every entry of dir and compares it with want, so that a
// scratch file the extraction left behind fails the test by being there.
func assertDirHolds(t *testing.T, dir string, want ...string) {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, de := range des {
		got = append(got, de.Name())
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s holds %v, want %v", dir, got, want)
	}
}

func assertFileContents(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Errorf("%s holds %q, want %q", path, data, want)
	}
}

// TestSolidFallback_IncrementalFreshDestination covers an incremental solid
// archive that takes the fallback: the scratch file the fallback puts in the
// destination must not turn the destination into one the extraction refuses to
// write into.
func TestSolidFallback_IncrementalFreshDestination(t *testing.T) {
	tmp := t.TempDir()
	inner := innerSolidArchive(t, []solidEntry{
		{name: "hello.txt", method: Deflate, data: "hello"},
		{name: ".zip_dumpdir", method: Store, data: "hello.txt\n"},
	})
	zipPath := writeSolidArchive(t, tmp, inner)

	dst := filepath.Join(tmp, "dst")
	mustMkdir(t, dst)

	e, err := NewExtractor(zipPath, dst, WithExtractorIncremental(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close extractor: %v", err)
	}

	assertDirHolds(t, dst, ".zip_dumpdir", "hello.txt")
	assertFileContents(t, filepath.Join(dst, "hello.txt"), "hello")
}

// TestSolidFallback_IncrementalSweep covers the sweep an incremental
// extraction owes its caller on the fallback path: it happens once, after the
// scratch file is gone, and it takes the file the new listing no longer names.
func TestSolidFallback_IncrementalSweep(t *testing.T) {
	tmp := t.TempDir()
	inner := innerSolidArchive(t, []solidEntry{
		{name: "hello.txt", method: Deflate, data: "hello"},
		{name: ".zip_dumpdir", method: Store, data: "hello.txt\n"},
	})
	zipPath := writeSolidArchive(t, tmp, inner)

	dst := filepath.Join(tmp, "dst")
	mustMkdir(t, dst)
	mustWriteFile(t, filepath.Join(dst, ".zip_dumpdir"), []byte("stale.txt\n"), 0644)
	mustWriteFile(t, filepath.Join(dst, "stale.txt"), []byte("from the last run"), 0644)

	e, err := NewExtractor(zipPath, dst, WithExtractorIncremental(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close extractor: %v", err)
	}

	assertDirHolds(t, dst, ".zip_dumpdir", "hello.txt")
	assertFileContents(t, filepath.Join(dst, "hello.txt"), "hello")
}

// stubScratchRemoval takes over the removal seams for one test and gives back
// the scratch file's name and the counters the assertions need.
type scratchStub struct {
	removals int
	sleeps   int
	name     string
}

func stubScratchRemoval(t *testing.T, remove func(s *scratchStub, name string) error, held func(error) bool) *scratchStub {
	t.Helper()
	stub := &scratchStub{}
	origRemove, origHeld, origSleep := scratchRemove, scratchHeldElsewhere, scratchSleep
	t.Cleanup(func() {
		scratchRemove, scratchHeldElsewhere, scratchSleep = origRemove, origHeld, origSleep
	})
	scratchRemove = func(name string) error {
		stub.removals++
		stub.name = name
		return remove(stub, name)
	}
	scratchHeldElsewhere = held
	scratchSleep = func(time.Duration) { stub.sleeps++ }
	return stub
}

func stubScratchCreate(t *testing.T, create func(dir, pattern string) (*os.File, error)) {
	t.Helper()
	orig := scratchCreate
	t.Cleanup(func() { scratchCreate = orig })
	scratchCreate = create
}

func extractSolidFixture(t *testing.T, opts ...ExtractorOption) (string, error) {
	t.Helper()
	tmp := t.TempDir()
	inner := innerSolidArchive(t, []solidEntry{{name: "hello.txt", method: Deflate, data: "hello"}})
	zipPath := writeSolidArchive(t, tmp, inner)
	dst := filepath.Join(tmp, "dst")
	mustMkdir(t, dst)

	e, err := NewExtractor(zipPath, dst, opts...)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	err = e.Extract(context.Background())
	if cerr := e.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return dst, err
}

// TestSolidFallback_ScratchRemovalRetried covers the holder that lets go: on
// Windows a scanner can still have the scratch file open the moment the
// extraction is done with it, and the removal is worth asking for again.
func TestSolidFallback_ScratchRemovalRetried(t *testing.T) {
	held := errors.New("still open somewhere else")
	realRemove := os.Remove
	stub := stubScratchRemoval(t,
		func(s *scratchStub, name string) error {
			if s.removals <= 2 {
				return held
			}
			return realRemove(name)
		},
		func(err error) bool { return errors.Is(err, held) },
	)

	dst, err := extractSolidFixture(t)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if stub.removals != 3 {
		t.Errorf("removal attempted %d times, want 3", stub.removals)
	}
	if stub.sleeps != 2 {
		t.Errorf("waited %d times, want 2", stub.sleeps)
	}
	assertDirHolds(t, dst, "hello.txt")
	assertFileContents(t, filepath.Join(dst, "hello.txt"), "hello")
}

// TestSolidFallback_ScratchRemovalFails covers the holder that does not let
// go: a destination left holding a copy of the archive is not an extraction
// the caller should be told succeeded, and the message has to name what is
// still there.
func TestSolidFallback_ScratchRemovalFails(t *testing.T) {
	boom := errors.New("removal refused")
	stub := stubScratchRemoval(t,
		func(s *scratchStub, name string) error { return boom },
		func(err error) bool { return false },
	)

	_, err := extractSolidFixture(t)
	if !errors.Is(err, boom) {
		t.Fatalf("Extract error = %v, want one wrapping %v", err, boom)
	}
	if !strings.Contains(err.Error(), stub.name) {
		t.Errorf("Extract error %q does not name the file left behind (%s)", err, stub.name)
	}
	if stub.removals != 1 {
		t.Errorf("removal attempted %d times, want 1 -- a permanent refusal is not worth repeating", stub.removals)
	}
	if stub.sleeps != 0 {
		t.Errorf("waited %d times, want 0", stub.sleeps)
	}
}

// TestSolidFallback_DestinationCannotBeCreated covers the fallback with
// nowhere to put its scratch file: the destination it was told to write into
// cannot be made a directory at all.
func TestSolidFallback_DestinationCannotBeCreated(t *testing.T) {
	tmp := t.TempDir()
	inner := innerSolidArchive(t, []solidEntry{{name: "hello.txt", method: Deflate, data: "hello"}})
	zipPath := writeSolidArchive(t, tmp, inner)

	blocker := filepath.Join(tmp, "blocker")
	mustWriteFile(t, blocker, []byte("a regular file"), 0644)

	e, err := NewExtractor(zipPath, filepath.Join(blocker, "dst"))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	err = e.Extract(context.Background())
	if err == nil || !strings.Contains(err.Error(), "fallback failed") {
		t.Fatalf("Extract error = %v, want a fallback failure", err)
	}
}

// TestSolidFallback_ScratchIsNotAnArchive covers a solid entry that is not an
// archive at all: a lone local file header, with no listing behind it and
// nothing to salvage. Opening the copy as an archive is where the extraction
// stops, and nothing is left behind.
func TestSolidFallback_ScratchIsNotAnArchive(t *testing.T) {
	tmp := t.TempDir()
	local := make([]byte, 30)
	binary.LittleEndian.PutUint32(local[0:4], fileHeaderSignature)
	binary.LittleEndian.PutUint16(local[8:10], Deflate)
	zipPath := writeSolidArchive(t, tmp, local)

	dst := filepath.Join(tmp, "dst")
	mustMkdir(t, dst)

	e, err := NewExtractor(zipPath, dst)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	err = e.Extract(context.Background())
	if !errors.Is(err, ErrFormat) {
		t.Fatalf("Extract error = %v, want the copy refused as an archive", err)
	}
	assertDirHolds(t, dst)
}

// TestSolid_EntryCannotBeOpened covers a solid entry there is no reader for at
// all: the method it declares has no decompressor registered, so the streaming
// pass never starts and the fallback is never reached.
func TestSolid_EntryCannotBeOpened(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "outer.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	// Method 6 is Implode, which nothing in the package registers a
	// decompressor for. CreateRaw stores the body as it is given.
	body := []byte("not that it will ever be read")
	w, err := zw.CreateRaw(&FileHeader{
		Name:               "Solid.zip",
		Method:             6,
		CRC32:              crc32.ChecksumIEEE(body),
		CompressedSize64:   uint64(len(body)),
		UncompressedSize64: uint64(len(body)),
	})
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w, body)
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	dst := filepath.Join(tmp, "dst")
	mustMkdir(t, dst)

	e, err := NewExtractor(zipPath, dst)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("Extract error = %v, want one wrapping %v", err, ErrAlgorithm)
	}
	assertDirHolds(t, dst)
}

// TestSolidFallback_ScratchCannotBeCreated covers a destination the fallback
// may enter but not write into, which is the one way to keep os.CreateTemp
// from succeeding in a directory os.MkdirAll has just accepted.
// TestSolidFallback_ScratchCannotBeCreated covers a destination that will not
// take the scratch file: the fallback has nowhere to put the copy it needs and
// says so, naming both what it could not do and what sent it here.
func TestSolidFallback_ScratchCannotBeCreated(t *testing.T) {
	t.Run("the destination refuses the file", func(t *testing.T) {
		refused := errors.New("no room for it here")
		var dirs []string
		stubScratchCreate(t, func(dir, _ string) (*os.File, error) {
			dirs = append(dirs, dir)
			return nil, refused
		})

		dst, err := extractSolidFixture(t)
		if err == nil || !strings.Contains(err.Error(), "fallback failed") {
			t.Fatalf("Extract error = %v, want a fallback failure", err)
		}
		if !strings.Contains(err.Error(), refused.Error()) {
			t.Errorf("Extract error %q does not say what went wrong", err)
		}
		if len(dirs) != 1 || dirs[0] != dst {
			t.Errorf("the scratch file was asked for in %v, want one attempt in %s", dirs, dst)
		}
		assertDirHolds(t, dst)
	})

	t.Run("in a directory that cannot be written", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("a directory's mode bits are not what decides who may write here")
		}
		if os.Geteuid() == 0 {
			t.Skip("root is not subject to the directory permissions this needs")
		}

		tmp := t.TempDir()
		inner := innerSolidArchive(t, []solidEntry{{name: "hello.txt", method: Deflate, data: "hello"}})
		zipPath := writeSolidArchive(t, tmp, inner)

		dst := filepath.Join(tmp, "dst")
		mustMkdir(t, dst)
		if err := os.Chmod(dst, 0500); err != nil {
			t.Fatal(err)
		}
		// t.TempDir cannot remove what it cannot write into.
		t.Cleanup(func() {
			if err := os.Chmod(dst, 0755); err != nil {
				t.Errorf("restoring the mode of %s: %v", dst, err)
			}
		})

		e, err := NewExtractor(zipPath, dst)
		if err != nil {
			t.Fatal(err)
		}
		closeAt(t, e)
		err = e.Extract(context.Background())
		if err == nil || !strings.Contains(err.Error(), "fallback failed") {
			t.Fatalf("Extract error = %v, want a fallback failure", err)
		}
	})
}

// headerProbeFailer serves an archive from memory and stops serving the one
// read that File.Open makes before anything else: findBodyOffset asks for the
// entry's local file header, fileHeaderLen bytes at the entry's own offset.
// Allowing none of those lets the central directory be read and leaves the
// extraction's open of the entry with nothing to open.
type headerProbeFailer struct {
	raw    []byte
	offset int64
	allow  int
	probes int
	err    error
}

func (h *headerProbeFailer) ReadAt(p []byte, off int64) (int, error) {
	if off == h.offset && len(p) == fileHeaderLen {
		h.probes++
		if h.probes > h.allow {
			return 0, h.err
		}
	}
	if off < 0 || off >= int64(len(h.raw)) {
		return 0, io.EOF
	}
	n := copy(p, h.raw[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// TestSolidFallback_EntryCannotBeOpened covers the archive that listed the
// entry and then would not hand it over. The copy never starts, and what the
// caller is told is what the archive refused.
func TestSolidFallback_EntryCannotBeOpened(t *testing.T) {
	inner := innerSolidArchive(t, []solidEntry{{name: "hello.txt", method: Deflate, data: "hello"}})
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	mustWrite(t, mustCreateHeader(t, zw, &FileHeader{Name: "Solid.zip", Method: Deflate}), inner)
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	raw := buf.Bytes()

	tmp := t.TempDir()
	dst := filepath.Join(tmp, "dst")
	mustMkdir(t, dst)

	gone := errors.New("the archive is no longer readable")
	probe := &headerProbeFailer{raw: raw, allow: len(raw), err: gone}
	e, err := NewExtractorFromReader(probe, int64(len(raw)), dst)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	// The central directory has been read; from here the entry cannot be
	// opened at all.
	probe.offset = e.zr.File[0].headerOffset
	probe.probes = 0
	probe.allow = 0

	err = e.Extract(context.Background())
	if !errors.Is(err, gone) {
		t.Fatalf("Extract error = %v, want %v", err, gone)
	}
	if probe.probes != 1 {
		t.Errorf("the entry's header was read %d times, want 1: the one open the copy makes", probe.probes)
	}
	assertDirHolds(t, dst)
}

// erroringCloseReader hands its input back byte for byte and then refuses to
// close, which is the one way a copy that read the whole entry can still be a
// copy the extraction should not trust.
type erroringCloseReader struct {
	io.Reader
	closes *int
	err    error
}

func (e *erroringCloseReader) Close() error {
	*e.closes++
	return e.err
}

// TestSolidFallback_CopyHandleCannotBeClosed covers the copy that read
// everything and then would not close. The fallback has produced nothing it can
// vouch for, so the caller is told what the close reported rather than that the
// extraction worked.
func TestSolidFallback_CopyHandleCannotBeClosed(t *testing.T) {
	inner := innerSolidArchive(t, []solidEntry{{name: "hello.txt", method: Deflate, data: "hello"}})

	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "outer.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	// Method 6 is Implode, which the package registers nothing for, so the
	// reader below is the only thing that can read this entry. CreateRaw
	// stores the body as it stands, and the reader hands it straight back.
	w, err := zw.CreateRaw(&FileHeader{
		Name:               "Solid.zip",
		Method:             6,
		CRC32:              crc32.ChecksumIEEE(inner),
		CompressedSize64:   uint64(len(inner)),
		UncompressedSize64: uint64(len(inner)),
	})
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w, inner)
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	dst := filepath.Join(tmp, "dst")
	mustMkdir(t, dst)

	e, err := NewExtractor(zipPath, dst)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	closes := 0
	stuck := errors.New("this handle will not close")
	e.zr.RegisterDecompressor(6, func(r io.Reader) io.ReadCloser {
		return &erroringCloseReader{Reader: r, closes: &closes, err: stuck}
	})

	err = e.Extract(context.Background())
	if !errors.Is(err, stuck) {
		t.Fatalf("Extract error = %v, want %v", err, stuck)
	}
	if closes != 1 {
		t.Errorf("the entry's reader was closed %d times, want 1: the one close after the copy", closes)
	}
	assertDirHolds(t, dst)
}

// solidStoredArchiveOver puts a stored solid archive behind a probe that can
// be made to stop serving the entry's local file header.
func solidStoredArchiveOver(t *testing.T, err error) (*Extractor, *headerProbeFailer) {
	t.Helper()
	inner := innerSolidArchive(t, []solidEntry{{name: "hello.txt", method: Store, data: "hello"}})
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	fh := &FileHeader{Name: "Solid.zip", Method: Store}
	fh.SetMode(0644)
	mustWrite(t, mustCreateHeader(t, zw, fh), inner)
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	raw := buf.Bytes()

	probe := &headerProbeFailer{raw: raw, allow: len(raw), err: err}
	e, terr := NewExtractorFromReader(probe, int64(len(raw)), filepath.Join(t.TempDir(), "dst"))
	if terr != nil {
		t.Fatal(terr)
	}
	closeAt(t, e)
	// The central directory has been read; from here the entry's header is
	// served as many times as the caller allows and no more.
	probe.offset = e.zr.File[0].headerOffset
	probe.probes = 0
	return e, probe
}

// TestSolid_StoredEntryThatCannotBeVerified: a stored solid entry is read
// where it lies rather than copied out, so its own checksum is verified in a
// pass of its own first. An archive that will not hand the entry over at all
// stops there.
func TestSolid_StoredEntryThatCannotBeVerified(t *testing.T) {
	gone := errors.New("the archive is no longer readable")
	e, probe := solidStoredArchiveOver(t, gone)
	probe.allow = 0

	if err := e.Extract(context.Background()); !errors.Is(err, gone) {
		t.Fatalf("Extract error = %v, want %v", err, gone)
	}
}

// TestSolid_StoredEntryThatStopsBeingLocatable is one step further in: the
// entry was read and verified, and the archive then would not say where its
// data begins.
func TestSolid_StoredEntryThatStopsBeingLocatable(t *testing.T) {
	gone := errors.New("the archive is no longer readable")
	e, probe := solidStoredArchiveOver(t, gone)
	probe.allow = 1

	if err := e.Extract(context.Background()); !errors.Is(err, gone) {
		t.Fatalf("Extract error = %v, want %v", err, gone)
	}
}

// TestSolid_StoredButEncryptedEntryIsNotReadInPlace: a stored solid entry is
// read where it lies, which is only the inner archive's bytes while nothing
// stands between them and the file. An encrypted one has the cipher in the
// way, so it goes through the copy the way a compressed one does; reading its
// section directly would hand a Reader the ciphertext.
func TestSolid_StoredButEncryptedEntryIsNotReadInPlace(t *testing.T) {
	const password = "pw"
	inner := innerSolidArchive(t, []solidEntry{{name: "hello.txt", method: Store, data: "hello"}})
	raw := buildZipCryptoStored(t, "Solid.zip", inner, password, byte(crc32.ChecksumIEEE(inner)>>24))

	dst := filepath.Join(t.TempDir(), "dst")
	e, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), dst,
		WithExtractorPassword(password), WithExtractorConcurrency(1), WithExtractorNoTimes(true))
	if err != nil {
		t.Fatalf("building the extractor: %v", err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extracting an encrypted solid archive: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dst, "hello.txt"))
	if err != nil {
		t.Fatalf("the inner entry was not extracted: %v", err)
	}
	if string(body) != "hello" {
		t.Errorf("hello.txt holds %q, want %q", body, "hello")
	}
}
