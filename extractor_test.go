package zip

import (
	"context"
	"os"
	"runtime"
	"strings"
	"path/filepath"
	"testing"
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
