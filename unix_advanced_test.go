//go:build !windows
// +build !windows

package zip

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUnixLinks_Zip(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	os.MkdirAll(srcDir, 0755)

	targetPath := filepath.Join(srcDir, "target.txt")
	if err := os.WriteFile(targetPath, []byte("link_target"), 0644); err != nil {
		t.Fatalf("Failed to create target file: %v", err)
	}

	symPath := filepath.Join(srcDir, "sym.txt")
	if err := os.Symlink("target.txt", symPath); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	hardPath := filepath.Join(srcDir, "hard.txt")
	if err := os.Link(targetPath, hardPath); err != nil {
		t.Fatalf("Failed to create hardlink: %v", err)
	}

	archivePath := filepath.Join(tmpDir, "links.zip")

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewArchiver(f, filepath.Dir(srcDir))
	if err != nil {
		t.Fatal(err)
	}

	files := make(map[string]os.FileInfo)
	filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if path != filepath.Dir(srcDir) {
			files[path] = info
		}
		return nil
	})

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatal(err)
	}
	a.Close()
	f.Close()

	// Diagnostic 1: Inspect the generated ZIP file structure before extracting
	zrCheck, errCheck := OpenReader(archivePath)
	if errCheck == nil {
		for _, f := range zrCheck.File {
			t.Logf("[DIAGNOSTIC ZIP] Name: %q, Linkname: %q, ExtraLen: %d, ExtraHex: %x", f.Name, f.Linkname, len(f.Extra), f.Extra)
		}
		zrCheck.Close()
	} else {
		t.Logf("[DIAGNOSTIC ZIP] Failed to open reader for check: %v", errCheck)
	}

	dstDir := filepath.Join(tmpDir, "dst")
	e, err := NewExtractor(archivePath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.Close()

	// Diagnostic 2: Inspect extracted files on disk
	targetPathDst := filepath.Join(dstDir, "src", "target.txt")
	hardPathDst := filepath.Join(dstDir, "src", "hard.txt")
	t1, err1 := os.Lstat(targetPathDst)
	t2, err2 := os.Lstat(hardPathDst)
	t.Logf("[DIAGNOSTIC DISK] target.txt: err=%v, stat=%+v", err1, t1)
	t.Logf("[DIAGNOSTIC DISK] hard.txt: err=%v, stat=%+v", err2, t2)
	if err1 == nil && err2 == nil {
		if sys1, ok1 := t1.Sys().(*unix.Stat_t); ok1 {
			if sys2, ok2 := t2.Sys().(*unix.Stat_t); ok2 {
				t.Logf("[DIAGNOSTIC DISK] Inodes: target.txt=%d, hard.txt=%d, Nlinks: target.txt=%d, hard.txt=%d", sys1.Ino, sys2.Ino, sys1.Nlink, sys2.Nlink)
			}
		}
	}

	symInfo, err := os.Lstat(filepath.Join(dstDir, "src", "sym.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if symInfo.Mode()&os.ModeSymlink == 0 {
		t.Errorf("sym.txt is not a symlink")
	}
	target, _ := os.Readlink(filepath.Join(dstDir, "src", "sym.txt"))
	if target != "target.txt" {
		t.Errorf("Symlink points to wrong target: %s", target)
	}

	targetStat, _ := os.Stat(targetPathDst)
	hardStat, _ := os.Stat(hardPathDst)
	if !os.SameFile(targetStat, hardStat) {
		t.Errorf("Hardlink does not point to the same physical file on disk")
	}
}

func TestExtractor_Fifo_Zip(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "fifo.zip")
	dstDir := filepath.Join(tmpDir, "extract")

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zw := NewWriter(f)

	fh := &FileHeader{
		Name: "my_fifo",
	}
	fh.SetMode(0600 | os.ModeNamedPipe)

	if _, err := zw.CreateHeader(fh); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	f.Close()

	ignoreChown := WithExtractorChownErrorHandler(func(name string, err error) error {
		return nil
	})
	e, err := NewExtractor(archivePath, dstDir, ignoreChown)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	err = e.Extract(context.Background())
	if err != nil {
		t.Fatalf("Failed to extract FIFO: %v", err)
	}

	fi, err := os.Lstat(filepath.Join(dstDir, "my_fifo"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		t.Error("Expected extracted file to be a Named Pipe / FIFO")
	}
}

func TestXattrs_Zip(t *testing.T) {
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "src.txt")
	os.WriteFile(srcFile, []byte("data"), 0644)

	err := unix.Setxattr(srcFile, "user.testattr", []byte("testvalue"), 0)
	if err != nil {
		t.Skipf("Filesystem does not support user xattrs: %v", err)
	}

	archivePath := filepath.Join(tmpDir, "xattr.zip")
	f, _ := os.Create(archivePath)
	a, err := NewArchiver(f, tmpDir, WithArchiverXattrs(true))
	if err != nil {
		t.Fatal(err)
	}

	fi, _ := os.Stat(srcFile)
	files := map[string]os.FileInfo{srcFile: fi}

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatal(err)
	}
	a.Close()
	f.Close()

	// Diagnostic 1: Inspect the generated ZIP file structure before extracting
	zrCheck, errCheck := OpenReader(archivePath)
	if errCheck == nil {
		for _, f := range zrCheck.File {
			t.Logf("[DIAGNOSTIC ZIP] Name: %q, Xattrs: %+v, ExtraLen: %d, ExtraHex: %x", f.Name, f.Xattrs, len(f.Extra), f.Extra)
		}
		zrCheck.Close()
	} else {
		t.Logf("[DIAGNOSTIC ZIP] Failed to open reader for check: %v", errCheck)
	}

	dstDir := filepath.Join(tmpDir, "dst")
	e, err := NewExtractor(archivePath, dstDir, WithExtractorXattrs(true))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.Close()

	dstFile := filepath.Join(dstDir, "src.txt")

	// Diagnostic 2: Inspect actual xattrs on the extracted file manually
	szList, errList := unix.Llistxattr(dstFile, nil)
	t.Logf("[DIAGNOSTIC DISK] Llistxattr size: %d, err: %v", szList, errList)
	if errList == nil && szList > 0 {
		listBuf := make([]byte, szList)
		unix.Llistxattr(dstFile, listBuf)
		t.Logf("[DIAGNOSTIC DISK] Extracted xattr keys list: %q", string(listBuf))
	}

	val := make([]byte, 100)
	sz, err := unix.Getxattr(dstFile, "user.testattr", val)
	if err != nil {
		t.Fatalf("Failed to get xattr on extracted file: %v", err)
	}
	if string(val[:sz]) != "testvalue" {
		t.Errorf("Expected 'testvalue', got %s", string(val[:sz]))
	}
}

func TestUnixOwnerStrings_Zip(t *testing.T) {
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "owner.zip")
	dstDir1 := filepath.Join(tmpDir, "extract_resolved")
	dstDir2 := filepath.Join(tmpDir, "extract_numeric")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := NewWriter(f)

	currentUser, err := user.Current()
	if err != nil {
		t.Skip("Skipping user resolution test as current user lookup failed")
	}
	currentGroup, _ := user.LookupGroupId(currentUser.Gid)

	fh := &FileHeader{
		Name: "test_owner.txt",
		Uid:  9999,
		Gid:  9999,
	}
	fh.OwnerSet = true
	fh.Uname = currentUser.Username
	if currentGroup != nil {
		fh.Gname = currentGroup.Name
	}

	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("owner data"))
	zw.Close()
	f.Close()

	e1, err := NewExtractor(zipPath, dstDir1, WithExtractorChownErrorHandler(func(name string, err error) error {
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := e1.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}
	e1.Close()

	e2, err := NewExtractor(zipPath, dstDir2, WithExtractorNumericOwner(true), WithExtractorChownErrorHandler(func(name string, err error) error {
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := e2.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}
	e2.Close()

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	fileHeader := &zr.File[0].FileHeader

	resolvedUid, resolvedGid := resolveIds(fileHeader, false)
	expectedUid, _ := strconv.Atoi(currentUser.Uid)
	if resolvedUid != expectedUid {
		t.Errorf("Expected resolved UID %d, got %d", expectedUid, resolvedUid)
	}
	if currentGroup != nil {
		expectedGid, _ := strconv.Atoi(currentGroup.Gid)
		if resolvedGid != expectedGid {
			t.Errorf("Expected resolved GID %d, got %d", expectedGid, resolvedGid)
		}
	}

	numericUid, numericGid := resolveIds(fileHeader, true)
	if numericUid != 9999 || numericGid != 9999 {
		t.Errorf("Expected numeric UID/GID 9999/9999, got %d/%d", numericUid, numericGid)
	}
}