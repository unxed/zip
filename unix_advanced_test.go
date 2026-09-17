//go:build !windows
// +build !windows

package zip

import (
	"bytes"
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
	mustMkdirAll(t, srcDir)

	targetPath := filepath.Join(srcDir, "target.txt")
	if err := os.WriteFile(targetPath, []byte("link_target"), 0600); err != nil {
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
	closeAt(t, f)
	a, err := NewArchiver(f, filepath.Dir(srcDir))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	files := make(map[string]os.FileInfo)
	if err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if path != filepath.Dir(srcDir) {
			files[path] = info
		}
		return nil
	}); err != nil {
		t.Fatal(err)
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

	// Diagnostic 1: Inspect the generated ZIP file structure before extracting
	zrCheck, errCheck := OpenReader(archivePath)
	if errCheck == nil {
		closeAt(t, zrCheck)
		for _, f := range zrCheck.File {
			t.Logf("[DIAGNOSTIC ZIP] Name: %q, Linkname: %q, ExtraLen: %d, ExtraHex: %x", f.Name, f.Linkname, len(f.Extra), f.Extra)
		}
	} else {
		t.Logf("[DIAGNOSTIC ZIP] Failed to open reader for check: %v", errCheck)
	}

	// Whichever of the two names the archiver reached second is the hard
	// link, and that entry alone carries the attribute bit fuse-zip and
	// mount-zip need before they resolve its 0x000d name as a link.
	zr, err := OpenReader(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)
	links := 0
	for _, f := range zr.File {
		if f.Linkname != "" {
			links++
		}
		if marked := f.ExternalAttrs&pkwareHardLinkAttr != 0; marked != (f.Linkname != "") {
			t.Errorf("%s: hard link flag is %v with link target %q (external attributes %#08x)", f.Name, marked, f.Linkname, f.ExternalAttrs)
		}
	}
	if links != 1 {
		t.Errorf("%d entries are hard links, want 1", links)
	}

	dstDir := filepath.Join(tmpDir, "dst")
	e, err := NewExtractor(archivePath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}

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
	closeAt(t, f)
	zw := NewWriter(f)

	fh := &FileHeader{
		Name: "my_fifo",
	}
	fh.SetMode(0600 | os.ModeNamedPipe)

	if _, err := zw.CreateHeader(fh); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", archivePath, err)
	}

	ignoreChown := WithExtractorChownErrorHandler(func(name string, err error) error {
		return nil
	})
	e, err := NewExtractor(archivePath, dstDir, ignoreChown)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)

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
	mustWriteFile(t, srcFile, []byte("data"), 0644)

	err := unix.Setxattr(srcFile, "user.testattr", []byte("testvalue"), 0)
	if err != nil {
		t.Skipf("Filesystem does not support user xattrs: %v", err)
	}

	archivePath := filepath.Join(tmpDir, "xattr.zip")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	a, err := NewArchiver(f, tmpDir, WithArchiverXattrs(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	fi, err := os.Stat(srcFile)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]os.FileInfo{srcFile: fi}

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", archivePath, err)
	}

	// Diagnostic 1: Inspect the generated ZIP file structure before extracting
	zrCheck, errCheck := OpenReader(archivePath)
	if errCheck == nil {
		closeAt(t, zrCheck)
		for _, f := range zrCheck.File {
			t.Logf("[DIAGNOSTIC ZIP] Name: %q, Xattrs: %+v, ExtraLen: %d, ExtraHex: %x", f.Name, f.Xattrs, len(f.Extra), f.Extra)
		}
	} else {
		t.Logf("[DIAGNOSTIC ZIP] Failed to open reader for check: %v", errCheck)
	}

	dstDir := filepath.Join(tmpDir, "dst")
	e, err := NewExtractor(archivePath, dstDir, WithExtractorXattrs(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}

	dstFile := filepath.Join(dstDir, "src.txt")

	// Diagnostic 2: Inspect actual xattrs on the extracted file manually
	szList, errList := unix.Llistxattr(dstFile, nil)
	t.Logf("[DIAGNOSTIC DISK] Llistxattr size: %d, err: %v", szList, errList)
	if errList == nil && szList > 0 {
		listBuf := make([]byte, szList)
		if _, err := unix.Llistxattr(dstFile, listBuf); err != nil {
			t.Logf("[DIAGNOSTIC DISK] Llistxattr into buffer failed: %v", err)
		} else {
			t.Logf("[DIAGNOSTIC DISK] Extracted xattr keys list: %q", string(listBuf))
		}
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
	closeAt(t, f)
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
	mustWrite(t, w, []byte("owner data"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	e1, err := NewExtractor(zipPath, dstDir1, WithExtractorChownErrorHandler(func(name string, err error) error {
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e1)
	if err := e1.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}

	e2, err := NewExtractor(zipPath, dstDir2, WithExtractorNumericOwner(true), WithExtractorChownErrorHandler(func(name string, err error) error {
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e2)
	if err := e2.Extract(context.Background()); err != nil {
		t.Fatal(err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)

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

// TestCreateWindowsSymlinkStub pins what the name means in a Unix build.
//
// createLink picks between os.Symlink and createWindowsSymlink at run time
// rather than at build time, so the name has to resolve in every build. On
// Unix the branch that calls it is never taken and the stub is what keeps the
// package compiling; it is a no-op, and specifically it does not quietly make
// something on a platform that has a real symlink to make instead.
func TestCreateWindowsSymlinkStub(t *testing.T) {
	tmp := t.TempDir()
	link := filepath.Join(tmp, "link")
	if err := createWindowsSymlink("target", filepath.Join(tmp, "target"), link, false, noLimitBudget("link")); err != nil {
		t.Errorf("the Unix stub answered %v, want nil", err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Errorf("the stub made something at %s: %v", link, err)
	}
}

// TestExtractor_IncrementalSweepReportsWhatItCannotDo covers the answers the
// sweep has to give rather than swallow.
//
// The walk's own answer used to be discarded, so a destination the sweep could
// not read or could not clean was a silent no-op: the extraction reported
// success and the stale files stayed. Both halves are reachable only through
// directory permissions, which is a Unix matter, and only as somebody who is
// subject to them -- root is not.
func TestExtractor_IncrementalSweepReportsWhatItCannotDo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is not subject to the directory permissions this needs")
	}

	// listing names the directory, so the sweep keeps it and walks into it.
	build := func(t *testing.T, dstDir, dirName string, mode os.FileMode, stale bool) string {
		t.Helper()
		tmp := filepath.Dir(dstDir)
		zipPath := filepath.Join(tmp, "incr.zip")
		f, err := os.Create(zipPath)
		if err != nil {
			t.Fatal(err)
		}
		closeAt(t, f)
		zw := NewWriter(f)
		for _, ent := range []struct{ name, content string }{
			{".zip_dumpdir", dirName + "/\n"},
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

		dir := filepath.Join(dstDir, dirName)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dstDir, ".zip_dumpdir"), []byte("\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if stale {
			if err := os.WriteFile(filepath.Join(dir, "stale.txt"), []byte("stale"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		// t.TempDir cannot clean up what it cannot enter or write.
		t.Cleanup(func() {
			if err := os.Chmod(dir, 0755); err != nil {
				t.Errorf("restoring the mode of %s: %v", dir, err)
			}
		})
		return zipPath
	}

	tests := []struct {
		name  string
		mode  os.FileMode
		stale bool
	}{
		// Not readable at all: the walk fails to list it and says so.
		{"a directory the sweep cannot read", 0o000, false},
		// Readable but not writable: the walk lists the stale file inside and
		// then cannot take it away.
		{"a directory the sweep cannot empty", 0o500, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			dstDir := filepath.Join(tmp, "out")
			if err := os.MkdirAll(dstDir, 0755); err != nil {
				t.Fatal(err)
			}
			zipPath := build(t, dstDir, "blocked", tt.mode, tt.stale)

			e, err := NewExtractor(zipPath, dstDir, WithExtractorIncremental(true))
			if err != nil {
				t.Fatal(err)
			}
			closeAt(t, e)
			if err := e.Extract(context.Background()); err == nil {
				t.Fatal("the sweep reported success on a destination it could not finish")
			}
		})
	}
}

// TestApplyXattrsIsBestEffort covers the extended attribute pass. Setting one
// fails with ENOTSUP on every filesystem that has nowhere to keep it, and the
// filesystem under a test is whichever one TMPDIR is on, so what this asserts
// is the part that has to hold either way: the pass reports success. Whether
// the attribute stuck is the filesystem's business and not the extraction's.
func TestApplyXattrsIsBestEffort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attrs.txt")
	mustWriteFile(t, path, []byte("data"), 0600)

	hdr := &FileHeader{Name: "attrs.txt", Xattrs: map[string]string{"user.zip_test": "value"}}
	if err := applyXattrs(path, hdr); err != nil {
		t.Errorf("applyXattrs on a best-effort pass: %v", err)
	}

	// An entry with nothing to apply stops before the loop.
	if err := applyXattrs(path, &FileHeader{Name: "attrs.txt"}); err != nil {
		t.Errorf("applyXattrs with no attributes: %v", err)
	}
}

// TestSysPlatformExtraDevice covers the device arm of the header pass. A
// character device on the system carries a major and a minor the kernel
// reports, and /dev/null is the one device every Unix has at a fixed place.
func TestSysPlatformExtraDevice(t *testing.T) {
	fi, err := os.Stat("/dev/null")
	if err != nil {
		t.Skipf("no /dev/null to read a device number from: %v", err)
	}
	if fi.Mode()&os.ModeCharDevice == 0 {
		t.Skipf("/dev/null is not a character device here: mode %v", fi.Mode())
	}

	var hdr FileHeader
	sysPlatformExtra(fi, &hdr)
	if hdr.Devmajor == 0 && hdr.Devminor == 0 {
		t.Errorf("no device number came back for /dev/null: %d:%d", hdr.Devmajor, hdr.Devminor)
	}
}

// TestExtractor_DirectoryStaysTraversable: a directory has to be enterable by
// whoever may read it, or the files the extraction wrote inside it cannot be
// opened, listed or removed. The mode an entry carries comes from its MS-DOS
// attributes when it has no Unix mode of its own, and those have no search bit
// at all -- so an archive this package's own writer produced extracted into
// directories nothing could go into, and reported success over them.
func TestExtractor_DirectoryStaysTraversable(t *testing.T) {
	body := []byte("this file has to be reachable afterwards")

	var buf bytes.Buffer
	zw := NewWriter(&buf)
	// No SetMode on either: the entries carry the attributes a writer puts
	// on a name, and nothing else.
	mustCreateHeader(t, zw, &FileHeader{Name: "dir/", Method: Store})
	mustWrite(t, mustCreateHeader(t, zw, &FileHeader{Name: "dir/inside.txt", Method: Store}), body)
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}

	root := t.TempDir()
	e, err := NewExtractorFromReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()), root,
		WithExtractorConcurrency(1), WithExtractorNoTimes(true))
	if err != nil {
		t.Fatalf("building the extractor: %v", err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extracting: %v", err)
	}

	dir := filepath.Join(root, "dir")
	// Whatever the assertions below decide, the framework has to be able to
	// take the directory away again.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("stat the extracted directory: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o100 == 0 {
		t.Errorf("the extracted directory is %v, which the owner cannot enter", info.Mode())
	}
	got, err := os.ReadFile(filepath.Join(dir, "inside.txt"))
	if err != nil {
		t.Fatalf("the file the extraction counted cannot be read back: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("inside.txt holds %d bytes, want the %d written", len(got), len(body))
	}
}

// TestExtractor_DirectoryModeKeepsWhatItWasGiven: the search bit is added
// beside a read bit and nowhere else, so a directory an archive deliberately
// closed to a group or to the world stays closed to them.
func TestExtractor_DirectoryModeKeepsWhatItWasGiven(t *testing.T) {
	for _, tc := range []struct {
		stored os.FileMode
		want   os.FileMode
	}{
		{0o700, 0o700},
		{0o755, 0o755},
		{0o644, 0o755},
		{0o600, 0o700},
		{0o640, 0o750},
		{0o604, 0o705},
		{0o000, 0o000},
	} {
		t.Run(tc.stored.String(), func(t *testing.T) {
			var buf bytes.Buffer
			zw := NewWriter(&buf)
			fh := &FileHeader{Name: "dir/", Method: Store}
			fh.SetMode(os.ModeDir | tc.stored)
			mustCreateHeader(t, zw, fh)
			if err := zw.Close(); err != nil {
				t.Fatalf("closing the writer: %v", err)
			}

			root := t.TempDir()
			e, err := NewExtractorFromReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()), root,
				WithExtractorConcurrency(1), WithExtractorNoTimes(true))
			if err != nil {
				t.Fatalf("building the extractor: %v", err)
			}
			closeAt(t, e)
			if err := e.Extract(context.Background()); err != nil {
				t.Fatalf("extracting: %v", err)
			}

			dir := filepath.Join(root, "dir")
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
			info, err := os.Lstat(dir)
			if err != nil {
				t.Fatalf("stat the extracted directory: %v", err)
			}
			// The umask takes bits away from what Mkdir asks for and
			// never from a chmod, so what is on disk is what was
			// applied.
			if got := info.Mode().Perm(); got != tc.want {
				t.Errorf("a directory stored as %v came out %v, want %v", tc.stored, got, tc.want)
			}
		})
	}
}
