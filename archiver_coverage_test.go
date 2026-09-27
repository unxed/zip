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
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	zlib4go "github.com/unxed/zlib4go"

	"github.com/unxed/zip/internal/filepool"
)

// The tests here work over the archiver's options, the entry loop and the two
// ways it compresses a file: straight into the archive, and through a staging
// file that lets several entries be compressed at once.

// ArchiverCovModTime is the timestamp every synthetic entry carries. A zero
// time is the archiver's "no timestamp known", so a fixed one keeps the
// entries it writes comparable with the ones a real file produces.
var ArchiverCovModTime = time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)

// ArchiverCovInfo is an os.FileInfo a test writes by hand, for entries that
// name something the filesystem does not have to hold: a file larger than any
// disk here, a device node on a platform without one, a name relative to the
// working directory.
type ArchiverCovInfo struct {
	name string
	size int64
	mode os.FileMode
	sys  func() interface{}
}

func (i ArchiverCovInfo) Name() string       { return i.name }
func (i ArchiverCovInfo) Size() int64        { return i.size }
func (i ArchiverCovInfo) Mode() os.FileMode  { return i.mode }
func (i ArchiverCovInfo) ModTime() time.Time { return ArchiverCovModTime }
func (i ArchiverCovInfo) IsDir() bool        { return i.mode.IsDir() }
func (i ArchiverCovInfo) Sys() interface{} {
	if i.sys == nil {
		return nil
	}
	return i.sys()
}

// ArchiverCovFailWriter accepts accept bytes and fails every write after
// that, the way a disk that has just filled up does.
type ArchiverCovFailWriter struct {
	accept int
	err    error
}

func (w *ArchiverCovFailWriter) Write(p []byte) (int, error) {
	if w.accept <= 0 {
		return 0, w.err
	}
	if len(p) <= w.accept {
		w.accept -= len(p)
		return len(p), nil
	}
	n := w.accept
	w.accept = 0
	return n, w.err
}

// ArchiverCovReader is a ReadSeeker over a fixed slice that can be told to
// fail its nth read, and to run a hook on the read that reports the end of the
// data. It stands for a file that goes away, or shrinks, while it is being
// read into the archive.
type ArchiverCovReader struct {
	r      *bytes.Reader
	failAt int
	reads  int
	err    error
	onEOF  func()
}

func ArchiverCovNewReader(data []byte) *ArchiverCovReader {
	return &ArchiverCovReader{r: bytes.NewReader(data)}
}

func (r *ArchiverCovReader) Read(p []byte) (int, error) {
	r.reads++
	if r.failAt > 0 && r.reads >= r.failAt {
		return 0, r.err
	}
	n, err := r.r.Read(p)
	if err == io.EOF && r.onEOF != nil {
		r.onEOF()
	}
	return n, err
}

func (r *ArchiverCovReader) Seek(offset int64, whence int) (int64, error) {
	return r.r.Seek(offset, whence)
}

// ArchiverCovCloseErrWriter is a compressor whose Close fails after every byte
// has been written, the way a compressor that cannot flush its last block
// does.
type ArchiverCovCloseErrWriter struct {
	w   io.Writer
	err error
}

func (w ArchiverCovCloseErrWriter) Write(p []byte) (int, error) { return w.w.Write(p) }
func (w ArchiverCovCloseErrWriter) Close() error                { return w.err }

// ArchiverCovMixedBytes returns n bytes over 200 distinct values, which the
// archiver's heuristic reads as worth deflating.
func ArchiverCovMixedBytes(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte(i % 200)
	}
	return data
}

// ArchiverCovNewArchiver builds an archiver over buf and registers it to be
// closed when the test ends.
func ArchiverCovNewArchiver(t *testing.T, w io.Writer, chroot string, opts ...ArchiverOption) *Archiver {
	t.Helper()
	a, err := NewArchiver(w, chroot, opts...)
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	closeAt(t, a)
	return a
}

// ArchiverCovPool returns a one-file staging pool in a directory of its own.
// bufferSize is what filepool.New takes: -1 for its default in-memory buffer,
// 0 to put every staged byte on disk.
func ArchiverCovPool(t *testing.T, bufferSize int) *filepool.FilePool {
	t.Helper()
	fp, err := filepool.New(t.TempDir(), 1, bufferSize)
	if err != nil {
		t.Fatalf("building the staging pool: %v", err)
	}
	closeAt(t, fp)
	return fp
}

// ArchiverCovHeader returns the header for an entry of the given name, method
// and size, along with a FileInfo that agrees with it.
func ArchiverCovHeader(name string, method uint16, size int) (*FileHeader, os.FileInfo) {
	// #nosec G115 -- not a narrowing: size is a fixture length of a few kilobytes, never negative
	declared := uint64(size)
	hdr := &FileHeader{
		Name:               name,
		Method:             method,
		UncompressedSize64: declared,
		Modified:           ArchiverCovModTime,
	}
	hdr.SetMode(0o644)
	return hdr, ArchiverCovInfo{name: name, size: int64(size), mode: 0o644}
}

// ArchiverCovArchiveOne writes an archive of everything under srcDir and
// returns its bytes.
func ArchiverCovArchiveOne(t *testing.T, srcDir string, opts ...ArchiverOption) []byte {
	t.Helper()
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, srcDir, opts...)
	if err := a.Archive(context.Background(), walkFilesFor(t, srcDir)); err != nil {
		t.Fatalf("archiving %s: %v", srcDir, err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("closing the archiver: %v", err)
	}
	return buf.Bytes()
}

// ArchiverCovRead opens an archive held in memory.
func ArchiverCovRead(t *testing.T, archive []byte, password string) *Reader {
	t.Helper()
	zr, err := NewReaderWithPassword(bytes.NewReader(archive), int64(len(archive)), password)
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	return zr
}

// ArchiverCovEntry returns the contents of the named entry.
func ArchiverCovEntry(t *testing.T, zr *Reader, name string) []byte {
	t.Helper()
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("opening entry %q: %v", name, err)
		}
		closeAt(t, rc)
		data, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("reading entry %q: %v", name, err)
		}
		return data
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	t.Fatalf("the archive has no entry %q, only %v", name, names)
	return nil
}

// TestArchiverCov_PathMappingRenamesTheEntry covers the option that gives an
// entry a name of the caller's choosing instead of the one its position under
// the archiver's root would produce.
func TestArchiverCov_PathMappingRenamesTheEntry(t *testing.T) {
	srcDir := t.TempDir()
	source := filepath.Join(srcDir, "on-disk.txt")
	mustWriteFile(t, source, []byte("mapped payload"), 0o600)

	mapping := map[string]string{filepath.Clean(source): "docs/renamed.txt"}
	archive := ArchiverCovArchiveOne(t, srcDir, WithArchiverPathMapping(mapping))

	zr := ArchiverCovRead(t, archive, "")
	if got := string(ArchiverCovEntry(t, zr, "docs/renamed.txt")); got != "mapped payload" {
		t.Errorf("the renamed entry holds %q, want %q", got, "mapped payload")
	}
	for _, f := range zr.File {
		if f.Name == "on-disk.txt" {
			t.Error("the entry was written under its on-disk name as well as the mapped one")
		}
	}
}

// TestArchiverCov_OffsetShiftsRecordedPositions covers the option that tells
// the archiver its output will be written at a position other than the start
// of the file. Every offset the archive records has to count from there, so
// that a reader handed the whole file still finds the entries.
func TestArchiverCov_OffsetShiftsRecordedPositions(t *testing.T) {
	srcDir := t.TempDir()
	mustWriteFile(t, filepath.Join(srcDir, "one.txt"), []byte("offset payload"), 0o600)

	const prefixLen = 512
	archive := ArchiverCovArchiveOne(t, srcDir, WithArchiverOffset(prefixLen))

	whole := append(bytes.Repeat([]byte{0xAA}, prefixLen), archive...)
	zr := ArchiverCovRead(t, whole, "")
	if got := string(ArchiverCovEntry(t, zr, "one.txt")); got != "offset payload" {
		t.Errorf("the entry holds %q, want %q", got, "offset payload")
	}

	// And the position the archive records for its own directory is the
	// one the prefix puts it at, not the one it would have on its own.
	plain := ArchiverCovArchiveOne(t, srcDir)
	if got, want := ArchiverCovDirectoryOffset(t, archive), ArchiverCovDirectoryOffset(t, plain)+prefixLen; got != want {
		t.Errorf("the archive records its directory at %d, want %d", got, want)
	}
}

// ArchiverCovDirectoryOffset returns the position an archive records for the
// start of its central directory.
func ArchiverCovDirectoryOffset(t *testing.T, archive []byte) uint32 {
	t.Helper()
	if len(archive) < directoryEndLen {
		t.Fatalf("the archive is %d bytes, too short to hold an end record", len(archive))
	}
	end := archive[len(archive)-directoryEndLen:]
	if binary.LittleEndian.Uint32(end[:4]) != uint32(directoryEndSignature) {
		t.Fatal("the archive does not end with its end-of-directory record")
	}
	return binary.LittleEndian.Uint32(end[16:20])
}

// TestArchiverCov_EncryptedDirectoryStaysReadable covers the option that asks
// for an encrypted central directory. The archiver writes the directory in the
// clear and leaves the encryption to the layer that wraps the finished
// archive, so what is pinned here is that the entries are still found and that
// their contents need the password.
func TestArchiverCov_EncryptedDirectoryStaysReadable(t *testing.T) {
	srcDir := t.TempDir()
	mustWriteFile(t, filepath.Join(srcDir, "secret.txt"), []byte("classified"), 0o600)

	// #nosec G101 -- not a credential: the literal this test encrypts a fixture archive with and then reads it back with, so it has to be in the source
	const password = "central-directory-password"
	archive := ArchiverCovArchiveOne(t, srcDir,
		WithArchiverEncryptCD(true),
		WithArchiverPassword(password))

	zr := ArchiverCovRead(t, archive, password)
	if got := string(ArchiverCovEntry(t, zr, "secret.txt")); got != "classified" {
		t.Errorf("the entry holds %q, want %q", got, "classified")
	}

	// The same archive without the password: the directory is readable, the
	// entry is not.
	zrNoPass := ArchiverCovRead(t, archive, "")
	if len(zrNoPass.File) != 1 {
		t.Fatalf("the directory lists %d entries, want 1", len(zrNoPass.File))
	}
	if rc, err := zrNoPass.File[0].Open(); err == nil {
		if _, rerr := io.ReadAll(rc); rerr == nil {
			t.Error("the encrypted entry was readable without the password")
		}
		if cerr := rc.Close(); cerr != nil {
			t.Logf("closing the entry: %v", cerr)
		}
	}
}

// TestArchiverCov_CommentComesBackOut covers the archive comment: what is set
// on the archiver is what a reader finds in the finished archive.
func TestArchiverCov_CommentComesBackOut(t *testing.T) {
	srcDir := t.TempDir()
	mustWriteFile(t, filepath.Join(srcDir, "one.txt"), []byte("commented"), 0o600)

	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, srcDir)
	const comment = "written by the archiver"
	if err := a.SetComment(comment); err != nil {
		t.Fatalf("setting the comment: %v", err)
	}
	if err := a.Archive(context.Background(), walkFilesFor(t, srcDir)); err != nil {
		t.Fatalf("archiving: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("closing the archiver: %v", err)
	}

	zr := ArchiverCovRead(t, buf.Bytes(), "")
	if zr.Comment != comment {
		t.Errorf("the archive comment is %q, want %q", zr.Comment, comment)
	}

	// A comment longer than the field that holds it is refused rather than
	// truncated.
	a2 := ArchiverCovNewArchiver(t, io.Discard, srcDir)
	if err := a2.SetComment(strings.Repeat("x", uint16max+1)); err == nil {
		t.Error("a comment too long for the field was accepted")
	}
}

// TestArchiverCov_ConcurrencyBelowOneIsRefused covers the option's own check
// and the archiver refusing to be built when an option rejects its argument.
func TestArchiverCov_ConcurrencyBelowOneIsRefused(t *testing.T) {
	for _, n := range []int{0, -1} {
		a, err := NewArchiver(io.Discard, t.TempDir(), WithArchiverConcurrency(n))
		if !errors.Is(err, ErrMinConcurrency) {
			t.Errorf("a concurrency of %d gave %v, want %v", n, err, ErrMinConcurrency)
		}
		if a != nil {
			t.Errorf("a concurrency of %d still produced an archiver", n)
		}
	}
}

// TestArchiverCov_NegativeBufferSizeStagesOnDisk covers the buffer size being
// raised to zero: a negative size means the staging pool's own default to
// filepool, which is not what a caller asking for less than nothing meant.
func TestArchiverCov_NegativeBufferSizeStagesOnDisk(t *testing.T) {
	srcDir := t.TempDir()
	payload := ArchiverCovMixedBytes(9000)
	mustWriteFile(t, filepath.Join(srcDir, "a.bin"), payload, 0o600)
	mustWriteFile(t, filepath.Join(srcDir, "b.bin"), payload, 0o600)

	archive := ArchiverCovArchiveOne(t, srcDir,
		WithArchiverConcurrency(2),
		WithArchiverBufferSize(-4096),
		WithStageDirectory(t.TempDir()))

	zr := ArchiverCovRead(t, archive, "")
	for _, name := range []string{"a.bin", "b.bin"} {
		if got := ArchiverCovEntry(t, zr, name); !bytes.Equal(got, payload) {
			t.Errorf("entry %s came back %d bytes, want %d", name, len(got), len(payload))
		}
	}
}

// TestArchiverCov_ChrootWithNoAbsoluteSpelling covers the archiver refusing a
// root it cannot resolve. A NUL byte is the portable way to name one on
// Windows, where resolving a path is a system call that rejects it; every
// other platform resolves the name by hand and has nothing to reject.
func TestArchiverCov_ChrootWithNoAbsoluteSpelling(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("resolving a relative path is not a system call here, so no root is unresolvable")
	}
	a, err := NewArchiver(io.Discard, "root\x00name")
	if err == nil {
		t.Error("a root with no absolute spelling was accepted")
	}
	if a != nil {
		t.Error("a root with no absolute spelling still produced an archiver")
	}
}

// TestArchiverCov_LevelledMethods covers the compressor the archiver registers
// when a level is asked for alongside a method that takes one.
func TestArchiverCov_LevelledMethods(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method uint16
		level  int
	}{
		{"zstd", ZSTD, 3},
		{"lzma", LZMA, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srcDir := t.TempDir()
			payload := ArchiverCovMixedBytes(20000)
			mustWriteFile(t, filepath.Join(srcDir, "one.bin"), payload, 0o600)

			archive := ArchiverCovArchiveOne(t, srcDir,
				WithArchiverMethod(tc.method),
				WithArchiverLevel(tc.level))

			zr := ArchiverCovRead(t, archive, "")
			if len(zr.File) != 1 {
				t.Fatalf("the archive holds %d entries, want 1", len(zr.File))
			}
			if zr.File[0].Method != tc.method {
				t.Errorf("the entry was written with method %d, want %d", zr.File[0].Method, tc.method)
			}
			if got := ArchiverCovEntry(t, zr, "one.bin"); !bytes.Equal(got, payload) {
				t.Errorf("the entry came back %d bytes, want %d", len(got), len(payload))
			}
		})
	}
}

// ArchiverCovHighEntropyBytes returns n bytes over all 256 values, spread
// evenly enough that neither the archiver's heuristic nor a compressor makes
// them any smaller. The generator is a plain xorshift so the fixture is the
// same on every run.
func ArchiverCovHighEntropyBytes(n int) []byte {
	data := make([]byte, 0, n+4)
	x := uint32(88675123)
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

// ArchiverCovSlowWriter holds up the first write through it, so that whatever
// runs alongside the writing has time to run.
type ArchiverCovSlowWriter struct {
	w       io.Writer
	delay   time.Duration
	delayed bool
}

func (w *ArchiverCovSlowWriter) Write(p []byte) (int, error) {
	if !w.delayed {
		w.delayed = true
		time.Sleep(w.delay)
	}
	return w.w.Write(p)
}

// TestArchiverCov_RelativeNameResolvesAgainstTheWorkingDirectory covers an
// entry named relative to where the process is running rather than by an
// absolute path.
func TestArchiverCov_RelativeNameResolvesAgainstTheWorkingDirectory(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("finding the working directory: %v", err)
	}

	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, wd)
	const name = "archiver-cov-relative"
	files := map[string]os.FileInfo{
		name: ArchiverCovInfo{name: name, mode: os.ModeDir | 0o755},
	}
	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatalf("archiving a relative name: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("closing the archiver: %v", err)
	}

	zr := ArchiverCovRead(t, buf.Bytes(), "")
	if len(zr.File) != 1 || zr.File[0].Name != name+"/" {
		t.Fatalf("the archive holds %d entries, want one named %q", len(zr.File), name+"/")
	}
}

var errArchiverCovNoWorkingDir = errors.New("the working directory has gone")

// TestArchiverCov_WorkingDirectoryFailure covers the archiver giving up when
// it cannot find out where the process is running. Every entry named relative
// to the working directory is resolved against it, so an archive written
// without it would hold entries under names that are not theirs.
func TestArchiverCov_WorkingDirectoryFailure(t *testing.T) {
	srcDir := t.TempDir()
	mustWriteFile(t, filepath.Join(srcDir, "one.txt"), []byte("payload"), 0o600)
	files := walkFilesFor(t, srcDir)

	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, srcDir)

	saved := getwd
	t.Cleanup(func() { getwd = saved })
	getwd = func() (string, error) { return "", errArchiverCovNoWorkingDir }

	if err := a.Archive(context.Background(), files); !errors.Is(err, errArchiverCovNoWorkingDir) {
		t.Fatalf("archiving returned %v, want %v", err, errArchiverCovNoWorkingDir)
	}
}

// TestArchiverCov_TorrentZipWithNothingToArchive covers the staging pool being
// sized for an archive with no entries at all. TorrentZip mode always stages,
// so the pool is built even when there is nothing to put in it, and a pool of
// no files is one nothing can ever be taken from.
func TestArchiverCov_TorrentZipWithNothingToArchive(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir(), WithArchiverTorrentZip(true))
	if err := a.Archive(context.Background(), map[string]os.FileInfo{}); err != nil {
		t.Fatalf("archiving nothing: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("closing the archiver: %v", err)
	}

	zr := ArchiverCovRead(t, buf.Bytes(), "")
	if len(zr.File) != 0 {
		t.Errorf("the archive holds %d entries, want none", len(zr.File))
	}
}

// TestArchiverCov_SolidWithAMethodNothingCompresses covers the outer entry of
// a solid archive failing to be created. Everything the archive holds goes
// inside that one entry, so an archiver that carried on would produce an
// archive with nothing in it and report success.
func TestArchiverCov_SolidWithAMethodNothingCompresses(t *testing.T) {
	srcDir := t.TempDir()
	mustWriteFile(t, filepath.Join(srcDir, "one.txt"), []byte("payload"), 0o600)

	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, srcDir,
		WithArchiverSolid(true),
		WithArchiverMethod(0xbeef))

	err := a.Archive(context.Background(), walkFilesFor(t, srcDir))
	if !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("archiving returned %v, want %v", err, ErrAlgorithm)
	}
}

// TestArchiverCov_SolidBelowTheSeekIndexThreshold covers a solid archive small
// enough not to be worth a seek index. The size comes from what the caller
// says the files are, and a caller that says less than nothing is below any
// threshold there is.
func TestArchiverCov_SolidBelowTheSeekIndexThreshold(t *testing.T) {
	srcDir := t.TempDir()
	source := filepath.Join(srcDir, "one.txt")
	mustWriteFile(t, source, []byte("payload"), 0o600)

	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, srcDir,
		WithArchiverSolid(true),
		WithArchiverSeekIndex(1024, false))

	files := map[string]os.FileInfo{
		source: ArchiverCovInfo{name: "one.txt", size: -1, mode: 0o644},
	}
	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatalf("archiving: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("closing the archiver: %v", err)
	}

	zr := ArchiverCovRead(t, buf.Bytes(), "")
	if len(zr.File) != 1 || zr.File[0].Name != "Solid.zip" {
		t.Fatalf("the archive holds %d entries, want one named Solid.zip", len(zr.File))
	}
	if zr.File[0].SeekChunkSize != 0 {
		t.Errorf("the outer entry carries a seek index of %d bytes, want none",
			zr.File[0].SeekChunkSize)
	}

	// The size the caller gave is used to pick a layout and nothing else:
	// the entry inside still holds the bytes the file actually had.
	inner := ArchiverCovEntry(t, zr, "Solid.zip")
	izr, err := NewReader(bytes.NewReader(inner), int64(len(inner)))
	if err != nil {
		t.Fatalf("reading the inner archive: %v", err)
	}
	if got := string(ArchiverCovEntry(t, izr, "one.txt")); got != "payload" {
		t.Errorf("the entry inside holds %q, want %q", got, "payload")
	}
}

// TestArchiverCov_SizeAboveTheThirtyTwoBitField covers a file too large for
// the size field a plain zip entry has. The field then carries the sentinel
// that says the real size is in the zip64 record, rather than the low half of
// the size.
func TestArchiverCov_SizeAboveTheThirtyTwoBitField(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir())

	const huge = 1<<32 + 4096
	var hdr FileHeader
	a.fileInfoHeaderFast("big.bin", ArchiverCovInfo{name: "big.bin", size: huge, mode: 0o644}, &hdr)

	if hdr.UncompressedSize != uint32max {
		t.Errorf("the 32-bit size field holds %d, want the sentinel %d",
			hdr.UncompressedSize, uint32(uint32max))
	}
	if hdr.UncompressedSize64 != huge {
		t.Errorf("the 64-bit size field holds %d, want %d",
			hdr.UncompressedSize64, uint64(huge))
	}
}

// TestArchiverCov_SolidProgressIsPublished covers the running count of bytes
// and entries a solid archive publishes while it is being written. Everything
// goes inside one outer entry, so without the count being copied out of the
// inner archiver a caller watching the archive would see nothing move until it
// finished.
func TestArchiverCov_SolidProgressIsPublished(t *testing.T) {
	srcDir := t.TempDir()
	payload := ArchiverCovHighEntropyBytes(200 * 1024)
	mustWriteFile(t, filepath.Join(srcDir, "one.bin"), payload, 0o600)

	var buf bytes.Buffer
	slow := &ArchiverCovSlowWriter{w: &buf, delay: 250 * time.Millisecond}
	a := ArchiverCovNewArchiver(t, slow, srcDir,
		WithArchiverSolid(true),
		WithArchiverMethod(Store))

	if err := a.Archive(context.Background(), walkFilesFor(t, srcDir)); err != nil {
		t.Fatalf("archiving: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("closing the archiver: %v", err)
	}

	written, entries := a.Written()
	if written <= 0 || entries != 2 {
		t.Errorf("the archiver reports %d bytes over %d entries, want some bytes over 2 entries",
			written, entries)
	}

	zr := ArchiverCovRead(t, buf.Bytes(), "")
	if len(zr.File) != 1 || zr.File[0].Name != "Solid.zip" {
		t.Fatalf("the archive holds %d entries, want one named Solid.zip", len(zr.File))
	}
}

// TestArchiverCov_SymlinkWithAnUnwritableHeader covers the header of a symlink
// entry failing to be written. The link target is the entry's contents, so an
// archiver that carried on would write the target of a link with no header in
// front of it.
func TestArchiverCov_SymlinkWithAnUnwritableHeader(t *testing.T) {
	srcDir := t.TempDir()
	link := filepath.Join(srcDir, "link")
	if err := os.Symlink("target.txt", link); err != nil {
		t.Skipf("symlinks cannot be created here: %v", err)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("stat %s: %v", link, err)
	}

	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, srcDir)

	hdr := &FileHeader{Name: strings.Repeat("n", 70000), Modified: ArchiverCovModTime}
	hdr.SetMode(fi.Mode())
	if err := a.createSymlink(link, fi, hdr); err == nil {
		t.Fatal("a symlink entry whose name does not fit its header was written")
	}
}

var (
	errArchiverCovDiskFull     = errors.New("no room left on the volume")
	errArchiverCovFileVanished = errors.New("the file went away mid-read")
	errArchiverCovNoCompressor = errors.New("the compressor could not be built")
	errArchiverCovUnflushable  = errors.New("the compressor could not flush its last block")
)

// ArchiverCovLongName is a name longer than the field a zip header has for it,
// so that writing the header fails after everything before it succeeded.
var ArchiverCovLongName = strings.Repeat("n", 70000)

// TestArchiverCov_ShortFileUnderALargeDeclaredSize covers a file that shrinks
// between being listed and being read. The archiver peeks at the head of it to
// decide how to compress it, and a peek that comes back shorter than the block
// the heuristic works over is no basis for a decision.
func TestArchiverCov_ShortFileUnderALargeDeclaredSize(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir())

	data := ArchiverCovMixedBytes(100)
	hdr, fi := ArchiverCovHeader("shrunk.bin", Deflate, 8192)

	if err := a.compressFile(context.Background(), ArchiverCovNewReader(data), fi, hdr, nil); err != nil {
		t.Fatalf("compressing a file shorter than it said it was: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("closing the archiver: %v", err)
	}

	zr := ArchiverCovRead(t, buf.Bytes(), "")
	if got := ArchiverCovEntry(t, zr, "shrunk.bin"); !bytes.Equal(got, data) {
		t.Errorf("the entry came back %d bytes, want the %d that were there", len(got), len(data))
	}
}

// TestArchiverCov_TorrentZipEmptyEntry covers the empty entry of a torrentzip
// archive. The format asks for an empty deflate block rather than no bytes at
// all, so an empty file is written by hand instead of going through a
// compressor.
func TestArchiverCov_TorrentZipEmptyEntry(t *testing.T) {
	srcDir := t.TempDir()
	mustWriteFile(t, filepath.Join(srcDir, "empty.txt"), nil, 0o600)

	archive := ArchiverCovArchiveOne(t, srcDir, WithArchiverTorrentZip(true))

	zr := ArchiverCovRead(t, archive, "")
	if len(zr.File) != 1 {
		t.Fatalf("the archive holds %d entries, want 1", len(zr.File))
	}
	if zr.File[0].CompressedSize64 != 2 {
		t.Errorf("the empty entry is %d bytes, want the 2 of an empty deflate block",
			zr.File[0].CompressedSize64)
	}
	if got := ArchiverCovEntry(t, zr, "empty.txt"); len(got) != 0 {
		t.Errorf("the empty entry came back %d bytes, want none", len(got))
	}
}

// TestArchiverCov_TorrentZipEmptyEntryWithAnUnwritableHeader covers the header
// of that empty entry failing to be written, which is the point at which the
// two bytes of its contents would otherwise be written on their own.
func TestArchiverCov_TorrentZipEmptyEntryWithAnUnwritableHeader(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir(), WithArchiverTorrentZip(true))

	hdr, fi := ArchiverCovHeader(ArchiverCovLongName, Store, 0)
	if err := a.compressFile(context.Background(), ArchiverCovNewReader(nil), fi, hdr, nil); err == nil {
		t.Fatal("an empty entry whose name does not fit its header was written")
	}
	if buf.Len() != 0 {
		t.Errorf("%d bytes were written for an entry that has no header", buf.Len())
	}
}

// TestArchiverCov_EncryptionStrengthNothingSupports covers an entry asking to
// be encrypted at a key length WinZip AES does not have.
func TestArchiverCov_EncryptionStrengthNothingSupports(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir())

	data := ArchiverCovMixedBytes(1024)
	hdr, fi := ArchiverCovHeader("secret.bin", Store, len(data))
	// #nosec G101 -- not a credential: any non-empty string turns encryption on for this entry
	hdr.Password = "strength-fixture"
	hdr.AESStrength = 9

	err := a.compressFile(context.Background(), ArchiverCovNewReader(data), fi, hdr, ArchiverCovPool(t, -1).Get())
	if err == nil {
		t.Fatal("an entry was encrypted at a strength WinZip AES does not have")
	}
}

// TestArchiverCov_CompressorThatCannotBeBuilt covers the compressor for an
// entry failing to start.
func TestArchiverCov_CompressorThatCannotBeBuilt(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir())
	a.zw.RegisterCompressor(Deflate, func(io.Writer) (io.WriteCloser, error) {
		return nil, errArchiverCovNoCompressor
	})

	data := ArchiverCovMixedBytes(1024)
	hdr, fi := ArchiverCovHeader("one.bin", Deflate, len(data))

	err := a.compressFile(context.Background(), ArchiverCovNewReader(data), fi, hdr, ArchiverCovPool(t, -1).Get())
	if !errors.Is(err, errArchiverCovNoCompressor) {
		t.Fatalf("compressing returned %v, want %v", err, errArchiverCovNoCompressor)
	}
}

// TestArchiverCov_CompressorThatCannotBeClosed covers the compressor's last
// block failing to be flushed. The bytes already staged are a prefix of the
// entry and nothing else, so the entry has to be given up rather than written.
func TestArchiverCov_CompressorThatCannotBeClosed(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir())
	a.zw.RegisterCompressor(Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return ArchiverCovCloseErrWriter{w: w, err: errArchiverCovUnflushable}, nil
	})

	data := ArchiverCovMixedBytes(1024)
	hdr, fi := ArchiverCovHeader("one.bin", Deflate, len(data))

	err := a.compressFile(context.Background(), ArchiverCovNewReader(data), fi, hdr, ArchiverCovPool(t, -1).Get())
	if !errors.Is(err, errArchiverCovUnflushable) {
		t.Fatalf("compressing returned %v, want %v", err, errArchiverCovUnflushable)
	}
	if buf.Len() != 0 {
		t.Errorf("%d bytes were written for an entry that was given up on", buf.Len())
	}
}

// TestArchiverCov_CancelledBeforeTheFirstRead covers an encrypted entry
// abandoned before a byte of it was read. Both the compressor and the
// encryption stream are closed on the way out, so neither is left holding the
// staging file open.
func TestArchiverCov_CancelledBeforeTheFirstRead(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	data := ArchiverCovMixedBytes(1024)
	hdr, fi := ArchiverCovHeader("secret.bin", Store, len(data))
	// #nosec G101 -- not a credential: any non-empty string turns encryption on for this entry
	hdr.Password = "cancellation-fixture"

	err := a.compressFile(ctx, ArchiverCovNewReader(data), fi, hdr, ArchiverCovPool(t, -1).Get())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("compressing returned %v, want %v", err, context.Canceled)
	}
}

// TestArchiverCov_ReadFailureWhileStaging covers a file that stops being
// readable part way into being staged.
func TestArchiverCov_ReadFailureWhileStaging(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir())

	data := ArchiverCovMixedBytes(1024)
	hdr, fi := ArchiverCovHeader("one.bin", Store, len(data))
	r := ArchiverCovNewReader(data)
	r.failAt = 1
	r.err = errArchiverCovFileVanished

	err := a.compressFile(context.Background(), r, fi, hdr, ArchiverCovPool(t, -1).Get())
	if !errors.Is(err, errArchiverCovFileVanished) {
		t.Fatalf("compressing returned %v, want %v", err, errArchiverCovFileVanished)
	}
}

// TestArchiverCov_HeaderFailureAfterStaging covers the header failing to be
// written once the entry has already been compressed into the staging file.
func TestArchiverCov_HeaderFailureAfterStaging(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir())

	data := ArchiverCovMixedBytes(1024)
	hdr, fi := ArchiverCovHeader(ArchiverCovLongName, Store, len(data))

	err := a.compressFile(context.Background(), ArchiverCovNewReader(data), fi, hdr, ArchiverCovPool(t, -1).Get())
	if err == nil {
		t.Fatal("an entry whose name does not fit its header was written")
	}
	if buf.Len() != 0 {
		t.Errorf("%d bytes were written for an entry that has no header", buf.Len())
	}
}

// TestArchiverCov_CancelledBeforeTheCopyOut covers an entry abandoned in the
// window between being staged and being copied into the archive. The
// cancellation lands on the read that reports the end of the file, so the
// staging pass finishes and the copy out is what sees it.
func TestArchiverCov_CancelledBeforeTheCopyOut(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	data := ArchiverCovMixedBytes(1024)
	hdr, fi := ArchiverCovHeader("one.bin", Store, len(data))
	r := ArchiverCovNewReader(data)
	r.onEOF = cancel

	err := a.compressFile(ctx, r, fi, hdr, ArchiverCovPool(t, -1).Get())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("compressing returned %v, want %v", err, context.Canceled)
	}
}

// TestArchiverCov_WriteFailureDuringTheCopyOut covers the archive itself
// running out of room while a staged entry is being copied into it. The entry
// is larger than the writer's own buffer, so the failure lands on the copy and
// not on the header.
func TestArchiverCov_WriteFailureDuringTheCopyOut(t *testing.T) {
	full := &ArchiverCovFailWriter{err: errArchiverCovDiskFull}
	a := ArchiverCovNewArchiver(t, full, t.TempDir())

	data := ArchiverCovHighEntropyBytes(128 * 1024)
	hdr, fi := ArchiverCovHeader("one.bin", Store, len(data))

	err := a.compressFile(context.Background(), ArchiverCovNewReader(data), fi, hdr, ArchiverCovPool(t, -1).Get())
	if !errors.Is(err, errArchiverCovDiskFull) {
		t.Fatalf("compressing returned %v, want %v", err, errArchiverCovDiskFull)
	}
}

// TestArchiverCov_StagingFileThatStopsBeingReadable covers the staging file
// failing to be read back. The entry's header is already in the archive by
// then, promising bytes that the copy can no longer produce, so the archive
// has to be abandoned rather than finished.
//
// The window is opened rather than raced for: the archiver takes its own lock
// between staging the entry and copying it out, so a test holding that lock
// stops the copy at exactly that point.
func TestArchiverCov_StagingFileThatStopsBeingReadable(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir())

	// A staging pool with no memory buffer at all puts every staged byte
	// in a file, which is the handle this test takes away.
	fp, err := filepool.New(t.TempDir(), 1, 0)
	if err != nil {
		t.Fatalf("building the staging pool: %v", err)
	}

	data := ArchiverCovMixedBytes(8192)
	hdr, fi := ArchiverCovHeader("one.bin", Store, len(data))
	staged := make(chan struct{})
	r := ArchiverCovNewReader(data)
	r.onEOF = func() { close(staged) }

	a.m.Lock()
	done := make(chan error, 1)
	go func() { done <- a.compressFile(context.Background(), r, fi, hdr, fp.Get()) }()

	<-staged
	if cerr := fp.Close(); cerr != nil {
		t.Errorf("closing the staging pool: %v", cerr)
	}
	a.m.Unlock()

	if err := <-done; err == nil {
		t.Fatal("an entry was reported written from a staging file that could not be read")
	}
}

// TestArchiverCov_MethodNothingCompresses covers an entry asking for a
// compression method the archive has no compressor for.
func TestArchiverCov_MethodNothingCompresses(t *testing.T) {
	srcDir := t.TempDir()
	mustWriteFile(t, filepath.Join(srcDir, "one.txt"), []byte("payload"), 0o600)

	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, srcDir, WithArchiverMethod(0xbeef))

	err := a.Archive(context.Background(), walkFilesFor(t, srcDir))
	if !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("archiving returned %v, want %v", err, ErrAlgorithm)
	}
}

// TestArchiverCov_CancelledWithoutStaging covers an entry written straight
// into the archive being abandoned before a byte of it was read.
func TestArchiverCov_CancelledWithoutStaging(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	data := ArchiverCovMixedBytes(1024)
	hdr, fi := ArchiverCovHeader("one.bin", Store, len(data))

	if err := a.compressFile(ctx, ArchiverCovNewReader(data), fi, hdr, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("compressing returned %v, want %v", err, context.Canceled)
	}
}

// TestArchiverCov_WriteFailureWithoutStaging covers the archive running out of
// room while an entry is written straight into it.
func TestArchiverCov_WriteFailureWithoutStaging(t *testing.T) {
	full := &ArchiverCovFailWriter{err: errArchiverCovDiskFull}
	a := ArchiverCovNewArchiver(t, full, t.TempDir())

	data := ArchiverCovHighEntropyBytes(128 * 1024)
	hdr, fi := ArchiverCovHeader("one.bin", Store, len(data))

	err := a.compressFile(context.Background(), ArchiverCovNewReader(data), fi, hdr, nil)
	if !errors.Is(err, errArchiverCovDiskFull) {
		t.Fatalf("compressing returned %v, want %v", err, errArchiverCovDiskFull)
	}
}

// TestArchiverCov_ReadFailureWithoutStaging covers a file that stops being
// readable while it is written straight into the archive.
func TestArchiverCov_ReadFailureWithoutStaging(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir())

	data := ArchiverCovMixedBytes(1024)
	hdr, fi := ArchiverCovHeader("one.bin", Store, len(data))
	r := ArchiverCovNewReader(data)
	r.failAt = 2
	r.err = errArchiverCovFileVanished

	if err := a.compressFile(context.Background(), r, fi, hdr, nil); !errors.Is(err, errArchiverCovFileVanished) {
		t.Fatalf("compressing returned %v, want %v", err, errArchiverCovFileVanished)
	}
}

// TestArchiverCov_NameEncodingFlag covers the flag that tells a reader how to
// read an entry's name. A name that needs more than ASCII is marked as UTF-8;
// an entry that says its name is not UTF-8 has the mark taken off, whatever
// was in the flags before.
func TestArchiverCov_NameEncodingFlag(t *testing.T) {
	t.Run("utf8", func(t *testing.T) {
		var buf bytes.Buffer
		a := ArchiverCovNewArchiver(t, &buf, t.TempDir())

		data := ArchiverCovMixedBytes(64)
		hdr, fi := ArchiverCovHeader("каталог/файл.txt", Store, len(data))
		if err := a.compressFile(context.Background(), ArchiverCovNewReader(data), fi, hdr, ArchiverCovPool(t, -1).Get()); err != nil {
			t.Fatalf("compressing: %v", err)
		}
		if hdr.Flags&0x800 == 0 {
			t.Errorf("the entry flags are %#04x, want the UTF-8 name bit set", hdr.Flags)
		}
	})

	t.Run("not utf8", func(t *testing.T) {
		var buf bytes.Buffer
		a := ArchiverCovNewArchiver(t, &buf, t.TempDir())

		data := ArchiverCovMixedBytes(64)
		hdr, fi := ArchiverCovHeader("каталог/файл.txt", Store, len(data))
		hdr.NonUTF8 = true
		hdr.Flags = 0x800
		if err := a.compressFile(context.Background(), ArchiverCovNewReader(data), fi, hdr, ArchiverCovPool(t, -1).Get()); err != nil {
			t.Fatalf("compressing: %v", err)
		}
		if hdr.Flags&0x800 != 0 {
			t.Errorf("the entry flags are %#04x, want the UTF-8 name bit clear", hdr.Flags)
		}
	})
}

// TestArchiverCov_TorrentZipStripsTheZlibWrapper covers the filter that turns
// a zlib stream into the bare deflate stream a zip entry holds: the two-byte
// header in front and the four-byte checksum behind it both go, however the
// writes they arrive in are split up.
func TestArchiverCov_TorrentZipStripsTheZlibWrapper(t *testing.T) {
	payload := []byte("the deflate stream a zip entry holds")
	stream := append([]byte{0x78, 0x9c}, payload...)

	for _, chunk := range []int{1, 2, 3, 5, len(stream)} {
		t.Run(fmt.Sprintf("chunks of %d", chunk), func(t *testing.T) {
			var out bytes.Buffer
			s := &tzStripZlibWriter{w: &out}
			for off := 0; off < len(stream); off += chunk {
				end := off + chunk
				if end > len(stream) {
					end = len(stream)
				}
				n, err := s.Write(stream[off:end])
				if err != nil {
					t.Fatalf("writing bytes %d..%d: %v", off, end, err)
				}
				if n != end-off {
					t.Fatalf("writing bytes %d..%d reported %d bytes", off, end, n)
				}
			}
			want := payload[:len(payload)-4]
			if !bytes.Equal(out.Bytes(), want) {
				t.Errorf("the filter passed %q, want %q", out.Bytes(), want)
			}
		})
	}
}

// ArchiverCovCancelInfo is a FileInfo that cancels a context the first time
// the archiver asks what the operating system knows about the file. That call
// sits between the archiver's last look at the context and the point where it
// hands the entry to a worker, which is the window this stands in for: the
// caller gives up while the entry is on its way to a worker that is not ready
// for it.
type ArchiverCovCancelInfo struct {
	os.FileInfo
	cancel   func()
	once     sync.Once
	Reported chan struct{}
}

func ArchiverCovNewCancelInfo(fi os.FileInfo, cancel func()) *ArchiverCovCancelInfo {
	return &ArchiverCovCancelInfo{FileInfo: fi, cancel: cancel, Reported: make(chan struct{})}
}

func (i *ArchiverCovCancelInfo) Sys() interface{} {
	i.once.Do(func() {
		i.cancel()
		close(i.Reported)
	})
	return nil
}

// ArchiverCovSubmitStalls builds the one state in which the archiver's entry
// loop can find the workers unable to take another entry: every worker is busy
// and the queue between them is full. It archives entries that all need the
// archiver's own lock, which the test holds, so the workers stop on the first
// entry each and the queue fills behind them; the last entry is the one whose
// FileInfo cancels the context, and it is the entry the loop cannot hand over.
//
// last is the entry that stalls, and comes after the fillers by name.
func ArchiverCovSubmitStalls(t *testing.T, last func(name string) os.FileInfo) error {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("hard links are not looked for here, so an entry's FileInfo is never asked what the system knows")
	}

	srcDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Two workers take one entry each and the queue holds four more, so
	// six entries are absorbed and the seventh is the one that stalls.
	const workers = 2
	const fillers = workers * 3

	files := make(map[string]os.FileInfo, fillers+1)
	for i := 0; i < fillers; i++ {
		name := filepath.Join(srcDir, fmt.Sprintf("filler%02d", i))
		files[name] = ArchiverCovInfo{name: filepath.Base(name), mode: os.ModeNamedPipe | 0o644}
	}
	stallName := filepath.Join(srcDir, "zz-stalls")
	stalls := ArchiverCovNewCancelInfo(last(filepath.Base(stallName)), cancel)
	files[stallName] = stalls

	var buf bytes.Buffer
	// Neither the owner metadata nor the extended attributes are wanted
	// here: both are read before the archiver's last look at the context,
	// and reading the owner is what would otherwise ask the FileInfo what
	// the system knows too early for this to be the window it stands for.
	a := ArchiverCovNewArchiver(t, &buf, srcDir,
		WithArchiverConcurrency(workers),
		WithArchiverXattrs(false),
		WithArchiverPlatformMetadata(false),
		WithStageDirectory(t.TempDir()))

	a.m.Lock()
	done := make(chan error, 1)
	go func() { done <- a.Archive(ctx, files) }()

	<-stalls.Reported
	// The loop reaches the queue a few statements after the cancellation,
	// and cannot get past it while the lock is held. Letting the workers go
	// any earlier would let one of them make room in the queue.
	time.Sleep(100 * time.Millisecond)
	a.m.Unlock()

	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		stack := make([]byte, 1<<16)
		n := runtime.Stack(stack, true)
		t.Fatalf("archiving did not return within 30s:\n%s", stack[:n])
		return nil
	}
}

// TestArchiverCov_CancelledHandingOverASpecialFile covers the archiver giving
// up on a device node or named pipe it cannot hand to a worker, and the
// workers throwing away the entries already queued behind it rather than
// writing them into an archive that is being abandoned.
func TestArchiverCov_CancelledHandingOverASpecialFile(t *testing.T) {
	err := ArchiverCovSubmitStalls(t, func(name string) os.FileInfo {
		return ArchiverCovInfo{name: name, mode: os.ModeNamedPipe | 0o644}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("archiving returned %v, want %v", err, context.Canceled)
	}
}

// TestArchiverCov_CancelledHandingOverAFile covers the same window for an
// ordinary file, which the archiver hands over at a different point in the
// loop.
func TestArchiverCov_CancelledHandingOverAFile(t *testing.T) {
	err := ArchiverCovSubmitStalls(t, func(name string) os.FileInfo {
		return ArchiverCovInfo{name: name, size: 4096, mode: 0o644}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("archiving returned %v, want %v", err, context.Canceled)
	}
}

// errArchiverCovNoRoom stands in for what the zlib build reports when its own
// heap has nowhere to put another stream.
var errArchiverCovNoRoom = errors.New("zlib: malloc fail")

// TestArchiverCov_TorrentZipZlibRefusesToStart covers the one refusal the
// torrentzip deflate stream can meet. The zlib behind it is a wasm module
// carrying a heap of its own, and a heap with nothing left refuses to open a
// stream -- a state no archive, option or file on disk can bring about. What
// is asserted is only that the refusal comes back out: an archiver that
// swallowed it would go on with no compressor at all.
func TestArchiverCov_TorrentZipZlibRefusesToStart(t *testing.T) {
	real := newZlibWriterLevel
	t.Cleanup(func() { newZlibWriterLevel = real })
	newZlibWriterLevel = func(io.Writer, int) (*zlib4go.Writer, error) {
		return nil, errArchiverCovNoRoom
	}

	srcDir := t.TempDir()
	mustWriteFile(t, filepath.Join(srcDir, "body.txt"), ArchiverCovMixedBytes(4096), 0o600)

	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, srcDir,
		WithArchiverTorrentZip(true), WithArchiverMethod(Deflate), WithArchiverLevel(9))

	err := a.Archive(context.Background(), walkFilesFor(t, srcDir))
	if !errors.Is(err, errArchiverCovNoRoom) {
		t.Fatalf("archiving gave %v, want the refusal the zlib allocator reported", err)
	}
}

// TestArchiverCov_WriteRawEntryTorrentZipEmptyBody covers writeRawEntry's own
// empty-body case under torrentzip: a hard link or a device node has no body
// at all, and torrentzip's answer for that is the same two-byte empty deflate
// block an empty regular file gets (TestArchiverCov_TorrentZipEmptyEntry),
// written by hand rather than through a compressor. createHardlink and
// createSpecialFile both refuse a torrentzip archive before they ever reach
// writeRawEntry (torrentzip_canonical_test.go), so it is called directly
// here, the same way aes_winzip_test.go reaches its own AES branch.
func TestArchiverCov_WriteRawEntryTorrentZipEmptyBody(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir(),
		WithArchiverTorrentZip(true), WithArchiverMethod(Deflate), WithArchiverLevel(9))

	hdr, fi := ArchiverCovHeader("empty.bin", Deflate, 0)
	if err := a.writeRawEntry(fi, hdr, nil); err != nil {
		t.Fatalf("writing an empty raw entry under torrentzip: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("closing the archiver: %v", err)
	}

	zr := ArchiverCovRead(t, buf.Bytes(), "")
	if len(zr.File) != 1 {
		t.Fatalf("the archive holds %d entries, want 1", len(zr.File))
	}
	if zr.File[0].CompressedSize64 != 2 {
		t.Errorf("the empty raw entry is %d bytes, want the 2 of an empty deflate block",
			zr.File[0].CompressedSize64)
	}
	if got := ArchiverCovEntry(t, zr, "empty.bin"); len(got) != 0 {
		t.Errorf("the empty raw entry came back %d bytes, want none", len(got))
	}
}

// TestArchiverCov_WriteRawEntryTorrentZipCompressesBody covers writeRawEntry's
// other torrentzip case: a non-empty body -- the target of a symlink, in
// createSymlink -- goes through the compressor torrentzip registers rather
// than through the empty-block shortcut above. Torrentzip refuses a symlink
// outright before createSymlink can ever reach writeRawEntry with one
// (torrentzip_canonical_test.go), so, as above, writeRawEntry is called
// directly.
func TestArchiverCov_WriteRawEntryTorrentZipCompressesBody(t *testing.T) {
	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir(),
		WithArchiverTorrentZip(true), WithArchiverMethod(Deflate), WithArchiverLevel(9))

	body := []byte("the target of a link, held in memory and deflated by hand")
	hdr, fi := ArchiverCovHeader("link.bin", Deflate, len(body))
	hdr.CRC32 = crc32.ChecksumIEEE(body)
	if err := a.writeRawEntry(fi, hdr, body); err != nil {
		t.Fatalf("writing a raw entry under torrentzip: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("closing the archiver: %v", err)
	}

	zr := ArchiverCovRead(t, buf.Bytes(), "")
	if len(zr.File) != 1 {
		t.Fatalf("the archive holds %d entries, want 1", len(zr.File))
	}
	if zr.File[0].Method != Deflate {
		t.Errorf("the raw entry is method %d, want %d", zr.File[0].Method, Deflate)
	}
	if got := ArchiverCovEntry(t, zr, "link.bin"); !bytes.Equal(got, body) {
		t.Errorf("the raw entry came back %q, want %q", got, body)
	}
}

// errArchiverCovRawEntryNoZlib stands in for what the zlib allocator reports
// when writeRawEntry's own compressor cannot even be opened.
var errArchiverCovRawEntryNoZlib = errors.New("zlib: malloc fail during a raw entry")

// TestArchiverCov_WriteRawEntryTorrentZipCompressorFails covers writeRawEntry
// giving up before writing anything when the compressor it asks for under
// torrentzip refuses to open -- the same zlib allocator refusal
// TestArchiverCov_TorrentZipZlibRefusesToStart covers for a regular file's own
// compressor, met here instead on the buffer-based path writeRawEntry uses for
// a hard link, a device node or a symlink's target.
func TestArchiverCov_WriteRawEntryTorrentZipCompressorFails(t *testing.T) {
	real := newZlibWriterLevel
	t.Cleanup(func() { newZlibWriterLevel = real })
	newZlibWriterLevel = func(io.Writer, int) (*zlib4go.Writer, error) {
		return nil, errArchiverCovRawEntryNoZlib
	}

	var buf bytes.Buffer
	a := ArchiverCovNewArchiver(t, &buf, t.TempDir(),
		WithArchiverTorrentZip(true), WithArchiverMethod(Deflate), WithArchiverLevel(9))

	body := []byte("the target of a link")
	hdr, fi := ArchiverCovHeader("link.bin", Deflate, len(body))
	err := a.writeRawEntry(fi, hdr, body)
	if !errors.Is(err, errArchiverCovRawEntryNoZlib) {
		t.Fatalf("writing a raw entry returned %v, want %v", err, errArchiverCovRawEntryNoZlib)
	}
	if buf.Len() != 0 {
		t.Errorf("%d bytes were written for an entry whose compressor never opened", buf.Len())
	}
}
