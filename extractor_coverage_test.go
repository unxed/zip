package zip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The tests here are about the write-to-disk side of an extraction: the paths
// an archive takes when what it describes cannot be put on the destination as
// it stands, and the ones a destination takes when what is already on it
// stands in the way.

// extractorCovArchive returns an archive holding the entries described, each
// written through CreateRaw so that the header reaches the reader exactly as
// given.
type extractorCovEntry struct {
	name   string
	data   []byte
	mode   fs.FileMode
	method uint16
	// declared overrides the uncompressed size the header carries, for the
	// entries that are about what the archive claims rather than what it holds.
	declared uint64
	badCRC   bool
	accessed time.Time
	owner    bool
}

func extractorCovArchive(t *testing.T, entries ...extractorCovEntry) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	for _, e := range entries {
		method := e.method
		fh := &FileHeader{
			Name:               e.name,
			Method:             method,
			CRC32:              crc32.ChecksumIEEE(e.data),
			CompressedSize64:   uint64(len(e.data)),
			UncompressedSize64: uint64(len(e.data)),
			Accessed:           e.accessed,
		}
		if e.declared != 0 {
			fh.UncompressedSize64 = e.declared
		}
		if e.badCRC {
			fh.CRC32 ^= 0xffffffff
		}
		if e.mode == 0 {
			fh.SetMode(0644)
		} else {
			fh.SetMode(e.mode)
		}
		if e.owner {
			fh.Extra = appendUnixExtra(fh.Extra, 12345, 12345)
		}
		if !e.accessed.IsZero() {
			fh.Extra = append(fh.Extra, extractorCovAccessedExtra(e.accessed)...)
		}
		w, err := zw.CreateRaw(fh)
		if err != nil {
			t.Fatalf("creating %q: %v", e.name, err)
		}
		if len(e.data) > 0 {
			mustWrite(t, w, e.data)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}
	return buf.Bytes()
}

// extractorCovAccessedExtra is the Info-ZIP extended timestamp field carrying
// an access time and nothing else, written out here because CreateRaw puts the
// header on the archive exactly as it is given.
func extractorCovAccessedExtra(atime time.Time) []byte {
	out := make([]byte, 9)
	binary.LittleEndian.PutUint16(out[0:2], extTimeExtraID)
	binary.LittleEndian.PutUint16(out[2:4], 5)
	out[4] = 2 // the access time is the only one present
	// #nosec G115 -- the field is four bytes of Unix time and this is the whole of it
	binary.LittleEndian.PutUint32(out[5:9], uint32(atime.Unix()))
	return out
}

// extractorCovExtract extracts raw into a fresh destination and returns the
// destination and whatever the extraction had to say.
func extractorCovExtract(t *testing.T, raw []byte, opts ...ExtractorOption) (string, error) {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "dst")
	return dst, extractorCovExtractInto(t, raw, dst, opts...)
}

// extractorCovExtractInto extracts raw over a destination the test has already
// prepared.
func extractorCovExtractInto(t *testing.T, raw []byte, dst string, opts ...ExtractorOption) error {
	t.Helper()
	e, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), dst, opts...)
	if err != nil {
		t.Fatalf("building the extractor: %v", err)
	}
	closeAt(t, e)
	return e.Extract(context.Background())
}

// extractorCovSkipIfPrivileged skips a test whose point is that the platform
// refuses something, where this user is refused nothing.
func extractorCovSkipIfPrivileged(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("file permissions do not refuse the owner here")
	}
	if os.Geteuid() == 0 {
		t.Skip("this user is refused nothing the permissions say")
	}
}

// extractorCovChmod puts mode on dir and puts it back when the test ends, so
// that the temporary directory can still be cleaned up.
func extractorCovChmod(t *testing.T, dir string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}

// --- the options and the constructors -------------------------------------

func TestExtractorCovConcurrencyBelowOne(t *testing.T) {
	// Concurrency is how many entries may be written at once, and none is
	// not a number of workers an extraction can be run with.
	raw := extractorCovArchive(t, extractorCovEntry{name: "entry.bin", data: []byte("x")})
	dst := filepath.Join(t.TempDir(), "dst")
	_, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), dst, WithExtractorConcurrency(0))
	if !errors.Is(err, ErrMinConcurrency) {
		t.Fatalf("building the extractor returned %v, want %v", err, ErrMinConcurrency)
	}
}

func TestExtractorCovReaderIsNotAnArchive(t *testing.T) {
	// What is handed in has to be an archive before there is anything to
	// extract from it, and the reader's refusal is the caller's answer.
	raw := []byte("this is not a zip file at all")
	dst := filepath.Join(t.TempDir(), "dst")
	if _, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), dst); err == nil {
		t.Fatal("a reader over something that is not an archive was accepted")
	}
}

func TestExtractorCovDestinationHasNoAbsoluteSpelling(t *testing.T) {
	// The destination is resolved to an absolute path before anything is
	// written into it. Windows resolves through the Win32 API, which refuses
	// a name it cannot spell, and there is then no destination to extract to.
	if runtime.GOOS != "windows" {
		t.Skip("only Windows refuses to resolve a name it cannot spell")
	}
	raw := extractorCovArchive(t, extractorCovEntry{name: "entry.bin", data: []byte("x")})
	if _, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), "dst\x00bad"); err == nil {
		t.Fatal("a destination with no absolute spelling was accepted")
	}
}

func TestExtractorCovFilesListsTheArchive(t *testing.T) {
	// Files is what the archive holds, and the access time an entry carries
	// travels with it: it is what the extraction restores instead of now.
	accessed := time.Unix(1000000000, 0)
	raw := extractorCovArchive(t, extractorCovEntry{
		name: "entry.bin", data: []byte("contents"), accessed: accessed,
	})
	dst := filepath.Join(t.TempDir(), "dst")
	e, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), dst)
	if err != nil {
		t.Fatalf("building the extractor: %v", err)
	}
	closeAt(t, e)

	files := e.Files()
	if len(files) != 1 || files[0].Name != "entry.bin" {
		t.Fatalf("Files() = %v, want the one entry the archive holds", files)
	}
	if files[0].Accessed.IsZero() {
		t.Fatal("the entry came back with no access time, so the extraction has none to restore")
	}
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dst, "entry.bin")); serr != nil {
		t.Fatalf("the entry was not extracted: %v", serr)
	}
}

// --- the default handler for an ownership that will not take ---------------

// extractorCovDefaultChownHandler returns the handler an extractor is built
// with when the caller names none.
func extractorCovDefaultChownHandler(t *testing.T) func(string, error) error {
	t.Helper()
	raw := extractorCovArchive(t, extractorCovEntry{name: "entry.bin", data: []byte("x")})
	dst := filepath.Join(t.TempDir(), "dst")
	e, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), dst)
	if err != nil {
		t.Fatalf("building the extractor: %v", err)
	}
	closeAt(t, e)
	return e.options.chownErrorHandler
}

func TestExtractorCovDefaultChownHandler(t *testing.T) {
	handler := extractorCovDefaultChownHandler(t)

	t.Run("an owner this user may not give away is passed over in silence", func(t *testing.T) {
		err := handler("entry.bin", &os.PathError{Op: "lchown", Path: "entry.bin", Err: syscall.EPERM})
		if err != nil {
			t.Fatalf("the handler returned %v, want nil: an ordinary user is refused every owner but its own", err)
		}
	})

	t.Run("anything else is reported and the extraction goes on", func(t *testing.T) {
		err := handler("entry.bin", &os.PathError{Op: "lchown", Path: "entry.bin", Err: syscall.ENOENT})
		if err != nil {
			t.Fatalf("the handler returned %v, want nil: ownership is not worth failing an extraction over", err)
		}
	})

	t.Run("an error that is not the filesystem's own is reported too", func(t *testing.T) {
		if err := handler("entry.bin", errors.New("no path, no errno")); err != nil {
			t.Fatalf("the handler returned %v, want nil", err)
		}
	})
}

// --- what an extraction does when it is cancelled -------------------------

// extractorCovCancelAt cancels an extraction once it has started reading the
// archive, and gives the pass that hands work out time to fill the queue and
// block on it first, so that the tasks already in the queue are the ones a
// worker picks up after the cancellation.
type extractorCovCancelAt struct {
	r      io.ReaderAt
	armed  atomic.Bool
	fired  atomic.Bool
	cancel context.CancelFunc
}

func (c *extractorCovCancelAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	if c.armed.Load() && c.fired.CompareAndSwap(false, true) {
		time.Sleep(100 * time.Millisecond)
		c.cancel()
	}
	return n, err
}

func extractorCovRunCancelled(t *testing.T, raw []byte) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := &extractorCovCancelAt{r: bytes.NewReader(raw), cancel: cancel}
	dst := filepath.Join(t.TempDir(), "dst")
	e, err := NewExtractorFromReader(src, int64(len(raw)), dst,
		WithExtractorConcurrency(1), WithExtractorTolerant(true))
	if err != nil {
		t.Fatalf("building the extractor: %v", err)
	}
	closeAt(t, e)
	src.armed.Store(true)
	return e.Extract(ctx)
}

func TestExtractorCovCancelledMidExtraction(t *testing.T) {
	// A cancelled extraction stops handing work out and drops the work it
	// has already handed out: the entry being written stops where it is, and
	// the entries queued behind it are passed over rather than extracted
	// into a tree the caller has stopped asking for.
	entries := []extractorCovEntry{
		{name: "first.bin", data: bytes.Repeat([]byte("a"), 4096)},
	}
	for i := 0; i < 8; i++ {
		entries = append(entries, extractorCovEntry{
			name: fmt.Sprintf("queued%02d.bin", i), data: []byte("x"),
		})
	}
	raw := extractorCovArchive(t, entries...)

	if err := extractorCovRunCancelled(t, raw); !errors.Is(err, context.Canceled) {
		t.Fatalf("the extraction returned %v, want the cancellation", err)
	}
}

func TestExtractorCovCancelledWithSpecialFilesQueued(t *testing.T) {
	// The same for the entries that are not ordinary files: a device, a
	// socket or a named pipe is queued through a channel of its own and is
	// dropped the same way.
	entries := []extractorCovEntry{
		{name: "first.bin", data: bytes.Repeat([]byte("a"), 4096)},
	}
	for i := 0; i < 8; i++ {
		entries = append(entries, extractorCovEntry{
			name: fmt.Sprintf("pipe%02d", i), mode: fs.ModeNamedPipe | 0644,
		})
	}
	raw := extractorCovArchive(t, entries...)

	if err := extractorCovRunCancelled(t, raw); !errors.Is(err, context.Canceled) {
		t.Fatalf("the extraction returned %v, want the cancellation", err)
	}
}

// --- stripping leading components -----------------------------------------

// An extraction goes over the archive more than once: the main pass writes the
// files and the directories, and the passes after it make the links, apply the
// directories' metadata and write the alternate data streams. Every one of
// them has to arrive at the same name for an entry, or the later ones act on a
// name nothing has written.

func TestExtractorCovStripComponentsAppliesToEveryPass(t *testing.T) {
	// A whole archive under one leading component, with an entry for each
	// pass in it. Everything lands under the stripped name and nothing under
	// the one the archive carries.
	raw := extractorCovArchive(t,
		extractorCovEntry{name: "top/dir/", mode: fs.ModeDir | 0700},
		extractorCovEntry{name: "top/dir/file.txt", data: []byte("contents")},
		extractorCovEntry{name: "top/link", data: []byte("dir/file.txt"), mode: fs.ModeSymlink | 0777},
		extractorCovEntry{name: "top/dir/file.txt:stream", data: []byte("the stream")},
	)

	dst, err := extractorCovExtract(t, raw, WithExtractorStripComponents(1))
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	if _, serr := os.Lstat(filepath.Join(dst, "top")); !os.IsNotExist(serr) {
		t.Errorf("something was written under the unstripped name: %v", serr)
	}

	fi, serr := os.Lstat(filepath.Join(dst, "dir"))
	if serr != nil || !fi.IsDir() {
		t.Fatalf("the directory entry did not land under its stripped name: %v", serr)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700 {
		t.Errorf("the directory came out %v, want 0700: its metadata went to another name", fi.Mode().Perm())
	}

	data, rerr := os.ReadFile(filepath.Join(dst, "dir", "file.txt"))
	if rerr != nil {
		t.Fatalf("the file entry did not land under its stripped name: %v", rerr)
	}
	if string(data) != "contents" {
		t.Errorf("dir/file.txt = %q, want %q", data, "contents")
	}

	if _, serr := os.Lstat(filepath.Join(dst, "link")); serr != nil {
		t.Errorf("the link entry did not land under its stripped name: %v", serr)
	}

	stream, rerr := os.ReadFile(filepath.Join(dst, "dir", "file.txt:stream"))
	if rerr != nil {
		t.Fatalf("the stream entry did not land under its stripped name: %v", rerr)
	}
	if string(stream) != "the stream" {
		t.Errorf("the stream holds %q, want %q", stream, "the stream")
	}
}

func TestExtractorCovStripComponentsSkipsShortNamesInEveryPass(t *testing.T) {
	// An entry with no more components than the strip asks for is not
	// extracted at all, and the passes after the main one have to pass over
	// it too rather than resolve a name the extraction never wrote.
	for _, tc := range []struct {
		name  string
		entry extractorCovEntry
	}{
		{"a link", extractorCovEntry{
			name: "link", data: []byte("keep/it.txt"), mode: fs.ModeSymlink | 0777,
		}},
		{"a directory", extractorCovEntry{name: "dir/", mode: fs.ModeDir | 0755}},
		{"a stream", extractorCovEntry{name: "file:stream", data: []byte("x")}},
		{"a name that is nothing but the current directory", extractorCovEntry{
			name: "./", mode: fs.ModeDir | 0755,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := extractorCovArchive(t, tc.entry,
				extractorCovEntry{name: "keep/it.txt", data: []byte("kept")})

			dst, err := extractorCovExtract(t, raw, WithExtractorStripComponents(1))
			if err != nil {
				t.Fatalf("extraction failed: %v", err)
			}
			data, rerr := os.ReadFile(filepath.Join(dst, "it.txt"))
			if rerr != nil {
				t.Fatalf("the entry that did have a component to strip was not extracted: %v", rerr)
			}
			if string(data) != "kept" {
				t.Errorf("it.txt = %q, want %q", data, "kept")
			}
			left := strings.TrimSuffix(strings.SplitN(tc.entry.name, ":", 2)[0], "/")
			if left == "." {
				return
			}
			if _, serr := os.Lstat(filepath.Join(dst, left)); !os.IsNotExist(serr) {
				t.Errorf("the entry with nothing left after the strip was extracted anyway: %v", serr)
			}
		})
	}
}

func TestExtractorCovDirectoryMetadataAfterAFailedCreate(t *testing.T) {
	// The metadata pass runs over every directory the archive names,
	// including one the main pass could not create, so the name it applies
	// the metadata to is not there. Whether that is the extraction's answer
	// or something it carries on past is what tolerance decides.
	extractorCovSkipIfPrivileged(t)

	raw := extractorCovArchive(t, extractorCovEntry{name: "held/sub/", mode: fs.ModeDir | 0755})

	// blocked prepares a destination in which "held" is a directory nothing
	// can be created inside.
	blocked := func(t *testing.T) string {
		t.Helper()
		dst := filepath.Join(t.TempDir(), "dst")
		held := filepath.Join(dst, "held")
		mustMkdirAll(t, held)
		extractorCovChmod(t, held, 0o500)
		return dst
	}

	t.Run("times", func(t *testing.T) {
		err := extractorCovExtractInto(t, raw, blocked(t),
			WithExtractorTolerant(true), WithExtractorNoTimes(false))
		if err != nil {
			t.Fatalf("a tolerant extraction returned %v, want it to carry on", err)
		}
	})

	t.Run("mode", func(t *testing.T) {
		err := extractorCovExtractInto(t, raw, blocked(t),
			WithExtractorTolerant(true), WithExtractorNoTimes(true))
		if err != nil {
			t.Fatalf("a tolerant extraction returned %v, want it to carry on", err)
		}
	})

	t.Run("strict", func(t *testing.T) {
		if err := extractorCovExtractInto(t, raw, blocked(t), WithExtractorNoTimes(true)); err == nil {
			t.Fatal("metadata applied to a directory that was never created was reported as applied")
		}
	})
}

// --- alternate data streams -----------------------------------------------

func TestExtractorCovStreamEntryCannotBeCreated(t *testing.T) {
	// An entry naming a stream is written in a pass of its own, after the
	// tree is otherwise final, and a destination that will not take it is
	// the extraction's answer.
	extractorCovSkipIfPrivileged(t)

	raw := extractorCovArchive(t, extractorCovEntry{name: "file:stream", data: []byte("x")})
	dst := filepath.Join(t.TempDir(), "dst")
	mustMkdirAll(t, dst)
	extractorCovChmod(t, dst, 0o500)

	if err := extractorCovExtractInto(t, raw, dst); err == nil {
		t.Fatal("a stream that could not be created was reported as extracted")
	}
}

func TestExtractorCovStreamEntryMetadataFailure(t *testing.T) {
	// The stream is written and the ownership it carries is refused, which
	// is the extraction's answer when the caller's handler says so.
	extractorCovSkipIfPrivileged(t)

	refused := errors.New("the owner could not be set")
	raw := extractorCovArchive(t, extractorCovEntry{
		name: "file:stream", data: []byte("x"), owner: true,
	})
	_, err := extractorCovExtract(t, raw,
		WithExtractorChownErrorHandler(func(string, error) error { return refused }))
	if !errors.Is(err, refused) {
		t.Fatalf("the extraction returned %v, want %v", err, refused)
	}
}

func TestExtractorCovZoneIdentifierBodyUnreadable(t *testing.T) {
	// A mark-of-the-web stream is read whole before it is sanitized, so an
	// entry whose bytes do not match its own checksum fails on the read
	// rather than on the write.
	raw := extractorCovArchive(t,
		extractorCovEntry{name: "file.txt", data: []byte("contents")},
		extractorCovEntry{name: "file.txt:Zone.Identifier", data: []byte("[ZoneTransfer]\r\nZoneId=3\r\n"), badCRC: true},
	)
	_, err := extractorCovExtract(t, raw)
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("the extraction returned %v, want %v", err, ErrChecksum)
	}
}

// --- what one entry's write runs into -------------------------------------

func TestExtractorCovEntryMethodUnsupported(t *testing.T) {
	// The entry cannot be opened at all: nothing in this build knows how to
	// undo the method its header names.
	raw := extractorCovArchive(t, extractorCovEntry{
		name: "entry.bin", data: []byte("compressed by something else"), method: 42,
	})
	_, err := extractorCovExtract(t, raw)
	if !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("the extraction returned %v, want %v", err, ErrAlgorithm)
	}
}

func TestExtractorCovEntryTooLargeToReserve(t *testing.T) {
	// With both limits turned off, the size the header declares is what the
	// extraction reserves room for, and a declaration no filesystem can hold
	// is refused by the filesystem rather than written around.
	raw := extractorCovArchive(t, extractorCovEntry{
		name: "entry.bin", data: []byte("a few bytes"), declared: 1 << 50,
	})
	_, err := extractorCovExtract(t, raw,
		WithExtractorMaxFileSize(0), WithExtractorMaxRatio(0))
	if err == nil {
		t.Fatal("an entry that declares more than the filesystem can hold was extracted")
	}
}

func TestExtractorCovSparseEntryUnreadable(t *testing.T) {
	// The sparse copy reads the entry the same way the ordinary one does,
	// and an entry whose bytes do not match its checksum stops it.
	raw := extractorCovArchive(t, extractorCovEntry{
		name: "entry.bin", data: bytes.Repeat([]byte("x"), 64), badCRC: true,
	})
	_, err := extractorCovExtract(t, raw, WithExtractorSparse(true))
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("the extraction returned %v, want %v", err, ErrChecksum)
	}
}

func TestExtractorCovSparseCopyStopsOnCancellation(t *testing.T) {
	// The sparse copy asks whether the extraction is still wanted before
	// every block it reads.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	f, err := os.Create(filepath.Join(t.TempDir(), "out.bin"))
	if err != nil {
		t.Fatalf("creating the destination file: %v", err)
	}
	closeAt(t, f)

	bw := extractorCovBudget("out.bin").file(f)
	if err := copySparseZip(f, bytes.NewReader([]byte("contents")), bw, ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("the copy returned %v, want the cancellation", err)
	}
}

func TestExtractorCovSparseCopyCannotSeekOverAHole(t *testing.T) {
	// A run of zeros is not written but seeked over, and a destination that
	// will not take the seek has not been given the hole.
	f, err := os.Create(filepath.Join(t.TempDir(), "out.bin"))
	if err != nil {
		t.Fatalf("creating the destination file: %v", err)
	}
	if cerr := f.Close(); cerr != nil {
		t.Fatalf("closing the destination file: %v", cerr)
	}

	bw := extractorCovBudget("out.bin").file(io.Discard)
	err = copySparseZip(f, bytes.NewReader(make([]byte, 64)), bw, context.Background())
	if err == nil {
		t.Fatal("a hole that could not be seeked over was reported as written")
	}
}

// extractorCovBudget is a budget with no limit turned on, for the tests that
// reach a write point directly.
func extractorCovBudget(name string) *entryBudget {
	return newExtractBudget(&extractorOptions{}, new(int64)).duplicate(name)
}

func TestExtractorCovAllZerosOnNothing(t *testing.T) {
	// No bytes are all of them zero, which is what makes an empty read a
	// hole of no length rather than a block to write.
	if !isAllZeros(nil) {
		t.Error("isAllZeros(nil) = false, want true")
	}
}

// --- links and parents ----------------------------------------------------

func TestExtractorCovLinksToDirsOutsideTheDestination(t *testing.T) {
	// A path that is not under the destination has no parents in it to
	// examine.
	e := &Extractor{chroot: filepath.Join(t.TempDir(), "dst")}
	if err := e.linksToDirs(filepath.Join(t.TempDir(), "elsewhere", "entry.bin")); err != nil {
		t.Fatalf("a path outside the destination returned %v, want nil", err)
	}
}

func TestExtractorCovLinksToDirsUnrelatablePath(t *testing.T) {
	// An empty destination is a prefix of every path and a base no absolute
	// path can be expressed against, so there is no chain of parents to walk.
	e := &Extractor{chroot: ""}
	if err := e.linksToDirs(string(filepath.Separator) + filepath.Join("some", "entry.bin")); err == nil {
		t.Fatal("a path that cannot be expressed against the destination was walked anyway")
	}
}

func TestExtractorCovLinksToDirsParentIsNotADirectory(t *testing.T) {
	// A parent that is a file is not a symlink to be taken away and not a
	// directory to descend into either; what the filesystem says about the
	// name below it is the answer.
	if runtime.GOOS == "windows" {
		t.Skip("a name below a file reads as missing here rather than as a bad path")
	}
	dst := t.TempDir()
	mustWriteFile(t, filepath.Join(dst, "blocker"), []byte("in the way"), 0o600)

	e := &Extractor{chroot: dst}
	if err := e.linksToDirs(filepath.Join(dst, "blocker", "sub", "entry.bin")); err == nil {
		t.Fatal("a parent chain running through a file was walked anyway")
	}
}

func TestExtractorCovLinksToDirsSymlinkWillNotGoAway(t *testing.T) {
	// A symlink standing where a directory belongs is taken away so that
	// nothing is written through it, and one that will not go away is the
	// extraction's answer rather than a link it writes through anyway.
	extractorCovSkipIfPrivileged(t)

	dst := t.TempDir()
	held := filepath.Join(dst, "held")
	mustMkdir(t, held)
	if err := os.Symlink(dst, filepath.Join(held, "link")); err != nil {
		t.Skipf("this machine does not make symlinks: %v", err)
	}
	extractorCovChmod(t, held, 0o500)

	e := &Extractor{chroot: dst}
	if err := e.linksToDirs(filepath.Join(dst, "held", "link", "entry.bin")); err == nil {
		t.Fatal("a symlink that could not be taken away was left in the path")
	}
}

func TestExtractorCovParentChainRunsThroughAFile(t *testing.T) {
	// The whole extraction: a file already stands where one of an entry's
	// parents belongs, and the parents below it cannot be examined.
	if runtime.GOOS == "windows" {
		t.Skip("a name below a file reads as missing here rather than as a bad path")
	}
	raw := extractorCovArchive(t, extractorCovEntry{name: "blocker/sub/deep.txt", data: []byte("x")})
	dst := filepath.Join(t.TempDir(), "dst")
	mustMkdirAll(t, dst)
	mustWriteFile(t, filepath.Join(dst, "blocker"), []byte("in the way"), 0o600)

	if err := extractorCovExtractInto(t, raw, dst); err == nil {
		t.Fatal("an entry whose parent chain runs through a file was reported as extracted")
	}
}

func TestExtractorCovSynthesizeParentsOutsideTheDestination(t *testing.T) {
	// The fallback walk is a walk of the destination's own parents, so a
	// path that is not under it has none to reconstruct.
	e := &Extractor{chroot: filepath.Join(t.TempDir(), "dst")}
	if err := e.synthesizeParentDirs("\x00" + string(filepath.Separator) + "entry.bin"); err != nil {
		t.Fatalf("a path outside the destination returned %v, want nil", err)
	}
}

func TestExtractorCovSynthesizeParentsUnrelatablePath(t *testing.T) {
	// An empty destination is a prefix of every path and a base no absolute
	// path can be expressed against.
	e := &Extractor{chroot: ""}
	err := e.synthesizeParentDirs(string(filepath.Separator) + "\x00" + string(filepath.Separator) + "entry.bin")
	if err == nil {
		t.Fatal("a path that cannot be expressed against the destination was reconstructed anyway")
	}
}

func TestExtractorCovSynthesizeParentsReplacesABlockingFile(t *testing.T) {
	// A file standing where a parent belongs is taken away and the parent is
	// made in its place, and the parents below it are made in turn.
	dst := t.TempDir()
	mustWriteFile(t, filepath.Join(dst, "blocker"), []byte("in the way"), 0o600)

	e := &Extractor{chroot: dst}
	target := filepath.Join(dst, "blocker", "sub", "entry.bin")
	if err := e.synthesizeParentDirs(target); err != nil {
		t.Fatalf("reconstructing the parents returned %v", err)
	}
	fi, err := os.Stat(filepath.Join(dst, "blocker", "sub"))
	if err != nil || !fi.IsDir() {
		t.Fatalf("the parents were not reconstructed: %v", err)
	}
}

func TestExtractorCovSynthesizeParentsCannotBeMade(t *testing.T) {
	// A parent that is missing and cannot be made is the extraction's
	// answer: nothing below it can be written.
	extractorCovSkipIfPrivileged(t)

	dst := t.TempDir()
	held := filepath.Join(dst, "held")
	mustMkdir(t, held)
	extractorCovChmod(t, held, 0o500)

	e := &Extractor{chroot: dst}
	if err := e.synthesizeParentDirs(filepath.Join(dst, "held", "sub", "entry.bin")); err == nil {
		t.Fatal("a parent that could not be made was reported as made")
	}
}

func TestExtractorCovSynthesizeParentsCannotBeExamined(t *testing.T) {
	// A parent the filesystem will not answer about at all is the answer
	// too: whether it is there and what it is are both unknown.
	extractorCovSkipIfPrivileged(t)

	dst := t.TempDir()
	closed := filepath.Join(dst, "closed")
	mustMkdir(t, closed)
	extractorCovChmod(t, closed, 0o000)

	e := &Extractor{chroot: dst}
	if err := e.synthesizeParentDirs(filepath.Join(dst, "closed", "sub", "entry.bin")); err == nil {
		t.Fatal("a parent that could not be examined was reported as reconstructed")
	}
}

// --- metadata that the destination will not take --------------------------

func TestExtractorCovOwnershipRefusedWithNoHandler(t *testing.T) {
	// An extraction built with no handler for a refused ownership carries on
	// without one: the file is extracted and the owner is whoever unpacked it.
	extractorCovSkipIfPrivileged(t)

	raw := extractorCovArchive(t, extractorCovEntry{
		name: "entry.bin", data: []byte("contents"), owner: true,
	})
	dst, err := extractorCovExtract(t, raw, WithExtractorChownErrorHandler(nil))
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	data, rerr := os.ReadFile(filepath.Join(dst, "entry.bin"))
	if rerr != nil {
		t.Fatalf("the entry was not extracted: %v", rerr)
	}
	if string(data) != "contents" {
		t.Errorf("entry.bin = %q, want %q", data, "contents")
	}
}

func TestExtractorCovOwnershipRefusedGoesToTheDefaultHandler(t *testing.T) {
	// With no handler named, the one the extractor is built with takes the
	// refusal and lets the extraction stand.
	extractorCovSkipIfPrivileged(t)

	raw := extractorCovArchive(t, extractorCovEntry{
		name: "entry.bin", data: []byte("contents"), owner: true,
	})
	dst, err := extractorCovExtract(t, raw)
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dst, "entry.bin")); serr != nil {
		t.Fatalf("the entry was not extracted: %v", serr)
	}
}

// --- the solid stream -----------------------------------------------------

// extractorCovInner is one entry of the archive inside a solid entry, written
// by hand so that a header can say what no writer would write.
type extractorCovInner struct {
	name    string
	flags   uint16
	method  uint16
	crc     uint32
	comp    uint32
	uncomp  uint32
	extra   []byte
	data    []byte
	trailer []byte
	// truncate cuts the assembled entry to this many bytes, for the headers
	// that stop in the middle.
	truncate int
}

func extractorCovInnerBytes(e extractorCovInner) []byte {
	h := make([]byte, 30)
	binary.LittleEndian.PutUint32(h[0:4], fileHeaderSignature)
	binary.LittleEndian.PutUint16(h[4:6], 20)
	binary.LittleEndian.PutUint16(h[6:8], e.flags)
	binary.LittleEndian.PutUint16(h[8:10], e.method)
	binary.LittleEndian.PutUint16(h[10:12], 0x6000)
	binary.LittleEndian.PutUint16(h[12:14], 0x5000)
	binary.LittleEndian.PutUint32(h[14:18], e.crc)
	binary.LittleEndian.PutUint32(h[18:22], e.comp)
	binary.LittleEndian.PutUint32(h[22:26], e.uncomp)
	// #nosec G115 -- every name in these fixtures is a handful of characters
	binary.LittleEndian.PutUint16(h[26:28], uint16(len(e.name)))
	// #nosec G115 -- every extra field in these fixtures is a handful of bytes
	binary.LittleEndian.PutUint16(h[28:30], uint16(len(e.extra)))

	out := append([]byte{}, h...)
	out = append(out, e.name...)
	out = append(out, e.extra...)
	out = append(out, e.data...)
	out = append(out, e.trailer...)
	if e.truncate > 0 && e.truncate < len(out) {
		out = out[:e.truncate]
	}
	return out
}

// extractorCovStored describes an inner entry whose header carries the sizes
// and the checksum of the bytes it holds, which is what a reader needs to
// salvage it from a local header.
func extractorCovStored(name string, data []byte) extractorCovInner {
	return extractorCovInner{
		name:   name,
		method: Store,
		crc:    crc32.ChecksumIEEE(data),
		// #nosec G115 -- every fixture here is a handful of bytes
		comp: uint32(len(data)),
		// #nosec G115 -- every fixture here is a handful of bytes
		uncomp: uint32(len(data)),
		data:   data,
	}
}

// extractorCovCentral is the four bytes that end the run of local headers,
// where a central directory would begin.
func extractorCovCentral() []byte {
	end := make([]byte, 4)
	binary.LittleEndian.PutUint32(end, directoryHeaderSignature)
	return end
}

// extractorCovSolid wraps body as the one entry of a solid archive.
func extractorCovSolid(t *testing.T, body []byte, badCRC bool) []byte {
	t.Helper()
	return extractorCovArchive(t, extractorCovEntry{
		name: "Solid.zip", data: body, badCRC: badCRC,
	})
}

// extractorCovInnerStream assembles the archive that lives inside a solid
// entry out of entries written by hand.
func extractorCovInnerStream(entries ...extractorCovInner) []byte {
	var body []byte
	for _, e := range entries {
		body = append(body, extractorCovInnerBytes(e)...)
	}
	return body
}

func TestExtractorCovSolidStopsAtTheEndOfTheStream(t *testing.T) {
	// A stream that simply runs out where an entry would begin has no more
	// entries, which is the same answer as a central directory there.
	body := extractorCovInnerStream(extractorCovStored("entry.bin", []byte("contents")))
	dst, err := extractorCovExtract(t, extractorCovSolid(t, body, false))
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	data, rerr := os.ReadFile(filepath.Join(dst, "entry.bin"))
	if rerr != nil {
		t.Fatalf("the inner entry was not extracted: %v", rerr)
	}
	if string(data) != "contents" {
		t.Errorf("entry.bin = %q, want %q", data, "contents")
	}
}

func TestExtractorCovSolidStopsOnAPartialSignature(t *testing.T) {
	// The same for a stream that stops in the middle of the four bytes an
	// entry begins with.
	body := extractorCovInnerStream(extractorCovStored("entry.bin", []byte("contents")))
	body = append(body, 0x50, 0x4b)
	if _, err := extractorCovExtract(t, extractorCovSolid(t, body, false)); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
}

func TestExtractorCovSolidUnreadableAtAnEntryBoundary(t *testing.T) {
	// The solid entry's own checksum is checked as its last bytes are read,
	// so an entry that does not match reports it where the pass asks for the
	// next inner entry.
	body := extractorCovInnerStream(extractorCovStored("entry.bin", []byte("contents")))
	_, err := extractorCovExtract(t, extractorCovSolid(t, body, true))
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("the extraction returned %v, want %v", err, ErrChecksum)
	}
}

func TestExtractorCovSolidHeaderTruncated(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry extractorCovInner
	}{
		{"the fixed part of the header", extractorCovInner{
			name: "entry.bin", method: Store, truncate: 12,
		}},
		{"the name", func() extractorCovInner {
			e := extractorCovStored("entry.bin", []byte("contents"))
			e.truncate = 33
			return e
		}()},
		{"the extra fields", func() extractorCovInner {
			e := extractorCovStored("entry.bin", []byte("contents"))
			e.extra = make([]byte, 16)
			e.truncate = 30 + len("entry.bin") + 4
			return e
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := extractorCovInnerStream(tc.entry)
			if _, err := extractorCovExtract(t, extractorCovSolid(t, body, false)); err == nil {
				t.Fatal("an entry whose header stops in the middle was read anyway")
			}
		})
	}
}

func TestExtractorCovSolidNameEscapesTheDestination(t *testing.T) {
	// An inner name is resolved against the destination like any other, so
	// one that resolves outside it is refused there.
	body := extractorCovInnerStream(extractorCovStored("../escape.txt", []byte("x")))
	body = append(body, extractorCovCentral()...)
	_, err := extractorCovExtract(t, extractorCovSolid(t, body, false))
	if !errors.Is(err, ErrInsecurePath) {
		t.Fatalf("the extraction returned %v, want %v", err, ErrInsecurePath)
	}
}

func TestExtractorCovSolidParentChainRunsThroughAFile(t *testing.T) {
	// A file the inner archive wrote a moment ago standing where a later
	// entry's parent belongs. The archive names one path as a file and as a
	// directory both, and this package promises nothing about which of the
	// two it ends up as: the entry that gets there first wins, and the other
	// one is what fails or is undone. So what is asserted here is what holds
	// in either order.
	if runtime.GOOS == "windows" {
		t.Skip("a name below a file reads as missing here rather than as a bad path")
	}
	body := extractorCovInnerStream(
		extractorCovStored("blocker", []byte("in the way")),
		extractorCovStored("blocker/sub/deep.txt", []byte("x")),
	)
	body = append(body, extractorCovCentral()...)
	dst, err := extractorCovExtract(t, extractorCovSolid(t, body, false))

	// Whatever the extraction answered, everything it left is something its
	// owner can walk into. A directory wearing an entry's file mode has no
	// search bit, and neither the caller nor this test's own temporary
	// directory could then be rid of it.
	if werr := filepath.WalkDir(dst, func(p string, d os.DirEntry, werr error) error {
		if werr != nil || !d.IsDir() {
			return werr
		}
		fi, serr := d.Info()
		if serr != nil {
			return serr
		}
		if fi.Mode().Perm()&0o100 == 0 {
			t.Errorf("%s is a directory with mode %v, which its owner cannot go into (Extract said %v)",
				p, fi.Mode().Perm(), err)
		}
		return nil
	}); werr != nil {
		t.Fatalf("walking what the extraction left: %v (Extract said %v)", werr, err)
	}

	blocker := filepath.Join(dst, "blocker")
	fi, serr := os.Lstat(blocker)
	switch {
	case err == nil:
		// The directory won and the file entry was undone: the entry
		// below the name has to be there, or nothing was gained by it.
		if serr != nil || !fi.IsDir() {
			t.Fatalf("the extraction reported success and %s is %v (%v)", blocker, fi, serr)
		}
		deep, rerr := os.ReadFile(filepath.Join(blocker, "sub", "deep.txt"))
		if rerr != nil || string(deep) != "x" {
			t.Fatalf("the extraction reported success and the entry below the name reads %q (%v)", deep, rerr)
		}
	case serr != nil:
		// The name was never made at all, which is a fine way to fail.
	case fi.IsDir():
		// The directory won and the file entry is what failed.
	default:
		// The file won and the entry below it is what failed.
		data, rerr := os.ReadFile(blocker)
		if rerr != nil || string(data) != "in the way" {
			t.Fatalf("the file entry won and %s holds %q (%v)", blocker, data, rerr)
		}
	}
}

func TestExtractorCovSolidStripsComponents(t *testing.T) {
	// Stripping applies to the inner names too: an entry with nothing left
	// after the strip is not written at all, and one with something left is
	// written under what is left.
	body := extractorCovInnerStream(
		extractorCovStored("skipped.txt", []byte("passed over")),
		extractorCovStored("dir/kept.txt", []byte("kept")),
	)
	body = append(body, extractorCovCentral()...)

	dst, err := extractorCovExtract(t, extractorCovSolid(t, body, false),
		WithExtractorStripComponents(1))
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	data, rerr := os.ReadFile(filepath.Join(dst, "kept.txt"))
	if rerr != nil {
		t.Fatalf("the entry that had a component to strip was not extracted: %v", rerr)
	}
	if string(data) != "kept" {
		t.Errorf("kept.txt = %q, want %q", data, "kept")
	}
	if _, serr := os.Lstat(filepath.Join(dst, "skipped.txt")); !os.IsNotExist(serr) {
		t.Errorf("the entry with nothing left after the strip was extracted anyway: %v", serr)
	}
}

func TestExtractorCovSolidSkippedEntryTruncated(t *testing.T) {
	// An entry that declares more bytes than the archive holds cannot be
	// read through to the end. The solid entry's own checksum is what the
	// attempt runs into here, since reading it reaches the end of the entry.
	e := extractorCovStored("skipped.txt", []byte("only some of it"))
	e.uncomp = 4096
	e.comp = 4096
	body := extractorCovInnerStream(e)
	_, err := extractorCovExtract(t, extractorCovSolid(t, body, true),
		WithExtractorStripComponents(1))
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("the extraction returned %v, want %v", err, ErrChecksum)
	}
}

func TestExtractorCovSolidExtraFieldTruncated(t *testing.T) {
	// An extra field that says it is longer than what is left of the field
	// area ends the reading of them; the entry itself is still extracted.
	e := extractorCovStored("entry.bin", []byte("contents"))
	e.extra = []byte{0x11, 0x78, 0x40, 0x00}
	body := extractorCovInnerStream(e)
	body = append(body, extractorCovCentral()...)

	dst, err := extractorCovExtract(t, extractorCovSolid(t, body, false))
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dst, "entry.bin")); serr != nil {
		t.Fatalf("the entry was not extracted: %v", serr)
	}
}

// extractorCovXattrExtra wraps the given field body in an extended attribute
// extra field.
func extractorCovXattrExtra(field []byte) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint16(out[0:2], xattrExtraID)
	// #nosec G115 -- every fixture here is a handful of bytes
	binary.LittleEndian.PutUint16(out[2:4], uint16(len(field)))
	return append(out, field...)
}

func TestExtractorCovSolidXattrs(t *testing.T) {
	pair := []byte{0x01, 0x00, 'a', 0x01, 0x00, 'b'}
	truncatedKey := []byte{0x10, 0x00, 'a', 'b', 'c', 'd'}
	truncatedValue := []byte{0x01, 0x00, 'a', 0x10, 0x00}

	for _, tc := range []struct {
		name  string
		field []byte
	}{
		{"a whole pair", pair},
		{"a key longer than the field", truncatedKey},
		{"a value longer than the field", truncatedValue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := extractorCovStored("entry.bin", []byte("contents"))
			e.extra = extractorCovXattrExtra(tc.field)
			body := extractorCovInnerStream(e)
			body = append(body, extractorCovCentral()...)

			dst, err := extractorCovExtract(t, extractorCovSolid(t, body, false))
			if err != nil {
				t.Fatalf("extraction failed: %v", err)
			}
			data, rerr := os.ReadFile(filepath.Join(dst, "entry.bin"))
			if rerr != nil {
				t.Fatalf("the entry was not extracted: %v", rerr)
			}
			if string(data) != "contents" {
				t.Errorf("entry.bin = %q, want %q", data, "contents")
			}
		})
	}
}

// extractorCovDescriptor returns the bytes that follow an entry whose sizes
// were deferred: a signature and the fields behind it.
func extractorCovDescriptor(signature uint32, fields int) []byte {
	out := make([]byte, 4+fields)
	binary.LittleEndian.PutUint32(out[0:4], signature)
	return out
}

func TestExtractorCovSolidDescriptorTruncated(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trailer []byte
	}{
		{"no descriptor at all", nil},
		{"a signature and nothing behind it", extractorCovDescriptor(dataDescriptorSignature, 2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := extractorCovStored("entry.bin", []byte("data"))
			e.flags = 0x8
			e.crc = 0
			e.trailer = tc.trailer
			body := extractorCovInnerStream(e)
			if _, err := extractorCovExtract(t, extractorCovSolid(t, body, false)); err == nil {
				t.Fatal("an entry whose descriptor is not there was read anyway")
			}
		})
	}
}

func TestExtractorCovSolidStopsOnCancellation(t *testing.T) {
	// The extraction asks whether it is still wanted before every entry it
	// writes, and the fallback that copies a solid entry out asks the same
	// before every block it copies.
	body := extractorCovInnerStream(extractorCovStored("entry.bin", []byte("contents")))
	body = append(body, extractorCovCentral()...)
	raw := extractorCovSolid(t, body, false)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dst := filepath.Join(t.TempDir(), "dst")
	e, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), dst)
	if err != nil {
		t.Fatalf("building the extractor: %v", err)
	}
	closeAt(t, e)
	if err := e.Extract(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("the extraction returned %v, want the cancellation", err)
	}
}

// --- a directory the destination will not take ----------------------------

func TestExtractorCovDirectoryEntryCannotBeCreated(t *testing.T) {
	// The parent is already there and is not writable, so the directory the
	// entry names cannot be made. Reporting it is the point: everything the
	// archive puts under that name would otherwise go missing quietly.
	extractorCovSkipIfPrivileged(t)

	raw := extractorCovArchive(t, extractorCovEntry{name: "held/sub/", mode: fs.ModeDir | 0755})
	dst := filepath.Join(t.TempDir(), "dst")
	held := filepath.Join(dst, "held")
	mustMkdirAll(t, held)
	extractorCovChmod(t, held, 0o500)

	if err := extractorCovExtractInto(t, raw, dst); err == nil {
		t.Fatal("a directory that could not be created was reported as extracted")
	}
}

// --- a destination that is not in its cleaned form -------------------------

// An entry's path is the destination joined with the entry's name, and joining
// cleans: a destination carrying a ".." of its own therefore resolves entries
// somewhere other than under itself. NewExtractorFromReader resolves the
// destination before it stores it, so the guard that stands between the joined
// path and the destination is reached by pointing an extractor at the
// unresolved form directly. The guard is written to hold for whatever the
// destination is rather than only for the form the constructor produces, and
// this is what it holds against.
func extractorCovOverDestination(t *testing.T, raw []byte, chroot string) error {
	t.Helper()
	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("reading the archive: %v", err)
	}
	e := &Extractor{chroot: chroot, zr: zr}
	e.options.concurrency = 1
	return e.Extract(context.Background())
}

// extractorCovUnclean names dir in a form filepath.Join will resolve away.
func extractorCovUnclean(dir string) string {
	return filepath.Join(dir, "sub") + string(filepath.Separator) + ".."
}

func TestExtractorCovEntryResolvesOutsideTheDestination(t *testing.T) {
	raw := extractorCovArchive(t, extractorCovEntry{name: "entry.bin", data: []byte("contents")})
	base := t.TempDir()

	err := extractorCovOverDestination(t, raw, extractorCovUnclean(base))
	if err == nil || !strings.Contains(err.Error(), "outside of chroot") {
		t.Fatalf("the extraction returned %v, want a refusal to write outside the destination", err)
	}
	if _, serr := os.Lstat(filepath.Join(base, "entry.bin")); !os.IsNotExist(serr) {
		t.Errorf("the entry was written outside the destination anyway: %v", serr)
	}
}

// errExtractorCovNoRoomLeft stands in for what a filesystem with nothing left
// reports when a directory is asked for.
var errExtractorCovNoRoomLeft = errors.New("no space left on device")

// TestExtractorCovSynthesizeParentsCannotReplaceABlockingFile covers the arm
// where the file standing in the way of a parent is taken away and the
// directory that should replace it cannot be made. Only a filesystem with no
// room left, or something putting a name back in the moment between the two
// calls, produces that, so the directory call is taken over here.
func TestExtractorCovSynthesizeParentsCannotReplaceABlockingFile(t *testing.T) {
	dst := t.TempDir()
	blocker := filepath.Join(dst, "blocker")
	mustWriteFile(t, blocker, []byte("in the way"), 0o600)

	real := mkdir
	t.Cleanup(func() { mkdir = real })
	mkdir = func(name string, perm os.FileMode) error {
		if strings.HasSuffix(name, "blocker") {
			return errExtractorCovNoRoomLeft
		}
		return real(name, perm)
	}

	e := &Extractor{chroot: dst}
	err := e.synthesizeParentDirs(filepath.Join(dst, "blocker", "sub", "entry.bin"))
	if !errors.Is(err, errExtractorCovNoRoomLeft) {
		t.Fatalf("reconstructing the parents gave %v, want the refusal from the filesystem", err)
	}
	if _, serr := os.Lstat(blocker); !os.IsNotExist(serr) {
		t.Errorf("the file in the way is still there: %v", serr)
	}
}
