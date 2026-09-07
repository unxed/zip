package zip

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
)

type ExtractorOption func(*extractorOptions) error

type extractorOptions struct {
	concurrency           int
	chownErrorHandler     func(name string, err error) error
	maxFileSize           int64
	maxDecompressionRatio int64
	xattrs                bool
	keepBroken            bool
	keepOldFiles          bool
	keepNewerFiles        bool
	noTimes               bool
	stripComponents       int
	sparse                bool
	safeWrites            bool
	unlinkFirst           bool
	numericOwner          bool
	incremental           bool
	tolerant              bool
	password              string
}

// WithExtractorPassword sets the password for WinZip AES and CDE decryption.
func WithExtractorPassword(password string) ExtractorOption {
	return func(o *extractorOptions) error {
		o.password = password
		return nil
	}
}

// WithExtractorSafeWrites extracts files atomically by writing to a temporary file and renaming (--safe-writes).
func WithExtractorSafeWrites(b bool) ExtractorOption {
	return func(o *extractorOptions) error {
		o.safeWrites = b
		return nil
	}
}

// WithExtractorUnlinkFirst removes existing files prior to extracting over them (-U, --unlink-first).
func WithExtractorUnlinkFirst(b bool) ExtractorOption {
	return func(o *extractorOptions) error {
		o.unlinkFirst = b
		return nil
	}
}

// WithExtractorKeepOldFiles prevents overwriting existing files (-k or --keep-old-files)
func WithExtractorKeepOldFiles(keep bool) ExtractorOption {
	return func(o *extractorOptions) error {
		o.keepOldFiles = keep
		return nil
	}
}

// WithExtractorKeepNewerFiles prevents overwriting files that are newer on disk (--keep-newer-files)
func WithExtractorKeepNewerFiles(keep bool) ExtractorOption {
	return func(o *extractorOptions) error {
		o.keepNewerFiles = keep
		return nil
	}
}

// WithExtractorNoTimes prevents restoring original modification times (-m / --touch)
func WithExtractorNoTimes(noTimes bool) ExtractorOption {
	return func(o *extractorOptions) error {
		o.noTimes = noTimes
		return nil
	}
}

// WithExtractorStripComponents strips the specified number of leading components from file names on extraction (--strip-components)
func WithExtractorStripComponents(count int) ExtractorOption {
	return func(o *extractorOptions) error {
		o.stripComponents = count
		return nil
	}
}

func stripComponents(name string, count int) (string, bool) {
	cleaned := filepath.ToSlash(filepath.Clean(name))
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "." || cleaned == "" {
		return "", false
	}
	parts := strings.Split(cleaned, "/")
	if len(parts) <= count {
		return "", false
	}
	return strings.Join(parts[count:], "/"), true
}

// strippedName is the name an entry is extracted under: the one the archive
// carries, with as many leading components taken off it as the caller asked
// for. It reports false for an entry that has no more components than that,
// which is an entry the extraction does not write at all.
//
// An extraction goes over the archive more than once -- the files and
// directories first, then the links, the directories' metadata and the
// alternate data streams -- and every pass has to arrive at the same name for
// an entry. The passes after the first used to take the archive's name as it
// stood, so with --strip-components a link was made under the name the entry
// carried rather than the one its target had been written under, and a
// directory's metadata was applied to a name nothing had created, which failed
// the extraction of any archive that had a directory entry in it.
func (e *Extractor) strippedName(name string) (string, bool) {
	if e.options.stripComponents <= 0 {
		return name, true
	}
	return stripComponents(name, e.options.stripComponents)
}

// WithExtractorSparse enables extracting files as sparse files by seeking over zero-blocks (-S, --sparse).
func WithExtractorSparse(b bool) ExtractorOption {
	return func(o *extractorOptions) error {
		o.sparse = b
		return nil
	}
}

var sparseBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 1024*1024)
		return &b
	},
}

func getSparseBuf() []byte {
	return *(sparseBufPool.Get().(*[]byte))
}

func putSparseBuf(b []byte) {
	sparseBufPool.Put(&b)
}

func isAllZeros(p []byte) bool {
	if len(p) == 0 {
		return true
	}
	if p[0] != 0 {
		return false
	}
	// Highly optimized SIMD-comparison via standard Go runtime bytealg
	return len(p) == 1 || p[0] == p[1] && bytes.Equal(p[:len(p)-1], p[1:])
}

func copySparseZip(dst *os.File, src io.Reader, bw *budgetWriter, ctx context.Context) error {
	buf := getSparseBuf()
	defer putSparseBuf(buf)

	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := src.Read(buf)
		if n > 0 {
			if isAllZeros(buf[:n]) {
				// A hole is as much a part of the file as the bytes
				// around it, so it is accounted for like them even
				// though nothing is written.
				if cErr := bw.skip(int64(n)); cErr != nil {
					return cErr
				}
				_, seekErr := dst.Seek(int64(n), io.SeekCurrent)
				if seekErr != nil {
					return seekErr
				}
			} else {
				_, wErr := bw.Write(buf[:n])
				if wErr != nil {
					return wErr
				}
			}
			total += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	// The length of the file is what came out of the entry, not what its
	// header said would: a hole at the end is only a hole up to there.
	return dst.Truncate(total)
}

// WithExtractorXattrs enables restoration of extended attributes (xattrs, POSIX ACLs, SELinux).
func WithExtractorXattrs(b bool) ExtractorOption {
	return func(o *extractorOptions) error {
		o.xattrs = b
		return nil
	}
}
func WithExtractorKeepBroken(b bool) ExtractorOption {
	return func(o *extractorOptions) error {
		o.keepBroken = b
		return nil
	}
}

func WithExtractorConcurrency(n int) ExtractorOption {
	return func(o *extractorOptions) error {
		if n <= 0 {
			return ErrMinConcurrency
		}
		o.concurrency = n
		return nil
	}
}

func WithExtractorChownErrorHandler(fn func(name string, err error) error) ExtractorOption {
	return func(o *extractorOptions) error {
		o.chownErrorHandler = fn
		return nil
	}
}

// WithExtractorNumericOwner always uses numeric user/group IDs from the archive rather than resolving Uname/Gname (--numeric-owner).
func WithExtractorNumericOwner(b bool) ExtractorOption {
	return func(o *extractorOptions) error {
		o.numericOwner = b
		return nil
	}
}

// WithExtractorIncremental enables processing of .zip_dumpdir headers to remove deleted files during incremental restores.
func WithExtractorIncremental(b bool) ExtractorOption {
	return func(o *extractorOptions) error {
		o.incremental = b
		return nil
	}
}

// WithExtractorTolerant allows extraction to continue even if some files are corrupted.
func WithExtractorTolerant(b bool) ExtractorOption {
	return func(o *extractorOptions) error {
		o.tolerant = b
		return nil
	}
}

// WithExtractorMaxFileSize sets how many bytes any one extracted file may be
// written. Zero turns the size limit off and leaves the ratio limit to work on
// its own; a negative limit is not a limit at all and is refused here rather
// than turning into one somewhere further in. A file that would be written
// past the limit fails with an error wrapping [ErrSizeLimit].
func WithExtractorMaxFileSize(n int64) ExtractorOption {
	return func(o *extractorOptions) error {
		if n < 0 {
			return fmt.Errorf("zip: maximum file size %d is negative", n)
		}
		o.maxFileSize = n
		return nil
	}
}

// WithExtractorMaxRatio sets how many bytes an entry may be written for each
// byte it takes up in the archive. Zero turns the ratio limit off; a negative
// ratio is refused. An entry that expands past the ratio fails with an error
// wrapping [ErrRatioLimit].
func WithExtractorMaxRatio(n int64) ExtractorOption {
	return func(o *extractorOptions) error {
		if n < 0 {
			return fmt.Errorf("zip: maximum decompression ratio %d is negative", n)
		}
		o.maxDecompressionRatio = n
		return nil
	}
}

// An extraction refuses to write more than its caller allowed it to: one file
// larger than the size limit, or an entry that expands out of all proportion
// to the room it takes up in the archive. Both are returned wrapped, so
// errors.Is finds them behind the name of the file that ran into them.
var (
	ErrSizeLimit  = errors.New("zip: extracted size exceeds limit")
	ErrRatioLimit = errors.New("zip: decompression ratio exceeds limit")
)

// maxSolidDepth is how far a solid archive may nest: the entry the archive
// holds, and one solid archive inside that.
//
// errSolidNesting is what is past it. Such an archive is well formed -- it is
// more than this extractor unpacks, not something a reader could not make
// sense of -- so it is neither ErrFormat nor one of the two limits above, and
// it has no exported spelling until a caller needs to tell it apart.
const maxSolidDepth = 2

var errSolidNesting = errors.New("zip: solid archive nested too deep")

// extractBudget is where an extraction accounts for what it writes. Every
// destination file goes through a writer taken from it -- the ordinary copy,
// the sparse copy, each inner file of a solid archive, and the temp copy the
// solid fallback makes -- so nothing reaches the disk uncounted, and the
// counting is in one place rather than in every path that happens to write.
type extractBudget struct {
	maxFileSize int64  // per destination file; zero means no size limit
	maxRatio    uint64 // per archive entry; zero means no ratio limit
	written     *int64 // the extraction's own total, read while it runs
}

func newExtractBudget(o *extractorOptions, written *int64) *extractBudget {
	return &extractBudget{
		maxFileSize: o.maxFileSize,
		// #nosec G115 -- WithExtractorMaxRatio refuses a negative ratio
		maxRatio: uint64(o.maxDecompressionRatio),
		written:  written,
	}
}

// fallbackTooLarge says whether a solid entry is too big to copy to a temp
// file before extracting it, at ten times the per-file limit on what the entry
// says it holds. Divided rather than multiplied: ten times a large limit
// overflowed into a negative number and from there into a 100 GB ceiling
// nobody asked for.
func (b *extractBudget) fallbackTooLarge(declared uint64) bool {
	return b.maxFileSize > 0 && declared/10 > uint64(b.maxFileSize)
}

// The solid fallback's scratch file is made and unmade through these four
// names. Whether a removal failed because something outside this process still
// holds the file is a property of the machine rather than of the archive -- on
// Windows a scanner opening what was just written is ordinary -- and a
// destination that will not take a file at all is a property of the
// filesystem, so both are driven through here from either platform.
var (
	scratchCreate        = os.CreateTemp
	scratchRemove        = os.Remove
	scratchSleep         = time.Sleep
	scratchHeldElsewhere = removeHeldElsewhere
)

const (
	scratchRemoveTries = 10
	scratchRemoveDelay = 100 * time.Millisecond
)

// removeScratch removes name, giving a holder outside this process the moment
// it needs to let go. Everything the extraction itself had open on the file is
// closed before the first attempt, so a refusal here comes from elsewhere and
// is usually over within a moment -- the same reason testing's own temp
// directory cleanup waits rather than failing on the first answer.
//
// The wait is for holders outside the process and for nothing else. A handle
// this package leaked would be let go of by a finalizer somewhere inside the
// same second and the removal would then succeed, which is why the tests count
// the attempts on the path that is meant to work: a retry there is the leak
// showing itself, not the wait doing its job.
func removeScratch(name string) error {
	err := scratchRemove(name)
	for tries := 1; err != nil && tries < scratchRemoveTries && scratchHeldElsewhere(err); tries++ {
		scratchSleep(scratchRemoveDelay)
		err = scratchRemove(name)
	}
	return err
}

// entryBudget accounts for one archive entry. The ratio is measured against
// this entry's compressed size, which is what the archive spends on it, and on
// the solid path every inner file the entry unpacks into counts towards the
// same entry: the ratio there is what the whole solid stream expands to.
type entryBudget struct {
	b          *extractBudget
	name       string
	compressed uint64
	ratio      uint64 // zero means no ratio applies to this entry
	written    int64  // over every destination file of this entry
}

func (b *extractBudget) entry(f *File) *entryBudget {
	return &entryBudget{b: b, name: f.Name, compressed: f.CompressedSize64, ratio: b.maxRatio}
}

// duplicate is a budget for a file the extraction copies from a file it has
// already written -- the bottom rung of the Windows link ladder, which puts
// the target's bytes in a file of their own when neither kind of link can be
// made. The bytes are a destination file's and count like any other, but
// nothing was decompressed to produce them and there is no compressed size
// behind them, so no ratio applies.
func (b *extractBudget) duplicate(name string) *entryBudget {
	return &entryBudget{b: b, name: name}
}

// checkHeader refuses an entry on what its header claims, before anything is
// opened. It is an early rejection and not the limit itself -- the header is
// the archive's word about bytes it has not produced yet -- so what is
// actually written is counted as it is written, wherever it is written.
func (e *entryBudget) checkHeader(uncompressed uint64) error {
	if e.b.maxFileSize > 0 && uncompressed > uint64(e.b.maxFileSize) {
		return fmt.Errorf("zip: file %q size %d exceeds limit %d: %w", e.name, uncompressed, e.b.maxFileSize, ErrSizeLimit)
	}
	// Divided, never multiplied: the product of a limit and a compressed
	// size the archive chose overflows, and a negative product is a limit
	// that lets everything through -- which is what a declared size above
	// MaxInt64 used to be measured against. The remainder is what keeps the
	// division exact: a quotient equal to the limit with anything left over
	// is more bytes per byte than the limit allows, and dropping it would
	// let every entry have one whole ratio more than it was given.
	if e.ratio > 0 && e.compressed > 0 {
		q, rem := uncompressed/e.compressed, uncompressed%e.compressed
		if q > e.ratio || (q == e.ratio && rem != 0) {
			return fmt.Errorf("zip: file %q suspicious compression ratio %d:1: %w", e.name, q, ErrRatioLimit)
		}
	}
	return nil
}

// preallocSize is how much of a declared size is worth reserving on disk. The
// declaration is the archive's own, so it is trusted only as far as a check
// has bounded it: the size limit bounds it directly, and with no size limit
// the ratio check bounds it against the compressed size -- when there is a
// ratio to check it against, since with both limits off the caller has asked
// for nothing to be bounded. An entry that declares no compressed bytes has
// been through neither check, there being nothing to divide by, and gets
// nothing reserved for it.
func (e *entryBudget) preallocSize(declared uint64) int64 {
	if e.b.maxFileSize > 0 {
		// #nosec G115 -- maxFileSize is positive here, so the minimum of the two is at most an int64 the caller supplied
		return int64(min(declared, uint64(e.b.maxFileSize)))
	}
	if e.compressed == 0 {
		return 0
	}
	// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose declared size is above MaxInt64
	return int64(declared)
}

// file returns the writer one destination file of this entry is written
// through.
func (e *entryBudget) file(w io.Writer) *budgetWriter {
	return &budgetWriter{e: e, w: w, limit: e.b.maxFileSize, total: e.b.written}
}

// scratch returns the writer for a file the extraction makes for itself rather
// than one the archive asked for: the copy the solid fallback takes of an
// entry before handing it to a second extractor. The size limit is a limit on
// an extracted file and this is not one -- the fallback's own ceiling allows
// an entry ten times that size, and refusing the copy at the size limit would
// refuse what the ceiling had just let through -- so what bounds it is the
// entry's ratio, on the bytes as they are copied. For the same reason its
// bytes are not the extraction's output and are counted nowhere the caller can
// read: what came out of the archive is what the second extractor writes.
func (e *entryBudget) scratch(w io.Writer) *budgetWriter {
	return &budgetWriter{e: e, w: w, total: new(int64)}
}

// charge accounts for bytes that are about to become part of a file, and says
// whether the extraction is still allowed to produce them.
func (e *entryBudget) charge(n int64) error {
	e.written += n
	if e.ratio == 0 || e.written == 0 {
		return nil
	}
	// Divided, never multiplied, and exactly: the product of a limit and a
	// compressed size the archive chose overflows, and a negative product
	// is a limit that lets everything through, while a quotient on its own
	// would allow a whole ratio more than the limit says. The section
	// reader stops at the compressed size, so measuring against it can only
	// understate the ratio of what was really consumed.
	if e.compressed > 0 {
		// #nosec G115 -- written counts the bytes this entry produced and only ever grows from zero
		q, rem := uint64(e.written)/e.compressed, uint64(e.written)%e.compressed
		if q < e.ratio || (q == e.ratio && rem == 0) {
			return nil
		}
	}
	// Nothing compressed cannot honestly produce a byte, so output from an
	// entry that declares none is a header that lies about one side or the
	// other.
	return fmt.Errorf("zip: file %q expands %d compressed bytes into %d: %w", e.name, e.compressed, e.written, ErrRatioLimit)
}

// budgetWriter is one destination file, and the only way bytes get into one.
type budgetWriter struct {
	e     *entryBudget
	w     io.Writer
	limit int64  // what this one file may take; zero means only the ratio bounds it
	total *int64 // where these bytes are counted, atomically
	n     int64  // bytes accounted for in this file
}

func (w *budgetWriter) Write(p []byte) (int, error) {
	if err := w.charge(int64(len(p))); err != nil {
		return 0, err
	}
	n, err := w.w.Write(p)
	atomic.AddInt64(w.total, int64(n))
	return n, err
}

// skip accounts for bytes that become part of the file without being written
// to it: a hole the sparse copy seeks over is as much a part of the file as
// the bytes around it, and counts the same in every total.
func (w *budgetWriter) skip(n int64) error {
	if err := w.charge(n); err != nil {
		return err
	}
	atomic.AddInt64(w.total, n)
	return nil
}

// charge accounts for bytes of this file, whether they are written or seeked
// over, and refuses them before they reach the disk rather than after.
func (w *budgetWriter) charge(n int64) error {
	if w.limit > 0 && w.n+n > w.limit {
		return fmt.Errorf("zip: file %q writes past the limit of %d bytes: %w", w.e.name, w.limit, ErrSizeLimit)
	}
	w.n += n
	return w.e.charge(n)
}

type Extractor struct {
	written, entries int64
	zr               *Reader
	closer           io.Closer
	m                sync.Mutex
	options          extractorOptions
	chroot           string
	dirCache         sync.Map
	// solidDepth is how many solid archives have been opened on the way to
	// this one. It is not a caller's choice, so it is not an option: the
	// extraction sets it on the extractor it builds for a solid entry's
	// contents.
	solidDepth int
}

// extractPasswordFromOpts reads the password out of the options before the
// archive is opened, because opening it needs the password. The options are
// applied again in newExtractor, which is where one the validator rejects
// stops the call; each option writes its own field, so what is wanted here is
// set whether or not another one is going to be refused.
func extractPasswordFromOpts(opts []ExtractorOption) string {
	var o extractorOptions
	for _, opt := range opts {
		_ = opt(&o)
	}
	return o.password
}

func NewExtractor(filename, chroot string, opts ...ExtractorOption) (*Extractor, error) {
	password := extractPasswordFromOpts(opts)
	zr, err := OpenReaderWithPassword(filename, password)
	if err != nil {
		return nil, err
	}
	e, err := newExtractor(&zr.Reader, zr, chroot, opts)
	if err != nil {
		// An option the caller got wrong is still an archive that was
		// opened, and the handle is the caller's only through the
		// extractor it is not getting. Nothing was written through it,
		// so what closing it says is not the answer to this call.
		_ = zr.Close()
		return nil, err
	}
	return e, nil
}

func NewExtractorFromReader(r io.ReaderAt, size int64, chroot string, opts ...ExtractorOption) (*Extractor, error) {
	password := extractPasswordFromOpts(opts)
	zr, err := NewReaderWithPassword(r, size, password)
	if err != nil {
		return nil, err
	}
	return newExtractor(zr, nil, chroot, opts)
}

func newExtractor(r *Reader, c io.Closer, chroot string, opts []ExtractorOption) (*Extractor, error) {
	var err error
	if chroot, err = filepath.Abs(chroot); err != nil {
		return nil, err
	}

	e := &Extractor{
		chroot: chroot,
		zr:     r,
		closer: c,
	}

	e.options.concurrency = runtime.GOMAXPROCS(0)
	e.options.maxFileSize = 1024 * 1024 * 1024 // 1GB default
	e.options.maxDecompressionRatio = 4000     // 4000:1 default (to prevent false positives on zero-filled files)
	e.options.xattrs = true
	e.options.chownErrorHandler = func(name string, err error) error {
		if pe, ok := err.(*os.PathError); ok {
			if errno, ok := pe.Err.(syscall.Errno); ok && errno == syscall.EPERM {
				return nil
			}
		}
		fmt.Fprintf(os.Stderr, "zip: %s: %v (continuing)\n", name, err)
		return nil
	}

	for _, o := range opts {
		if err := o(&e.options); err != nil {
			return nil, err
		}
	}
	if e.options.password != "" && e.zr != nil {
		e.zr.SetPassword(e.options.password)
	}
	return e, nil
}

func (e *Extractor) Files() []*File {
	return e.zr.File
}

func (e *Extractor) Close() error {
	if e.closer == nil {
		return nil
	}
	return e.closer.Close()
}

func (e *Extractor) Written() (bytes, entries int64) {
	return atomic.LoadInt64(&e.written), atomic.LoadInt64(&e.entries)
}

func (e *Extractor) Extract(ctx context.Context) (err error) {
	parentCtx := ctx
	if e.options.incremental {
		dumpdirPath := filepath.Join(e.chroot, ".zip_dumpdir")
		if _, err := os.Stat(dumpdirPath); os.IsNotExist(err) {
			f, err := os.Open(e.chroot)
			if err == nil {
				names, err := f.Readdirnames(1)
				// A directory that was only listed; the listing is
				// already in hand.
				_ = f.Close()
				if err == nil && len(names) > 0 {
					return errors.New("zip: refusing to extract incremental archive into a non-empty directory without a pre-existing .zip_dumpdir marker (prevents accidental data loss)")
				}
			}
		}
	}

	// One budget for the whole extraction, and every path that writes takes
	// its destination files from it.
	budget := newExtractBudget(&e.options, &e.written)

	if len(e.zr.File) == 1 && (e.zr.File[0].Name == "Solid.zip" || strings.HasSuffix(e.zr.File[0].Name, ".solid")) {
		if serr := e.extractSolid(ctx, budget); serr != nil {
			return serr
		}
	} else {
		type extractTask struct {
			file        *File
			path        string
			isIrregular bool
		}

		// Where every entry goes, resolved once by the pass below and read
		// by the three passes after it, so that they act on the name the
		// extraction wrote rather than resolving the archive's own name a
		// second time. An empty path is an entry the extraction does not
		// write: one --strip-components leaves nothing of.
		paths := make([]string, len(e.zr.File))

		taskCh := make(chan extractTask, e.options.concurrency)

		wg, ctx := errgroup.WithContext(ctx)
		defer func() {
			if werr := wg.Wait(); werr != nil {
				err = werr
			}
		}()

		for i := 0; i < e.options.concurrency; i++ {
			wg.Go(func() error {
				for task := range taskCh {
					if ctx.Err() != nil {
						continue
					}
					var err error
					if task.isIrregular {
						err = extractSpecialFile(task.path, &task.file.FileHeader)
						if err == nil {
							err = e.updateFileMetadata(task.path, task.file)
						}
					} else {
						err = e.createFile(ctx, task.path, task.file, budget)
						if err == nil {
							err = e.updateFileMetadata(task.path, task.file)
						}
					}
					if err != nil {
						if e.options.tolerant {
							fmt.Printf("zip: skipping corrupted file %q: %v\n", task.file.Name, err)
						} else {
							return err
						}
					}
				}
				return nil
			})
		}

		err = func() error {
			defer close(taskCh)
			for i, file := range e.zr.File {
				name, ok := e.strippedName(file.Name)
				if !ok {
					continue // Skip file with fewer or equal components
				}

				path, err := e.absPath(name)
				if err != nil {
					return err
				}
				paths[i] = path

				prefix := e.chroot
				if !strings.HasSuffix(prefix, string(filepath.Separator)) {
					prefix += string(filepath.Separator)
				}
				if !strings.HasPrefix(path, prefix) && path != e.chroot {
					return fmt.Errorf("%s cannot be extracted outside of chroot (%s)", path, e.chroot)
				}

				if err := e.linksToDirs(path); err != nil {
					return err
				}

				// Synthesize and guarantee parent directories structures
				if err := e.synthesizeParentDirs(path); err != nil {
					return err
				}

				if ctx.Err() != nil {
					return ctx.Err()
				}

				// Overwrite control policies
				if file.Mode()&os.ModeDir == 0 && file.Mode()&os.ModeSymlink == 0 && file.Linkname == "" {
					if e.options.unlinkFirst {
						// The point of unlinkFirst is that nothing
						// of the old name survives to be written
						// into -- a file the caller asked to have
						// removed and that is still there is a
						// symlink or a read-only file the write
						// would otherwise follow or overwrite.
						// RemoveAll is quiet about a name that was
						// not there, and safer than Remove against
						// a directory swapped in mid-extraction.
						if rerr := os.RemoveAll(fixOSPath(path)); rerr != nil {
							return rerr
						}
					}
					if e.options.keepOldFiles {
						if _, err := os.Stat(fixOSPath(path)); err == nil {
							continue // Skip extracting, file already exists
						}
					}
					if e.options.keepNewerFiles {
						if fi, err := os.Stat(fixOSPath(path)); err == nil {
							if fi.ModTime().After(file.Modified) {
								continue // Skip extracting, disk file is newer
							}
						}
					}
				}

				switch {
				case file.Mode()&os.ModeSymlink != 0 || file.Linkname != "" || strings.Contains(file.Name, ":"):
					continue

				case file.Mode().IsDir():
					err = e.createDirectory(path, file)

				case file.Mode()&irregularModes != 0:
					select {
					case taskCh <- extractTask{file: e.zr.File[i], path: path, isIrregular: true}:
					case <-ctx.Done():
						return ctx.Err()
					}

				default:
					select {
					case taskCh <- extractTask{file: e.zr.File[i], path: path, isIrregular: false}:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				if err != nil && !e.options.tolerant {
					return err
				}
			}
			return nil
		}()

		waitErr := wg.Wait()
		if err != nil {
			return err
		}
		if waitErr != nil {
			return waitErr
		}

		for i, file := range e.zr.File {
			if file.Mode()&os.ModeSymlink == 0 && file.Linkname == "" {
				continue
			}
			path := paths[i]
			if path == "" {
				continue
			}
			if err := e.createLink(path, file, budget); err != nil {
				return err
			}
		}

		for i, file := range e.zr.File {
			if !file.Mode().IsDir() {
				continue
			}
			path := paths[i]
			if path == "" {
				continue
			}
			if err := e.updateFileMetadata(path, file); err != nil {
				if e.options.tolerant {
					continue
				}
				return err
			}
		}

		for i, file := range e.zr.File {
			if !strings.Contains(file.Name, ":") {
				continue
			}
			path := paths[i]
			if path == "" {
				continue
			}
			if err := e.createFile(parentCtx, path, file, budget); err != nil {
				return err
			}
			if err := e.updateFileMetadata(path, file); err != nil {
				return err
			}
		}
	}

	if e.options.incremental {
		dumpdirPath := filepath.Join(e.chroot, ".zip_dumpdir")
		if f, err := os.Open(dumpdirPath); err == nil {
			// The listing is only read; nothing is written through
			// this handle.
			defer func() { _ = f.Close() }()
			scanner := bufio.NewScanner(f)
			activeFiles := make(map[string]bool)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					// The listing is written from the source tree, so a
					// line in it is the archive's own bytes, while what is
					// on disk went to disk through the platform's spelling.
					// Comparing the two as they stand finds no match for an
					// undecodable name, and the sweep below then takes the
					// file that was extracted a moment earlier.
					activeFiles[osRawBytes([]byte(line))] = true
				}
			}
			activeFiles[".zip_dumpdir"] = true

			// Removing a directory pulls the ground out from under the
			// walk's own descent into it: the walk asks again with the error
			// that follows, and handing that back ends the walk, so one stale
			// directory left everything sorting after it in place. SkipDir
			// says there is nothing down there to visit, which is true --
			// it has just been taken away -- and the walk carries on.
			//
			// Whatever the walk does answer is the extraction's answer now.
			// It was thrown away before, so a destination that could not be
			// read was a silent no-op rather than a failure.
			// The walk names a path and the removal below acts on it
			// a moment later; in between, a directory on the way to it
			// can be replaced by a symlink pointing anywhere, and a
			// removal that followed one would delete outside the
			// destination. A root resolves every component against the
			// destination itself and refuses to leave it.
			root, rerr := openRoot(e.chroot)
			if rerr != nil {
				return rerr
			}
			defer func() { _ = root.Close() }()

			if werr := filepath.WalkDir(e.chroot, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if path == e.chroot {
					return nil
				}
				// WalkDir hands back paths under the root it was given, so
				// the root is a prefix of every one of them and what is left
				// after it is the name the listing would carry.
				rel := strings.TrimPrefix(path[len(e.chroot):], string(filepath.Separator))
				relClean := filepath.ToSlash(rel)
				if d.IsDir() {
					relClean += "/"
				}
				if !activeFiles[relClean] {
					if rerr := root.RemoveAll(rel); rerr != nil {
						return rerr
					}
					if d.IsDir() {
						return fs.SkipDir
					}
				}
				return nil
			}); werr != nil {
				return werr
			}
		}
	}

	return nil
}

// extractSolid unpacks the single entry a solid archive holds, which is a
// whole archive of its own. The entry is opened as an archive and handed to a
// second extractor, so what lands on disk is what that archive's central
// directory lists and every check this extraction makes applies to the inner
// entries as well.
//
// Walking the inner local headers as they arrived would be cheaper, and it is
// what this used to do, but a local header is not a listing: the directory
// sits at the end of the stream, so an entry that no listing shows -- not this
// package's Reader, not Extractor.Files, not any other tool -- had already
// been written by the time the directory could be read. Nothing an extraction
// writes may be invisible to whoever inspects the archive first.
func (e *Extractor) extractSolid(ctx context.Context, budget *extractBudget) error {
	outer := e.zr.File[0]

	// A solid archive inside a solid archive is unpacked one level at a
	// time, and each level is a whole archive to verify and to read, so the
	// work grows with the square of the size of the outermost one and every
	// level holds a reader and an extractor open. The archiver never writes
	// a solid archive inside a solid archive, so one level of nesting is
	// generosity rather than a requirement and anything past it is either a
	// mistake or an amplifier. This is where it stops, before anything of
	// this level has been read or written.
	depth := e.solidDepth + 1
	if depth > maxSolidDepth {
		return fmt.Errorf("zip: solid archive nested %d deep, past the %d this extractor unpacks: %w",
			depth, maxSolidDepth, errSolidNesting)
	}

	// A stored entry that is not encrypted is the inner archive's bytes
	// exactly as they lie in the file the reader already has open, so it is
	// read where it is rather than copied first. The length is the shorter
	// of what the entry says it stores and what it says it holds; for a
	// stored entry any writer produces, the two are the same number.
	if outer.Method == Store && !outer.IsEncrypted() {
		// Reading the entry in place goes around the checksum the reader
		// would otherwise verify on the way past, and that checksum covers
		// the whole inner archive -- its headers and its listing included,
		// which no inner entry's checksum covers. So it is verified first,
		// in a pass of its own, and an archive that does not match its own
		// checksum is refused before it has written anything.
		if verr := e.verifySolidEntry(ctx, outer); verr != nil {
			return verr
		}
		off, derr := outer.DataOffset()
		if derr != nil {
			return derr
		}
		// #nosec G115 -- readDirectoryHeader and salvage both refuse an entry whose declared sizes are above MaxInt64
		// No ceiling on the size of an entry read this way, and none is
		// wanted: fallbackTooLarge below bounds the disk the scratch copy
		// takes, and this branch takes none. The checksum pass and the
		// extraction are linear reads of bytes the caller already has on
		// disk, and what lands on disk is bounded by the per-file limit
		// and the ratio through the budget the two extractions share.
		size := int64(min(outer.CompressedSize64, outer.UncompressedSize64))
		inner, ierr := NewExtractorFromReader(io.NewSectionReader(outer.zipr, off, size), size, e.chroot, e.solidInnerOptions()...)
		if ierr != nil {
			return ierr
		}
		return e.runSolidInner(ctx, inner)
	}

	// Anything else has to be produced before it can be read as an archive
	// at all, so it is copied to a scratch file first, against the budget.
	if budget.fallbackTooLarge(outer.UncompressedSize64) {
		return fmt.Errorf("zip: Solid archive too large for temp file fallback (%d bytes)", outer.UncompressedSize64)
	}
	return e.extractSolidFallback(ctx, budget)
}

// verifySolidEntry reads the solid entry through the reader, which is where
// its checksum is verified, and discards what comes out.
func (e *Extractor) verifySolidEntry(ctx context.Context, outer *File) error {
	rc, err := outer.Open()
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, &ctxReader{r: rc, ctx: ctx})
	if cerr := rc.Close(); err == nil {
		err = cerr
	}
	return err
}

// solidInnerOptions is what the second extractor is given. The inner
// extraction is not an incremental one, whatever the caller asked this one
// for: an incremental extractor refuses a destination that holds anything it
// did not put there, and its closing sweep would take this extraction's own
// scratch file for a leftover. The sweep this extraction owes its caller runs
// in Extract instead, once the tree is final.
func (e *Extractor) solidInnerOptions() []ExtractorOption {
	return []ExtractorOption{
		WithExtractorConcurrency(e.options.concurrency),
		WithExtractorChownErrorHandler(e.options.chownErrorHandler),
		WithExtractorMaxFileSize(e.options.maxFileSize),
		WithExtractorMaxRatio(e.options.maxDecompressionRatio),
		WithExtractorXattrs(e.options.xattrs),
		WithExtractorKeepBroken(e.options.keepBroken),
		WithExtractorKeepOldFiles(e.options.keepOldFiles),
		WithExtractorKeepNewerFiles(e.options.keepNewerFiles),
		WithExtractorNoTimes(e.options.noTimes),
		WithExtractorStripComponents(e.options.stripComponents),
		WithExtractorSparse(e.options.sparse),
		WithExtractorSafeWrites(e.options.safeWrites),
		WithExtractorUnlinkFirst(e.options.unlinkFirst),
		WithExtractorNumericOwner(e.options.numericOwner),
		WithExtractorTolerant(e.options.tolerant),
	}
}

// runSolidInner runs the second extractor and takes over what it wrote: the
// archive was handed on to it, and the caller asked this extraction what came
// out.
func (e *Extractor) runSolidInner(ctx context.Context, inner *Extractor) error {
	// Both branches come through here, so this is where the nesting is
	// counted: the extractor about to run is one solid archive further in
	// than the one that built it.
	inner.solidDepth = e.solidDepth + 1
	err := inner.Extract(ctx)
	ibytes, ientries := inner.Written()
	atomic.AddInt64(&e.written, ibytes)
	atomic.AddInt64(&e.entries, ientries)
	dclose(inner, &err)
	return err
}

// extractSolidFallback copies the solid entry to a scratch file and extracts
// that, for the entries that have to be produced before they can be read as an
// archive: a compressed one, and an encrypted one.
//
// The scratch file goes into the destination rather than a system temp
// directory: the destination is the only place the caller gave permission to
// write, and it is the volume the extraction was sized against. The random
// suffix os.CreateTemp gives it is what keeps an inner entry from colliding
// with it by choosing a name.
func (e *Extractor) extractSolidFallback(ctx context.Context, budget *extractBudget) error {
	outer := e.zr.File[0]

	if err := os.MkdirAll(e.chroot, 0755); err != nil {
		return fmt.Errorf("zip: solid fallback failed: %w", err)
	}
	tempFile, terr := scratchCreate(e.chroot, "solid_fallback_*.zip")
	if terr != nil {
		return fmt.Errorf("zip: solid fallback failed: %w", terr)
	}
	scratch := tempFile.Name()

	// The safety net for the paths that give up before the teardown at the
	// end. An extraction that already failed has an answer for the caller
	// and a scratch file it could not remove is not a better one, so what
	// happens here is deliberately not looked at.
	tornDown := false
	defer func() {
		if tornDown {
			return
		}
		_ = tempFile.Close()
		_ = removeScratch(scratch)
	}()

	r2, terr := outer.Open()
	if terr != nil {
		return terr
	}

	// The copy is measured on its own rather than against the budget the
	// inner extraction uses: charging both to one budget makes an honest
	// archive look like it expanded twice as far as it did.
	fb := budget.entry(outer)

	buf := getSparseBuf()
	_, terr = io.CopyBuffer(fb.scratch(tempFile), &ctxReader{r: r2, ctx: ctx}, buf)
	putSparseBuf(buf)
	if cerr := r2.Close(); cerr != nil && terr == nil {
		terr = cerr
	}
	if terr != nil {
		return terr
	}

	innerExtractor, terr := NewExtractor(scratch, e.chroot, e.solidInnerOptions()...)
	if terr != nil {
		return terr
	}

	err := e.runSolidInner(ctx, innerExtractor)

	// Teardown in the order the scratch file can be removed in: the second
	// extractor's reader over it is already closed, then the handle the copy
	// was written through, then the name. A removal that fails after the
	// extraction succeeded is the extraction's failure -- a destination left
	// holding a copy of the archive is not what the caller asked for -- and
	// the message says which file is still there.
	tornDown = true
	dclose(tempFile, &err)
	if rerr := removeScratch(scratch); rerr != nil && err == nil {
		err = fmt.Errorf("zip: solid fallback could not remove its scratch file %s: %w", scratch, rerr)
	}
	return err
}

func (e *Extractor) createDirectory(path string, file *File) error {
	err := os.Mkdir(fixOSPath(path), 0777)
	if os.IsExist(err) {
		err = nil
	}
	incOnSuccess(&e.entries, err)
	return err
}

// isAbsArchiveTarget reports whether a link target read out of an archive is
// anchored somewhere other than the directory the link lives in.
//
// filepath.IsAbs cannot be used for this on its own, because it answers for
// the platform it is running on and an archive carries the paths of the
// machine that wrote it. On Windows it calls "/etc/passwd" relative, so the
// target is resolved against the extraction directory and, because
// createWindowsSymlink falls back to copying when it cannot make a link,
// the contents of C:\etc\passwd are pulled into the tree. On Unix it calls
// `C:\Windows\...` relative for the mirror-image reason. Each spelling slips
// through on exactly the platform it was aimed at, so both are rejected
// everywhere, along with drive-relative "C:name", which resolves against
// that drive's own working directory.
func isAbsArchiveTarget(target string) bool {
	if target == "" {
		return false
	}
	if target[0] == '/' || target[0] == '\\' {
		return true
	}
	if len(target) < 2 || target[1] != ':' {
		return false
	}
	c := target[0]
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func (e *Extractor) createLink(path string, file *File, budget *extractBudget) error {
	if err := os.Remove(fixOSPath(path)); err != nil && !os.IsNotExist(err) {
		return err
	}

	if file.Mode()&os.ModeSymlink != 0 {
		r, err := file.Open()
		if err != nil {
			return err
		}
		name, err := io.ReadAll(r)
		// The entry was read to its end, so the checksum has already
		// been checked and this handle has nothing left to say.
		_ = r.Close()
		if err != nil {
			return err
		}

		// The target is the entry's body, so it arrives as bytes and takes
		// the same spelling every name takes before it goes to the
		// filesystem -- otherwise it names the file by bytes that were never
		// written on the platforms that cannot store them.
		target := osRawBytes(name)
		if isAbsArchiveTarget(target) {
			return fmt.Errorf("zip: absolute symlink target not allowed: %s", target)
		}

		resolvedTarget := filepath.Clean(filepath.Join(filepath.Dir(path), target))
		prefix := e.chroot
		if !strings.HasSuffix(prefix, string(filepath.Separator)) {
			prefix += string(filepath.Separator)
		}
		if !strings.HasPrefix(resolvedTarget, prefix) && resolvedTarget != e.chroot {
			return fmt.Errorf("zip: symlink target escapes chroot: %s", target)
		}

		if runtime.GOOS == "windows" {
			isDir := false
			if fi, err := os.Stat(fixOSPath(resolvedTarget)); err == nil {
				isDir = fi.IsDir()
			}
			if err := createWindowsSymlink(target, resolvedTarget, path, isDir, budget.duplicate(file.Name)); err != nil {
				return err
			}
		} else {
			if err := os.Symlink(target, fixOSPath(path)); err != nil {
				return err
			}
		}
	} else if file.Linkname != "" {
		// A hard link names its target relative to the extraction root, and
		// filepath.Join cleans, so a leading ".." used to eat the root and
		// leave a link to a file outside it -- after which the metadata below
		// chmods and chowns that outside file through the link. absPath is the
		// same resolution every other entry goes through: it applies the
		// on-disk spelling and refuses a name that climbs out. It cannot see a
		// drive-letter or leading-separator target for what it is on the wrong
		// platform, which is what isAbsArchiveTarget is for.
		if isAbsArchiveTarget(file.Linkname) {
			return fmt.Errorf("zip: absolute hard link target not allowed: %s", file.Linkname)
		}
		targetPath, err := e.absPath(file.Linkname)
		if err != nil {
			return err
		}
		if err := os.Link(fixOSPath(targetPath), fixOSPath(path)); err != nil {
			return err
		}
	}

	err := e.updateFileMetadata(path, file)
	incOnSuccess(&e.entries, err)

	return err
}

// trimToWritten cuts a file back to the position it has been written up to.
// preallocate may have made it longer than the entry it holds, and a tail of
// zeros left behind is a file bigger than the archive said, which nothing
// downstream would report. It is a function of its own so that what it does
// when the file will not take it can be tested; from createFile the handle is
// always one this package opened for writing and just wrote through.
func trimToWritten(f *os.File) error {
	currentOffset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	return f.Truncate(currentOffset)
}

func (e *Extractor) createFile(ctx context.Context, path string, file *File, budget *extractBudget) (err error) {
	// The header is the archive's word about bytes it has not produced
	// yet, so it is worth a rejection before anything is opened and worth
	// nothing after that: what is written is counted as it is written.
	eb := budget.entry(file)
	if err := eb.checkHeader(file.UncompressedSize64); err != nil {
		return err
	}

	if err := os.Remove(fixOSPath(path)); err != nil && !os.IsNotExist(err) {
		return err
	}

	r, err := file.Open()
	if err != nil {
		return err
	}
	defer dclose(r, &err)

	writePath := path
	if e.options.safeWrites {
		writePath = path + ".tmp"
	}

	f, err := os.OpenFile(fixOSPath(writePath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}

	cleanup := true
	closed := false
	// The net for every path out of this function that is not the ordinary
	// one: the file is finished by hand at the end, because the move that
	// follows it cannot be done while the handle is still open.
	defer func() {
		if !closed {
			dclose(f, &err)
		}
		if err != nil && cleanup && !e.options.keepBroken {
			// The entry is already failing; this is the partial file
			// it produced being swept up.
			_ = os.Remove(fixOSPath(writePath))
		}
	}()

	if err := preallocate(f, eb.preallocSize(file.UncompressedSize64)); err != nil {
		return err
	}

	// Every byte of the file goes through the budget, which is what makes
	// the limits limits: the reader used to be wrapped in a LimitedReader
	// and then probed for one byte more, a second mechanism beside the
	// header check that the solid path had no share of at all.
	bw := eb.file(f)

	if strings.HasSuffix(file.Name, ":Zone.Identifier") {
		// The whole of it is read before any of it can be sanitized, and
		// what bounds that is not the budget: File.Open wraps the
		// decompressor in a reader limited to the declared uncompressed
		// size, and the header check above has already held that number
		// to the size limit. With no size limit the caller has asked for
		// none, here as everywhere else.
		data, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		sanitized := sanitizeZoneIdentifier(data)
		_, err = bw.Write(sanitized)
		if err == nil {
			// Sanitising shortens the stream, so what is left of the
			// original past the new end has to go with it.
			err = f.Truncate(int64(len(sanitized)))
		}
		incOnSuccess(&e.entries, err)
		return err
	}

	if e.options.sparse {
		err = copySparseZip(f, r, bw, ctx)
	} else {
		buf := getSparseBuf()
		defer putSparseBuf(buf)

		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			n, errRead := r.Read(buf)
			if n > 0 {
				if _, werr := bw.Write(buf[:n]); werr != nil {
					err = werr
					break
				}
			}
			if errRead == io.EOF {
				break
			}
			if errRead != nil {
				err = errRead
				break
			}
		}
	}

	// Finishing the file has an order and it is this one: cut it back to
	// what was written, let the handle go, and only then move it into
	// place. Windows will not rename a file that is still open, and the
	// rename used to be done from here with the close still deferred, so
	// safeWrites failed on every entry of every archive there -- and the
	// sweep of the temporary file, being in the same deferred call, failed
	// with it and left the file behind as well.
	if err == nil {
		err = trimToWritten(f)
	}
	// The mode goes on through the handle that wrote the bytes, while that
	// handle still names the file they went into. Put on by path afterwards
	// it lands on whatever stands at that name by then, and what stands
	// there need not be this file: an entry named as another entry's parent
	// directory has the extraction replace it with a directory, and a
	// directory wearing a file's mode has lost the search bit it needs to be
	// entered at all. Only the mode is moved here -- times and extended
	// attributes stay by path, where landing on the wrong object is untidy
	// rather than a directory nobody can go into.
	if err == nil {
		err = f.Chmod(file.Mode().Perm())
	}
	dclose(f, &err)
	closed = true

	if err == nil && e.options.safeWrites {
		err = e.finishSafeWrite(writePath, path)
	}
	if err == nil {
		cleanup = false
	}
	// Counted after the move, not before it: an entry that was written and
	// then failed to be put where it belongs has not been extracted.
	incOnSuccess(&e.entries, err)

	return err
}

// rename is os.Rename, named here so that a test can make the move fail. It
// is the one step of an extraction with no error of its own to provoke:
// everything up to it has already succeeded by then.
var rename = os.Rename

// openRoot is os.OpenRoot, named here for the same reason: by the time the
// incremental sweep opens the destination as a root, an entry inside it has
// already been read, so nothing short of the directory being taken away
// underneath the extraction makes this fail.
var openRoot = os.OpenRoot

// finishSafeWrite moves the temporary file an entry was written to onto the
// name the archive gave it. Both paths go through fixOSPath: on Windows a
// name ending in a dot or a space, or one longer than MAX_PATH, is only
// reachable in its extended form, and renaming without it would move the file
// to a different name than the one everything else in the extraction used.
func (e *Extractor) finishSafeWrite(writePath, path string) error {
	if rerr := rename(fixOSPath(writePath), fixOSPath(path)); rerr != nil {
		// The move is the error being returned; the temporary file it
		// left behind is swept up. The handle is closed by now, so this
		// removal works on Windows too.
		_ = os.Remove(fixOSPath(writePath))
		return rerr
	}
	return nil
}

func (e *Extractor) updateFileMetadata(path string, file *File) error {
	mode := file.Mode()
	if mode.IsDir() {
		// A directory has to be enterable by whoever may read it. The
		// search bit goes on beside each read bit that is set and
		// nowhere else, so a directory an archive deliberately closed to
		// a group or to the world stays closed to them, while one open
		// to them can be gone into. Without it the extraction writes
		// files into a directory and then takes away the right to reach
		// them: an entry with no Unix mode of its own arrives here with
		// the mode its MS-DOS attributes give it, and those have no
		// search bit at all.
		mode |= (mode & 0444) >> 2
	}

	if !e.options.noTimes {
		atime := time.Now()
		if !file.Accessed.IsZero() {
			atime = file.Accessed
		}
		if err := lchtimes(path, mode, atime, file.Modified); err != nil {
			return err
		}
	}

	// A regular file has its mode already: createFile put it on through the
	// handle it wrote the bytes with, which is the only way to be sure it
	// went to that file rather than to whatever now answers to its name.
	// What is left here is what has no handle of its own to be reached
	// through: directories, in the pass that runs once the tree is final,
	// and the links and device nodes another call made.
	if !mode.IsRegular() {
		if err := lchmod(path, mode); err != nil {
			return err
		}
	}

	// Access control lists and extended attributes are best effort
	// whatever the extractor's tolerance is set to: they fail on what the
	// destination filesystem can hold rather than on the archive, so FAT,
	// exFAT, SMB shares and tmpfs would each turn a strict extraction into
	// a failure for carrying metadata they have no place to put.
	if len(file.Acl) > 0 {
		_ = applyNtfsAclFunc(path, file.Acl)
	}

	if e.options.xattrs {
		_ = applyXattrs(path, &file.FileHeader)
	}

	if !file.OwnerSet {
		return nil
	}

	uid, gid := resolveIds(&file.FileHeader, e.options.numericOwner)
	err := lchown(path, uid, gid)
	if err == nil {
		return nil
	}

	if e.options.chownErrorHandler == nil {
		return nil
	}

	e.m.Lock()
	defer e.m.Unlock()
	return e.options.chownErrorHandler(file.Name, err)
}
func (e *Extractor) absPath(name string) (string, error) {
	// An entry whose name ends in a separator is a directory, and a directory
	// entry that names the extraction root itself is the one harmless way to
	// clean to ".": it goes to MkdirAll, which has nothing left to do.
	isDirEntry := strings.HasSuffix(name, "/") || strings.HasSuffix(name, `\`)
	name = osFileName(name)
	cleanName := filepath.ToSlash(filepath.Clean(name))
	// filepath.Clean answers ".." with itself, which has neither a "../"
	// prefix nor a "/" one, so a bare ".." resolved to the parent of the
	// extraction directory and said nothing. "." is the same hole one step
	// short: it names the extraction directory, and a file entry there is
	// written over the directory the caller handed in -- os.Remove takes an
	// empty one away and OpenFile puts a regular file where it was.
	if cleanName == ".." || strings.HasPrefix(cleanName, "../") || strings.HasPrefix(cleanName, "/") {
		return "", ErrInsecurePath
	}
	if cleanName == "." && !isDirEntry {
		return "", ErrInsecurePath
	}
	return filepath.Join(e.chroot, cleanName), nil
}

type ctxReader struct {
	r   io.Reader
	ctx context.Context
}

func (cr *ctxReader) Read(p []byte) (int, error) {
	if err := cr.ctx.Err(); err != nil {
		return 0, err
	}
	return cr.r.Read(p)
}
func (e *Extractor) linksToDirs(targetPath string) error {
	if !strings.HasPrefix(targetPath, e.chroot) {
		return nil
	}
	rel, err := filepath.Rel(e.chroot, targetPath)
	if err != nil {
		return err
	}
	if rel == "." || rel == "" {
		return nil
	}

	parts := strings.Split(filepath.Clean(rel), string(filepath.Separator))
	current := e.chroot
	for i := 0; i < len(parts)-1; i++ {
		current = filepath.Join(current, parts[i])
		fi, err := os.Lstat(fixOSPath(current))
		if err != nil {
			if os.IsNotExist(err) {
				break
			}
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(fixOSPath(current)); err != nil {
				return err
			}
		}
	}
	return nil
}

// synthesizeParentDirs guarantees that all parent folders for the target path
// exist on disk, recovering missing or corrupted directory headers on the fly,
// while safely resolving path conflicts.
func (e *Extractor) synthesizeParentDirs(targetPath string) error {
	dir := filepath.Dir(targetPath)
	if _, ok := e.dirCache.Load(dir); ok {
		return nil
	}

	// Fast path: ensure parent directory chain exists using standard OS tools
	err := os.MkdirAll(fixOSPath(dir), 0755)
	if err == nil {
		e.dirCache.Store(dir, struct{}{})
		return nil
	}

	// If MkdirAll fails, it usually means a non-directory file is blocking one of the parent paths.
	// We fall back to manual recursive path reconstruction.
	if !strings.HasPrefix(targetPath, e.chroot) {
		return nil
	}
	rel, errRel := filepath.Rel(e.chroot, targetPath)
	if errRel != nil {
		return errRel
	}

	parts := strings.Split(filepath.Clean(rel), string(filepath.Separator))
	current := e.chroot

	for i := 0; i < len(parts)-1; i++ {
		current = filepath.Join(current, parts[i])
		fi, errStat := os.Lstat(fixOSPath(current))
		if errStat != nil {
			if os.IsNotExist(errStat) {
				if errMk := mkdir(fixOSPath(current), 0755); errMk != nil && !os.IsExist(errMk) {
					return errMk
				}
			} else {
				return errStat
			}
		} else if !fi.IsDir() {
			// Resolve conflict: remove blocking file and create directory
			if errRm := os.Remove(fixOSPath(current)); errRm == nil {
				if errMk := mkdir(fixOSPath(current), 0755); errMk != nil {
					return errMk
				}
			} else {
				return errRm
			}
		}
	}
	return nil
}
