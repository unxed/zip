package zip

import (
	"bufio"
    "bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

var bufioWriterPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewWriterSize(nil, 32*1024)
	},
}

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

// WithExtractorSparse enables extracting files as sparse files by seeking over zero-blocks (-S, --sparse).
func WithExtractorSparse(b bool) ExtractorOption {
	return func(o *extractorOptions) error {
		o.sparse = b
		return nil
	}
}

var sparseBufPool = sync.Pool{
	New: func() any {
		return make([]byte, 32*1024)
	},
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

func copySparseZip(dst *os.File, src io.Reader, size uint64, written *int64, ctx context.Context) error {
	bufInterface := sparseBufPool.Get()
	defer sparseBufPool.Put(bufInterface)
	buf := bufInterface.([]byte)

	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := src.Read(buf)
		if n > 0 {
			if isAllZeros(buf[:n]) {
				_, seekErr := dst.Seek(int64(n), io.SeekCurrent)
				if seekErr != nil {
					return seekErr
				}
			} else {
				_, wErr := dst.Write(buf[:n])
				if wErr != nil {
					return wErr
				}
			}
			total += int64(n)
			atomic.AddInt64(written, int64(n))
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return dst.Truncate(int64(size))
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
func WithExtractorMaxFileSize(n int64) ExtractorOption {
	return func(o *extractorOptions) error {
		o.maxFileSize = n
		return nil
	}
}

func WithExtractorMaxRatio(n int64) ExtractorOption {
	return func(o *extractorOptions) error {
		o.maxDecompressionRatio = n
		return nil
	}
}

type Extractor struct {
	written, entries int64
	zr               *Reader
	closer           io.Closer
	m                sync.Mutex
	options          extractorOptions
	chroot           string
}

func NewExtractor(filename, chroot string, opts ...ExtractorOption) (*Extractor, error) {
	zr, err := OpenReader(filename)
	if err != nil {
		return nil, err
	}
	return newExtractor(&zr.Reader, zr, chroot, opts)
}

func NewExtractorFromReader(r io.ReaderAt, size int64, chroot string, opts ...ExtractorOption) (*Extractor, error) {
	zr, err := NewReader(r, size)
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
	e.options.maxDecompressionRatio = 200      // 200:1 default

	for _, o := range opts {
		if err := o(&e.options); err != nil {
			return nil, err
		}
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
	limiter := make(chan struct{}, e.options.concurrency)

	wg, ctx := errgroup.WithContext(ctx)
	defer func() {
		if werr := wg.Wait(); werr != nil {
			err = werr
		}
	}()

	for i, file := range e.zr.File {
		name := file.Name
		if e.options.stripComponents > 0 {
			stripped, ok := stripComponents(name, e.options.stripComponents)
			if !ok {
				continue // Skip file with fewer or equal components
			}
			name = stripped
		}

		path, err := filepath.Abs(filepath.Join(e.chroot, name))
		if err != nil {
			return err
		}

		if !strings.HasPrefix(path, e.chroot+string(filepath.Separator)) && path != e.chroot {
			return fmt.Errorf("%s cannot be extracted outside of chroot (%s)", path, e.chroot)
		}

		if err := e.linksToDirs(path); err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(path), 0777); err != nil {
			return err
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Overwrite control policies
		if file.Mode()&os.ModeDir == 0 && file.Mode()&os.ModeSymlink == 0 && file.Linkname == "" {
			if e.options.unlinkFirst {
				os.Remove(path) // Unconditionally remove before extraction
			}
			if e.options.keepOldFiles {
				if _, err := os.Stat(path); err == nil {
					continue // Skip extracting, file already exists
				}
			}
			if e.options.keepNewerFiles {
				if fi, err := os.Stat(path); err == nil {
					if fi.ModTime().After(file.Modified) {
						continue // Skip extracting, disk file is newer
					}
				}
			}
		}

		switch {
		case file.Mode()&os.ModeSymlink != 0 || file.Linkname != "":
			continue

		case file.Mode().IsDir():
			err = e.createDirectory(path, file)

		case file.Mode()&irregularModes != 0:
			limiter <- struct{}{}
			gf := e.zr.File[i]
			p := path
			wg.Go(func() error {
				defer func() { <-limiter }()
				err := extractSpecialFile(p, &gf.FileHeader)
				if err == nil {
					err = e.updateFileMetadata(p, gf)
				}
				return err
			})

		default:
			limiter <- struct{}{}
			gf := e.zr.File[i]
			p := path
			wg.Go(func() error {
				defer func() { <-limiter }()
				err := e.createFile(ctx, p, gf)
				if err == nil {
					err = e.updateFileMetadata(p, gf)
				}
				return err
			})
		}
		if err != nil {
			return err
		}
	}

	if err := wg.Wait(); err != nil {
		return err
	}

	for _, file := range e.zr.File {
		if file.Mode()&os.ModeSymlink == 0 && file.Linkname == "" {
			continue
		}
		path, err := filepath.Abs(filepath.Join(e.chroot, file.Name))
		if err != nil {
			return err
		}
		if err := e.createLink(path, file); err != nil {
			return err
		}
	}

	for _, file := range e.zr.File {
		if !file.Mode().IsDir() {
			continue
		}
		path, err := filepath.Abs(filepath.Join(e.chroot, file.Name))
		if err != nil {
			return err
		}
		err = e.updateFileMetadata(path, file)
		if err != nil {
			return err
		}
	}

	return nil
}

func (e *Extractor) createDirectory(path string, file *File) error {
	err := os.Mkdir(path, 0777)
	if os.IsExist(err) {
		err = nil
	}
	incOnSuccess(&e.entries, err)
	return err
}

func (e *Extractor) createLink(path string, file *File) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}

	if file.Mode()&os.ModeSymlink != 0 {
		r, err := file.Open()
		if err != nil {
			return err
		}
		name, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			return err
		}
		if err := os.Symlink(string(name), path); err != nil {
			return err
		}
	} else if file.Linkname != "" {
		targetPath := filepath.Join(e.chroot, file.Linkname)
		if err := os.Link(targetPath, path); err != nil {
			return err
		}
	}

	err := e.updateFileMetadata(path, file)
	incOnSuccess(&e.entries, err)

	return err
}

func (e *Extractor) createFile(ctx context.Context, path string, file *File) (err error) {
	// 1. Preliminary check based on the header
	if e.options.maxFileSize > 0 && file.UncompressedSize64 > uint64(e.options.maxFileSize) {
		return fmt.Errorf("zip: file %q size %d exceeds limit %d", file.Name, file.UncompressedSize64, e.options.maxFileSize)
	}

	if e.options.maxDecompressionRatio > 0 && file.CompressedSize64 > 0 {
		// Use multiplication instead of division to avoid rounding issues and division by zero
		if int64(file.UncompressedSize64) > e.options.maxDecompressionRatio*int64(file.CompressedSize64) {
			ratio := int64(file.UncompressedSize64 / file.CompressedSize64)
			return fmt.Errorf("zip: file %q suspicious compression ratio %d:1", file.Name, ratio)
		}
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
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

	f, err := os.OpenFile(writePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}

	cleanup := true
	defer func() {
		dclose(f, &err)
		if err != nil && cleanup && !e.options.keepBroken {
			os.Remove(writePath)
		}
	}()

	if err := preallocate(f, int64(file.UncompressedSize64)); err != nil {
		return err
	}

	if strings.HasSuffix(file.Name, ":Zone.Identifier") {
		data, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		sanitized := sanitizeZoneIdentifier(data)
		_, err = f.Write(sanitized)
		if err == nil {
			f.Truncate(int64(len(sanitized)))
			atomic.AddInt64(&e.written, int64(len(sanitized)))
		}
		incOnSuccess(&e.entries, err)
		return err
	}

	var lr io.Reader = r
	if e.options.maxFileSize > 0 {
		lr = &io.LimitedReader{R: r, N: e.options.maxFileSize}
	}

	if e.options.sparse {
		err = copySparseZip(f, lr, file.UncompressedSize64, &e.written, ctx)
	} else {
		bw := bufioWriterPool.Get().(*bufio.Writer)
		defer bufioWriterPool.Put(bw)

		bw.Reset(ctxCountWriter{f, &e.written, ctx})
		_, err = bw.ReadFrom(lr)
		if err != nil {
			return err
		}

		err = bw.Flush()
	}

	// If we read everything allowed by the limit, but data still remains in the source reader - it's a bomb
	if e.options.maxFileSize > 0 {
		tmp := make([]byte, 1)
		if n, _ := r.Read(tmp); n > 0 {
			return fmt.Errorf("zip: file %q decompression exceeded maxFileSize limit", file.Name)
		}
	}

	if err == nil {
		cleanup = false
	}
	incOnSuccess(&e.entries, err)

	if err == nil && e.options.safeWrites {
		if rerr := os.Rename(writePath, path); rerr != nil {
			os.Remove(writePath)
			return rerr
		}
	}

	return err
}

func (e *Extractor) updateFileMetadata(path string, file *File) error {
	if !e.options.noTimes {
		atime := time.Now()
		if !file.Accessed.IsZero() {
			atime = file.Accessed
		}
		if err := lchtimes(path, file.Mode(), atime, file.Modified); err != nil {
			return err
		}
	}

	if err := lchmod(path, file.Mode()); err != nil {
		return err
	}

	// Apply Windows ACL if present
	if len(file.Acl) > 0 {
		applyNtfsAclFunc(path, file.Acl)
	}

	if e.options.xattrs {
		applyXattrs(path, &file.FileHeader)
	}

	if !file.OwnerSet {
		return nil
	}

	err := lchown(path, file.Uid, file.Gid)
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
		fi, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				break
			}
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(current); err != nil {
				return err
			}
		}
	}
	return nil
}
