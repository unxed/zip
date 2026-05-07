package zip

import (
	"bufio"
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
	concurrency          int
	chownErrorHandler    func(name string, err error) error
	maxFileSize          int64
	maxDecompressionRatio int64
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
		if file.Mode()&irregularModes != 0 {
			continue
		}

		path, err := filepath.Abs(filepath.Join(e.chroot, file.Name))
		if err != nil {
			return err
		}

		if !strings.HasPrefix(path, e.chroot+string(filepath.Separator)) && path != e.chroot {
			return fmt.Errorf("%s cannot be extracted outside of chroot (%s)", path, e.chroot)
		}

		if err := os.MkdirAll(filepath.Dir(path), 0777); err != nil {
			return err
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		switch {
		case file.Mode()&os.ModeSymlink != 0:
			continue

		case file.Mode().IsDir():
			err = e.createDirectory(path, file)

		default:
			limiter <- struct{}{}
			gf := e.zr.File[i]
			wg.Go(func() error {
				defer func() { <-limiter }()
				err := e.createFile(ctx, path, gf)
				if err == nil {
					err = e.updateFileMetadata(path, gf)
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
		if file.Mode()&os.ModeSymlink == 0 {
			continue
		}
		path, err := filepath.Abs(filepath.Join(e.chroot, file.Name))
		if err != nil {
			return err
		}
		if err := e.createSymlink(path, file); err != nil {
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

func (e *Extractor) createSymlink(path string, file *File) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}

	r, err := file.Open()
	if err != nil {
		return err
	}
	defer r.Close()

	name, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	if err := os.Symlink(string(name), path); err != nil {
		return err
	}

	err = e.updateFileMetadata(path, file)
	incOnSuccess(&e.entries, err)

	return err
}

func (e *Extractor) createFile(ctx context.Context, path string, file *File) (err error) {
	// 1. Предварительная проверка по заголовку
	if e.options.maxFileSize > 0 && file.UncompressedSize64 > uint64(e.options.maxFileSize) {
		return fmt.Errorf("zip: file %q size %d exceeds limit %d", file.Name, file.UncompressedSize64, e.options.maxFileSize)
	}

	if e.options.maxDecompressionRatio > 0 && file.CompressedSize64 > 0 {
		// Используем умножение вместо деления, чтобы избежать проблем с округлением и нулем
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

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer dclose(f, &err)

	bw := bufioWriterPool.Get().(*bufio.Writer)
	defer bufioWriterPool.Put(bw)

	// Используем LimitedReader для физического ограничения чтения (защита от поддельных заголовков)
	var lr io.Reader = r
	if e.options.maxFileSize > 0 {
		lr = &io.LimitedReader{R: r, N: e.options.maxFileSize}
	}

	bw.Reset(ctxCountWriter{f, &e.written, ctx})
	_, err = bw.ReadFrom(lr)
	if err != nil {
		return err
	}

	// Если мы прочитали все, что позволил лимит, но в основном ридере еще есть данные - это бомба
	if e.options.maxFileSize > 0 {
		tmp := make([]byte, 1)
		if n, _ := r.Read(tmp); n > 0 {
			return fmt.Errorf("zip: file %q decompression exceeded maxFileSize limit", file.Name)
		}
	}

	err = bw.Flush()
	incOnSuccess(&e.entries, err)

	return err
}

func (e *Extractor) updateFileMetadata(path string, file *File) error {
	atime := time.Now()
	if !file.Accessed.IsZero() {
		atime = file.Accessed
	}
	if err := lchtimes(path, file.Mode(), atime, file.Modified); err != nil {
		return err
	}

	if err := lchmod(path, file.Mode()); err != nil {
		return err
	}

	// Apply Windows ACL if present
	if len(file.Acl) > 0 {
		applyNtfsAcl(path, file.Acl)
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