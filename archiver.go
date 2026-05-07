package zip

import (
	"hash/crc32"
	"errors"
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/unxed/zip/internal/filepool"
	"golang.org/x/sync/errgroup"
)

const irregularModes = os.ModeSocket | os.ModeDevice | os.ModeCharDevice | os.ModeNamedPipe

var ErrMinConcurrency = errors.New("concurrency must be at least 1")

var bufioReaderPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewReaderSize(nil, 32*1024)
	},
}

type ArchiverOption func(*archiverOptions) error

type archiverOptions struct {
	method      uint16
	concurrency int
	bufferSize  int
	stageDir    string
	offset      int64
	includePlatformMetadata bool
}

func WithArchiverMethod(method uint16) ArchiverOption {
	return func(o *archiverOptions) error {
		o.method = method
		return nil
	}
}

func WithArchiverConcurrency(n int) ArchiverOption {
	return func(o *archiverOptions) error {
		if n <= 0 {
			return ErrMinConcurrency
		}
		o.concurrency = n
		return nil
	}
}

func WithArchiverBufferSize(n int) ArchiverOption {
	return func(o *archiverOptions) error {
		if n < 0 {
			n = 0
		}
		o.bufferSize = n
		return nil
	}
}

func WithStageDirectory(dir string) ArchiverOption {
	return func(o *archiverOptions) error {
		o.stageDir = dir
		return nil
	}
}

func WithArchiverOffset(n int64) ArchiverOption {
	return func(o *archiverOptions) error {
		o.offset = n
		return nil
	}
}
// WithArchiverPlatformMetadata enables inclusion of local OS metadata (UID/GID)
// for this archiver instance.
func WithArchiverPlatformMetadata(enable bool) ArchiverOption {
	return func(o *archiverOptions) error {
		o.includePlatformMetadata = enable
		return nil
	}
}

type Archiver struct {
	written, entries int64
	zw               *Writer
	options          archiverOptions
	chroot           string
	m                sync.Mutex
}

func NewArchiver(w io.Writer, chroot string, opts ...ArchiverOption) (*Archiver, error) {
	var err error
	if chroot, err = filepath.Abs(chroot); err != nil {
		return nil, err
	}

	a := &Archiver{
		chroot: chroot,
	}

	a.options.method = Deflate
	a.options.concurrency = runtime.GOMAXPROCS(0)
	a.options.stageDir = chroot
	a.options.bufferSize = -1

	for _, o := range opts {
		if err := o(&a.options); err != nil {
			return nil, err
		}
	}

	a.zw = NewWriter(w)
	a.zw.SetOffset(a.options.offset)
	return a, nil
}

func (a *Archiver) Close() error {
	return a.zw.Close()
}

func (a *Archiver) Written() (bytes, entries int64) {
	return atomic.LoadInt64(&a.written), atomic.LoadInt64(&a.entries)
}

func (a *Archiver) Archive(ctx context.Context, files map[string]os.FileInfo) (err error) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var fp *filepool.FilePool
	concurrency := a.options.concurrency
	if len(files) < concurrency {
		concurrency = len(files)
	}
	if concurrency > 1 {
		fp, err = filepool.New(a.options.stageDir, concurrency, a.options.bufferSize)
		if err != nil {
			return err
		}
		defer dclose(fp, &err)
	}

	wg, ctx := errgroup.WithContext(ctx)
	defer func() {
		if werr := wg.Wait(); werr != nil {
			err = werr
		}
	}()

	hdrs := make([]FileHeader, len(names))

	for i, name := range names {
		fi := files[name]
		if fi.Mode()&irregularModes != 0 {
			continue
		}

		path, err := filepath.Abs(name)
		if err != nil {
			return err
		}

		if !strings.HasPrefix(path, a.chroot+string(filepath.Separator)) && path != a.chroot {
			return fmt.Errorf("%s cannot be archived from outside of chroot (%s)", name, a.chroot)
		}

		rel, err := filepath.Rel(a.chroot, path)
		if err != nil {
			return err
		}

		hdr := &hdrs[i]
		a.fileInfoHeaderFast(rel, fi, hdr)

		if ctx.Err() != nil {
			return ctx.Err()
		}

		switch {
		case hdr.Mode()&os.ModeSymlink != 0:
			err = a.createSymlink(path, fi, hdr)

		case hdr.Mode().IsDir():
			err = a.createDirectory(fi, hdr)

		default:
			if hdr.UncompressedSize64 > 0 {
				hdr.Method = a.options.method
			}

			if fp == nil {
				err = a.createFile(ctx, path, fi, hdr, nil)
				incOnSuccess(&a.entries, err)
			} else {
				f := fp.Get()
				wg.Go(func() error {
					err := a.createFile(ctx, path, fi, hdr, f)
					fp.Put(f)
					incOnSuccess(&a.entries, err)
					return err
				})
			}
		}

		if err != nil {
			return err
		}
	}

	return wg.Wait()
}

func (a *Archiver) fileInfoHeaderFast(name string, fi os.FileInfo, hdr *FileHeader) {
	hdr.Name = filepath.ToSlash(name)
	hdr.UncompressedSize64 = uint64(fi.Size())
	hdr.Modified = fi.ModTime()
	hdr.SetMode(fi.Mode())
	if hdr.Mode().IsDir() {
		hdr.Name += "/"
	}
	if hdr.UncompressedSize64 > uint32max {
		hdr.UncompressedSize = uint32max
	} else {
		hdr.UncompressedSize = uint32(hdr.UncompressedSize64)
	}

	// Respect archiver options for metadata
	appendPlatformExtra(fi, hdr, a.options.includePlatformMetadata)
}

func (a *Archiver) createDirectory(fi os.FileInfo, hdr *FileHeader) error {
	a.m.Lock()
	defer a.m.Unlock()
	_, err := a.zw.CreateHeader(hdr)
	incOnSuccess(&a.entries, err)
	return err
}

func (a *Archiver) createSymlink(path string, fi os.FileInfo, hdr *FileHeader) error {
	a.m.Lock()
	defer a.m.Unlock()

	link, err := os.Readlink(path)
	if err != nil {
		return err
	}

	hdr.Flags &= ^uint16(0x8)
	hdr.Method = Store
	hdr.CompressedSize64 = uint64(len(link))
	hdr.UncompressedSize64 = hdr.CompressedSize64
	hdr.CRC32 = crc32.ChecksumIEEE([]byte(link))

	w, err := a.createHeaderRaw(fi, hdr)
	if err != nil {
		return err
	}

	_, err = io.WriteString(w, link)
	incOnSuccess(&a.entries, err)
	return err
}

func (a *Archiver) createFile(ctx context.Context, path string, fi os.FileInfo, hdr *FileHeader, tmp *filepool.File) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return a.compressFile(ctx, f, fi, hdr, tmp)
}

func (a *Archiver) compressFile(ctx context.Context, f *os.File, fi os.FileInfo, hdr *FileHeader, tmp *filepool.File) error {
	comp := a.zw.compressor(hdr.Method)
	if comp == nil || tmp == nil {
		return a.compressFileSimple(ctx, f, fi, hdr)
	}

	fw, err := comp(tmp)
	if err != nil {
		return err
	}

	br := bufioReaderPool.Get().(*bufio.Reader)
	defer bufioReaderPool.Put(br)
	br.Reset(f)

	_, err = io.Copy(io.MultiWriter(fw, tmp.Hasher()), br)
	dclose(fw, &err)
	if err != nil {
		return err
	}

	hdr.Flags |= 0x8
	hdr.CompressedSize64 = tmp.Written()
	if hdr.CompressedSize64 > hdr.UncompressedSize64 {
		f.Seek(0, io.SeekStart)
		hdr.Method = Store
		return a.compressFileSimple(ctx, f, fi, hdr)
	}
	hdr.CRC32 = tmp.Checksum()

	a.m.Lock()
	defer a.m.Unlock()

	w, err := a.createHeaderRaw(fi, hdr)
	if err != nil {
		return err
	}

	br.Reset(tmp)
	_, err = br.WriteTo(ctxCountWriter{w, &a.written, ctx})
	return err
}

func (a *Archiver) compressFileSimple(ctx context.Context, f *os.File, fi os.FileInfo, hdr *FileHeader) error {
	br := bufioReaderPool.Get().(*bufio.Reader)
	defer bufioReaderPool.Put(br)
	br.Reset(f)

	a.m.Lock()
	defer a.m.Unlock()

	w, err := a.zw.CreateHeader(hdr)
	if err != nil {
		return err
	}

	_, err = br.WriteTo(ctxCountWriter{w, &a.written, ctx})
	return err
}

func (a *Archiver) createHeaderRaw(fi os.FileInfo, fh *FileHeader) (io.Writer, error) {
	utf8Valid1, utf8Require1 := detectUTF8(fh.Name)
	utf8Valid2, utf8Require2 := detectUTF8(fh.Comment)
	switch {
	case fh.NonUTF8:
		fh.Flags &^= 0x800
	case (utf8Require1 || utf8Require2) && (utf8Valid1 && utf8Valid2):
		fh.Flags |= 0x800
	}

	fh.CreatorVersion = fh.CreatorVersion&0xff00 | zipVersion20
	fh.ReaderVersion = zipVersion20

	fh.injectAutoExtras()

	return a.zw.CreateRaw(fh)
}

type ctxCountWriter struct {
	w       io.Writer
	written *int64
	ctx     context.Context
}

func (w ctxCountWriter) Write(p []byte) (n int, err error) {
	if err = w.ctx.Err(); err == nil {
		n, err = w.w.Write(p)
		atomic.AddInt64(w.written, int64(n))
	}
	return n, err
}

func dclose(c io.Closer, err *error) {
	if cerr := c.Close(); cerr != nil && *err == nil {
		*err = cerr
	}
}

func incOnSuccess(inc *int64, err error) {
	if err == nil {
		atomic.AddInt64(inc, 1)
	}
}