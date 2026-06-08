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
	method                  uint16
	concurrency             int
	bufferSize              int
	stageDir                string
	offset                  int64
	includePlatformMetadata bool
	xattrs                  bool
	solid                   bool
	incremental             bool
	seekChunkSize           uint32
	seekContinuous          bool
	password                string
	encryptCD               bool
	torrentZip              bool
	recoveryPct             int
	recoveryFile            *os.File
}

func WithArchiverTorrentZip(b bool) ArchiverOption {
	return func(o *archiverOptions) error {
		o.torrentZip = b
		if b {
			o.method = Deflate
			o.concurrency = 1
		}
		return nil
	}
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

// WithArchiverXattrs enables archiving of extended attributes (xattrs, POSIX ACLs, SELinux).
func WithArchiverXattrs(b bool) ArchiverOption {
	return func(o *archiverOptions) error {
		o.xattrs = b
		return nil
	}
}

// WithArchiverSolid enables solid ZIP-in-ZIP packaging to achieve maximum compression ratio.
func WithArchiverSolid(b bool) ArchiverOption {
	return func(o *archiverOptions) error {
		o.solid = b
		return nil
	}
}

// WithArchiverSeekIndex enables generation of a Seek Index for large files or solid archives.
func WithArchiverSeekIndex(chunkSize uint32, continuous bool) ArchiverOption {
	return func(o *archiverOptions) error {
		o.seekChunkSize = chunkSize
		o.seekContinuous = continuous
		return nil
	}
}

// WithArchiverPassword sets the password for WinZip AES encryption.
func WithArchiverPassword(password string) ArchiverOption {
	return func(o *archiverOptions) error {
		o.password = password
		return nil
	}
}

// WithArchiverEncryptCD enables Central Directory Encryption (CDE).
func WithArchiverEncryptCD(enable bool) ArchiverOption {
	return func(o *archiverOptions) error {
		o.encryptCD = enable
		return nil
	}
}

// WithArchiverIncremental includes a .zip_dumpdir index of all active files for incremental restore.
func WithArchiverIncremental(b bool) ArchiverOption {
	return func(o *archiverOptions) error {
		o.incremental = b
		return nil
	}
}

type Archiver struct {
	written, entries int64
	zw               *Writer
	options          archiverOptions
	chroot           string
	m                sync.Mutex
	seenHardLinks    map[hardlinkKey]string
}

// WithArchiverRecovery устанавливает параметры PAR2 избыточности
func WithArchiverRecovery(pct int, f interface{ Name() string }) ArchiverOption {
	return func(o *archiverOptions) error {
		o.recoveryPct = pct
		if osFile, ok := f.(*os.File); ok {
			o.recoveryFile = osFile
		}
		return nil
	}
}

func NewArchiver(w io.Writer, chroot string, opts ...ArchiverOption) (*Archiver, error) {
	var err error
	if chroot, err = filepath.Abs(chroot); err != nil {
		return nil, err
	}

	a := &Archiver{
		chroot:        chroot,
		seenHardLinks: make(map[hardlinkKey]string),
	}

	a.options.method = Deflate
	a.options.concurrency = runtime.GOMAXPROCS(0)
	a.options.stageDir = chroot
	a.options.bufferSize = -1
	a.options.includePlatformMetadata = true
	a.options.xattrs = true

	for _, o := range opts {
		if err := o(&a.options); err != nil {
			return nil, err
		}
	}

	if a.options.torrentZip {
		a.options.concurrency = 1
	}

	a.zw = NewWriter(w)
	a.zw.SetOffset(a.options.offset)
	if a.options.recoveryPct > 0 && a.options.recoveryFile != nil {
		a.zw.recoveryPct = a.options.recoveryPct
		a.zw.recoveryFile = a.options.recoveryFile
	}
	if a.options.encryptCD && a.options.password != "" {
		a.zw.SetEncryptCentralDirectory(true, a.options.password)
	}
	if a.options.torrentZip {
		a.zw.SetTorrentZip(true)
	}
	return a, nil
}

func (a *Archiver) Close() error {
	return a.zw.Close()
}

func (a *Archiver) Written() (bytes, entries int64) {
	return atomic.LoadInt64(&a.written), atomic.LoadInt64(&a.entries)
}

func (a *Archiver) Archive(ctx context.Context, files map[string]os.FileInfo) (err error) {
	if a.options.solid {
		seekChunk := a.options.seekChunkSize
		if seekChunk == 0 {
			seekChunk = 1024 * 1024 // 1MB default
		}
		hdr := &FileHeader{
			Name:           "Solid.zip",
			Method:         a.options.method,
			SeekChunkSize:  seekChunk,
			SeekContinuous: a.options.seekContinuous,
		}
		hdr.SetMode(0644)

		a.m.Lock()
		w, err := a.zw.CreateHeader(hdr)
		a.m.Unlock()
		if err != nil {
			return err
		}

		innerZw := NewWriter(w)

		if a.options.incremental {
			var list []string
			for name := range files {
				path, err := filepath.Abs(name)
				if err != nil {
					innerZw.Close()
					return err
				}
				rel, err := filepath.Rel(a.chroot, path)
				if err != nil {
					innerZw.Close()
					return err
				}
				relClean := filepath.ToSlash(rel)
				if files[name].IsDir() {
					relClean += "/"
				}
				list = append(list, relClean)
			}
			sort.Strings(list)
			dumpdirContent := strings.Join(list, "\n") + "\n"

			fh := &FileHeader{
				Name:               ".zip_dumpdir",
				Method:             Store,
				UncompressedSize64: uint64(len(dumpdirContent)),
				CompressedSize64:   uint64(len(dumpdirContent)),
			}
			innerW, err := innerZw.CreateHeader(fh)
			if err != nil {
				innerZw.Close()
				return err
			}
			innerW.Write([]byte(dumpdirContent))
		}

		innerA := &Archiver{
			zw:            innerZw,
			options:       a.options,
			chroot:        a.chroot,
			seenHardLinks: a.seenHardLinks,
		}
		innerA.options.method = Store
		innerA.options.solid = false

		err = innerA.Archive(ctx, files)
		innerZw.Close()

		atomic.AddInt64(&a.entries, atomic.LoadInt64(&innerA.entries))
		atomic.AddInt64(&a.written, atomic.LoadInt64(&innerA.written))

		incOnSuccess(&a.entries, err)
		return err
	}

	if a.options.xattrs {
		type virtualFile struct {
			path string
			info os.FileInfo
		}
		var virtualFiles []virtualFile

		for name, fi := range files {
			if fi != nil && fi.Mode().IsRegular() {
				streams, _ := getAlternativeDataStreamsFunc(name)
				for _, stream := range streams {
					streamPath := name + stream
					if streamFi, serr := os.Stat(streamPath); serr == nil {
						virtualFiles = append(virtualFiles, virtualFile{
							path: streamPath,
							info: streamFi,
						})
					}
				}
			}
		}

		for _, vf := range virtualFiles {
			files[vf.path] = vf.info
		}
	}

	if a.options.torrentZip {
		dirs := make(map[string]bool)
		for name, fi := range files {
			if fi != nil && fi.IsDir() {
				dirs[filepath.ToSlash(name)] = true
			}
		}
		for name := range files {
			dir := filepath.ToSlash(name)
			for {
				idx := strings.LastIndex(dir, "/")
				if idx <= 0 {
					break
				}
				dir = dir[:idx]
				delete(dirs, dir)
			}
		}
		for name, fi := range files {
			if fi != nil && fi.IsDir() && !dirs[filepath.ToSlash(name)] {
				delete(files, name)
			}
		}
	}

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	if a.options.torrentZip {
		sort.Slice(names, func(i, j int) bool {
			relI, _ := filepath.Rel(a.chroot, names[i])
			relJ, _ := filepath.Rel(a.chroot, names[j])
			fiI := files[names[i]]
			fiJ := files[names[j]]

			pathI := filepath.ToSlash(relI)
			pathJ := filepath.ToSlash(relJ)
			if fiI != nil && fiI.IsDir() && !strings.HasSuffix(pathI, "/") {
				pathI += "/"
			}
			if fiJ != nil && fiJ.IsDir() && !strings.HasSuffix(pathJ, "/") {
				pathJ += "/"
			}
			return strings.ToLower(pathI) < strings.ToLower(pathJ)
		})
	} else {
		sort.Strings(names)
	}

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
		if fi.Mode()&os.ModeSocket != 0 {
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

		if a.options.xattrs {
			if acl, err := getFileSecurityFunc(path); err == nil && len(acl) > 0 {
				hdr.Acl = acl
			}
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		switch {
		case hdr.Mode()&os.ModeSymlink != 0:
			if a.options.xattrs {
				sysXattrs(path, hdr)
			}
			err = a.createSymlink(path, fi, hdr)

		case hdr.Mode().IsDir():
			if a.options.xattrs {
				sysXattrs(path, hdr)
			}
			err = a.createDirectory(fi, hdr)

		default:
			link := getHardLinkTarget(fi, a.seenHardLinks)
			if link != "" {
				hdr.Linkname = link
				hdr.Method = Store
				hdr.CompressedSize64 = 0
				hdr.UncompressedSize64 = 0
				hdr.CRC32 = 0
				if a.options.xattrs {
					sysXattrs(path, hdr)
				}
				err = a.createHardlink(fi, hdr)
				break
			}
			rememberHardLink(fi, rel, a.seenHardLinks)

			if hdr.Mode()&irregularModes != 0 {
				hdr.Method = Store
				hdr.CompressedSize64 = 0
				hdr.UncompressedSize64 = 0
				hdr.CRC32 = 0
				if a.options.xattrs {
					sysXattrs(path, hdr)
				}
				err = a.createSpecialFile(fi, hdr)
				break
			}

			if a.options.xattrs {
				sysXattrs(path, hdr)
			}

			if hdr.UncompressedSize64 > 0 {
				hdr.Method = a.options.method
			}

			if fp == nil {
				err = a.createFile(ctx, path, fi, hdr, nil)
				incOnSuccess(&a.entries, err)
			} else {
				f := fp.Get()
				p := path
				fInfo := fi
				h := hdr
				wg.Go(func() error {
					err := a.createFile(ctx, p, fInfo, h, f)
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

	hdr.SeekChunkSize = a.options.seekChunkSize
	hdr.SeekContinuous = a.options.seekContinuous
	hdr.Password = a.options.password

	// Respect archiver options for metadata
	if !a.options.torrentZip {
		appendPlatformExtra(fi, hdr, a.options.includePlatformMetadata)
	}
}

func (a *Archiver) createDirectory(fi os.FileInfo, hdr *FileHeader) error {
	a.m.Lock()
	defer a.m.Unlock()
	_, err := a.zw.CreateHeader(hdr)
	incOnSuccess(&a.entries, err)
	return err
}
func (a *Archiver) createHardlink(fi os.FileInfo, hdr *FileHeader) error {
	a.m.Lock()
	defer a.m.Unlock()
	hdr.Flags &= ^uint16(0x8)
	_, err := a.createHeaderRaw(fi, hdr)
	incOnSuccess(&a.entries, err)
	return err
}

func (a *Archiver) createSpecialFile(fi os.FileInfo, hdr *FileHeader) error {
	a.m.Lock()
	defer a.m.Unlock()
	hdr.Flags &= ^uint16(0x8)
	_, err := a.createHeaderRaw(fi, hdr)
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
	defer func() {
		br.Reset(nil)
		bufioReaderPool.Put(br)
	}()
	br.Reset(f)

	_, err = io.Copy(io.MultiWriter(fw, tmp.Hasher()), br)
	dclose(fw, &err)
	if err != nil {
		return err
	}

	if !a.zw.forceNoDescriptor {
		hdr.Flags |= 0x8
	}
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
	_, err = br.WriteTo(&ctxCountWriter{w, &a.written, ctx})
	return err
}

func (a *Archiver) compressFileSimple(ctx context.Context, f *os.File, fi os.FileInfo, hdr *FileHeader) error {
	br := bufioReaderPool.Get().(*bufio.Reader)
	defer func() {
		br.Reset(nil)
		bufioReaderPool.Put(br)
	}()
	br.Reset(f)

	a.m.Lock()
	defer a.m.Unlock()

	w, err := a.zw.CreateHeader(hdr)
	if err != nil {
		return err
	}

	_, err = br.WriteTo(&ctxCountWriter{w, &a.written, ctx})
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

	if a.zw.forceNoDescriptor {
		fh.Flags &^= 0x8
	}

	return a.zw.CreateRaw(fh)
}

type ctxCountWriter struct {
	w       io.Writer
	written *int64
	ctx     context.Context
}

func (w *ctxCountWriter) Write(p []byte) (n int, err error) {
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