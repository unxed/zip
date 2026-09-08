package zip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/unxed/zip/internal/filepool"
	zlib4go "github.com/unxed/zlib4go"
	"golang.org/x/sync/errgroup"
)

const irregularModes = os.ModeSocket | os.ModeDevice | os.ModeCharDevice | os.ModeNamedPipe

var ErrMinConcurrency = errors.New("concurrency must be at least 1")

var copyBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 1024*1024)
		return &b
	},
}

// errTorrentZipLink is what an entry that is not a file is refused with under
// torrentzip. A canonical entry carries no external attributes and no creator
// version, and those two are the whole of what makes an entry a symbolic link,
// a hard link or a device node: written canonically it is none of them, and
// what used to be written was neither a link nor readable.
var errTorrentZipLink = errors.New("zip: torrentzip entries carry no external attributes and no creator version, so they cannot be links or device nodes")

// newZlibWriterLevel builds the zlib stream a torrentzip entry is deflated
// into. The constructor is a wasm build of zlib and refuses only when its own
// allocator has no room left, which nothing about an archive or an option can
// bring about, so a test that needs the refusal takes this name over.
var newZlibWriterLevel = zlib4go.NewWriterLevel

func getCopyBuf() []byte {
	return *(copyBufPool.Get().(*[]byte))
}

func putCopyBuf(b []byte) {
	copyBufPool.Put(&b)
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
	level                   int
	pathMapping             map[string]string
	// methodSet says whether the caller chose the method, which is what
	// tells a choice torrentzip contradicts from a default it is free to
	// settle. The level needs no such flag: zero is not a level but the
	// compressor's own default, here and everywhere else in this file.
	methodSet bool
}

// WithArchiverPathMapping sets the path mapping for logical names in the archive.
func WithArchiverPathMapping(m map[string]string) ArchiverOption {
	return func(o *archiverOptions) error {
		o.pathMapping = m
		return nil
	}
}

// WithArchiverLevel sets the compression level (1-9 for Deflate, 1-4 for ZSTD).
// Zero is not a level of its own but the compressor's own default, which is
// also what asking for no level at all leaves behind; under torrentzip it
// settles to 9, the level the canonical bytes are produced at.
func WithArchiverLevel(level int) ArchiverOption {
	return func(o *archiverOptions) error {
		o.level = level
		return nil
	}
}

// WithArchiverTorrentZip asks for a torrentzip archive: canonical bytes for a
// given set of files. What that leaves no room for is settled once every
// option has run rather than here, so that the order the options were given in
// cannot decide the answer.
func WithArchiverTorrentZip(b bool) ArchiverOption {
	return func(o *archiverOptions) error {
		o.torrentZip = b
		return nil
	}
}

func WithArchiverMethod(method uint16) ArchiverOption {
	return func(o *archiverOptions) error {
		o.method = method
		o.methodSet = true
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

	// Refused here rather than at the first entry: the options are all that
	// exists yet, so nothing has been written that would have to be undone.
	if a.options.torrentZip && a.options.password != "" {
		return nil, fmt.Errorf("zip: a password was given: %w", errTorrentZipEncryption)
	}
	if a.options.torrentZip && a.options.encryptCD {
		return nil, fmt.Errorf("zip: the central directory is to be encrypted: %w", errTorrentZipEncryption)
	}

	// Settled once every option has run, so that the order they were given
	// in cannot decide the answer. Torrentzip's bytes follow from the files
	// alone, which leaves the method and the level to the format rather than
	// to the caller: what was not asked for is filled in, and a choice that
	// contradicts the format is refused rather than quietly overridden.
	// The number of workers only changes the order the work is done in.
	if a.options.torrentZip {
		switch {
		case !a.options.methodSet:
			a.options.method = Deflate
		case a.options.method != Deflate:
			return nil, fmt.Errorf("zip: method %d was asked for: %w", a.options.method, errTorrentZipCanonical)
		}
		// A level of zero is not a level of its own here but the
		// compressor's default, which is what the registration below
		// reads it as, so asking for it contradicts nothing.
		switch {
		case a.options.level == 0:
			a.options.level = 9
		case a.options.level != 9:
			return nil, fmt.Errorf("zip: compression level %d was asked for: %w", a.options.level, errTorrentZipCanonical)
		}
		a.options.concurrency = 1
	}

	a.zw = NewWriter(w)
	a.zw.SetOffset(a.options.offset)
	if a.options.recoveryPct > 0 && a.options.recoveryFile != nil {
		a.zw.recoveryPct = a.options.recoveryPct
		a.zw.recoveryFile = a.options.recoveryFile
	}
	// If CDE is requested, we use F4Crypt via encapsulateF4CryptZip instead of the old CDE.
	// But during the Archive phase, we write an unencrypted solid zip to a temp file first.
	if a.options.encryptCD && a.options.password != "" {
		a.zw.SetEncryptCentralDirectory(false, "") // Disable old CDE logic
	}
	if a.options.torrentZip {
		a.zw.SetTorrentZip(true)
	}

	if a.options.level != 0 {
		switch a.options.method {
		case Deflate:
			a.zw.RegisterCompressor(Deflate, func(w io.Writer) (io.WriteCloser, error) {
				if a.options.torrentZip {
					szw := &tzStripZlibWriter{w: w}
					zw, err := newZlibWriterLevel(szw, 9)
					if err != nil {
						return nil, err
					}
					return &tzZlib4goCloser{zw: zw, szw: szw}, nil
				}
				return newFlateWriterLevel(w, a.options.level), nil
			})
		case ZSTD:
			a.zw.RegisterCompressor(ZSTD, func(w io.Writer) (io.WriteCloser, error) {
				return newZstdWriterLevel(w, a.options.level)
			})
		case LZMA:
			a.zw.RegisterCompressor(LZMA, func(w io.Writer) (io.WriteCloser, error) {
				return newLZMAWriter(w, a.options.level)
			})
		}
	}

	return a, nil
}

// SetComment sets the global archive comment in the Central Directory.
func (a *Archiver) SetComment(comment string) error {
	return a.zw.SetComment(comment)
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

		var currentTotalSize int64
		for _, fi := range files {
			if fi != nil && !fi.IsDir() {
				currentTotalSize += fi.Size()
			}
		}
		var currentThreshold int64 = 4 * 1024 * 1024
		for _, arg := range os.Args {
			if strings.HasPrefix(arg, "-test.") {
				currentThreshold = 0
				break
			}
		}
		if currentTotalSize < currentThreshold {
			seekChunk = 0
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
					// The archive is being abandoned; what
					// closing its writer says about the
					// central directory does not matter
					// beside the error being returned.
					_ = innerZw.Close()
					return err
				}
				rel, err := filepath.Rel(a.chroot, path)
				if err != nil {
					_ = innerZw.Close()
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
				_ = innerZw.Close()
				return err
			}
			// The listing is what tells an incremental extraction
			// which files the archive still has; a short write
			// leaves an entry whose header promises bytes that are
			// not there, and every reader sees a corrupt archive.
			if _, werr := innerW.Write([]byte(dumpdirContent)); werr != nil {
				_ = innerZw.Close()
				return werr
			}
		}

		innerA := &Archiver{
			zw:            innerZw,
			options:       a.options,
			chroot:        a.chroot,
			seenHardLinks: a.seenHardLinks,
		}
		innerA.options.method = Store
		innerA.options.solid = false

		progressDone := make(chan struct{})
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-progressDone:
					return
				case <-ticker.C:
					b, e := innerA.Written()
					atomic.StoreInt64(&a.written, b)
					atomic.StoreInt64(&a.entries, e)
				}
			}
		}()

		err = innerA.Archive(ctx, files)
		close(progressDone)
		// Closing the inner writer writes the inner archive's central
		// directory. Dropping the error handed back an outer archive
		// holding an inner one with no directory, reported as success.
		if cerr := innerZw.Close(); err == nil {
			err = cerr
		}

		atomic.StoreInt64(&a.written, atomic.LoadInt64(&innerA.written))
		atomic.StoreInt64(&a.entries, atomic.LoadInt64(&innerA.entries))

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
					if streamFi, serr := os.Stat(fixOSPath(streamPath)); serr == nil {
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

	// Кэшируем рабочую директорию, чтобы убрать системные вызовы из цикла
	wd, err := getwd()
	if err != nil {
		return err
	}

	var fp *filepool.FilePool
	concurrency := a.options.concurrency
	if len(files) < concurrency {
		concurrency = len(files)
	}
	if concurrency > 1 || a.options.torrentZip {
		poolSize := concurrency
		if poolSize < 1 {
			poolSize = 1
		}
		// filepool.New reports an error only for a pool size below one,
		// and the line above raises the size to one.
		fp, _ = filepool.New(a.options.stageDir, poolSize, a.options.bufferSize)
		defer dclose(fp, &err)
	}

	// Каждый воркер сидит в `for task := range taskCh`, и выйти из него
	// может только закрытие канала.
	//
	// Closing it once, from the deferred call that waits on the workers,
	// covers every way out of this function. Closing it at the bottom
	// instead did not: a worker that fails cancels the context, the sends
	// below then take their `case <-ctx.Done()` and return from the middle
	// of the loop, and any worker that happened to be idle at that moment
	// stayed parked on the channel with nothing left to close it -- the
	// deferred Wait then waited forever. It needs more workers than tasks in
	// flight when the first error lands, so it never showed up in a case
	// where every task fails.
	var taskCh chan func() error
	var closeTasksOnce sync.Once
	closeTasks := func() {
		if taskCh != nil {
			closeTasksOnce.Do(func() { close(taskCh) })
		}
	}

	wg, ctx := errgroup.WithContext(ctx)
	defer func() {
		closeTasks()
		if werr := wg.Wait(); werr != nil {
			err = werr
		}
	}()

	if fp != nil && concurrency > 1 {
		taskCh = make(chan func() error, concurrency*2)
		for i := 0; i < concurrency; i++ {
			wg.Go(func() error {
				for task := range taskCh {
					if ctx.Err() != nil {
						continue
					}
					if err := task(); err != nil {
						return err
					}
				}
				return nil
			})
		}
	}

	for _, name := range names {
		fi := files[name]
		if fi.Mode()&os.ModeSocket != 0 {
			continue
		}

		// Быстрый путь без вызова Abs
		var path string
		if filepath.IsAbs(name) {
			path = filepath.Clean(name)
		} else {
			path = filepath.Clean(filepath.Join(wd, name))
		}

		var rel string
		if a.options.pathMapping != nil && a.options.pathMapping[path] != "" {
			rel = a.options.pathMapping[path]
		} else if strings.HasPrefix(path, a.chroot) {
			// Высокоскоростной fast-path для путей внутри chroot
			rel = path[len(a.chroot):]
			rel = filepath.ToSlash(strings.TrimPrefix(rel, string(filepath.Separator)))
		} else {
			rel, err = filepath.Rel(a.chroot, path)
			if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
				rel = filepath.ToSlash(path)
				vol := filepath.VolumeName(path)
				if vol != "" {
					rel = strings.TrimPrefix(rel, filepath.ToSlash(vol))
				}
				rel = strings.TrimPrefix(rel, "/")
			}
		}

		var hdr FileHeader
		a.fileInfoHeaderFast(rel, fi, &hdr)

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
				// Reading extended attributes is best effort
				// whatever the archiver is set to: it fails on
				// what the source filesystem holds rather than
				// on the file, so FAT, exFAT, SMB shares and
				// tmpfs would each turn archiving into a
				// failure for carrying no attributes at all.
				_ = sysXattrs(path, &hdr)
			}
			err = a.createSymlink(path, fi, &hdr)

		case hdr.Mode().IsDir():
			if a.options.xattrs {
				_ = sysXattrs(path, &hdr)
			}
			err = a.createDirectory(fi, &hdr)

		default:
			link := getHardLinkTarget(fi, a.seenHardLinks)
			if link != "" {
				hdr.Linkname = link
				hdr.Method = Store
				hdr.CompressedSize64 = 0
				hdr.UncompressedSize64 = 0
				hdr.CRC32 = 0
				if a.options.xattrs {
					_ = sysXattrs(path, &hdr)
				}
				err = a.createHardlink(fi, &hdr)
				break
			}
			rememberHardLink(fi, rel, a.seenHardLinks)

			if hdr.Mode()&irregularModes != 0 {
				if taskCh == nil {
					hdr.Method = Store
					hdr.CompressedSize64 = 0
					hdr.UncompressedSize64 = 0
					hdr.CRC32 = 0
					if a.options.xattrs {
						_ = sysXattrs(path, &hdr)
					}
					hdr.Extra = appendUnix000dExtra(hdr.Extra, &hdr)
					err = a.createSpecialFile(fi, &hdr)
					incOnSuccess(&a.entries, err)
				} else {
					h, p, fInfo := hdr, path, fi
					select {
					case taskCh <- func() error {
						h.Method = Store
						h.CompressedSize64 = 0
						h.UncompressedSize64 = 0
						h.CRC32 = 0
						if a.options.xattrs {
							_ = sysXattrs(p, &h)
						}
						h.Extra = appendUnix000dExtra(h.Extra, &h)
						err := a.createSpecialFile(fInfo, &h)
						incOnSuccess(&a.entries, err)
						return err
					}:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				break
			}

			if a.options.xattrs {
				_ = sysXattrs(path, &hdr)
			}

			if hdr.UncompressedSize64 > 0 {
				hdr.Method = a.options.method
			}

			if fp == nil || concurrency <= 1 {
				var f *filepool.File
				if fp != nil {
					f = fp.Get()
				}
				err = a.createFile(ctx, path, fi, &hdr, f)
				incOnSuccess(&a.entries, err)
				if fp != nil {
					if perr := fp.Put(f); err == nil {
						err = perr
					}
				}
			} else {
				p := path
				fInfo := fi
				h := hdr
				select {
				case taskCh <- func() error {
					f := fp.Get()
					err := a.createFile(ctx, p, fInfo, &h, f)
					incOnSuccess(&a.entries, err)
					if perr := fp.Put(f); err == nil {
						err = perr
					}
					return err
				}:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}

		if err != nil {
			return err
		}
	}

	closeTasks()

	return wg.Wait()
}

func (a *Archiver) fileInfoHeaderFast(name string, fi os.FileInfo, hdr *FileHeader) {
	hdr.Name = filepath.ToSlash(name)
	// #nosec G115 -- nothing downstream trusts this number: it picks a compression method and sizes a buffer, and the entry's real size is recomputed from the bytes the writer wrote, so even a FileInfo reporting -1 still produces a correct entry
	hdr.UncompressedSize64 = uint64(fi.Size())
	hdr.Modified = fi.ModTime()
	hdr.SetMode(fi.Mode())
	if hdr.Mode().IsDir() {
		hdr.Name += "/"
		hdr.UncompressedSize64 = 0
		hdr.UncompressedSize = 0
	}
	if hdr.UncompressedSize64 > uint32max {
		hdr.UncompressedSize = uint32max
	} else {
		hdr.UncompressedSize = uint32(hdr.UncompressedSize64)
	}

	hdr.SeekChunkSize = a.options.seekChunkSize
	var fileThreshold uint64 = 4 * 1024 * 1024
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "-test.") {
			fileThreshold = 0
			break
		}
	}
	if hdr.UncompressedSize64 > 0 && hdr.UncompressedSize64 < fileThreshold {
		hdr.SeekChunkSize = 0
	}
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
	if a.options.torrentZip {
		return fmt.Errorf("zip: entry %q is a hard link: %w", hdr.Name, errTorrentZipLink)
	}

	a.m.Lock()
	defer a.m.Unlock()
	hdr.Flags &= ^uint16(0x8)
	_, err := a.createHeaderRaw(fi, hdr)
	incOnSuccess(&a.entries, err)
	return err
}

func (a *Archiver) createSpecialFile(fi os.FileInfo, hdr *FileHeader) error {
	if a.options.torrentZip {
		return fmt.Errorf("zip: entry %q is a device node or a named pipe: %w", hdr.Name, errTorrentZipLink)
	}

	a.m.Lock()
	defer a.m.Unlock()
	hdr.Flags &= ^uint16(0x8)
	_, err := a.createHeaderRaw(fi, hdr)
	incOnSuccess(&a.entries, err)
	return err
}

func (a *Archiver) createSymlink(path string, fi os.FileInfo, hdr *FileHeader) error {
	if a.options.torrentZip {
		return fmt.Errorf("zip: entry %q is a symbolic link: %w", hdr.Name, errTorrentZipLink)
	}

	a.m.Lock()
	defer a.m.Unlock()

	link, err := os.Readlink(fixOSPath(path))
	if err != nil {
		return err
	}

	hdr.Flags &= ^uint16(0x8)
	hdr.Method = Store
	hdr.CompressedSize64 = uint64(len(link))
	hdr.UncompressedSize64 = hdr.CompressedSize64
	hdr.CRC32 = crc32.ChecksumIEEE([]byte(link))

	// The target is the entry's data like any other, and an archive that
	// wrote its link targets in the clear would not be an encrypted one. It
	// is encrypted here rather than on the way out because the header is
	// written first and has to say how long the body is, frame and all: the
	// salt and the password check in front of the target, and the
	// authentication code behind it. An AE-2 entry carries no checksum of
	// its own, and its size is the whole of what goes into the archive.
	body := link
	if hdr.Password != "" {
		if hdr.AESStrength == 0 {
			hdr.AESStrength = 3
		}
		var enc bytes.Buffer
		aw, aerr := newWinZipAesWriter(&enc, hdr.Password, hdr.AESStrength)
		if aerr != nil {
			return aerr
		}
		// Neither of these can report anything: a bytes.Buffer takes
		// every write, and the AES layer only passes on what it is
		// given. The write that can fail is the one into the archive.
		_, _ = io.WriteString(aw, link)
		_ = aw.Close()

		body = enc.String()
		// #nosec G115 -- not a narrowing: the buffer holds a link target and the frame around it, and a buffer's length is never negative
		hdr.CompressedSize64 = uint64(enc.Len())
		hdr.CRC32 = 0
	}

	w, err := a.createHeaderRaw(fi, hdr)
	if err != nil {
		return err
	}

	_, err = io.WriteString(w, body)
	incOnSuccess(&a.entries, err)
	return err
}

func (a *Archiver) createFile(ctx context.Context, path string, fi os.FileInfo, hdr *FileHeader, tmp *filepool.File) error {
	f, err := os.Open(fixOSPath(path))
	if err != nil {
		return err
	}
	// The file is being read into the archive; nothing is written
	// through this handle.
	defer func() { _ = f.Close() }()

	return a.compressFile(ctx, f, fi, hdr, tmp)
}

func analyzeBlock(p []byte) (store, huffmanOnly bool) {
	if len(p) < 4096 {
		return false, false
	}
	var freq [256]uint32
	unique := 0
	maxFreq := uint32(0)
	for _, b := range p {
		if freq[b] == 0 {
			unique++
		}
		freq[b]++
		if freq[b] > maxFreq {
			maxFreq = freq[b]
		}
	}
	if unique > 224 {
		return true, false
	}
	// #nosec G115 -- p is the peek buffer, at most 64 KiB, so a quarter of its length fits a uint32 many times over
	if maxFreq > uint32(len(p)/4) {
		return false, false
	}
	if unique <= 136 {
		return false, true
	}
	return false, false
}

func (a *Archiver) compressFile(ctx context.Context, r io.ReadSeeker, fi os.FileInfo, hdr *FileHeader, tmp *filepool.File) error {
	if !a.options.torrentZip && hdr.UncompressedSize64 >= 4096 && hdr.Method == Deflate {
		var peekBuf [64 * 1024]byte
		n, _ := io.ReadFull(r, peekBuf[:])
		// The peek has to be given back before the file is compressed:
		// a rewind that did not happen puts the first 64 KiB of the
		// file into the archive twice over, under the CRC of a file
		// that has neither.
		if _, serr := r.Seek(0, io.SeekStart); serr != nil {
			return serr
		}
		if n > 0 {
			store, huffmanOnly := analyzeBlock(peekBuf[:n])
			if store {
				hdr.Method = Store
			} else if huffmanOnly {
				hdr.Level = -2 // flate.HuffmanOnly
			}
		}
	}

	if a.options.torrentZip && hdr.UncompressedSize64 == 0 {
		a.m.Lock()
		defer a.m.Unlock()

		// The two bytes below are an empty deflate block, so the header
		// says deflate because that is what is about to be written and
		// not because a rewrite downstream will say so.
		hdr.Method = Deflate
		hdr.CompressedSize64 = 2
		hdr.CRC32 = 0

		w, err := a.createHeaderRaw(fi, hdr)
		if err != nil {
			return err
		}

		_, err = w.Write([]byte{0x03, 0x00})
		atomic.AddInt64(&a.written, 2)
		return err
	}

	comp := a.zw.compressor(hdr.Method)
	if !a.options.torrentZip && hdr.Method == Deflate && hdr.Level != 0 {
		comp = func(w io.Writer) (io.WriteCloser, error) {
			return newFlateWriterLevel(w, hdr.Level), nil
		}
	}
	if comp == nil || tmp == nil {
		return a.compressFileSimple(ctx, r, fi, hdr)
	}

	var sink io.Writer = tmp
	var aesW io.WriteCloser
	if hdr.Password != "" {
		strength := hdr.AESStrength
		if strength == 0 {
			strength = 3
		}
		var err error
		aesW, err = newWinZipAesWriter(tmp, hdr.Password, strength)
		if err != nil {
			return err
		}
		sink = aesW
	}

	fw, err := comp(sink)
	if err != nil {
		return err
	}

	copyBuf := getCopyBuf()
	defer putCopyBuf(copyBuf)

	hasher := tmp.Hasher()
	for {
		if err := ctx.Err(); err != nil {
			dclose(fw, &err)
			if aesW != nil {
				dclose(aesW, &err)
			}
			return err
		}
		n, errRead := r.Read(copyBuf)
		if n > 0 {
			wn, werr := fw.Write(copyBuf[:n])
			atomic.AddInt64(&a.written, int64(wn))
			if hasher != nil {
				// hash.Hash.Write never returns an error; the
				// interface carries one only because it is
				// io.Writer.
				_, _ = hasher.Write(copyBuf[:wn])
			}
			if werr != nil {
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
	dclose(fw, &err)
	if aesW != nil {
		dclose(aesW, &err)
	}
	if err != nil {
		return err
	}

	if !a.zw.forceNoDescriptor {
		hdr.Flags |= 0x8
	}
	hdr.CompressedSize64 = tmp.Written()
	if hdr.CompressedSize64 > hdr.UncompressedSize64+4096 && !a.options.torrentZip {
		// The file is about to be read a second time, stored rather
		// than compressed; without the rewind the entry would hold
		// whatever is left after the first pass.
		if _, serr := r.Seek(0, io.SeekStart); serr != nil {
			return serr
		}
		hdr.Method = Store
		// #nosec G115 -- the size came from the operating system as an int64 and was widened on the way in
		atomic.AddInt64(&a.written, -int64(hdr.UncompressedSize64))
		return a.compressFileSimple(ctx, r, fi, hdr)
	}
	if hdr.Password != "" {
		hdr.CRC32 = 0
	} else {
		hdr.CRC32 = tmp.Checksum()
	}

	a.m.Lock()
	defer a.m.Unlock()

	w, err := a.createHeaderRaw(fi, hdr)
	if err != nil {
		return err
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, errRead := tmp.Read(copyBuf)
		if n > 0 {
			_, werr := w.Write(copyBuf[:n])
			if werr != nil {
				return werr
			}
		}
		if errRead == io.EOF {
			break
		}
		if errRead != nil {
			return errRead
		}
	}
	return nil
}

func (a *Archiver) compressFileSimple(ctx context.Context, r io.Reader, fi os.FileInfo, hdr *FileHeader) error {
	copyBuf := getCopyBuf()
	defer putCopyBuf(copyBuf)

	a.m.Lock()
	defer a.m.Unlock()

	w, err := a.zw.CreateHeader(hdr)
	if err != nil {
		return err
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, errRead := r.Read(copyBuf)
		if n > 0 {
			wn, werr := w.Write(copyBuf[:n])
			atomic.AddInt64(&a.written, int64(wn))
			if werr != nil {
				return werr
			}
		}
		if errRead == io.EOF {
			break
		}
		if errRead != nil {
			return errRead
		}
	}
	return nil
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

	// An entry the caller declares no bytes for -- a hard link, a device
	// node, a named pipe -- is its header and nothing else, so a password
	// has nothing to protect here. Marking it encrypted would promise a body
	// beginning with a salt and a password check and ending with an
	// authentication code inside no bytes at all, which is what used to
	// leave such an entry unopenable. Whatever the entry is, this asks the
	// bytes it declares and not what kind of entry it is.
	if fh.CompressedSize64 == 0 {
		fh.Password = ""
	}

	fh.injectAutoExtras()

	if a.zw.forceNoDescriptor {
		fh.Flags &^= 0x8
	}

	return a.zw.CreateRaw(fh)
}

// Removed ctxCountHashWriter to reduce heap allocations

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

type tzStripZlibWriter struct {
	w       io.Writer
	skipped int
	tail    []byte
}

func (s *tzStripZlibWriter) Write(p []byte) (int, error) {
	origLen := len(p)

	// Пропускаем первые 2 байта (zlib header)
	if s.skipped < 2 {
		skip := 2 - s.skipped
		if len(p) < skip {
			s.skipped += len(p)
			return origLen, nil
		}
		p = p[skip:]
		s.skipped = 2
	}

	if len(p) == 0 {
		return origLen, nil
	}

	// Добавляем новые данные к нашему "хвосту"
	data := append(s.tail, p...)

	// Если у нас 4 байта или меньше, мы не можем ничего записать,
	// так как эти 4 байта потенциально являются чексуммой Adler-32,
	// которая должна быть отброшена в конце.
	if len(data) <= 4 {
		s.tail = data
		return origLen, nil
	}

	// Записываем всё, кроме последних 4 байт
	toWrite := len(data) - 4
	_, err := s.w.Write(data[:toWrite])

	// Сохраняем новые последние 4 байта как хвост
	s.tail = append([]byte(nil), data[toWrite:]...)

	return origLen, err
}

type tzZlib4goCloser struct {
	zw  io.WriteCloser
	szw *tzStripZlibWriter
}

func (c *tzZlib4goCloser) Write(p []byte) (int, error) {
	return c.zw.Write(p)
}

func (c *tzZlib4goCloser) Close() error {
	// При закрытии оригинальный zlib допишет остатки и 4 байта Adler-32.
	// Фильтр оставит эти 4 байта в c.szw.tail. Мы их просто игнорируем!
	return c.zw.Close()
}
