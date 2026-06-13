package zip

import (
    "errors"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
    "io/fs"
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

func extractPasswordFromOpts(opts []ExtractorOption) string {
	var o extractorOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o.password
}

func NewExtractor(filename, chroot string, opts ...ExtractorOption) (*Extractor, error) {
	password := extractPasswordFromOpts(opts)
	zr, err := OpenReaderWithPassword(filename, password)
	if err != nil {
		return nil, err
	}
	return newExtractor(&zr.Reader, zr, chroot, opts)
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
	e.options.maxDecompressionRatio = 200      // 200:1 default
	e.options.xattrs = true
	e.options.chownErrorHandler = func(name string, err error) error {
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
				f.Close()
				if err == nil && len(names) > 0 {
					return errors.New("zip: refusing to extract incremental archive into a non-empty directory without a pre-existing .zip_dumpdir marker (prevents accidental data loss)")
				}
			}
		}
	}

	if len(e.zr.File) == 1 && (e.zr.File[0].Name == "Solid.zip" || strings.HasSuffix(e.zr.File[0].Name, ".solid")) {
		r, err := e.zr.File[0].Open()
		if err != nil {
			return err
		}
		defer r.Close()

		err = e.extractSolidStream(r, ctx)
		if err != nil {
			maxFallback := int64(e.options.maxFileSize) * 10
			if maxFallback <= 0 {
				maxFallback = 100 * 1024 * 1024 * 1024 // 100 GB default limit
			}
			if int64(e.zr.File[0].UncompressedSize64) > maxFallback {
				return fmt.Errorf("zip: Solid archive too large for temp file fallback (%d bytes)", e.zr.File[0].UncompressedSize64)
			}

			// Use chroot instead of /tmp to ensure enough space and security
			os.MkdirAll(e.chroot, 0755)
			tempFile, terr := os.CreateTemp(e.chroot, "solid_fallback_*.zip")
			if terr != nil {
				return fmt.Errorf("fallback failed: %v, original: %v", terr, err)
			}
			defer os.Remove(tempFile.Name())
			defer tempFile.Close()

			r2, terr := e.zr.File[0].Open()
			if terr != nil {
				return err
			}
			_, terr = io.Copy(tempFile, &ctxReader{r: r2, ctx: ctx})
			r2.Close()
			if terr != nil {
				return err
			}

			innerOpts := []ExtractorOption{
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
				WithExtractorIncremental(e.options.incremental),
			}

			innerExtractor, terr := NewExtractor(tempFile.Name(), e.chroot, innerOpts...)
			if terr != nil {
				return err
			}
			defer innerExtractor.Close()

			return innerExtractor.Extract(ctx)
		}
	} else {
		limiter := make(chan struct{}, e.options.concurrency)

		wg, ctx := errgroup.WithContext(ctx)
		defer func() {
			if werr := wg.Wait(); werr != nil {
				err = werr
			}
		}()

		err = func() error {
			for i, file := range e.zr.File {
				name := file.Name
			if e.options.stripComponents > 0 {
				stripped, ok := stripComponents(name, e.options.stripComponents)
				if !ok {
					continue // Skip file with fewer or equal components
				}
				name = stripped
			}

			path, err := e.absPath(name)
			if err != nil {
				return err
			}

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
					os.RemoveAll(path) // Safer than os.Remove for preventing TOCTOU directory overwrites
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
			case file.Mode()&os.ModeSymlink != 0 || file.Linkname != "" || strings.Contains(file.Name, ":"):
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
				gf, p := e.zr.File[i], path // Local copies
				wg.Go(func() error {
					defer func() { <-limiter }()
					err := e.createFile(ctx, p, gf)
					if err == nil {
						err = e.updateFileMetadata(p, gf)
					}
					if err != nil && e.options.tolerant {
						fmt.Printf("zip: skipping corrupted file %q: %v\n", gf.Name, err)
						return nil // Suppress error to continue
					}
					return err
				})
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

		for _, file := range e.zr.File {
			if file.Mode()&os.ModeSymlink == 0 && file.Linkname == "" {
				continue
			}
			path, err := e.absPath(file.Name)
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
			path, err := e.absPath(file.Name)
			if err != nil {
				if e.options.tolerant {
					continue
				}
				return err
			}
			err = e.updateFileMetadata(path, file)
			if err != nil {
				if e.options.tolerant {
					continue
				}
				return err
			}
		}

		for _, file := range e.zr.File {
			if !strings.Contains(file.Name, ":") {
				continue
			}
			path, err := e.absPath(file.Name)
			if err != nil {
				return err
			}
			if err := e.createFile(parentCtx, path, file); err != nil {
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
			defer f.Close()
			scanner := bufio.NewScanner(f)
			activeFiles := make(map[string]bool)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					activeFiles[line] = true
				}
			}
			activeFiles[".zip_dumpdir"] = true

			filepath.Walk(e.chroot, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if path == e.chroot {
					return nil
				}
				rel, err := filepath.Rel(e.chroot, path)
				if err != nil {
					return err
				}
				relClean := filepath.ToSlash(rel)
				if info.IsDir() {
					relClean += "/"
				}
				if !activeFiles[relClean] {
					os.RemoveAll(path)
				}
				return nil
			})
		}
	}

	return nil
}

func (e *Extractor) extractSolidStream(r io.Reader, ctx context.Context) error {
	buf := make([]byte, 30)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := io.ReadFull(r, buf[:4]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return err
		}
		sig := binary.LittleEndian.Uint32(buf[:4])
		if sig != fileHeaderSignature {
			break // Reached Central Directory
		}

		if _, err := io.ReadFull(r, buf[4:30]); err != nil {
			return err
		}

		flags := binary.LittleEndian.Uint16(buf[6:8])
		method := binary.LittleEndian.Uint16(buf[8:10])
		modTime := binary.LittleEndian.Uint16(buf[10:12])
		modDate := binary.LittleEndian.Uint16(buf[12:14])
		crc32Val := binary.LittleEndian.Uint32(buf[14:18])
		compSize := binary.LittleEndian.Uint32(buf[18:22])
		uncompSize := binary.LittleEndian.Uint32(buf[22:26])
		filenameLen := binary.LittleEndian.Uint16(buf[26:28])
		extraLen := binary.LittleEndian.Uint16(buf[28:30])

		filenameBuf := make([]byte, filenameLen)
		if _, err := io.ReadFull(r, filenameBuf); err != nil {
			return err
		}
		extraBuf := make([]byte, extraLen)
		if _, err := io.ReadFull(r, extraBuf); err != nil {
			return err
		}

		name := string(filenameBuf)
		if method != Store || (uncompSize == 0 && flags&0x8 != 0) {
			return fmt.Errorf("zip: sequential extraction not supported for method %d with flags %x", method, flags)
		}

		if e.options.stripComponents > 0 {
			stripped, ok := stripComponents(name, e.options.stripComponents)
			if !ok {
				if err := skipBytes(r, int64(uncompSize), flags); err != nil {
					return err
				}
				continue
			}
			name = stripped
		}

		path, err := e.absPath(name)
		if err != nil {
			return err
		}

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

		fh := &FileHeader{
			Name:               name,
			Method:             method,
			Flags:              flags,
			CRC32:              crc32Val,
			CompressedSize64:   uint64(compSize),
			UncompressedSize64: uint64(uncompSize),
			Extra:              extraBuf,
		}
		fh.Modified = msDosTimeToTime(modDate, modTime)

		for extra := readBuf(extraBuf); len(extra) >= 4; {
			fieldTag := extra.uint16()
			fieldSize := int(extra.uint16())
			if len(extra) < fieldSize {
				break
			}
			fieldBuf := extra.sub(fieldSize)
			switch fieldTag {
			case infoZipNewUnixExtraID:
				if uid, gid, ok := parseUnixExtra(extraBuf); ok {
					fh.Uid = uid
					fh.Gid = gid
					fh.OwnerSet = true
				}
			case unixOwnerNameExtraID:
				if uname, gname, ok := parseUnixOwnerNamesExtra(extraBuf); ok {
					fh.Uname = uname
					fh.Gname = gname
				}
			case ntfsAclExtraID:
				fh.Acl = parseNtfsAcl(extraBuf)
			case xattrExtraID:
				if fh.Xattrs == nil {
					fh.Xattrs = make(map[string]string)
				}
				for len(fieldBuf) >= 4 {
					klen := int(fieldBuf.uint16())
					if len(fieldBuf) < klen+2 {
						break
					}
					k := string(fieldBuf.sub(klen))
					vlen := int(fieldBuf.uint16())
					if len(fieldBuf) < vlen {
						break
					}
					v := string(fieldBuf.sub(vlen))
					fh.Xattrs[k] = v
				}
			}
		}

		isDir := len(name) > 0 && name[len(name)-1] == '/'
		if isDir {
			fh.SetMode(fs.ModeDir | 0755)
		} else {
			fh.SetMode(0644)
		}

		if isDir {
			os.MkdirAll(path, 0755)
			e.updateFileMetadata(path, &File{FileHeader: *fh})
		} else {
			if e.options.unlinkFirst {
				os.Remove(path)
			}
			os.MkdirAll(filepath.Dir(path), 0755)

			writePath := path
			if e.options.safeWrites {
				writePath = path + ".tmp"
			}

			f, err := os.OpenFile(writePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				return err
			}

			hasher := crc32.NewIEEE()
			var limitR io.Reader = io.LimitReader(r, int64(uncompSize))
			_, err = io.Copy(f, io.TeeReader(limitR, hasher))
			f.Close()
			if err == nil && crc32Val != 0 && hasher.Sum32() != crc32Val {
				err = ErrChecksum
			}
			if err != nil {
				os.Remove(writePath)
				return err
			}

			if flags&0x8 != 0 {
				var sigBuf [4]byte
				if _, err := io.ReadFull(r, sigBuf[:]); err != nil {
					return err
				}
				sig := binary.LittleEndian.Uint32(sigBuf[:])
				isZip64 := compSize == 0xFFFFFFFF || uncompSize == 0xFFFFFFFF
				var remaining int
				if sig == dataDescriptorSignature {
					if isZip64 {
						remaining = 20
					} else {
						remaining = 12
					}
				} else {
					if isZip64 {
						remaining = 16
					} else {
						remaining = 8
					}
				}
				discardBuf := make([]byte, remaining)
				if _, err := io.ReadFull(r, discardBuf); err != nil {
					return err
				}
			}

			if e.options.safeWrites {
				if rerr := os.Rename(writePath, path); rerr != nil {
					os.Remove(writePath)
					return rerr
				}
			}

			e.updateFileMetadata(path, &File{FileHeader: *fh})
			atomic.AddInt64(&e.written, int64(uncompSize))
		}
		atomic.AddInt64(&e.entries, 1)
	}
	return nil
}

func skipBytes(r io.Reader, n int64, flags uint16) error {
	if _, err := io.CopyN(io.Discard, r, n); err != nil {
		return err
	}
	if flags&0x8 != 0 {
		var sigBuf [4]byte
		if _, err := io.ReadFull(r, sigBuf[:]); err != nil {
			return err
		}
		sig := binary.LittleEndian.Uint32(sigBuf[:])
		isZip64 := n >= int64(uint32max)
		var remaining int
		if sig == dataDescriptorSignature {
			if isZip64 {
				remaining = 20
			} else {
				remaining = 12
			}
		} else {
			if isZip64 {
				remaining = 16
			} else {
				remaining = 8
			}
		}
		discardBuf := make([]byte, remaining)
		if _, err := io.ReadFull(r, discardBuf); err != nil {
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

		target := string(name)
		if filepath.IsAbs(target) {
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
			if fi, err := os.Stat(filepath.Join(filepath.Dir(path), target)); err == nil {
				isDir = fi.IsDir()
			}
			if err := createWindowsSymlink(target, path, isDir); err != nil {
				return err
			}
		} else {
			if err := os.Symlink(target, path); err != nil {
				return err
			}
		}
	} else if file.Linkname != "" {
		linkname := file.Linkname
		if strings.Contains(linkname, MappedStringMarkStr) {
			linkname = string(encodeMappedString(linkname))
		}
		targetPath := filepath.Join(e.chroot, linkname)
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
		if err == nil {
			if currentOffset, serr := f.Seek(0, io.SeekCurrent); serr == nil {
				f.Truncate(currentOffset)
			}
		}
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
		defer func() {
			bw.Reset(nil)
			bufioWriterPool.Put(bw)
		}()

		bw.Reset(&ctxCountWriter{f, &e.written, ctx})
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

	if strings.Contains(file.Name, MappedStringMarkStr) {
		path = filepath.Join(filepath.Dir(path), string(encodeMappedString(file.Name)))
	}

	if e.options.xattrs {
		applyXattrs(path, &file.FileHeader)
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
	if strings.Contains(name, MappedStringMarkStr) {
		name = string(encodeMappedString(name))
	}
	return filepath.Abs(filepath.Join(e.chroot, name))
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
// synthesizeParentDirs guarantees that all parent folders for the target path
// exist on disk, recovering missing or corrupted directory headers on the fly,
// while safely resolving path conflicts.
func (e *Extractor) synthesizeParentDirs(targetPath string) error {
	dir := filepath.Dir(targetPath)

	// Fast path: ensure parent directory chain exists using standard OS tools
	err := os.MkdirAll(dir, 0755)
	if err == nil {
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
		fi, errStat := os.Lstat(current)
		if errStat != nil {
			if os.IsNotExist(errStat) {
				if errMk := os.Mkdir(current, 0755); errMk != nil && !os.IsExist(errMk) {
					return errMk
				}
			} else {
				return errStat
			}
		} else if !fi.IsDir() {
			// Resolve conflict: remove blocking file and create directory
			if errRm := os.Remove(current); errRm == nil {
				if errMk := os.Mkdir(current, 0755); errMk != nil {
					return errMk
				}
			} else {
				return errRm
			}
		}
	}
	return nil
}
