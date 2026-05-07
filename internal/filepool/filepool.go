package filepool

import (
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"strings"
)

var ErrPoolSizeLessThanZero = errors.New("pool size must be greater than zero")

const defaultBufferSize = 2 * 1024 * 1024

type filePoolCloseError []error

func (e filePoolCloseError) Len() int { return len(e) }

func (e filePoolCloseError) Error() string {
	if len(e) == 1 {
		return e[0].Error()
	}
	var sb strings.Builder
	for _, err := range e {
		sb.WriteString(err.Error() + "\n")
	}
	return sb.String()
}

func (e filePoolCloseError) Unwrap() error {
	if len(e) > 1 {
		return e[1:]
	}
	return nil
}

// FilePool represents a pool of files that can be used as buffers.
type FilePool struct {
	files   []*File
	limiter chan int
}

func New(dir string, poolSize int, bufferSize int) (*FilePool, error) {
	if poolSize <= 0 {
		return nil, ErrPoolSizeLessThanZero
	}
	fp := &FilePool{}

	fp.files = make([]*File, poolSize)
	fp.limiter = make(chan int, poolSize)

	if bufferSize < 0 {
		bufferSize = defaultBufferSize
	}

	for i := range fp.files {
		fp.files[i] = newFile(dir, i, bufferSize)
		fp.limiter <- i
	}

	return fp, nil
}

func (fp *FilePool) Get() *File {
	idx := <-fp.limiter
	return fp.files[idx]
}

func (fp *FilePool) Put(f *File) {
	f.reset()
	fp.limiter <- f.idx
}

func (fp *FilePool) Close() error {
	var err filePoolCloseError
	for _, f := range fp.files {
		if f == nil || f.f == nil {
			continue
		}
		if cerr := f.f.Close(); cerr != nil {
			err = append(err, cerr)
		}
		if rerr := os.Remove(f.f.Name()); rerr != nil && !os.IsNotExist(rerr) {
			err = append(err, rerr)
		}
	}
	fp.files = nil
	if err.Len() > 0 {
		return err
	}
	return nil
}

// File is a file backed buffer.
type File struct {
	dir string
	idx int
	w   int64
	r   int64
	crc hash.Hash32

	f    *os.File
	buf  []byte
	size int
}

func newFile(dir string, idx, size int) *File {
	return &File{
		dir:  dir,
		idx:  idx,
		size: size,
		crc:  crc32.NewIEEE(),
	}
}

func (f *File) Write(p []byte) (n int, err error) {
	if f.buf == nil && f.size > 0 {
		f.buf = make([]byte, f.size)
	}

	if f.w < int64(len(f.buf)) {
		n = copy(f.buf[f.w:], p)
		p = p[n:]
		f.w += int64(n)
	}

	if len(p) > 0 {
		if f.f == nil {
			f.f, err = os.CreateTemp(f.dir, "fastzip_*")
			if err != nil {
				return n, err
			}
		}

		bn := n
		n, err = f.f.WriteAt(p, f.w-int64(len(f.buf)))
		f.w += int64(n)
		n += bn
		if err != nil {
			return n, err
		}
	}

	return n, err
}

func (f *File) Read(p []byte) (n int, err error) {
	remaining := f.w - f.r
	if remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}

	if f.r < int64(len(f.buf)) {
		n = copy(p, f.buf[f.r:])
		f.r += int64(n)
		p = p[n:]
	}

	if len(p) > 0 && f.r >= int64(len(f.buf)) {
		bn := n
		n, err = f.f.ReadAt(p, f.r-int64(len(f.buf)))
		f.r += int64(n)
		n += bn
	}

	return n, err
}

func (f *File) Written() uint64 {
	return uint64(f.w)
}

func (f *File) Hasher() io.Writer {
	return f.crc
}

func (f *File) Checksum() uint32 {
	return f.crc.Sum32()
}

func (f *File) reset() {
	f.w = 0
	f.r = 0
	f.crc.Reset()
	if f.f != nil {
		f.f.Truncate(0)
	}
}