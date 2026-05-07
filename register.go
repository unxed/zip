package zip

import (
	"errors"
	"io"
	"sync"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/zstd"
)

type Compressor func(w io.Writer) (io.WriteCloser, error)
type Decompressor func(r io.Reader) io.ReadCloser

var flateWriterPool sync.Pool

func newFlateWriter(w io.Writer) io.WriteCloser {
	fw, ok := flateWriterPool.Get().(*flate.Writer)
	if ok {
		fw.Reset(w)
	} else {
		fw, _ = flate.NewWriter(w, 5) // klauspost default
	}
	return &pooledFlateWriter{fw: fw}
}

type pooledFlateWriter struct {
	mu sync.Mutex
	fw *flate.Writer
}

func (w *pooledFlateWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fw == nil {
		return 0, errors.New("Write after Close")
	}
	return w.fw.Write(p)
}

func (w *pooledFlateWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var err error
	if w.fw != nil {
		err = w.fw.Close()
		flateWriterPool.Put(w.fw)
		w.fw = nil
	}
	return err
}

var flateReaderPool sync.Pool

func newFlateReader(r io.Reader) io.ReadCloser {
	fr, ok := flateReaderPool.Get().(io.ReadCloser)
	if ok {
		fr.(flate.Resetter).Reset(r, nil)
	} else {
		fr = flate.NewReader(r)
	}
	return &pooledFlateReader{fr: fr}
}

type pooledFlateReader struct {
	mu sync.Mutex
	fr io.ReadCloser
}

func (r *pooledFlateReader) Read(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fr == nil {
		return 0, errors.New("Read after Close")
	}
	return r.fr.Read(p)
}

func (r *pooledFlateReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var err error
	if r.fr != nil {
		err = r.fr.Close()
		flateReaderPool.Put(r.fr)
		r.fr = nil
	}
	return err
}

// ZSTD Pools
type zstdReader struct {
	pool *sync.Pool
	*zstd.Decoder
}

func (zr *zstdReader) Close() error {
	err := zr.Decoder.Reset(nil)
	zr.pool.Put(zr)
	return err
}

func newZstdReader(r io.Reader) io.ReadCloser {
	pool := &sync.Pool{}
	pool.New = func() interface{} {
		decoder, _ := zstd.NewReader(nil, zstd.WithDecoderLowmem(true), zstd.WithDecoderConcurrency(1))
		return &zstdReader{pool, decoder}
	}
	fr := pool.Get().(*zstdReader)
	fr.Decoder.Reset(r)
	return fr
}

func newZstdWriter(w io.Writer) (io.WriteCloser, error) {
	pool := &sync.Pool{}
	pool.New = func() interface{} {
		encoder, _ := zstd.NewWriter(nil, zstd.WithEncoderCRC(false))
		return encoder
	}
	encoder := pool.Get().(*zstd.Encoder)
	encoder.Reset(w)

	// Create a wrapper that puts the encoder back to the pool
	return &pooledZstdWriter{pool: pool, enc: encoder}, nil
}

type pooledZstdWriter struct {
	mu   sync.Mutex
	pool *sync.Pool
	enc  *zstd.Encoder
}

func (pw *pooledZstdWriter) Write(p []byte) (int, error) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if pw.enc == nil {
		return 0, errors.New("Write after Close")
	}
	return pw.enc.Write(p)
}

func (pw *pooledZstdWriter) Close() error {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if pw.enc == nil {
		return nil
	}
	err := pw.enc.Close()
	pw.pool.Put(pw.enc)
	pw.enc = nil
	return err
}

type nopCloser struct {
	io.Writer
}

func (w nopCloser) Close() error { return nil }

var (
	compressors   sync.Map
	decompressors sync.Map
)

func init() {
	compressors.Store(Store, Compressor(func(w io.Writer) (io.WriteCloser, error) { return &nopCloser{w}, nil }))
	compressors.Store(Deflate, Compressor(func(w io.Writer) (io.WriteCloser, error) { return newFlateWriter(w), nil }))
	compressors.Store(ZSTD, Compressor(newZstdWriter))

	decompressors.Store(Store, Decompressor(io.NopCloser))
	decompressors.Store(Deflate, Decompressor(newFlateReader))
	decompressors.Store(ZSTD, Decompressor(newZstdReader))
}

func RegisterDecompressor(method uint16, dcomp Decompressor) {
	if _, dup := decompressors.LoadOrStore(method, dcomp); dup {
		panic("decompressor already registered")
	}
}

func RegisterCompressor(method uint16, comp Compressor) {
	if _, dup := compressors.LoadOrStore(method, comp); dup {
		panic("compressor already registered")
	}
}

func compressor(method uint16) Compressor {
	ci, ok := compressors.Load(method)
	if !ok {
		return nil
	}
	return ci.(Compressor)
}

func decompressor(method uint16) Decompressor {
	di, ok := decompressors.Load(method)
	if !ok {
		return nil
	}
	return di.(Decompressor)
}