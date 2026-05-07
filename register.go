package zip

import (
	"errors"
	"io"
	"sync"
	"compress/bzip2"
	"bytes"
	"encoding/binary"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz/lzma"
	"github.com/dovydenkovas/ppmd"
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
var zstdReaderPool sync.Pool

type pooledZstdReader struct {
	mu  sync.Mutex
	dec *zstd.Decoder
}

func (r *pooledZstdReader) Read(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dec == nil {
		return 0, errors.New("Read after Close")
	}
	return r.dec.Read(p)
}

func (r *pooledZstdReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var err error
	if r.dec != nil {
		err = r.dec.Reset(nil)
		zstdReaderPool.Put(r.dec)
		r.dec = nil
	}
	return err
}

func newZstdReader(r io.Reader) io.ReadCloser {
	dec, _ := zstdReaderPool.Get().(*zstd.Decoder)
	if dec == nil {
		dec, _ = zstd.NewReader(nil, zstd.WithDecoderLowmem(true), zstd.WithDecoderConcurrency(1))
	}
	if dec != nil {
		dec.Reset(r)
	}
	return &pooledZstdReader{dec: dec}
}

var zstdWriterPool sync.Pool

type pooledZstdWriter struct {
	mu  sync.Mutex
	enc *zstd.Encoder
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
	var err error
	if pw.enc != nil {
		err = pw.enc.Close()
		zstdWriterPool.Put(pw.enc)
		pw.enc = nil
	}
	return err
}

func newZstdWriter(w io.Writer) (io.WriteCloser, error) {
	enc, _ := zstdWriterPool.Get().(*zstd.Encoder)
	if enc == nil {
		enc, _ = zstd.NewWriter(nil, zstd.WithEncoderCRC(false))
	}
	if enc == nil {
		return nil, errors.New("zip: zstd encoder initialization failed")
	}
	enc.Reset(w)
	return &pooledZstdWriter{enc: enc}, nil
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
	decompressors.Store(BZIP2, Decompressor(func(r io.Reader) io.ReadCloser { return io.NopCloser(bzip2.NewReader(r)) }))
	decompressors.Store(LZMA, Decompressor(newLZMAReader))
	decompressors.Store(ZSTD, Decompressor(newZstdReader))
}

func newPPMdReader(r io.Reader, size uint64) io.ReadCloser {
	// APPNOTE 5.10.3: Параметры PPMd хранятся в первых 2 байтах данных.
	props := make([]byte, 2)
	if _, err := io.ReadFull(r, props); err != nil {
		return nil
	}
	val := binary.LittleEndian.Uint16(props)

	// Разбор параметров:
	// Order: bits 0-3 (+1)
	// MemSize: bits 4-11 (+1) в МБ
	// Restoration: bits 12-15
	order := int(val&0xF) + 1
	memSize := (int((val>>4)&0xFF) + 1)

	rd, err := ppmd.NewH7zReader(r, order, memSize, int(size))
	if err != nil {
		return nil
	}
	return io.NopCloser(&rd)
}
func newLZMAReader(r io.Reader) io.ReadCloser {
	// APPNOTE 5.8.8: LZMA Properties Header в ZIP:
	// 2 байта - LZMA Version
	// 2 байта - Properties Size (обычно 5)
	// N байт - Properties Data (1 байт параметров + 4 байта размера словаря)

	meta := make([]byte, 4)
	if _, err := io.ReadFull(r, meta); err != nil {
		return nil
	}

	propSize := int(binary.LittleEndian.Uint16(meta[2:4]))
	if propSize != 5 {
		// Для ZIP Method 14 по спецификации ожидается 5 байт LZMA1 свойств.
		return nil
	}

	props := make([]byte, propSize)
	if _, err := io.ReadFull(r, props); err != nil {
		return nil
	}

	// Библиотека ulikunitz/xz/lzma ожидает классический .lzma заголовок (13 байт):
	// [1b props][4b dict size][8b uncompressed size]
	fullHeader := make([]byte, 13)
	copy(fullHeader[0:5], props)
	for i := 0; i < 8; i++ {
		// Указываем 0xFF, что значит "размер неизвестен, читать до EOS маркера"
		fullHeader[5+i] = 0xFF
	}

	mr := io.MultiReader(bytes.NewReader(fullHeader), r)
	rd, err := lzma.NewReader(mr)
	if err != nil {
		return nil
	}
	// lzma.Reader из этого пакета не реализует Close, так как работает с потоком.
	// Оборачиваем в NopCloser.
	return io.NopCloser(rd)
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