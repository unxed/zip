package zip

import (
	"bytes"
	"compress/bzip2"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/dovydenkovas/ppmd"
	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/zstd"
	"github.com/unxed/xz/lzma"
)

type Compressor func(w io.Writer) (io.WriteCloser, error)
type Decompressor func(r io.Reader) io.ReadCloser

var flateWriterPool sync.Pool

var (
	flatePoolsMu sync.Mutex
	flatePools   = make(map[int]*sync.Pool)
)

func getFlateWriterPool(level int) *sync.Pool {
	flatePoolsMu.Lock()
	defer flatePoolsMu.Unlock()
	p, ok := flatePools[level]
	if !ok {
		p = &sync.Pool{}
		flatePools[level] = p
	}
	return p
}

type pooledFlateWriter struct {
	mu   sync.Mutex
	fw   *flate.Writer
	w    io.Writer
	pool *sync.Pool
}

func newFlateWriter(w io.Writer) io.WriteCloser {
	return newFlateWriterLevel(w, 5)
}

func newFlateWriterLevel(w io.Writer, level int) io.WriteCloser {
	pool := getFlateWriterPool(level)
	fw, ok := pool.Get().(*flate.Writer)
	if ok {
		fw.Reset(w)
	} else {
		fw, _ = flate.NewWriter(w, level)
	}
	return &pooledFlateWriter{fw: fw, w: w, pool: pool}
}

func (w *pooledFlateWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fw == nil {
		return 0, errors.New("Write after Close")
	}
	return w.fw.Write(p)
}

func (w *pooledFlateWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fw == nil {
		return errors.New("Flush after Close")
	}
	return w.fw.Flush()
}
func (w *pooledFlateWriter) ResetDict() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fw != nil && w.w != nil {
		w.fw.ResetDict(w.w, nil)
	}
}

func (w *pooledFlateWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var err error
	if w.fw != nil {
		err = w.fw.Close()
		if w.pool != nil {
			w.pool.Put(w.fw)
		} else {
			flateWriterPool.Put(w.fw)
		}
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

var (
	zstdPoolsMu sync.Mutex
	zstdPools   = make(map[int]*sync.Pool)
)

func getZstdWriterPool(level int) *sync.Pool {
	zstdPoolsMu.Lock()
	defer zstdPoolsMu.Unlock()
	p, ok := zstdPools[level]
	if !ok {
		p = &sync.Pool{}
		zstdPools[level] = p
	}
	return p
}

type pooledZstdWriter struct {
	mu   sync.Mutex
	enc  *zstd.Encoder
	w    io.Writer
	pool *sync.Pool
}

func (pw *pooledZstdWriter) Write(p []byte) (int, error) {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if pw.enc == nil {
		return 0, errors.New("Write after Close")
	}
	return pw.enc.Write(p)
}

func (pw *pooledZstdWriter) Flush() error {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if pw.enc == nil {
		return errors.New("Flush after Close")
	}
	return pw.enc.Flush()
}

func (pw *pooledZstdWriter) ResetDict() {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	if pw.enc != nil && pw.w != nil {
		pw.enc.Reset(pw.w)
	}
}

func (pw *pooledZstdWriter) Close() error {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	var err error
	if pw.enc != nil {
		err = pw.enc.Close()
		if pw.pool != nil {
			pw.pool.Put(pw.enc)
		} else {
			zstdWriterPool.Put(pw.enc)
		}
		pw.enc = nil
	}
	return err
}

func newZstdWriter(w io.Writer) (io.WriteCloser, error) {
	return newZstdWriterLevel(w, 3)
}

func newZstdWriterLevel(w io.Writer, level int) (io.WriteCloser, error) {
	pool := getZstdWriterPool(level)
	enc, _ := pool.Get().(*zstd.Encoder)
	if enc == nil {
		enc, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)), zstd.WithEncoderCRC(false))
	}
	if enc == nil {
		return nil, errors.New("zip: zstd encoder initialization failed")
	}
	enc.Reset(w)
	return &pooledZstdWriter{enc: enc, w: w, pool: pool}, nil
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
	compressors.Store(Deflate64, Compressor(func(w io.Writer) (io.WriteCloser, error) { return newDeflate64Writer(w), nil }))
	compressors.Store(ZSTD, Compressor(newZstdWriter))
	compressors.Store(LZMA, Compressor(func(w io.Writer) (io.WriteCloser, error) { return newLZMAWriter(w, 5) }))

	decompressors.Store(Store, Decompressor(io.NopCloser))
	decompressors.Store(Deflate, Decompressor(newFlateReader))
	decompressors.Store(Deflate64, Decompressor(func(r io.Reader) io.ReadCloser { return decodeDeflate64(r) }))
	decompressors.Store(BZIP2, Decompressor(func(r io.Reader) io.ReadCloser { return io.NopCloser(bzip2.NewReader(r)) }))
	decompressors.Store(LZMA, Decompressor(newLZMAReader))
	decompressors.Store(ZSTD, Decompressor(newZstdReader))
}

// MaxDecompressionDictSize defines the maximum dictionary memory allocation (in bytes)
// allowed for PPMd and LZMA decompilers to prevent RAM bomb DoS attacks.
// Defaults to 128 MB.
var MaxDecompressionDictSize int64 = 128 << 20

type errorReader struct{ err error }

func (e errorReader) Read(p []byte) (int, error) { return 0, e.err }
func (e errorReader) Close() error               { return nil }
func newPPMdReader(r io.Reader, size uint64) io.ReadCloser {
	// APPNOTE 5.10.3: PPMd parameters are stored in the first 2 bytes of the data.
	props := make([]byte, 2)
	if _, err := io.ReadFull(r, props); err != nil {
		return nil
	}
	val := binary.LittleEndian.Uint16(props)

	// Parameter parsing:
	// Order: bits 0-3 (+1)
	// MemSize: bits 4-11 (+1) in MB
	// Restoration: bits 12-15
	order := int(val&0xF) + 1
	memSize := (int((val>>4)&0xFF) + 1)

	if int64(memSize) > MaxDecompressionDictSize/(1024*1024) {
		return errorReader{fmt.Errorf("zip: PPMd memory limit exceeded (%d MB)", memSize)}
	}

	rd, err := ppmd.NewH7zReader(r, order, memSize, int(size))
	if err != nil {
		return errorReader{err}
	}
	return io.NopCloser(&rd)
}
func newLZMAReader(r io.Reader) io.ReadCloser {
	// APPNOTE 5.8.8: LZMA Properties Header in ZIP:
	// 2 bytes - LZMA Version
	// 2 bytes - Properties Size (usually 5)
	// N bytes - Properties Data (1 byte of parameters + 4 bytes of dictionary size)

	meta := make([]byte, 4)
	if _, err := io.ReadFull(r, meta); err != nil {
		return nil
	}

	propSize := int(binary.LittleEndian.Uint16(meta[2:4]))
	if propSize != 5 {
		// For ZIP Method 14, 5 bytes of LZMA1 properties are expected per specification.
		return nil
	}

	props := make([]byte, propSize)
	if _, err := io.ReadFull(r, props); err != nil {
		return nil
	}

	dictSize := binary.LittleEndian.Uint32(props[1:5])
	if int64(dictSize) > MaxDecompressionDictSize {
		return errorReader{fmt.Errorf("zip: LZMA dictionary limit exceeded (%d bytes)", dictSize)}
	}

	// The unxed/xz/lzma library expects a classic .lzma header (13 bytes):
	// [1b props][4b dict size][8b uncompressed size]
	fullHeader := make([]byte, 13)
	copy(fullHeader[0:5], props)

	for i := 0; i < 8; i++ {
		// Set to 0xFF, meaning "size unknown, read until EOS marker"
		fullHeader[5+i] = 0xFF
	}

	mr := io.MultiReader(bytes.NewReader(fullHeader), r)
	rd, err := lzma.NewReader(mr)
	if err != nil {
		return nil
	}
	// lzma.Reader from this package does not implement Close as it works with the stream.
	// Wrap in NopCloser.
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

type lzmaWriter struct {
	w io.WriteCloser
}

func (lw *lzmaWriter) Write(p []byte) (int, error) { return lw.w.Write(p) }
func (lw *lzmaWriter) Close() error                { return lw.w.Close() }

type headerSwallower struct {
	w     io.Writer
	count int
}

func (s *headerSwallower) Write(p []byte) (int, error) {
	if s.count < 13 {
		skip := 13 - s.count
		if len(p) <= skip {
			s.count += len(p)
			return len(p), nil
		}
		p = p[skip:]
		s.count = 13
		n, err := s.w.Write(p)
		return n + skip, err
	}
	return s.w.Write(p)
}

func newLZMAWriter(w io.Writer, level int) (io.WriteCloser, error) {
	// ZIP-LZMA Header (APPNOTE 5.8.8)
	// 2 bytes: Version (9.0 -> 0x0900)
	// 2 bytes: Properties Size (5 -> 0x0500)
	header := []byte{0x09, 0x00, 0x05, 0x00}
	if _, err := w.Write(header); err != nil {
		return nil, err
	}

	// LZMA1 Properties (1 byte) + Dictionary Size (4 bytes)
	// Default: lc=3, lp=0, pb=2 (0x5d)
	dictSize := uint32(1 << 23)
	if level > 0 {
		dictSize = uint32(1 << (18 + level))
	}

	// 1. Write the 5-byte properties segment for ZIP Method 14
	props := []byte{0x5d}
	if err := binary.Write(w, binary.LittleEndian, props[0]); err != nil {
		return nil, err
	}
	if err := binary.Write(w, binary.LittleEndian, dictSize); err != nil {
		return nil, err
	}

	// 2. Configure the LZMA encoder using correct field names from the library
	config := lzma.WriterConfig{
		DictCap: int(dictSize),
		Properties: &lzma.Properties{
			LC: 3,
			LP: 0,
			PB: 2,
		},
	}

	// 3. Create a swallower to prevent lzma.NewWriter from writing its own
	// 13-byte header, as we've already written the ZIP-compatible version.
	swallower := &headerSwallower{w: w}
	z, err := config.NewWriter(swallower)
	if err != nil {
		return nil, err
	}

	return &lzmaWriter{w: z}, nil
}
