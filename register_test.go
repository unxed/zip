package zip

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"golang.org/x/sync/errgroup"

	"github.com/klauspost/compress/zstd"
)

func TestZstdCompressionLoop(t *testing.T) {
	data := []byte("zstd compression test data with some repetitive content content content")
	buf := new(bytes.Buffer)

	// Compress
	zw := NewWriter(buf)
	w, err := zw.CreateHeader(&FileHeader{
		Name:   "test.zstd",
		Method: ZSTD,
	})
	if err != nil {
		t.Fatalf("failed to create zstd entry: %v", err)
	}
	w.Write(data)
	zw.Close()

	// Decompress
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("failed to create reader: %v", err)
	}
	f := zr.File[0]
	if f.Method != ZSTD {
		t.Errorf("expected method ZSTD, got %d", f.Method)
	}
	rc, err := f.Open()
	if err != nil {
		t.Fatalf("failed to open zstd file: %v", err)
	}
	decompressed, _ := io.ReadAll(rc)
	rc.Close()

	if !bytes.Equal(decompressed, data) {
		t.Errorf("data mismatch: expected %q, got %q", string(data), string(decompressed))
	}
}

func TestZstdConcurrencyStress(t *testing.T) {
	data := []byte("repetitive data repetitive data")
	ctx := context.Background()
	errGrp, _ := errgroup.WithContext(ctx)

	for i := 0; i < 20; i++ {
		errGrp.Go(func() error {
			buf := new(bytes.Buffer)
			zw := NewWriter(buf)
			w, _ := zw.Create("test")
			w.Write(data)
			zw.Close()

			zr, _ := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			rc, _ := zr.File[0].Open()
			res, _ := io.ReadAll(rc)
			rc.Close()
			if !bytes.Equal(res, data) {
				return fmt.Errorf("data corruption")
			}
			return nil
		})
	}

	if err := errGrp.Wait(); err != nil {
		t.Errorf("stress test failed: %v", err)
	}
}
func TestLevelAwarePooling(t *testing.T) {
	var buf1, buf2 bytes.Buffer

	// 1. Тест пулинга Deflate с кастомными уровнями
	w1 := newFlateWriterLevel(&buf1, 4).(*pooledFlateWriter)
	fw1 := w1.fw
	w1.Close()

	// Получение нового писателя на том же уровне должно вернуть тот же экземпляр
	w2 := newFlateWriterLevel(&buf2, 4).(*pooledFlateWriter)
	fw2 := w2.fw
	w2.Close()

	if fw1 != fw2 {
		t.Errorf("expected flate.Writer to be reused from the level-aware pool, but got different instances")
	}

	// Получение писателя на другом уровне не должно переиспользовать прошлый объект
	w3 := newFlateWriterLevel(&buf2, 5).(*pooledFlateWriter)
	fw3 := w3.fw
	w3.Close()

	if fw1 == fw3 {
		t.Errorf("did not expect flate.Writer from level 4 to be reused for level 5")
	}

	// 2. Тест пулинга ZSTD с кастомными уровнями
	zw1, err := newZstdWriterLevel(&buf1, 4)
	if err != nil {
		t.Fatalf("failed to create zstd writer: %v", err)
	}
	pzw1 := zw1.(*pooledZstdWriter)
	enc1 := pzw1.enc
	pzw1.Close()

	zw2, err := newZstdWriterLevel(&buf2, 4)
	if err != nil {
		t.Fatalf("failed to create zstd writer: %v", err)
	}
	pzw2 := zw2.(*pooledZstdWriter)
	enc2 := pzw2.enc
	pzw2.Close()

	if enc1 != enc2 {
		t.Errorf("expected zstd.Encoder to be reused from the level-aware pool, but got different instances")
	}

	zw3, err := newZstdWriterLevel(&buf2, 5)
	if err != nil {
		t.Fatalf("failed to create zstd writer: %v", err)
	}
	pzw3 := zw3.(*pooledZstdWriter)
	enc3 := pzw3.enc
	pzw3.Close()

	if enc1 == enc3 {
		t.Errorf("did not expect zstd.Encoder from level 4 to be reused for level 5")
	}
}
func TestZstdLargeWindowDecompression(t *testing.T) {
	data := []byte("verification of zstd large window decoding capability")

	var compBuf bytes.Buffer
	enc, err := zstd.NewWriter(&compBuf)
	if err != nil {
		t.Fatalf("failed to create zstd encoder: %v", err)
	}
	enc.Write(data)
	enc.Close()

	dec := newZstdReader(&compBuf)
	defer dec.Close()

	decompressed, err := io.ReadAll(dec)
	if err != nil {
		t.Fatalf("failed to decompress data: %v", err)
	}

	if !bytes.Equal(decompressed, data) {
		t.Errorf("content mismatch: got %q, want %q", string(decompressed), string(data))
	}
}
func TestZstd_CorruptedData(t *testing.T) {
	data := []byte("some data to compress and then corrupt it")
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	w, _ := zw.CreateHeader(&FileHeader{Name: "bad.zstd", Method: ZSTD})
	w.Write(data)
	zw.Close()

	raw := buf.Bytes()
	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("failed to read valid zip: %v", err)
	}

	// Find the exact offset of the start of the compressed data
	offset, err := zr.File[0].DataOffset()
	if err != nil {
		t.Fatalf("failed to get data offset: %v", err)
	}

	// Corrupt specifically the compressed data, without touching the headers
	for i := offset; i < offset+5 && i < int64(len(raw)); i++ {
		raw[i] = 0xAA
	}

	rc, err := zr.File[0].Open()
	if err != nil {
		// An error might occur right here during decompressor initialization
		return
	}
	defer rc.Close()

	_, err = io.ReadAll(rc)
	if err == nil {
		t.Error("expected decompression error for corrupted ZSTD stream, got nil")
	}
}
func TestZstd_WithDataDescriptor(t *testing.T) {
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)

	fh := &FileHeader{
		Name:   "dd.zstd",
		Method: ZSTD,
	}
	fh.Flags |= 0x8 // Force enable Data Descriptor

	w, _ := zw.CreateHeader(fh)
	w.Write([]byte("zstd data with descriptor"))
	zw.Close()

	zr, _ := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	rc, _ := zr.File[0].Open()
	data, _ := io.ReadAll(rc)
	rc.Close()

	if string(data) != "zstd data with descriptor" {
		t.Errorf("Data mismatch with DD: got %q", string(data))
	}
}
func TestSolidSeekIndex_RandomAccess(t *testing.T) {
	for _, continuous := range []bool{false, true} {
		chunkSize := uint32(1024)
		numChunks := 5
		var fullData bytes.Buffer
		for i := 0; i < numChunks; i++ {
			block := make([]byte, chunkSize)
			for j := 0; j < int(chunkSize); j++ {
				block[j] = byte('A' + ((i*int(chunkSize) + j) % 26))
			}
			fullData.Write(block)
		}

		buf := new(bytes.Buffer)
		zw := NewWriter(buf)

		fh := &FileHeader{
			Name:               "seekable.bin",
			Method:             Deflate,
			SeekChunkSize:      chunkSize,
			SeekContinuous:     continuous,
			UncompressedSize64: uint64(fullData.Len()),
		}

		w, _ := zw.CreateHeader(fh)
		w.Write(fullData.Bytes())
		zw.Close()

		zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatal(err)
		}

		f := zr.File[0]
		rs, err := f.OpenSeekable()
		if err != nil {
			t.Fatalf("failed to open seekable (continuous=%v): %v", continuous, err)
		}

		targetOff := int64(chunkSize * 3)
		rs.Seek(targetOff, io.SeekStart)

		out := make([]byte, 10)
		io.ReadFull(rs, out)
		// For block 3 (start index 3072), 3072 % 26 = 4 ('E')
		if string(out) != "EFGHIJKLMN" {
			t.Errorf("seek to block 3 failed, got %q (continuous=%v)", string(out), continuous)
		}

		rs.Seek(int64(chunkSize), io.SeekStart)
		io.ReadFull(rs, out)
		// For block 1 (start index 1024), 1024 % 26 = 10 ('K')
		if string(out) != "KLMNOPQRST" {
			t.Errorf("seek to block 1 failed, got %q (continuous=%v)", string(out), continuous)
		}

		rs.Seek(0, io.SeekEnd)
		n, err := rs.Read(out)
		if n != 0 || err != io.EOF {
			t.Errorf("expected EOF at end of file, got n=%d, err=%v", n, err)
		}
	}
}

func TestRegister_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic when registering duplicate method")
		}
	}()
	// Method 8 (Deflate) is already registered in init()
	RegisterCompressor(Deflate, nil)
}

func TestDecompressor_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic when registering duplicate decompressor")
		}
	}()
	RegisterDecompressor(Deflate, nil)
}

func TestPPMd_HeaderParsing(t *testing.T) {
	// Simulate 2 bytes of the PPMd header
	// Order=8 (val 7), Mem=50MB (val 49)
	// 7 + (49 << 4) = 7 + 784 = 791 (0x0317)
	header := []byte{0x17, 0x03}

	r := bytes.NewReader(header)
	// newPPMdReader will attempt to initialize the library.
	// Verify that there is no panic when reading properties.
	rc := newPPMdReader(r, 1000)
	if rc != nil {
		// Wait for error or empty result as there is no data after the header
	}
}
func TestPPMd_MemoryLimit(t *testing.T) {
	// MemSize is bits 4-11 (+1) in MB.
	// Set to 255 (which means 256MB).
	// val = 0 | (255 << 4) = 4080 (0x0FF0)
	header := []byte{0xF0, 0x0F}
	r := bytes.NewReader(header)
	rc := newPPMdReader(r, 1000)
	if rc == nil {
		t.Fatal("expected non-nil errorReader")
	}
	buf := make([]byte, 10)
	_, err := rc.Read(buf)
	if err == nil || !strings.Contains(err.Error(), "PPMd memory limit exceeded") {
		t.Errorf("expected PPMd memory limit error, got: %v", err)
	}
}

func TestLZMA_MemoryLimit(t *testing.T) {
	// Header: 2b version, 2b propSize (5), then 5b props.
	// props[1:5] is dictSize. Set it to 256MB (268435456 = 0x10000000)
	header := []byte{
		0x09, 0x00, // Version
		0x05, 0x00, // propSize
		0x5d,                   // props[0]
		0x00, 0x00, 0x00, 0x10, // dictSize 256MB
	}
	r := bytes.NewReader(header)
	rc := newLZMAReader(r)
	if rc == nil {
		t.Fatal("expected non-nil errorReader")
	}
	buf := make([]byte, 10)
	_, err := rc.Read(buf)
	if err == nil || !strings.Contains(err.Error(), "LZMA dictionary limit exceeded") {
		t.Errorf("expected LZMA memory limit error, got: %v", err)
	}
}
