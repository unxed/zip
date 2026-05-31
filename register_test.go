package zip

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"golang.org/x/sync/errgroup"
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
	// Create a repetitive data set with cross-chunk patterns to test ResetDict seeking
	chunkSize := uint32(1024)
	numChunks := 5
	var fullData bytes.Buffer
	for i := 0; i < numChunks; i++ {
		// The pattern "ABCDEFGH..." repeats across chunks. Without ResetDict, 
		// jumping to block 3 will fail because it expects back-references from previous blocks.
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
		UncompressedSize64: uint64(fullData.Len()),
	}

	w, _ := zw.CreateHeader(fh)
	w.Write(fullData.Bytes())
	zw.Close()

	// Read and verify seek index
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	f := zr.File[0]
	if f.SeekChunkSize != chunkSize {
		t.Errorf("expected chunk size %d, got %d", chunkSize, f.SeekChunkSize)
	}
	if len(f.SeekIndex) != numChunks {
		t.Errorf("expected %d index entries, got %d", numChunks, len(f.SeekIndex))
	}

	rs, err := f.OpenSeekable()
	if err != nil {
		t.Fatalf("failed to open seekable: %v", err)
	}

	// 1. Seek to block 3 
	targetOff := int64(chunkSize * 3)
	rs.Seek(targetOff, io.SeekStart)

	out := make([]byte, 10)
	io.ReadFull(rs, out)
	// For block 3 (start index 3072), 3072 % 26 = 4 ('E')
	if string(out) != "EFGHIJKLMN" {
		t.Errorf("seek to block 3 failed, got %q", string(out))
	}

	// 2. Seek back to block 1
	rs.Seek(int64(chunkSize), io.SeekStart)
	io.ReadFull(rs, out)
	// For block 1 (start index 1024), 1024 % 26 = 10 ('K')
	if string(out) != "KLMNOPQRST" {
		t.Errorf("seek to block 1 failed, got %q", string(out))
	}

	// 3. Test EOF
	rs.Seek(0, io.SeekEnd)
	n, err := rs.Read(out)
	if n != 0 || err != io.EOF {
		t.Errorf("expected EOF at end of file, got n=%d, err=%v", n, err)
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
		0x5d,       // props[0]
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
