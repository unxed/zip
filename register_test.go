package zip

import (
	"bytes"
	"context"
	"fmt"
	"io"
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

	// Находим точное смещение начала сжатых данных
	offset, err := zr.File[0].DataOffset()
	if err != nil {
		t.Fatalf("failed to get data offset: %v", err)
	}

	// Портим именно сжатые данные, не трогая заголовки
	for i := offset; i < offset+5 && i < int64(len(raw)); i++ {
		raw[i] = 0xAA
	}

	rc, err := zr.File[0].Open()
	if err != nil {
		// Ошибка может возникнуть уже здесь при инициализации декомпрессора
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
	fh.Flags |= 0x8 // Принудительно включаем Data Descriptor

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
func TestRegister_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic when registering duplicate method")
		}
	}()
	// Метод 8 (Deflate) уже зарегистрирован в init()
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
