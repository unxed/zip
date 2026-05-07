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
