package zip

import (
	"bytes"
	"io"
	"testing"
)

func TestLZMA_Writer_Roundtrip(t *testing.T) {
	data := []byte("LZMA compression roundtrip test data. This should be compressed effectively.")
	// Repeat data to make it worth compressing
	for i := 0; i < 5; i++ {
		data = append(data, data...)
	}

	buf := new(bytes.Buffer)
	zw := NewWriter(buf)

	w, err := zw.CreateHeader(&FileHeader{
		Name:   "test_lzma.txt",
		Method: LZMA,
	})
	if err != nil {
		t.Fatalf("Failed to create LZMA header: %v", err)
	}

	if _, err := w.Write(data); err != nil {
		t.Fatalf("Failed to write LZMA data: %v", err)
	}
	zw.Close()

	// Read back
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("Failed to create reader: %v", err)
	}

	if len(zr.File) != 1 {
		t.Fatal("Expected 1 file in archive")
	}

	f := zr.File[0]
	if f.Method != LZMA {
		t.Errorf("Expected method LZMA (14), got %v", f.Method)
	}

	rc, err := f.Open()
	if err != nil {
		t.Fatalf("Failed to open LZMA file: %v", err)
	}
	defer rc.Close()

	decompressed, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("Failed to read LZMA data: %v", err)
	}

	if !bytes.Equal(decompressed, data) {
		t.Error("Decompressed data mismatch")
	}
}