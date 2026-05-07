package zip

import (
	"bytes"
	"io"
	"testing"
)

func TestDeflate64_Registration(t *testing.T) {
	// Проверяем, что метод зарегистрирован в глобальной карте
	dcomp := decompressor(Deflate64)
	if dcomp == nil {
		t.Fatal("Deflate64 decompressor not registered")
	}
}

func TestDeflate64_Reader(t *testing.T) {
	// Deflate64 обратно совместим с Deflate на малых объемах данных.
	// Проверяем, что наш декодер справляется с обычным потоком.
	data := []byte("deflate64 compatibility test data")
	buf := new(bytes.Buffer)

	zw := NewWriter(buf)
	w, err := zw.CreateHeader(&FileHeader{
		Name:   "test.d64",
		Method: Deflate64,
	})
	if err != nil {
		t.Fatalf("failed to create deflate64 header: %v", err)
	}
	w.Write(data)
	zw.Close()

	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("failed to read zip: %v", err)
	}
	if len(zr.File) == 0 {
		t.Fatal("no files in zip")
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("failed to open deflate64 file: %v", err)
	}
	res, _ := io.ReadAll(rc)
	rc.Close()

	if !bytes.Equal(res, data) {
		t.Errorf("got %q, want %q", string(res), string(data))
	}
}