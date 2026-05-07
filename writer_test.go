package zip

import (
	"bytes"
	"testing"
)

func TestWriter_ZIP64Forced(t *testing.T) {
	buf := new(bytes.Buffer)
	w := NewWriter(buf)

	// Имитируем огромный файл через заголовок, не записывая терабайты данных
	fh := &FileHeader{
		Name:               "huge.txt",
		Method:             Store,
		UncompressedSize64: uint64(uint32max) + 1, // Больше 4GB
		CompressedSize64:   uint64(uint32max) + 1,
	}

	// CreateRaw позволяет нам записать данные "как есть"
	wr, err := w.CreateRaw(fh)
	if err != nil {
		t.Fatal(err)
	}
	wr.Write([]byte("fake data"))
	w.Close()

	// Теперь читаем и проверяем, что флаг zip64 проставился
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	if !zr.File[0].zip64 {
		t.Error("expected ZIP64 header for file > 4GB, but it was not set")
	}

	if zr.File[0].UncompressedSize64 != uint64(uint32max)+1 {
		t.Errorf("size mismatch in ZIP64: got %d", zr.File[0].UncompressedSize64)
	}
}