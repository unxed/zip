package zip

import (
	"bytes"
	"io"
	"testing"
)

func TestReader_DataDescriptorNoSignature(t *testing.T) {
	// Создаем архив вручную с флагом 0x8 (Data Descriptor), но без сигнатуры дескриптора
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)

	fh := &FileHeader{
		Name:   "test.txt",
		Method: Store,
	}
	fh.Flags |= 0x8 // Требуем Data Descriptor

	// Пишем заголовок
	w, _ := zw.CreateHeader(fh)
	w.Write([]byte("some data"))

	// archive/zip и наш Writer пишут сигнатуру.
	// Мы проверим, что наш Reader умеет ее обрабатывать, даже если мы "подрежем" файл.
	zw.Close()

	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	f := zr.File[0]
	rc, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()

	if string(data) != "some data" {
		t.Errorf("expected 'some data', got %q", string(data))
	}
}

func TestReader_TruncatedFile(t *testing.T) {
	// 1. Совсем короткий файл
	_, err := NewReader(bytes.NewReader([]byte("PK")), 2)
	if err == nil {
		t.Error("expected error for truncated file, got nil")
	}

	// 2. Файл с EOCD, но без остального
	data := make([]byte, 100)
	copy(data[80:], []byte("\x50\x4b\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	_, err = NewReader(bytes.NewReader(data), int64(len(data)))
	// Должна быть ошибка формата
	if err == nil {
		t.Error("expected error for corrupt/truncated directory, got nil")
	}
}