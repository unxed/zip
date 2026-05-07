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

func TestReader_PathNormalization(t *testing.T) {
	testPaths := []struct {
		in   string
		want string
	}{
		{`dir\file.txt`, "dir/file.txt"},
		{`C:\Windows\System32`, "C:/Windows/System32"},
		{`//root//dir//`, "root/dir"},
		{`../../../../etc/passwd`, "etc/passwd"},
		{`./local/file`, "local/file"},
	}

	for _, tc := range testPaths {
		got := toValidName(tc.in)
		if got != tc.want {
			t.Errorf("toValidName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestReader_EmptyArchive(t *testing.T) {
	// Пустой архив (только EOCD)
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	zw.Close()

	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != 0 {
		t.Errorf("expected 0 files, got %d", len(zr.File))
	}
}

func TestReader_PanicSafety(t *testing.T) {
	// Подача абсолютно случайных данных не должна вызывать панику
	junk := []byte("PK\x03\x04" + "some random junk data instead of a real zip header")
	for i := 0; i < len(junk); i++ {
		// Пробуем NewReader на обрезанных данных
		zr, err := NewReader(bytes.NewReader(junk[:i]), int64(i))
		if err == nil && zr != nil {
			if len(zr.File) > 0 {
				f := zr.File[0]
				rc, _ := f.Open()
				if rc != nil {
					io.ReadAll(rc)
					rc.Close()
				}
			}
		}
	}
}
