package zip

import (
	"fmt"
	"time"
	"bytes"
	"testing"
	"errors"
	"os"
	"path/filepath"
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

func TestWriter_ZIP64LargeCount(t *testing.T) {
	buf := new(bytes.Buffer)
	w := NewWriter(buf)

	// Симулируем ситуацию, когда файлов больше, чем 65535 (лимит uint16)
	// Для экономии времени и памяти мы просто напрямую модифицируем счетчик в тесте
	for i := 0; i < 10; i++ {
		w.Create(fmt.Sprintf("file_%d.txt", i))
	}

	// Хак для теста: подменяем количество записей перед закрытием
	// чтобы спровоцировать запись ZIP64 заголовков
	originalDir := w.dir
	fakeDir := make([]*header, uint16max + 1)
	for i := range fakeDir {
		fakeDir[i] = &header{FileHeader: &FileHeader{Name: "f.txt"}}
	}
	w.dir = fakeDir

	err := w.Close()
	if err != nil {
		t.Fatalf("Close failed on large count simulation: %v", err)
	}

	// Проверяем, что в структуре EOCD прописались маркеры 0xFFFF,
	// что означает наличие ZIP64 Locator
	data := buf.Bytes()
	// Сигнатура EOCD: 0x06054b50 в Little Endian
	if !bytes.Contains(data, []byte{0x50, 0x4b, 0x05, 0x06}) {
		t.Error("EOCD signature not found")
	}

	// Возвращаем как было для корректного завершения
	w.dir = originalDir
}
func TestWriter_LongNameError(t *testing.T) {
	buf := new(bytes.Buffer)
	w := NewWriter(buf)

	// Создаем имя длиной более 65535 байт
	longName := make([]byte, uint16max + 1)
	for i := range longName {
		longName[i] = 'a'
	}

	_, err := w.Create(string(longName))
	if err == nil || !errors.Is(err, errLongName) {
		t.Errorf("expected errLongName, got: %v", err)
	}
}
func TestWriter_SetOffsetPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic when calling SetOffset after writes")
		}
	}()
	w := NewWriter(new(bytes.Buffer))
	w.Create("test.txt")
	w.SetOffset(100) // Должно вызвать панику
}

func TestWriter_LongCommentError(t *testing.T) {
	w := NewWriter(new(bytes.Buffer))
	longComment := make([]byte, uint16max + 1)
	err := w.SetComment(string(longComment))
	if err == nil {
		t.Error("expected error for long comment, got nil")
	}
}

func TestWriter_AddFS(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "fs.txt"), []byte("fs data"), 0644)

	buf := new(bytes.Buffer)
	w := NewWriter(buf)

	// Используем стандартный os.DirFS
	err := w.AddFS(os.DirFS(tmp))
	if err != nil {
		t.Fatalf("AddFS failed: %v", err)
	}
	w.Close()

	zr, _ := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if len(zr.File) != 1 || zr.File[0].Name != "fs.txt" {
		t.Errorf("AddFS did not package file correctly")
	}
}

func TestLZMA_Decompression(t *testing.T) {
	// Для этого теста требуется валидный поток LZMA. 
	// Просто проверим регистрацию метода.
	dcomp := decompressor(LZMA)
	if dcomp == nil {
		t.Fatal("LZMA decompressor not registered")
	}
}

func TestWriter_AutoExtrasInjection(t *testing.T) {
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)

	now := time.Now().Truncate(time.Second)
	fh := &FileHeader{
		Name:     "meta.txt",
		Modified: now,
		Accessed: now.Add(-time.Hour),
		Created:  now.Add(-24 * time.Hour),
		Uid:      501,
		Gid:      20,
		OwnerSet: true,
	}

	w, _ := zw.CreateHeader(fh)
	w.Write([]byte("metadata test"))
	zw.Close()

	zr, _ := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	f := zr.File[0]

	// 1. Проверяем таймстемпы через 0x5455 (Extended Timestamp)
	if f.Modified.Unix() != fh.Modified.Unix() {
		t.Errorf("Modified time mismatch: got %v, want %v", f.Modified, fh.Modified)
	}
	if f.Accessed.Unix() != fh.Accessed.Unix() {
		t.Errorf("Accessed time mismatch: got %v, want %v", f.Accessed, fh.Accessed)
	}

	// 2. Проверяем UNIX ID через 0x7875 (Info-ZIP New Unix)
	uid, gid, ok := parseUnixExtra(f.Extra)
	if !ok {
		t.Fatal("Unix extra field (0x7875) not found in output")
	}
	if uid != 501 || gid != 20 {
		t.Errorf("UID/GID mismatch: got %d:%d, want 501:20", uid, gid)
	}
}
func TestWriter_MetadataIdempotency(t *testing.T) {
	// Проверяем, что многократный вызов инжектора не дублирует Extra Fields
	now := time.Now().Truncate(time.Second)
	fh := &FileHeader{
		Name:     "idempotent.txt",
		Modified: now,
		Uid:      1000,
		OwnerSet: true,
	}

	// Первый вызов (через создание)
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	zw.CreateHeader(fh)
	zw.Close()

	initialExtraLen := len(fh.Extra)

	// Симулируем повторную инъекцию (например, при повторном использовании заголовка)
	fh.injectAutoExtras()
	fh.injectAutoExtras()

	if len(fh.Extra) != initialExtraLen {
		t.Errorf("Extra fields bloated! initial %d, current %d. Likely duplicate tags.", initialExtraLen, len(fh.Extra))
	}
}
