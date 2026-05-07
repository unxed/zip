package zip

import (
	"context"
	"os"
	"strings"
	"path/filepath"
	"testing"
)

func TestExtractor_ChownErrorHandling(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "test.zip")
	dstDir := filepath.Join(tmp, "dst")

	// Создаем архив с Unix метаданными
	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	fh := &FileHeader{Name: "file.txt"}
	fh.Extra = appendUnixExtra(nil, 1000, 1000)
	w, _ := zw.CreateHeader(fh)
	w.Write([]byte("data"))
	zw.Close()
	f.Close()

	// Настраиваем экстрактор с обработчиком ошибок chown
	chownCalled := false
	handler := func(name string, err error) error {
		chownCalled = true
		return nil // Игнорируем ошибку
	}

	e, _ := NewExtractor(zipPath, dstDir, WithExtractorChownErrorHandler(handler))
	err := e.Extract(context.Background())
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	// На обычных ОС (не root) lchown скорее всего вернет ошибку.
	// Используем переменную, чтобы удовлетворить компилятор и логгируем результат.
	if chownCalled {
		t.Log("Chown error handler was successfully triggered and executed")
	}
}

func TestExtractor_OutsideChroot(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "evil.zip")
	dstDir := filepath.Join(tmp, "safe")
	os.Mkdir(dstDir, 0755)

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	// Пытаемся выйти за пределы директории через относительный путь
	zw.Create("../evil.txt")
	zw.Close()
	f.Close()

	e, _ := NewExtractor(zipPath, dstDir)
	err := e.Extract(context.Background())
	if err == nil {
		t.Error("expected error for path outside of chroot, got nil")
	}
}

func TestExtractor_ZipSlipSecurity(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "slip.zip")
	dstDir := filepath.Join(tmp, "safe")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	// Прямая попытка записать в корень системы (на Unix) или выйти далеко вверх
	zw.Create("/tmp/pwned.txt")
	zw.Create("../../../opt/pwned.txt")
	zw.Close()
	f.Close()

	e, _ := NewExtractor(zipPath, dstDir)
	err := e.Extract(context.Background())

	// NewExtractor использует filepath.Abs(filepath.Join(chroot, file.Name))
	// и затем проверяет HasPrefix. Это должно отсечь такие пути.
	if err == nil {
		t.Error("Extractor allowed Zip Slip path! Security violation.")
	}
}

func TestExtractor_ZipBomb(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "bomb.zip")
	dstDir := filepath.Join(tmp, "extract")

	// Создаем архив. Записываем 2048 байт.
	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	w, _ := zw.Create("bomb.txt")
	w.Write(make([]byte, 2048))
	zw.Close()
	f.Close()

	// Устанавливаем лимит 1024 байта. 2048 > 1024, должно упасть.
	e, _ := NewExtractor(zipPath, dstDir, WithExtractorMaxFileSize(1024))
	err := e.Extract(context.Background())

	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("expected zip bomb error (limit exceeded), got: %v", err)
	}
}

func TestExtractor_RatioBomb(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "ratio.zip")
	dstDir := filepath.Join(tmp, "extract")

	// Создаем архив с данными, которые ОЧЕНЬ хорошо сжимаются (нули).
	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	w, _ := zw.CreateHeader(&FileHeader{
		Name:   "ratio.txt",
		Method: Deflate,
	})
	// Пишем 100КБ нулей. Сжатый размер будет около ~100-200 байт.
	w.Write(make([]byte, 1024*100))
	zw.Close()
	f.Close()

	// Устанавливаем лимит Ratio 2:1. Реальный ratio будет > 500:1.
	e, _ := NewExtractor(zipPath, dstDir, WithExtractorMaxRatio(2))
	err := e.Extract(context.Background())

	if err == nil || !strings.Contains(err.Error(), "ratio") {
		t.Errorf("expected ratio bomb error, got: %v", err)
	}
}
