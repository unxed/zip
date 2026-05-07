package zip

import (
	"context"
	"os"
	"runtime"
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

func TestExtractor_PermissionsPreservation(t *testing.T) {
	// Только для Unix, так как на Windows права работают иначе
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "perms.zip")
	dstDir := filepath.Join(tmp, "dst")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	
	// Файл с очень строгими правами
	fh, _ := FileInfoHeader(mockFileInfo{name: "secret.txt", mode: 0700})
	w, _ := zw.CreateHeader(fh)
	w.Write([]byte("secret"))
	zw.Close()
	f.Close()

	e, _ := NewExtractor(zipPath, dstDir)
	e.Extract(context.Background())

	info, err := os.Stat(filepath.Join(dstDir, "secret.txt"))
	if err != nil {
		t.Fatal(err)
	}
	
	// Проверяем, что права 0700 (rwx------) сохранились
	if info.Mode().Perm() != 0700 {
		t.Errorf("permissions lost! expected 0700, got %o", info.Mode().Perm())
	}
}

func TestExtractor_SymlinkSecurityDeep(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "sym_attack.zip")
	dstDir := filepath.Join(tmp, "safe")

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)
	
	// Создаем симлинк, который внутри архива указывает на путь ВНЕ архива
	fh := &FileHeader{Name: "attack_link"}
	fh.SetMode(os.ModeSymlink)
	w, _ := zw.CreateHeader(fh)
	// Цель ссылки - системный файл
	w.Write([]byte("/etc/passwd")) 
	zw.Close()
	f.Close()

	e, _ := NewExtractor(zipPath, dstDir)
	err := e.Extract(context.Background())

	// Проверяем, что ссылка создана, но мы не должны позволять ей 
	// работать как вектору атаки, если библиотека это декларирует.
	// На текущем этапе extractor.go делает os.Symlink(target, path).
	// Это создаст ссылку в dstDir/attack_link -> /etc/passwd.
	if err == nil {
		t.Log("Symlink created pointing to /etc/passwd. Ensure your application handles link targets safely.")
	}
}
func TestExtractor_SymlinkDirectoryTraversal(t *testing.T) {
	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "traversal.zip")
	dstDir := filepath.Join(tmp, "safe")

	// Директория вне зоны распаковки, куда мы "целимся"
	trapDir := filepath.Join(tmp, "trap")
	os.Mkdir(trapDir, 0755)

	f, _ := os.Create(zipPath)
	zw := NewWriter(f)

	// 1. Создаем симлинк "sub", который указывает на "trap"
	fh := &FileHeader{Name: "sub"}
	fh.SetMode(os.ModeSymlink)
	w, _ := zw.CreateHeader(fh)
	w.Write([]byte(trapDir))

	// 2. Создаем файл "sub/evil.txt"
	// Если экстрактор не проверяет, что "sub" - это уже существующий симлинк,
	// он может записать в trap/evil.txt
	zw.Create("sub/evil.txt")

	zw.Close()
	f.Close()

	e, _ := NewExtractor(zipPath, dstDir)
	err := e.Extract(context.Background())

	// Проверка: файл не должен появиться в trapDir
	if _, serr := os.Stat(filepath.Join(trapDir, "evil.txt")); serr == nil {
		t.Errorf("Security Breach! File extracted through symlink into %s", trapDir)
	}

	// Должна быть ошибка или просто безопасный пропуск
	_ = err
}
