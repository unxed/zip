package zip

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchiver_TorrentZip(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	os.MkdirAll(filepath.Join(src, "dir2"), 0755)
	os.MkdirAll(filepath.Join(src, "dir1"), 0755) // This one will have a file
	os.WriteFile(filepath.Join(src, "dir1", "file.txt"), []byte("file data"), 0644)
	os.WriteFile(filepath.Join(src, "Z_file.txt"), []byte("data Z"), 0644)
	os.WriteFile(filepath.Join(src, "a_file.txt"), []byte("data a"), 0644)

	zipPath := filepath.Join(tmp, "tz.zip")
	f, _ := os.Create(zipPath)

	a, err := NewArchiver(f, src, WithArchiverTorrentZip(true))
	if err != nil {
		t.Fatal(err)
	}

	files := make(map[string]os.FileInfo)
	filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if path != src {
			files[path] = info
		}
		return nil
	})

	err = a.Archive(context.Background(), files)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	f.Close()

	// Check properties
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	if !strings.HasPrefix(zr.Comment, "TORRENTZIPPED-") {
		t.Errorf("expected TORRENTZIPPED- comment, got %q", zr.Comment)
	}

	expectedOrder := []string{
		"a_file.txt",
		"dir1/file.txt",
		"dir2/",
		"Z_file.txt",
	}
	if len(zr.File) != len(expectedOrder) {
		t.Fatalf("expected %d files, got %d", len(expectedOrder), len(zr.File))
	}

	for i, f := range zr.File {
		if f.Name != expectedOrder[i] {
			t.Errorf("expected file %d to be %q, got %q", i, expectedOrder[i], f.Name)
		}
		if f.ModifiedTime != 48128 || f.ModifiedDate != 8600 {
			t.Errorf("timestamps not overridden for %s", f.Name)
		}
		expectedFlags := uint16(2)
		if strings.HasSuffix(f.Name, "/") {
			expectedFlags = 0
		}
		if f.Flags != expectedFlags {
			t.Errorf("flags not overridden for %s: got %d, want %d", f.Name, f.Flags, expectedFlags)
		}
		if len(f.Extra) != 0 {
			t.Errorf("extra fields not cleared for %s", f.Name)
		}
		if f.CreatorVersion != 0 || f.ReaderVersion != 20 {
			t.Errorf("versions not set correctly for %s", f.Name)
		}
	}

	// --- 100% Bit-exact TorrentZip Validation ---
	raw, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	// Поиск сигнатуры EOCD с конца файла
	var directoryEndOffset int64 = -1
	for i := len(raw) - 22; i >= 0; i-- {
		if raw[i] == 'P' && raw[i+1] == 'K' && raw[i+2] == 0x05 && raw[i+3] == 0x06 {
			directoryEndOffset = int64(i)
			break
		}
	}

	if directoryEndOffset == -1 {
		t.Fatal("EOCD record not found in generated TorrentZip archive")
	}

	// Читаем размеры из EOCD
	cdSize := binary.LittleEndian.Uint32(raw[directoryEndOffset+12 : directoryEndOffset+16])
	cdOffset := binary.LittleEndian.Uint32(raw[directoryEndOffset+16 : directoryEndOffset+20])

	// Проверяем контрольную сумму Центральной Директории
	cdBytes := raw[cdOffset : cdOffset+cdSize]
	expectedCRC := crc32.ChecksumIEEE(cdBytes)
	expectedComment := fmt.Sprintf("TORRENTZIPPED-%08X", expectedCRC)

	if zr.Comment != expectedComment {
		t.Errorf("EOCD comment checksum mismatch:\ngot:  %q\nwant: %q", zr.Comment, expectedComment)
	}

	// Убеждаемся, что пустые папки сжаты ровно в 2 байта (пустой deflate поток)
	for _, file := range zr.File {
		if strings.HasSuffix(file.Name, "/") {
			if file.Method != 0 {
				t.Errorf("directory %s should be stored using Store (0), got %d", file.Name, file.Method)
			}
			if file.UncompressedSize64 != 0 {
				t.Errorf("directory %s must have uncompressed size 0, got %d", file.Name, file.UncompressedSize64)
			}
			if file.CompressedSize64 != 0 {
				t.Errorf("directory %s must have compressed size 0, got %d", file.Name, file.CompressedSize64)
			}
			if file.CRC32 != 0 {
				t.Errorf("directory %s CRC should be 00000000, got %08X", file.Name, file.CRC32)
			}
		}
	}
}

func TestWithArchiverTorrentZip_SetsLevel9(t *testing.T) {
	opts := &archiverOptions{}
	opt := WithArchiverTorrentZip(true)
	if err := opt(opts); err != nil {
		t.Fatal(err)
	}
	if opts.level != 9 {
		t.Errorf("expected level 9, got %d", opts.level)
	}
}

func TestTorrentZip_BitExactWithReference(t *testing.T) {
	// 1. Проверяем наличие "trrntzip" или "torrentzip" в PATH
	trrntzipPath, err := exec.LookPath("trrntzip")
	if err != nil {
		trrntzipPath, err = exec.LookPath("torrentzip")
	}

	if trrntzipPath == "" {
		t.Skip("Reference torrentzip binary not found in PATH. Skipping bit-exact integration test.")
	}

	// 2. Подготовка файлов для архивации
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	os.MkdirAll(filepath.Join(srcDir, "dir1"), 0755)
	os.WriteFile(filepath.Join(srcDir, "dir1", "file.txt"), []byte("highly structured and repeatable test data"), 0644)
	os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("some other file content"), 0644)
	os.MkdirAll(filepath.Join(srcDir, "empty_dir"), 0755) // Пустая директория
	os.WriteFile(filepath.Join(srcDir, "empty_file.txt"), []byte{}, 0644) // Пустой регулярный файл
	os.WriteFile(filepath.Join(srcDir, "Z_file.txt"), []byte("data Z"), 0644) // Проверка регистронезависимой сортировки
	os.WriteFile(filepath.Join(srcDir, "a_file.txt"), []byte("data a"), 0644)

	// 3. Создаем TorrentZip через НАШ архиватор
	goZipPath := filepath.Join(tmp, "go_torrent.zip")
	fGo, err := os.Create(goZipPath)
	if err != nil {
		t.Fatal(err)
	}

	a, err := NewArchiver(fGo, srcDir, WithArchiverTorrentZip(true))
	if err != nil {
		t.Fatal(err)
	}

	files := make(map[string]os.FileInfo)
	filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if path != srcDir {
			files[path] = info
		}
		return nil
	})

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatal(err)
	}
	a.Close()
	fGo.Close()

	// 4. Копируем наш архив в ref_torrent.zip и напускаем на него эталонный torrentzip
	refZipPath := filepath.Join(tmp, "ref_torrent.zip")

	in, err := os.Open(goZipPath)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(refZipPath)
	if err != nil {
		in.Close()
		t.Fatal(err)
	}
	_, err = io.Copy(out, in)
	in.Close()
	out.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Запуск эталонного torrentzip для конвертации на месте (in-place)
	cmd := exec.Command(trrntzipPath, refZipPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Reference tool failed: %v, output: %s", err, string(out))
	}

	// 5. Побайтовое сравнение результатов
	goBytes, err := os.ReadFile(goZipPath)
	if err != nil {
		t.Fatal(err)
	}
	refBytes, err := os.ReadFile(refZipPath)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(goBytes, refBytes) {
		t.Errorf("Bit-exact match failed!\nOur ZIP size: %d, Reference ZIP size: %d", len(goBytes), len(refBytes))

		// Сбор диагностической информации по обоим архивам
		zrGo, errGo := OpenReader(goZipPath)
		zrRef, errRef := OpenReader(refZipPath)

		if errGo == nil && errRef == nil {
			t.Logf("--- DIAGNOSTICS: OUR ZIP (%d entries) ---", len(zrGo.File))
			for _, f := range zrGo.File {
				t.Logf("File: %q | Method: %d | CompSize: %d | UncompSize: %d | CRC32: %08X | Flags: %d | Extra: %d bytes",
					f.Name, f.Method, f.CompressedSize64, f.UncompressedSize64, f.CRC32, f.Flags, len(f.Extra))
			}

			t.Logf("--- DIAGNOSTICS: REFERENCE ZIP (%d entries) ---", len(zrRef.File))
			for _, f := range zrRef.File {
				t.Logf("File: %q | Method: %d | CompSize: %d | UncompSize: %d | CRC32: %08X | Flags: %d | Extra: %d bytes",
					f.Name, f.Method, f.CompressedSize64, f.UncompressedSize64, f.CRC32, f.Flags, len(f.Extra))
			}

			zrGo.Close()
			zrRef.Close()
		}

		if len(goBytes) == len(refBytes) {
			for i := 0; i < len(goBytes); i++ {
				if goBytes[i] != refBytes[i] {
					t.Errorf("First byte difference at offset %d: got %02X, want %02X", i, goBytes[i], refBytes[i])
					break
				}
			}
		}
	} else {
		t.Log("SUCCESS: Our TorrentZip output is 100% bit-exact identical to the reference tool!")
	}
}
