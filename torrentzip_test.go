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
	"runtime"
	"strings"
	"testing"
)

func TestArchiver_TorrentZip(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src")
	mustMkdirAll(t, filepath.Join(src, "dir2"))
	mustMkdirAll(t, filepath.Join(src, "dir1")) // This one will have a file
	mustWriteFile(t, filepath.Join(src, "dir1", "file.txt"), []byte("file data"), 0644)
	mustWriteFile(t, filepath.Join(src, "Z_file.txt"), []byte("data Z"), 0644)
	mustWriteFile(t, filepath.Join(src, "a_file.txt"), []byte("data a"), 0644)

	zipPath := filepath.Join(tmp, "tz.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)

	a, err := NewArchiver(f, src, WithArchiverTorrentZip(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	files := make(map[string]os.FileInfo)
	if err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if path != src {
			files[path] = info
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	err = a.Archive(context.Background(), files)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", zipPath, err)
	}

	// Check properties
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)

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
			if file.Method != 8 {
				t.Errorf("directory %s should be stored using Deflate (8), got %d", file.Name, file.Method)
			}
			if file.UncompressedSize64 != 0 {
				t.Errorf("directory %s must have uncompressed size 0, got %d", file.Name, file.UncompressedSize64)
			}
			if file.CompressedSize64 != 2 {
				t.Errorf("directory %s must have compressed size 2, got %d", file.Name, file.CompressedSize64)
			}
			if file.CRC32 != 0 {
				t.Errorf("directory %s CRC should be 00000000, got %08X", file.Name, file.CRC32)
			}
		}
	}
}

// TestWithArchiverTorrentZip_RecordsOnlyTheRequest pins that the option itself
// settles nothing. The method and the level a torrentzip archive is written
// with follow from the format once every option has run, so that giving the
// options in either order cannot change the answer;
// TestTorrentZipSettlesWhatWasNotAskedFor pins the settlement.
func TestWithArchiverTorrentZip_RecordsOnlyTheRequest(t *testing.T) {
	opts := &archiverOptions{}
	opt := WithArchiverTorrentZip(true)
	if err := opt(opts); err != nil {
		t.Fatal(err)
	}
	if !opts.torrentZip {
		t.Error("the option did not record that torrentzip was asked for")
	}
	if opts.methodSet || opts.level != 0 {
		t.Error("the option decided the method or the level before the other options had run")
	}
}

func TestTorrentZip_BitExactWithReference(t *testing.T) {
	tmp := t.TempDir()

	// 1. Проверяем наличие "trrntzip" или "torrentzip" в PATH.
	// A lookup that reports an error has named nothing usable, so the path is
	// left empty and the build from the sibling checkout below takes over.
	trrntzipPath, err := exec.LookPath("trrntzip")
	if err != nil {
		trrntzipPath, err = exec.LookPath("torrentzip")
	}
	if err != nil {
		trrntzipPath = ""
	}

	var buildErr error
	var buildOut []byte

	if trrntzipPath == "" {
		// Пытаемся собрать эталонный torrentzip из папки ../torrentzip
		cwd, err := os.Getwd()
		if err == nil {
			tzDir := filepath.Join(cwd, "..", "torrentzip")
			tzBin := filepath.Join(tmp, "torrentzip_ref")
			if runtime.GOOS == "windows" {
				tzBin += ".exe"
			}
			buildCmd := exec.Command("go", "build", "-o", tzBin, "./cmd/torrentzip")
			buildCmd.Dir = tzDir
			buildOut, buildErr = buildCmd.CombinedOutput()
			if buildErr == nil {
				trrntzipPath = tzBin
			}
		}
	}

	if trrntzipPath == "" {
		t.Logf("WARNING: Reference torrentzip binary not found in PATH and failed to build. Skipping bit-exact integration test.\nBuild Error: %v\nBuild Output:\n%s", buildErr, string(buildOut))
		t.Skip("Reference torrentzip binary not found")
	}

	// 2. Подготовка файлов для архивации
	srcDir := filepath.Join(tmp, "src")
	mustMkdirAll(t, filepath.Join(srcDir, "dir1"))

	// Создаем большой файл (655360 байт, типичный TRD образ),
	// который будет сжиматься по-разному в Go flate и C zlib
	var buf bytes.Buffer
	for buf.Len() < 655360 {
		fmt.Fprintf(&buf, "This is some highly structured and repeating data that will test the LZ77 match finder differences between standard Go flate and C zlib. Line number: %d\n", buf.Len())
	}

	mustWriteFile(t, filepath.Join(srcDir, "Aaargh!.trd"), buf.Bytes()[:655360], 0644)
	mustWriteFile(t, filepath.Join(srcDir, "dir1", "file.txt"), []byte("highly structured and repeatable test data"), 0644)
	mustWriteFile(t, filepath.Join(srcDir, "a.txt"), []byte("some other file content"), 0644)
	mustMkdirAll(t, filepath.Join(srcDir, "empty_dir"))                           // Пустая директория
	mustWriteFile(t, filepath.Join(srcDir, "empty_file.txt"), []byte{}, 0644)     // Пустой регулярный файл
	mustWriteFile(t, filepath.Join(srcDir, "Z_file.txt"), []byte("data Z"), 0644) // Проверка регистронезависимой сортировки
	mustWriteFile(t, filepath.Join(srcDir, "a_file.txt"), []byte("data a"), 0644)

	// 3. Создаем TorrentZip через НАШ архиватор
	goZipPath := filepath.Join(tmp, "go_torrent.zip")
	fGo, err := os.Create(goZipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, fGo)

	a, err := NewArchiver(fGo, srcDir, WithArchiverTorrentZip(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	files := make(map[string]os.FileInfo)
	if err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if path != srcDir {
			files[path] = info
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close archiver: %v", err)
	}
	if err := fGo.Close(); err != nil {
		t.Fatalf("close %s: %v", goZipPath, err)
	}

	// 4. Копируем наш архив в ref_torrent.zip и напускаем на него эталонный torrentzip
	refZipPath := filepath.Join(tmp, "ref_torrent.zip")

	in, err := os.Open(goZipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, in)
	out, err := os.Create(refZipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, out)
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := in.Close(); err != nil {
		t.Fatalf("close %s: %v", goZipPath, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close %s: %v", refZipPath, err)
	}

	// Запуск эталонного torrentzip для конвертации
	var cmd *exec.Cmd
	isGoTool := false
	if trrntzipPath != "" {
		out, _ := exec.Command(trrntzipPath).CombinedOutput()
		if bytes.Contains(out, []byte("Uwe Hoffmann")) {
			isGoTool = true
		}
	}

	if isGoTool {
		// Go-версия требует явного указания -out и файлов
		cmd = exec.Command(trrntzipPath, "-out", refZipPath, ".")
		cmd.Dir = srcDir
	} else {
		// C-версия (trrntzip) работает in-place над готовым архивом
		cmd = exec.Command(trrntzipPath, refZipPath)
	}

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
		if errGo == nil {
			closeAt(t, zrGo)
		}
		zrRef, errRef := OpenReader(refZipPath)
		if errRef == nil {
			closeAt(t, zrRef)
		}

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

func TestTorrentZip_SlashNormalization(t *testing.T) {
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	zw.SetTorrentZip(true)

	// Имя с Windows-стилем разделителя
	const badName = "dir1\\file.txt"
	fh := &FileHeader{
		Name:   badName,
		Method: Deflate,
	}

	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, w, []byte("data"))
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	// Проверяем результат
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	expectedName := "dir1/file.txt"
	if zr.File[0].Name != expectedName {
		t.Errorf("expected slash normalization, got %q", zr.File[0].Name)
	}
}

// TestTorrentZip_DirectoriesOnlySortDeterministically pins the ordering rule
// on an archive of nothing but directories. The comparator gives a directory a
// trailing slash before it compares, on either side of the comparison, and an
// archive that mixes files with directories only reaches the second of those
// two when the order the names arrive in happens to put a directory on the
// right; with nothing but directories every comparison is one.
func TestTorrentZip_DirectoriesOnlySortDeterministically(t *testing.T) {
	src := t.TempDir()
	for _, name := range []string{"beta", "alpha", "gamma"} {
		mustMkdirAll(t, filepath.Join(src, name))
	}

	var buf bytes.Buffer
	a, err := NewArchiver(&buf, src, WithArchiverTorrentZip(true))
	if err != nil {
		t.Fatalf("new archiver: %v", err)
	}
	if err := a.Archive(context.Background(), walkFilesFor(t, src)); err != nil {
		t.Fatalf("archiving: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	r, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	var got []string
	for _, f := range r.File {
		got = append(got, f.Name)
	}
	want := []string{"alpha/", "beta/", "gamma/"}
	if len(got) != len(want) {
		t.Fatalf("the archive lists %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the archive lists %v, and torrentzip orders them %v", got, want)
		}
	}
}
