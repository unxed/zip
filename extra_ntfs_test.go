package zip

import (
    "context"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNtfsAcl_SerDes(t *testing.T) {
	fakeAcl := []byte{0x01, 0x00, 0x04, 0x80, 0x30, 0x00, 0x00, 0x00} // Mock SD
	extra := appendNtfsAcl(nil, fakeAcl)

	parsed := parseNtfsAcl(extra)
	if !bytes.Equal(parsed, fakeAcl) {
		t.Errorf("NTFS ACL mismatch. Got %x, want %x", parsed, fakeAcl)
	}
}

func TestWriter_NtfsAclIntegration(t *testing.T) {
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)

	acl := []byte("windows-security-descriptor")
	fh := &FileHeader{
		Name: "acl.txt",
		Acl:  acl,
	}
	zw.CreateHeader(fh)
	zw.Close()

	zr, _ := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if !bytes.Equal(zr.File[0].Acl, acl) {
		t.Errorf("Acl field was not recovered: %q", string(zr.File[0].Acl))
	}
}

func TestNtfsAclAndAds_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping Windows-specific test")
	}

	tmp := t.TempDir()
	filePath := filepath.Join(tmp, "test.txt")
	err := os.WriteFile(filePath, []byte("main data"), 0644)
	if err != nil {
		t.Fatalf("failed to write main file: %v", err)
	}

	// Write an alternate data stream
	adsPath := filePath + ":my_stream"
	err = os.WriteFile(adsPath, []byte("stream data"), 0644)
	if err != nil {
		t.Fatalf("failed to write alternate data stream: %v", err)
	}

	// Verify getAlternativeDataStreams
	streams, err := getAlternativeDataStreams(filePath)
	if err != nil {
		t.Fatalf("getAlternativeDataStreams failed: %v", err)
	}
	found := false
	for _, s := range streams {
		if s == ":my_stream" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find stream ':my_stream', got %v", streams)
	}

	// Verify getFileSecurity
	acl, err := getFileSecurity(filePath)
	if err != nil {
		t.Fatalf("getFileSecurity failed: %v", err)
	}
	if len(acl) == 0 {
		t.Error("expected non-empty security descriptor")
	}

	// Verify applyNtfsAcl
	err = applyNtfsAcl(filePath, acl)
	if err != nil {
		t.Errorf("applyNtfsAcl failed: %v", err)
	}
}
func TestNtfsAclAndAds_Mocked(t *testing.T) {
	// Сохраняем оригинальные функции для последующего восстановления
	origGetFileSecurity := getFileSecurityFunc
	origApplyNtfsAcl := applyNtfsAclFunc
	origGetAlternativeDataStreams := getAlternativeDataStreamsFunc

	defer func() {
		getFileSecurityFunc = origGetFileSecurity
		applyNtfsAclFunc = origApplyNtfsAcl
		getAlternativeDataStreamsFunc = origGetAlternativeDataStreams
	}()

	mockAcl := []byte("mock-security-descriptor-data")
	mockStreams := []string{":Zone.Identifier", ":custom_stream"}

	// Настраиваем моки
	getFileSecurityFunc = func(path string) ([]byte, error) {
		return mockAcl, nil
	}

	appliedAcl := []byte{}
	applyNtfsAclFunc = func(path string, acl []byte) error {
		appliedAcl = acl
		return nil
	}

	getAlternativeDataStreamsFunc = func(path string) ([]string, error) {
		return mockStreams, nil
	}

	// Проверяем логику работы архиватора с моками
	tmp := t.TempDir()
	filePath := filepath.Join(tmp, "test_file.txt")
	os.WriteFile(filePath, []byte("some content"), 0644)

	// Создаем виртуальные потоки на диске, чтобы os.Stat не падал при архивации
	os.WriteFile(filePath+":Zone.Identifier", []byte("zone data"), 0644)
	os.WriteFile(filePath+":custom_stream", []byte("custom data"), 0644)

	zipPath := filepath.Join(tmp, "archive.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}

	// Включаем xattrs для вызова sysXattrs и getAlternativeDataStreamsFunc
	a, err := NewArchiver(f, tmp, WithArchiverXattrs(true))
	if err != nil {
		t.Fatal(err)
	}

	info, _ := os.Stat(filePath)
	files := map[string]os.FileInfo{filePath: info}

	err = a.Archive(context.Background(), files)
	if err != nil {
		t.Fatalf("Archiving with mocks failed: %v", err)
	}
	a.Close()
	f.Close()

	// Извлекаем и проверяем вызовы функций восстановления
	dstDir := filepath.Join(tmp, "extracted")
	e, err := NewExtractor(zipPath, dstDir, WithExtractorXattrs(true))
	if err != nil {
		t.Fatal(err)
	}

	err = e.Extract(context.Background())
	if err != nil {
		t.Fatalf("Extraction with mocks failed: %v", err)
	}
	e.Close()

	// Проверяем, что восстановленный ACL совпадает с моком
	if !bytes.Equal(appliedAcl, mockAcl) {
		t.Errorf("expected applied ACL %q, got %q", string(mockAcl), string(appliedAcl))
	}
}
