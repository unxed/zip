package zip

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDeflate64_Registration(t *testing.T) {
	// Verify that the method is registered in the global map
	dcomp := decompressor(Deflate64)
	if dcomp == nil {
		t.Fatal("Deflate64 decompressor not registered")
	}
}
func TestDeflate64_GoNative(t *testing.T) {
	// Compress some repeating text using standard Deflate
	data := []byte("deflate64 native decoder compatibility test with repeating data repeating data repeating data")
	buf := new(bytes.Buffer)

	zw := NewWriter(buf)
	fh := &FileHeader{
		Name:   "native.txt",
		Method: Deflate, // Write using standard Deflate
	}
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(data)
	zw.Close()

	// Open and override Method to Deflate64 so the reader uses decodeDeflate64
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]
	f.Method = Deflate64 // Force reader to use Deflate64 decoder

	rc, err := f.Open()
	if err != nil {
		t.Fatalf("failed to open using Deflate64 decoder: %v", err)
	}
	defer rc.Close()

	decompressed, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("Deflate64 decompression failed: %v", err)
	}

	if !bytes.Equal(decompressed, data) {
		t.Errorf("decompressed content mismatch: got %q, want %q", string(decompressed), string(data))
	}
}

func TestDeflate64_External7z(t *testing.T) {
	p7zPath, err := exec.LookPath("7z")
	if err != nil {
		t.Skip("7z utility not found, skipping external Deflate64 compression test")
	}

	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "test.txt")

	// Create content with repeating patterns to test huffman/LZ references
	var content bytes.Buffer
	for i := 0; i < 1000; i++ {
		content.WriteString("Deflate64 compression test data repeating multiple times to verify backreferences on larger streams. ")
	}
	err = os.WriteFile(srcFile, content.Bytes(), 0644)
	if err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(tmpDir, "deflate64_7z.zip")

	// Run 7z to compress to Deflate64 method
	cmd := exec.Command(p7zPath, "a", "-tzip", "-m0=deflate64", zipPath, srcFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("7z compression failed: %v, output: %s", err, string(output))
	}

	// Open with our library
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open generated zip: %v", err)
	}
	defer zr.Close()

	if len(zr.File) == 0 {
		t.Fatal("no files in the zip archive")
	}

	f := zr.File[0]
	if f.Method != Deflate64 {
		t.Errorf("expected compression method Deflate64 (%d), got %d", Deflate64, f.Method)
	}

	rc, err := f.Open()
	if err != nil {
		t.Fatalf("failed to open file inside zip: %v", err)
	}
	defer rc.Close()

	decompressed, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("decompression failed: %v", err)
	}

	if !bytes.Equal(decompressed, content.Bytes()) {
		t.Error("decompressed content mismatch with original")
	}
}
