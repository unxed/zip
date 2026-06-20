package filepool

import (
	"errors"
	"io"
	"os"
	"testing"
)

func TestFilePool_Basic(t *testing.T) {
	tmpDir := t.TempDir()

	fp, err := New(tmpDir, 2, 1024)
	if err != nil {
		t.Fatalf("Failed to create file pool: %v", err)
	}

	f1 := fp.Get()
	if f1 == nil {
		t.Fatal("Expected non-nil file from pool")
	}

	n, err := f1.Write([]byte("hello pool"))
	if err != nil || n != 10 {
		t.Errorf("Failed to write to pool file: %d, %v", n, err)
	}

	if f1.Written() != 10 {
		t.Errorf("Expected 10 written bytes, got %d", f1.Written())
	}

	f1.Hasher().Write([]byte("hello pool"))
	if f1.Checksum() == 0 {
		t.Error("Expected non-zero checksum")
	}

	buf := make([]byte, 10)
	n, err = f1.Read(buf)
	if err != nil && err != io.EOF {
		t.Errorf("Failed to read from pool file: %d, %v", n, err)
	}
	if string(buf[:n]) != "hello pool" {
		t.Errorf("Expected 'hello pool', got %q", string(buf[:n]))
	}

	fp.Put(f1)

	// Verify that the file was reset
	f2 := fp.Get()
	if f2.Written() != 0 {
		t.Errorf("Expected file to be reset, but written size is %d", f2.Written())
	}
	fp.Put(f2)

	err = fp.Close()
	if err != nil {
		t.Fatalf("Failed to close file pool: %v", err)
	}
}

func TestFilePool_ZeroSize(t *testing.T) {
	_, err := New(".", 0, 1024)
	if err != ErrPoolSizeLessThanZero {
		t.Errorf("Expected ErrPoolSizeLessThanZero, got %v", err)
	}
}

func TestFilePool_WritePastBuffer(t *testing.T) {
	tmpDir := t.TempDir()

	// Create pool with extremely small buffer to force writing to temp file
	fp, err := New(tmpDir, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer fp.Close()

	f := fp.Get()
	defer fp.Put(f)

	data := []byte("this data exceeds the small buffer size of 4 bytes")
	n, err := f.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected %d bytes written, got %d", len(data), n)
	}

	if f.f == nil {
		t.Error("Expected backing file to be created, but it's nil")
	}

	readBuf := make([]byte, len(data))
	n, err = f.Read(readBuf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected %d bytes read, got %d", len(data), n)
	}

	if string(readBuf) != string(data) {
		t.Errorf("Data mismatch. Got %q, want %q", string(readBuf), string(data))
	}
}

func TestFilePoolCloseError(t *testing.T) {
	errs := filePoolCloseError{errors.New("error 1"), errors.New("error 2")}

	if errs.Len() != 2 {
		t.Errorf("Expected length 2, got %d", errs.Len())
	}

	str := errs.Error()
	if str != "error 1\nerror 2\n" {
		t.Errorf("Unexpected error string: %q", str)
	}

	unwrapped := errs.Unwrap()
	if unwrapped == nil {
		t.Errorf("Expected unwrapped error, got nil")
	}

	singleErr := filePoolCloseError{errors.New("single error")}
	if singleErr.Error() != "single error" {
		t.Errorf("Unexpected single error string: %q", singleErr.Error())
	}
}

func TestFilePool_CleanupOnClose(t *testing.T) {
	tmpDir := t.TempDir()

	fp, err := New(tmpDir, 1, 4)
	if err != nil {
		t.Fatal(err)
	}

	f := fp.Get()
	f.Write([]byte("exceed buffer size to create physical file"))

	physicalName := f.f.Name()
	if _, err := os.Stat(physicalName); os.IsNotExist(err) {
		t.Fatalf("Physical file %s was not created", physicalName)
	}

	fp.Put(f)

	err = fp.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if _, err := os.Stat(physicalName); err == nil {
		t.Errorf("Physical file %s was not deleted during cleanup", physicalName)
	}
}
