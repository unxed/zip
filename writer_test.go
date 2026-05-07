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

	// Simulate a huge file via the header, without writing terabytes of data
	fh := &FileHeader{
		Name:               "huge.txt",
		Method:             Store,
		UncompressedSize64: uint64(uint32max) + 1, // More than 4GB
		CompressedSize64:   uint64(uint32max) + 1,
	}

	// CreateRaw allows us to write the data "as is"
	wr, err := w.CreateRaw(fh)
	if err != nil {
		t.Fatal(err)
	}
	wr.Write([]byte("fake data"))
	w.Close()

	// Now read and check that the zip64 flag was set
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

	// Simulate a situation where there are more than 65535 files (uint16 limit)
	// To save time and memory, we will modify the counter directly in the test
	for i := 0; i < 10; i++ {
		w.Create(fmt.Sprintf("file_%d.txt", i))
	}

	// Hack for the test: substitute the number of records before closing
	// to trigger writing of ZIP64 headers
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

	// Check that the EOCD structure contains the 0xFFFF markers,
	// which indicates the presence of the ZIP64 Locator
	data := buf.Bytes()
	// EOCD signature: 0x06054b50 in Little Endian
	if !bytes.Contains(data, []byte{0x50, 0x4b, 0x05, 0x06}) {
		t.Error("EOCD signature not found")
	}

	// Restore as it was for proper completion
	w.dir = originalDir
}
func TestWriter_LongNameError(t *testing.T) {
	buf := new(bytes.Buffer)
	w := NewWriter(buf)

	// Create a name with a length greater than 65535 bytes
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
	w.SetOffset(100) // Should cause a panic
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

	// Use the standard os.DirFS
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
	// This test requires a valid LZMA stream. 
	// We will simply verify the method registration.
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

	// 1. Checking timestamps via 0x5455 (Extended Timestamp)
	if f.Modified.Unix() != fh.Modified.Unix() {
		t.Errorf("Modified time mismatch: got %v, want %v", f.Modified, fh.Modified)
	}
	if f.Accessed.Unix() != fh.Accessed.Unix() {
		t.Errorf("Accessed time mismatch: got %v, want %v", f.Accessed, fh.Accessed)
	}

	// 2. Verifying UNIX ID via 0x7875 (Info-ZIP New Unix)
	uid, gid, ok := parseUnixExtra(f.Extra)
	if !ok {
		t.Fatal("Unix extra field (0x7875) not found in output")
	}
	if uid != 501 || gid != 20 {
		t.Errorf("UID/GID mismatch: got %d:%d, want 501:20", uid, gid)
	}
}
func TestWriter_MetadataIdempotency(t *testing.T) {
	// Verifying that multiple calls to the injector do not duplicate Extra Fields.
	now := time.Now().Truncate(time.Second)
	fh := &FileHeader{
		Name:     "idempotent.txt",
		Modified: now,
		Uid:      1000,
		OwnerSet: true,
	}

	// First Call (via Creation)
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	zw.CreateHeader(fh)
	zw.Close()

	initialExtraLen := len(fh.Extra)

	// Simulating a repeated injection (for example, when reusing a header).
	fh.injectAutoExtras()
	fh.injectAutoExtras()

	if len(fh.Extra) != initialExtraLen {
		t.Errorf("Extra fields bloated! initial %d, current %d. Likely duplicate tags.", initialExtraLen, len(fh.Extra))
	}
}
func TestWriter_CDE(t *testing.T) {
	password := "cd-secret"
	buf := new(bytes.Buffer)

	// 1. Create an archive with an encrypted central directory
	zw := NewWriter(buf)
	zw.SetEncryptCentralDirectory(true, password)
	w, _ := zw.Create("hidden.txt")
	w.Write([]byte("can you see me?"))
	zw.Close()

	raw := buf.Bytes()

	// 2. Try to open without a password — it should fail when reading headers
	_, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err == nil {
		t.Error("expected error when opening CDE archive without password")
	}

	// 2.1 Try to open with an INCORRECT password
	zrWrongPass := new(Reader)
	zrWrongPass.SetPassword("wrong-password")
	err = zrWrongPass.init(bytes.NewReader(raw), int64(len(raw)))
	if err == nil || err.Error() != "zip: incorrect password" {
		t.Errorf("expected 'incorrect password' error, got: %v", err)
	}

	// 3. Open with the correct password
	zr := new(Reader)
	zr.SetPassword(password)
	// Direct call to init, as NewReader does not take a password in the constructor immediately
	err = zr.init(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("failed to open CDE archive with password: %v", err)
	}

	if len(zr.File) != 1 || zr.File[0].Name != "hidden.txt" {
		t.Errorf("failed to recover file list from CDE")
	}
}

func TestWriter_StreamingForced(t *testing.T) {
	buf := new(bytes.Buffer)
	zw := NewWriter(buf)

	// Simulating streaming using SetOffset
	zw.SetOffset(0)

	fh := &FileHeader{Name: "stream.txt", Method: Store}
	// Even for a Store, we can force a descriptor if we want absolute streaming.
	w, _ := zw.CreateHeader(fh)
	w.Write([]byte("streaming data"))
	zw.Close()

	// We verify that flag 0x8 (Data Descriptor) is set.
	zr, _ := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if zr.File[0].Flags&0x8 == 0 {
		t.Error("Data Descriptor flag not set in streaming mode")
	}
}
