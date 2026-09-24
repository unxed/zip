package zip

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestCoverageSectionReaderWriterConstructor(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "section")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if newSectionReaderWriter(f) == nil {
		t.Fatal("constructor returned nil")
	}
}

func TestCoverageSectionReaderWriterSeek(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "section")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	s := newSectionReaderWriter(f)
	if _, err := s.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
}

func TestCoverageSectionReaderWriterRead(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "section")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	s := newSectionReaderWriter(f)
	if _, err := s.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if n, err := s.Read(buf); err != nil || n != 4 {
		t.Fatalf("Read = %d, %v", n, err)
	}
}

func TestCoverageSectionReaderWriterWrite(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "section")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	s := newSectionReaderWriter(f)
	if n, err := s.Write([]byte("data")); err != nil || n != 4 {
		t.Fatalf("Write = %d, %v", n, err)
	}
}

func TestCoverageDirectoryHeaderOffset(t *testing.T) {
	d := &Directory{offset: 42}
	if got := d.HeaderOffset(); got != 42 {
		t.Fatalf("HeaderOffset = %d", got)
	}
}

func TestCoverageUpdaterAppendHeader(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "archive-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	w := NewWriter(f)
	entry, err := w.Create("old.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	u, err := NewUpdater(f)
	if err != nil {
		t.Fatal(err)
	}
	entry, err = u.AppendHeader(&FileHeader{Name: "new.txt", Method: Store}, APPEND_MODE_KEEP_ORIGINAL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCoverageUpdaterAppendHeaderRejectsInvalidExtra(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "archive-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	w := NewWriter(f)
	if _, err := w.Create("old.txt"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	u, err := NewUpdater(f)
	if err != nil {
		t.Fatal(err)
	}
	_, err = u.AppendHeader(&FileHeader{Name: "bad.txt", Extra: []byte{1, 2, 3}}, APPEND_MODE_KEEP_ORIGINAL)
	if err == nil {
		t.Fatal("invalid extra was accepted")
	}
	_ = u.Close()
}

func TestCoverageChunkSeekWriter(t *testing.T) {
	buf := new(bytes.Buffer)
	w := NewWriter(buf)
	fh := &FileHeader{Name: "chunk.txt", Method: Deflate, SeekChunkSize: 4}
	entry, err := w.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("chunked data")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCoverageChunkSeekWriterContinuous(t *testing.T) {
	buf := new(bytes.Buffer)
	w := NewWriter(buf)
	fh := &FileHeader{Name: "chunk.txt", Method: Deflate, SeekChunkSize: 4, SeekContinuous: true}
	entry, err := w.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte("chunked data")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
