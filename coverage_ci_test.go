package zip

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
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

func coverageDirectoryHeader(extra []byte, disk uint16) []byte {
	b := make([]byte, directoryHeaderLen+len(extra))
	binary.LittleEndian.PutUint32(b, directoryHeaderSignature)
	binary.LittleEndian.PutUint16(b[26:], 0)
	binary.LittleEndian.PutUint16(b[28:], uint16(len(extra)))
	binary.LittleEndian.PutUint16(b[30:], 0)
	binary.LittleEndian.PutUint16(b[34:], disk)
	copy(b[directoryHeaderLen:], extra)
	return b
}

func coverageZip64Extra(size int) []byte {
	extra := make([]byte, 4+size)
	binary.LittleEndian.PutUint16(extra, zip64ExtraID)
	binary.LittleEndian.PutUint16(extra[2:], uint16(size))
	return extra
}

func coverageMarkZip64Fields(header []byte) {
	binary.LittleEndian.PutUint32(header[18:], uint32max)
	binary.LittleEndian.PutUint32(header[22:], uint32max)
	binary.LittleEndian.PutUint32(header[42:], uint32max)
}

func TestCoverageSplitVolumeMissingArchive(t *testing.T) {
	if got, ok := splitVolumeArchiveName("missing.z01"); ok || got != "" {
		t.Fatalf("missing split volume = %q, %v", got, ok)
	}
}

func TestCoverageSplitVolumeFindsZipx(t *testing.T) {
	stem := filepath.Join(t.TempDir(), "archive")
	if err := os.WriteFile(stem+".zipx", []byte("zipx"), 0600); err != nil {
		t.Fatal(err)
	}
	got, ok := splitVolumeArchiveName(stem + ".z01")
	if !ok || got != stem+".zipx" {
		t.Fatalf("zipx split volume = %q, %v", got, ok)
	}
}

func TestCoverageVolumeStartRejectsUnknownDisk(t *testing.T) {
	if got, ok := volumeStart([]int64{0}, 1); ok || got != 0 {
		t.Fatalf("unknown volume start = %d, %v", got, ok)
	}
}

func TestCoverageHasDirectoryHeaderReadError(t *testing.T) {
	if hasDirectoryHeader(bytes.NewReader(nil), 0) {
		t.Fatal("short reader reported a directory header")
	}
}

func TestCoverageHasDirectoryHeaderRejectsWrongSignature(t *testing.T) {
	if hasDirectoryHeader(bytes.NewReader([]byte{1, 2, 3, 4}), 0) {
		t.Fatal("wrong signature reported as a directory header")
	}
}

func TestCoverageReadDirectoryHeaderRejectsMissingDiskNumber(t *testing.T) {
	extra := coverageZip64Extra(24)
	header := coverageDirectoryHeader(extra, uint16(^uint16(0)))
	coverageMarkZip64Fields(header)
	var f File
	if err := readDirectoryHeader(&f, bytes.NewReader(header)); err != ErrFormat {
		t.Fatalf("missing ZIP64 disk number error = %v", err)
	}
}

func TestCoverageReadDirectoryHeaderReadsDiskNumber(t *testing.T) {
	extra := coverageZip64Extra(28)
	binary.LittleEndian.PutUint64(extra[4:], 11)
	binary.LittleEndian.PutUint64(extra[12:], 22)
	binary.LittleEndian.PutUint64(extra[20:], 33)
	binary.LittleEndian.PutUint32(extra[28:], 7)
	header := coverageDirectoryHeader(extra, uint16(^uint16(0)))
	coverageMarkZip64Fields(header)
	var f File
	if err := readDirectoryHeader(&f, bytes.NewReader(header)); err != nil {
		t.Fatal(err)
	}
	if f.diskNbr != 7 {
		t.Fatalf("disk number = %d", f.diskNbr)
	}
}

func TestCoverageReadDirectoryHeaderRejectsBadSignature(t *testing.T) {
	var f File
	if err := readDirectoryHeader(&f, bytes.NewReader(make([]byte, directoryHeaderLen))); err != ErrFormat {
		t.Fatalf("bad signature error = %v", err)
	}
}

func TestCoverageSplitVolumeRejectsNonNumericSuffix(t *testing.T) {
	if got, ok := splitVolumeArchiveName("archive.zx1"); ok || got != "" {
		t.Fatalf("non-numeric suffix = %q, %v", got, ok)
	}
}

func TestCoverageSplitVolumeRejectsShortSuffix(t *testing.T) {
	if got, ok := splitVolumeArchiveName("archive.z"); ok || got != "" {
		t.Fatalf("short suffix = %q, %v", got, ok)
	}
}