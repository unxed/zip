//go:build unix

package zip

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// An entry's mode used to be put on by path once the file had been written and
// closed, which is a different thing from putting it on the file: between the
// two, another entry whose parent chain runs through the same name has the
// extraction replace the file with a directory, and the mode then lands on the
// directory. A file's mode carries no search bit, so what is left is a
// directory its owner cannot go into -- and an extraction that failed halfway
// leaves it behind, where not even the caller can be rid of it. Found by
// fuzzing.
//
// Unix only: on Windows a file that is open cannot be replaced, so the two
// steps cannot be prised apart there.

// extractorModeEntry builds a one-entry archive and hands back the entry, so
// that a test can run one step of the extraction over it by hand.
func extractorModeEntry(t *testing.T, name string, mode os.FileMode) (*Extractor, *File) {
	t.Helper()
	var buf bytes.Buffer
	w := NewWriter(&buf)
	fh := &FileHeader{Name: name, Method: Store}
	fh.SetMode(mode)
	fw, err := w.CreateHeader(fh)
	if err != nil {
		t.Fatalf("CreateHeader: %v", err)
	}
	if _, err := fw.Write([]byte("the entry")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	e, err := NewExtractorFromReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()), t.TempDir(),
		WithExtractorConcurrency(1), WithExtractorNoTimes(true))
	if err != nil {
		t.Fatalf("new extractor: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e, e.zr.File[0]
}

// TestExtractorModeIsNotPutOnByPath pins the fix at its narrowest: by the time
// the metadata step runs, the name may belong to a directory another entry's
// parent chain put there, and that directory must come through the step as it
// was.
func TestExtractorModeIsNotPutOnByPath(t *testing.T) {
	e, file := extractorModeEntry(t, "entry.txt", 0o640)

	dir := t.TempDir()
	path := filepath.Join(dir, "entry.txt")
	// What another entry's parent chain leaves at that name.
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("putting a directory there: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "deep.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("filling it: %v", err)
	}

	if err := e.updateFileMetadata(path, file); err != nil {
		t.Fatalf("the metadata step: %v", err)
	}

	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("looking at the name: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("the name holds %v, and the whole point of this is that it is a directory", fi.Mode())
	}
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("the directory came out of the metadata step with mode %v: a file entry's mode was put on by name",
			fi.Mode().Perm())
	}
	if _, err := os.ReadDir(path); err != nil {
		t.Fatalf("the directory cannot be gone into: %v", err)
	}
}

// TestExtractorModeGoesOnThroughTheHandle is the other half: the mode does
// reach the file, and it reaches it through the handle that wrote it, so a
// name taken over in the meantime does not take the mode with it.
func TestExtractorModeGoesOnThroughTheHandle(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	fh := &FileHeader{Name: "a.txt", Method: Store}
	fh.SetMode(0o640)
	fw, err := w.CreateHeader(fh)
	if err != nil {
		t.Fatalf("CreateHeader: %v", err)
	}
	if _, err := fw.Write([]byte("body")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	dst := t.TempDir()
	e, err := NewExtractorFromReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()), dst,
		WithExtractorConcurrency(1), WithExtractorNoTimes(true))
	if err != nil {
		t.Fatalf("new extractor: %v", err)
	}
	defer func() { _ = e.Close() }()
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extracting: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(dst, "a.txt"))
	if err != nil {
		t.Fatalf("looking at the extracted file: %v", err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("the extracted file has mode %v, and the archive said 0640", fi.Mode().Perm())
	}
}
