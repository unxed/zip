package zip

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/flate"
)

// updaterLevelPayload returns compressible text whose Deflate output size
// varies noticeably across levels, so a level that got silently swapped for
// another one is caught by a size mismatch rather than a coincidence.
func updaterLevelPayload() []byte {
	words := []string{
		"the", "archive", "file", "manager", "panel", "folder", "window", "keyboard",
		"selected", "quick", "search", "history", "settings", "compress", "packed",
		"stream", "level", "default", "method", "deflate", "entry", "header", "block",
	}
	var buf bytes.Buffer
	state := uint32(778899)
	for buf.Len() < 96*1024 {
		state = state*1664525 + 1013904223
		buf.WriteString(words[int(state>>16)%len(words)])
		if (state>>8)%13 == 0 {
			buf.WriteString(".\n")
		} else {
			buf.WriteByte(' ')
		}
	}
	return buf.Bytes()
}

// TestUpdaterAppendHeaderRespectsLevel guards the fix in
// unxed/zip#1 ("[Bug] Compression level always defaults to 5 in
// newFlateWriter"): AppendHeader must feed fh.Level to the flate writer it
// actually uses, not fall back to Updater.compressor's un-leveled default.
// Regression: before the fix an in-place update via the Updater ignored
// fh.Level and every entry came out compressed at the package default,
// regardless of what the caller asked for.
func TestUpdaterAppendHeaderRespectsLevel(t *testing.T) {
	payload := updaterLevelPayload()

	appendAtLevel := func(t *testing.T, level int) uint64 {
		t.Helper()
		tmp := t.TempDir()
		zipPath := filepath.Join(tmp, "update_level.zip")

		f, err := os.Create(zipPath)
		if err != nil {
			t.Fatalf("create zip: %v", err)
		}
		closeAt(t, f)
		zw := NewWriter(f)
		if err := zw.Close(); err != nil {
			t.Fatalf("close empty writer: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close zip: %v", err)
		}

		fRW, err := os.OpenFile(zipPath, os.O_RDWR, 0)
		if err != nil {
			t.Fatalf("open zip for update: %v", err)
		}
		closeAt(t, fRW)
		u, err := NewUpdater(fRW)
		if err != nil {
			t.Fatalf("init updater: %v", err)
		}
		fh := &FileHeader{
			Name:   "doc.txt",
			Method: Deflate,
			Level:  level,
		}
		w, err := u.AppendHeader(fh, APPEND_MODE_KEEP_ORIGINAL)
		if err != nil {
			t.Fatalf("AppendHeader failed: %v", err)
		}
		mustWrite(t, w, payload)
		if err := u.Close(); err != nil {
			t.Fatalf("close updater: %v", err)
		}
		if err := fRW.Close(); err != nil {
			t.Fatalf("close zip after update: %v", err)
		}

		zr, err := OpenReader(zipPath)
		if err != nil {
			t.Fatalf("open reader: %v", err)
		}
		closeAt(t, zr)
		if len(zr.File) != 1 {
			t.Fatalf("archive holds %d entries, want 1", len(zr.File))
		}
		return zr.File[0].CompressedSize64
	}

	directFlateSize := func(level int) uint64 {
		var buf bytes.Buffer
		w, err := flate.NewWriter(&buf, level)
		if err != nil {
			t.Fatalf("flate.NewWriter(level %d): %v", level, err)
		}
		if _, err := w.Write(payload); err != nil {
			t.Fatalf("flate write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("flate close: %v", err)
		}
		return uint64(buf.Len()) // #nosec G115 -- buf.Len() is always non-negative
	}

	for _, level := range []int{1, 9} {
		got := appendAtLevel(t, level)
		want := directFlateSize(level)
		if got != want {
			t.Errorf("level %d: Updater produced %d compressed bytes, want %d (direct flate.Writer at the same level) -- fh.Level was not propagated to the compressor", level, got, want)
		}
	}

	// The two levels must not have collapsed onto the same compressor
	// call: this is what "always defaults to 5, ignoring the custom
	// level" would look like here.
	sizeLevel1 := appendAtLevel(t, 1)
	sizeLevel9 := appendAtLevel(t, 9)
	if sizeLevel1 == sizeLevel9 {
		t.Errorf("level 1 and level 9 produced identical compressed sizes (%d): fh.Level looks ignored", sizeLevel1)
	}
}

// TestNewFlateWriterMatchesFlateDefaultCompression guards the other half of
// the unxed/zip#1 fix: the package-default Deflate compressor (used when no
// explicit level is registered) must derive from flate.DefaultCompression,
// not from a level hardcoded independently of it.
func TestNewFlateWriterMatchesFlateDefaultCompression(t *testing.T) {
	payload := updaterLevelPayload()

	var gotBuf bytes.Buffer
	w := newFlateWriter(&gotBuf)
	mustWrite(t, w, payload)
	if err := w.Close(); err != nil {
		t.Fatalf("close newFlateWriter: %v", err)
	}

	var wantBuf bytes.Buffer
	fw, err := flate.NewWriter(&wantBuf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter(DefaultCompression): %v", err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}

	if !bytes.Equal(gotBuf.Bytes(), wantBuf.Bytes()) {
		t.Errorf("newFlateWriter output (%d bytes) does not match flate.NewWriter(flate.DefaultCompression) output (%d bytes)", gotBuf.Len(), wantBuf.Len())
	}
}
