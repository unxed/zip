package zip

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// proseLike returns n bytes of pseudo-random words: plain text, well under 136
// distinct byte values, with the repeats a real document has.
func proseLike(n int) []byte {
	words := []string{
		"the", "archive", "file", "manager", "panel", "folder", "window", "keyboard",
		"selected", "quick", "search", "history", "settings", "compress", "packed",
		"stream", "level", "default", "method", "deflate", "entry", "header", "block",
		"of", "and", "to", "in", "with", "for", "is", "a", "an", "it", "on", "as",
	}
	var buf bytes.Buffer
	state := uint32(12345)
	for buf.Len() < n {
		state = state*1664525 + 1013904223
		buf.WriteString(words[int(state>>16)%len(words)])
		if (state>>8)%13 == 0 {
			buf.WriteString(".\n")
		} else {
			buf.WriteByte(' ')
		}
	}
	return buf.Bytes()[:n]
}

// archiveRatio packs one file with the given options and returns
// compressed/uncompressed size in percent.
func archiveRatio(t *testing.T, data []byte, opts ...ArchiverOption) float64 {
	t.Helper()
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	mustMkdirAll(t, srcDir)
	mustWriteFile(t, filepath.Join(srcDir, "doc.txt"), data, 0o644)

	zipPath := filepath.Join(tmpDir, "out.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	a, err := NewArchiver(f, srcDir, opts...)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, a)

	files := make(map[string]os.FileInfo)
	if err := filepath.Walk(srcDir, func(p string, info os.FileInfo, err error) error {
		if p != srcDir {
			files[p] = info
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.Archive(context.Background(), files); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, zr)
	if len(zr.File) != 1 {
		t.Fatalf("archive holds %d entries, want 1", len(zr.File))
	}
	return float64(zr.File[0].CompressedSize64) / float64(zr.File[0].UncompressedSize64) * 100
}

// A text file is what the byte-histogram heuristic mistakes for "entropy coding
// is enough": few distinct bytes, none dominant. At the default level that cut
// LZ77 out entirely and a 120 KB text came out at ~72% (f4 issue #1243) where a
// real Deflate gets a third of that. Only the explicit BestSpeed level, which
// the heuristic was written for, keeps the shortcut.
func TestArchiver_DefaultLevelKeepsLZ77ForText(t *testing.T) {
	data := proseLike(120 * 1024)

	ratio := archiveRatio(t, data, WithArchiverMethod(Deflate))
	t.Logf("default level: %.1f%%", ratio)
	if ratio > 45 {
		t.Errorf("default level packed prose to %.1f%%, want the LZ77 result (under 45%%)", ratio)
	}

	ratio = archiveRatio(t, data, WithArchiverLevel(9), WithArchiverMethod(Deflate))
	t.Logf("level 9: %.1f%%", ratio)
	if ratio > 45 {
		t.Errorf("level 9 packed prose to %.1f%%, want the LZ77 result (under 45%%)", ratio)
	}
}
