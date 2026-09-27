package zip

import (
	"bytes"
	"context"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// writeRawNamedZip builds an archive whose entry names are handed over as raw
// bytes, undecodable ones included, and returns its path.
func writeRawNamedZip(t *testing.T, dir string, entries map[string]string) string {
	t.Helper()
	zipPath := filepath.Join(dir, "pua.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fh := &FileHeader{Name: name, Method: Store}
		fh.SetMode(0644)
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(entries[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return zipPath
}

// wantOnDisk is the spelling an entry name is expected to have on disk here.
//
// It is written out longhand rather than by calling osFileName, so that the
// test states the contract instead of restating the implementation: on a
// filesystem that takes a name as bytes the name is the archive's bytes,
// and on Windows and macOS every byte that is not part of a valid UTF-8
// sequence becomes one private-use character while the valid runs survive
// untouched -- which is what keeps an extension readable.
func wantOnDisk(raw string) string {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		return raw
	}
	b := []byte(raw)
	out := make([]rune, 0, len(b))
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 {
			out = append(out, rune(0xE000)+rune(b[i]))
			i++
			continue
		}
		out = append(out, r)
		i += size
	}
	return string(out)
}

func extractTo(t *testing.T, zipPath, dstDir string) []string {
	t.Helper()
	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("Extraction failed: %v", err)
	}

	ents, err := os.ReadDir(dstDir)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(ents))
	for _, ent := range ents {
		got = append(got, ent.Name())
	}
	sort.Strings(got)
	return got
}

func TestPUA_Zip_EncodingPreservation(t *testing.T) {
	tmpDir := t.TempDir()
	rawName := "bad_utf8_\xff\xfe_name.txt"

	zipPath := writeRawNamedZip(t, tmpDir, map[string]string{rawName: "pua-data"})
	dstDir := filepath.Join(tmpDir, "extract")
	onDisk := extractTo(t, zipPath, dstDir)

	want := wantOnDisk(rawName)
	if len(onDisk) != 1 || onDisk[0] != want {
		t.Fatalf("extracted names = %q, want exactly [%q]", onDisk, want)
	}

	data, err := os.ReadFile(filepath.Join(dstDir, want))
	if err != nil {
		t.Fatalf("reading the extracted file: %v", err)
	}
	if string(data) != "pua-data" {
		t.Errorf("content = %q, want %q", data, "pua-data")
	}

	// The undecodable bytes are escaped one by one, so everything around them
	// is still the text it was -- an extension included. A name turned into a
	// row of boxes would satisfy "reversible" and be useless to look at.
	if !strings.HasSuffix(want, "_name.txt") || !strings.HasPrefix(want, "bad_utf8_") {
		t.Errorf("the readable parts of the name did not survive: %q", want)
	}
}

// TestPUA_Zip_DistinctUndecodableNames pins the collision that replacing the
// undecodable bytes causes. The two names differ only in one byte that no
// decoder can turn into a character, so a platform that replaces such bytes
// with U+FFFD sees one name twice and the second entry overwrites the first.
func TestPUA_Zip_DistinctUndecodableNames(t *testing.T) {
	tmpDir := t.TempDir()
	first, second := "a_\xfe.txt", "a_\xff.txt"

	zipPath := writeRawNamedZip(t, tmpDir, map[string]string{first: "one", second: "two"})
	dstDir := filepath.Join(tmpDir, "extract")
	onDisk := extractTo(t, zipPath, dstDir)

	want := []string{wantOnDisk(first), wantOnDisk(second)}
	sort.Strings(want)
	if len(onDisk) != 2 || onDisk[0] != want[0] || onDisk[1] != want[1] {
		t.Fatalf("extracted names = %q, want exactly %q", onDisk, want)
	}

	for name, content := range map[string]string{first: "one", second: "two"} {
		data, err := os.ReadFile(filepath.Join(dstDir, wantOnDisk(name)))
		if err != nil {
			t.Fatalf("reading the file for %q: %v", name, err)
		}
		if string(data) != content {
			t.Errorf("file for %q has content %q, want %q", name, data, content)
		}
	}
}

func TestEscapeInvalidUTF8(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"nothing to escape", "plain.txt", "plain.txt"},
		{"empty", "", ""},
		{"one bad byte", "a\xffb", "a\ue0ffb"},
		{"bad byte at the end", "name.\xfe", "name.\ue0fe"},
		{"two bad bytes stay distinct", "\xfe\xff", "\ue0fe\ue0ff"},
		{"multi-byte runes are copied whole", "é中\xff", "é中\ue0ff"},
		// A real U+FFFD is three bytes of valid UTF-8 and must survive as
		// itself rather than be taken for a decoding failure.
		{"a genuine replacement character is not a failure", "a�b", "a�b"},
		{"a truncated sequence is escaped byte by byte", "\xe4\xb8", "\ue0e4\ue0b8"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeInvalidUTF8([]byte(tt.in)); got != tt.want {
				t.Errorf("escapeInvalidUTF8(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestPUA_Zip_NestedUndecodableNameMetadata pins the path the metadata pass
// works on for an undecodable name that is not at the top of the archive.
//
// The path came out of absPath, which has already spelled the name for the
// filesystem. Spelling it a second time from the parent directory appends the
// whole relative name to a directory that is already part of it, so
// "dir/bad_<byte>.txt" turns into ".../dir/dir/bad_<byte>.txt" -- a path that
// does not exist, which is where the ownership and the extended attributes
// then went.
func TestPUA_Zip_NestedUndecodableNameMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	rawName := "dir/bad_\xff.txt"

	uid, gid := os.Getuid(), os.Getgid()
	if uid < 0 {
		// Windows has no numeric owner to ask for, and lchown there does
		// nothing; any value serves to put the extra field in the entry.
		uid, gid = 0, 0
	}

	zipPath := filepath.Join(tmpDir, "nested.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	dir := &FileHeader{Name: "dir/", Method: Store}
	dir.SetMode(os.ModeDir | 0755)
	if _, err := zw.CreateHeader(dir); err != nil {
		t.Fatal(err)
	}
	fh := &FileHeader{Name: rawName, Method: Store}
	fh.SetMode(0644)
	fh.Extra = appendUnixExtra(nil, uid, gid)
	fh.Acl = []byte("not a real security descriptor, and never handed to Windows")
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("nested-data")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// The ownership pass is what catches this on Unix. Windows has no
	// numeric owner and lchown there does nothing at all, so the security
	// descriptor is what catches it instead: applyXattrs is the other caller
	// the respelling fed, and on Windows it goes to applyNtfsAclFunc.
	origApplyNtfsAcl := applyNtfsAclFunc
	t.Cleanup(func() { applyNtfsAclFunc = origApplyNtfsAcl })
	var aclPaths []string
	applyNtfsAclFunc = func(path string, acl []byte) error {
		aclPaths = append(aclPaths, path)
		return nil
	}

	dstDir := filepath.Join(tmpDir, "extract")
	var chownErrs []string
	e, err := NewExtractor(zipPath, dstDir, WithExtractorXattrs(true), WithExtractorPreserveOwner(true), WithExtractorChownErrorHandler(func(name string, cerr error) error {
		chownErrs = append(chownErrs, fmt.Sprintf("%s: %v", name, cerr))
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	want := filepath.Join(dstDir, "dir", wantOnDisk("bad_\xff.txt"))
	data, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("reading the extracted file: %v", err)
	}
	if string(data) != "nested-data" {
		t.Errorf("content = %q, want %q", data, "nested-data")
	}
	// The owner is the one running the test, so setting it can only fail if
	// the path it is set on is not the path the file was written to.
	if len(chownErrs) != 0 {
		t.Errorf("the ownership pass worked on a path that is not the file's: %v", chownErrs)
	}
	if len(aclPaths) == 0 {
		t.Fatal("the security descriptor was never applied")
	}
	for _, p := range aclPaths {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("the descriptor pass worked on a path that is not the file's: %v", err)
		}
	}
}

// TestPUA_Zip_SymlinkToUndecodableName covers the target of a link, which
// takes the same spelling as a name and never got it.
//
// A name arrives through the central directory and carries the mark that says
// it had to be mapped; a symlink target arrives as the bytes of the entry's
// body and carries nothing at all. Handing it to osFileName is therefore a
// no-op, and the link is pointed at bytes that never reached the filesystem
// under that spelling on the two platforms that cannot store them.
func TestPUA_Zip_SymlinkToUndecodableName(t *testing.T) {
	tmpDir := t.TempDir()
	rawName := "target_\xff.txt"

	zipPath := filepath.Join(tmpDir, "symlink.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	fh := &FileHeader{Name: rawName, Method: Store}
	fh.SetMode(0644)
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("link-data")); err != nil {
		t.Fatal(err)
	}
	link := &FileHeader{Name: "link", Method: Store}
	link.SetMode(os.ModeSymlink | 0777)
	w, err = zw.CreateHeader(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(rawName)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	dstDir := filepath.Join(tmpDir, "extract")
	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	// Symlink, hard link or copy, following the entry has to arrive at the
	// file the archive named.
	data, err := os.ReadFile(filepath.Join(dstDir, "link"))
	if err != nil {
		t.Fatalf("following the extracted link: %v", err)
	}
	if string(data) != "link-data" {
		t.Errorf("the link carries %q, want %q", data, "link-data")
	}
}

// TestDecodeUTF8OrMap and TestEncodeMappedString cover the two directions of
// the in-memory mapping on their own terms, including the case each one
// passes straight through: decodeUTF8OrMap is what decides a name needs
// mapping at all, and encodeMappedString takes back only what carries the
// mark it puts on the front.
func TestDecodeUTF8OrMap(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"valid utf-8 is its own decoding", "plain.txt", "plain.txt"},
		{"valid non-ascii is left alone", "имя-é中.txt", "имя-é中.txt"},
		{"empty is valid", "", ""},
		{"one bad byte marks and maps the whole name", "a\xff", "￾"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeUTF8OrMap([]byte(tt.in)); got != tt.want {
				t.Errorf("decodeUTF8OrMap(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestEncodeMappedString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"a marked string is taken back byte for byte", "￾", "a\xff"},
		{"the mark alone is an empty name", "￾", ""},
		{"an unmarked string is its own bytes", "plain.txt", "plain.txt"},
		{"a mark that is not the first rune is not a mark", "a￾b", "a￾b"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(encodeMappedString(tt.in)); got != tt.want {
				t.Errorf("encodeMappedString(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestPUA_Zip_HardLinkToUndecodableName is the hard link's half of the same
// point the symlink makes.
//
// A hard link names its target in the unix extra field, and that field was the
// one archive-derived string the reader never put through decodeUTF8OrMap --
// so the mark that says "this had to be mapped" was missing, osFileName handed
// the name straight back, and the link was made to raw bytes that no file on
// Windows or macOS had been written under.
func TestPUA_Zip_HardLinkToUndecodableName(t *testing.T) {
	tmpDir := t.TempDir()
	rawName := "target_\xff.txt"

	zipPath := filepath.Join(tmpDir, "hardlink.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	fh := &FileHeader{Name: rawName, Method: Store}
	fh.SetMode(0644)
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("shared content")); err != nil {
		t.Fatal(err)
	}
	link := &FileHeader{Name: "hard.txt", Method: Store, Linkname: rawName}
	link.SetMode(0644)
	if _, err := zw.CreateHeader(link); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	dstDir := filepath.Join(tmpDir, "extract")
	e, err := NewExtractor(zipPath, dstDir)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	// One file under two names, whichever spelling the platform gave the
	// first of them.
	if err := os.WriteFile(filepath.Join(dstDir, wantOnDisk(rawName)), []byte("rewritten....."), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dstDir, "hard.txt"))
	if err != nil {
		t.Fatalf("reading the hard link: %v", err)
	}
	if string(data) != "rewritten....." {
		t.Errorf("hard.txt did not follow a write through the target: got %q", data)
	}
}

// TestPUA_Zip_SolidUndecodableName covers the third way a name reaches the
// filesystem: a solid archive, which is one entry holding a whole zip, whose
// inner names come out of the inner archive rather than out of the one the
// caller opened.
func TestPUA_Zip_SolidUndecodableName(t *testing.T) {
	tmpDir := t.TempDir()
	rawName := "solid_\xff.txt"

	// The inner entry is written by hand so that its header carries the
	// sizes and the checksum rather than deferring them to a data
	// descriptor.
	payload := []byte("solid-data")
	var inner bytes.Buffer
	izw := NewWriter(&inner)
	ifh := &FileHeader{
		Name:               rawName,
		Method:             Store,
		CRC32:              crc32.ChecksumIEEE(payload),
		CompressedSize64:   uint64(len(payload)),
		UncompressedSize64: uint64(len(payload)),
	}
	ifh.SetMode(0644)
	iw, err := izw.CreateRaw(ifh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := izw.Close(); err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(tmpDir, "solid.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, f)
	zw := NewWriter(f)
	oh := &FileHeader{Name: "Solid.zip", Method: Store}
	oh.SetMode(0644)
	ow, err := zw.CreateHeader(oh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ow.Write(inner.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	dstDir := filepath.Join(tmpDir, "extract")
	onDisk := extractTo(t, zipPath, dstDir)
	want := wantOnDisk(rawName)
	if len(onDisk) != 1 || onDisk[0] != want {
		t.Fatalf("extracted names = %q, want exactly [%q]", onDisk, want)
	}
	data, err := os.ReadFile(filepath.Join(dstDir, want))
	if err != nil {
		t.Fatalf("reading the extracted file: %v", err)
	}
	if string(data) != string(payload) {
		t.Errorf("content = %q, want %q", data, payload)
	}
}

// TestPUA_Zip_IncrementalUndecodableName covers the last place an
// archive-derived name is measured against a name on disk.
//
// An incremental archive carries a .zip_dumpdir listing every entry it holds,
// and the extraction sweeps whatever the listing does not name -- that is what
// makes it incremental. The listing is written from the source tree, so a line
// in it is the archive's own bytes, while the file that was just extracted
// went to disk through the platform's spelling. Comparing the two as they
// stand finds no match for an undecodable name on Windows or macOS, and the
// file is deleted the moment after it is written.
func TestPUA_Zip_IncrementalUndecodableName(t *testing.T) {
	tmpDir := t.TempDir()
	rawName := "bad_\xff.txt"
	rawDir := "dir_\xfe"
	// Already on disk from an earlier run, and named by the listing.
	rawKept := "old_\xfd.txt"
	// Already on disk and not named by the listing, which is the whole point
	// of an incremental extraction: it has to go.
	rawGone := "stale_\xfc.txt"

	zipPath := writeRawNamedZip(t, tmpDir, map[string]string{
		rawName:            "kept",
		rawDir + "/in.txt": "also kept",
		".zip_dumpdir":     rawName + "\n" + rawDir + "/\n" + rawDir + "/in.txt\n" + rawKept + "\n",
	})

	// The marker is what says this directory is one of ours; without it an
	// incremental extraction refuses a destination that is not empty.
	dstDir := filepath.Join(tmpDir, "extract")
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		".zip_dumpdir":      "\n",
		wantOnDisk(rawKept): "from the earlier run",
		wantOnDisk(rawGone): "no longer in the archive",
	} {
		if err := os.WriteFile(filepath.Join(dstDir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}

	e, err := NewExtractor(zipPath, dstDir, WithExtractorIncremental(true))
	if err != nil {
		t.Fatal(err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	// Everything the listing names is still there: the entries this run wrote,
	// and the one that was already on disk under the spelling the platform
	// gave it. The second is the direction that has no other check -- the name
	// came back from the filesystem rather than going to it.
	for _, name := range []string{
		wantOnDisk(rawName),
		wantOnDisk(rawDir),
		filepath.Join(wantOnDisk(rawDir), "in.txt"),
		wantOnDisk(rawKept),
	} {
		if _, err := os.Lstat(filepath.Join(dstDir, name)); err != nil {
			t.Errorf("the incremental sweep took something the listing names: %v", err)
		}
	}
	if data, err := os.ReadFile(filepath.Join(dstDir, wantOnDisk(rawKept))); err == nil && string(data) != "from the earlier run" {
		t.Errorf("the surviving file was rewritten: %q", data)
	}

	// And the sweep still sweeps, so none of this was bought by leaving every
	// undecodable name alone.
	if _, err := os.Lstat(filepath.Join(dstDir, wantOnDisk(rawGone))); !os.IsNotExist(err) {
		t.Errorf("the sweep left a file the listing does not name: %v", err)
	}
}
