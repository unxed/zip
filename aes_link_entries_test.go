package zip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// An entry marked WinZip AES promises a body that begins with a salt and a two
// byte password check and ends with a ten byte authentication code. The
// archiver used to put that marking on entries it wrote through the raw path
// and never encrypted: a symbolic link's body was the plain link target, and a
// hard link's or a device node's was nothing at all, so opening either ran off
// the end of it. Found by fuzzing.
//
// The rule now is the one the marking states: what has bytes is encrypted, and
// what has none is not marked.

// aesEntryFrame is what a WinZip AES body carries besides the data: the salt,
// the two byte password check and the ten byte authentication code.
func aesEntryFrame(t *testing.T, strength byte) uint64 {
	t.Helper()
	switch strength {
	case 1:
		return 8 + 2 + 10
	case 2:
		return 12 + 2 + 10
	case 3:
		return 16 + 2 + 10
	}
	t.Fatalf("no frame is defined for AES strength %d", strength)
	return 0
}

// aesExtraStrength returns the strength recorded in an entry's 0x9901 field,
// and whether the field is there at all.
func aesExtraStrength(extra []byte) (byte, bool) {
	for b := readBuf(extra); len(b) >= 4; {
		tag := b.uint16()
		size := int(b.uint16())
		if len(b) < size {
			return 0, false
		}
		if tag == winzipAesExtraID && size >= 7 {
			// The record is a two byte version, the strength, the two
			// byte vendor and the method the entry would have had.
			return b[2], true
		}
		b = b[size:]
	}
	return 0, false
}

// TestAESArchiveKeepsItsSymlinksReadable pins the round trip: a symbolic link
// in an encrypted archive opens like any other entry, gives back its target,
// and is still a link. Its target is data like any other, so it is encrypted
// rather than written in the clear.
func TestAESArchiveKeepsItsSymlinksReadable(t *testing.T) {
	const password = "pw"
	const target = "target.txt"

	srcDir := t.TempDir()
	mustWriteFile(t, filepath.Join(srcDir, target), []byte("body"), 0o600)
	if err := os.Symlink(target, filepath.Join(srcDir, "link")); err != nil {
		t.Skipf("symlinks cannot be created here: %v", err)
	}

	archive := ArchiverCovArchiveOne(t, srcDir, WithArchiverPassword(password))
	zr := ArchiverCovRead(t, archive, password)

	var link *File
	for _, f := range zr.File {
		if f.Name == "link" {
			link = f
		}
	}
	if link == nil {
		t.Fatal("the archive holds no entry for the link")
	}

	if link.Method != winzipAesExtraID {
		t.Errorf("the link entry uses method %d, want %d", link.Method, winzipAesExtraID)
	}
	if link.Flags&0x1 == 0 {
		t.Errorf("the link entry carries flags %#04x, which is not marked encrypted", link.Flags)
	}
	if link.CRC32 != 0 {
		t.Errorf("the link entry carries checksum %#08x, and an AE-2 entry carries none", link.CRC32)
	}
	strength, ok := aesExtraStrength(link.Extra)
	if !ok {
		t.Fatalf("the link entry carries no AES field: extra %x", link.Extra)
	}
	if want := uint64(len(target)) + aesEntryFrame(t, strength); link.CompressedSize64 != want {
		t.Errorf("the link entry is %d bytes, want %d for %d bytes of target inside the frame",
			link.CompressedSize64, want, len(target))
	}
	if link.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("the entry the archiver wrote for a symbolic link has mode %v", link.Mode())
	}

	rc, err := link.Open()
	if err != nil {
		t.Fatalf("opening the link entry: %v", err)
	}
	got, err := io.ReadAll(rc)
	if cerr := rc.Close(); cerr != nil {
		t.Fatalf("closing the link entry: %v", cerr)
	}
	if err != nil {
		t.Fatalf("reading the link entry: %v", err)
	}
	if string(got) != target {
		t.Errorf("the link target came back as %q, want %q", got, target)
	}

	// The target is inside the encryption rather than beside it: what the
	// entry holds is the frame and ciphertext, not the target in the clear.
	entry, ok2 := findLocalEntry(t, archive, "link")
	if !ok2 {
		t.Fatal("the archive holds no local entry for the link")
	}
	if bytes.Contains(entry.payload, []byte(target)) {
		t.Errorf("the link entry holds its target in the clear: %x", entry.payload)
	}
}

// TestAESSymlinkRefusesTheWrongPassword pins that the link entry is protected
// like any other: a wrong password is turned away rather than handing back
// something that looks like a target.
func TestAESSymlinkRefusesTheWrongPassword(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.Symlink("target.txt", filepath.Join(srcDir, "link")); err != nil {
		t.Skipf("symlinks cannot be created here: %v", err)
	}

	archive := ArchiverCovArchiveOne(t, srcDir, WithArchiverPassword("pw"))
	zr := ArchiverCovRead(t, archive, "not the password")

	rc, err := zr.File[0].Open()
	if err == nil {
		_, err = io.ReadAll(rc)
		if cerr := rc.Close(); err == nil {
			err = cerr
		}
	}
	if !errors.Is(err, ErrPassword) {
		t.Fatalf("the link entry answered a wrong password with %v", err)
	}
}

// TestAESSymlinkFramesEveryStrength pins the size the header declares against
// the frame each of the three key lengths carries, and the one refusal there
// is: a strength WinZip AES does not define is turned away rather than written
// into a size nothing can produce.
func TestAESSymlinkFramesEveryStrength(t *testing.T) {
	const password = "pw"
	const target = "target.txt"

	srcDir := t.TempDir()
	linkPath := filepath.Join(srcDir, "link")
	if err := os.Symlink(target, linkPath); err != nil {
		t.Skipf("symlinks cannot be created here: %v", err)
	}
	fi, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("stat %s: %v", linkPath, err)
	}

	newLinkHeader := func(strength byte) *FileHeader {
		hdr := &FileHeader{Name: "link", Password: password, AESStrength: strength}
		hdr.SetMode(fi.Mode())
		return hdr
	}

	for _, strength := range []byte{1, 2, 3} {
		t.Run(string(rune('0'+strength))+" of the three key lengths", func(t *testing.T) {
			var buf bytes.Buffer
			a := ArchiverCovNewArchiver(t, &buf, srcDir, WithArchiverPassword(password))
			if err := a.createSymlink(linkPath, fi, newLinkHeader(strength)); err != nil {
				t.Fatalf("writing the link entry: %v", err)
			}
			if err := a.Close(); err != nil {
				t.Fatalf("closing the archiver: %v", err)
			}

			entry := ArchiverCovRead(t, buf.Bytes(), password).File[0]
			if want := uint64(len(target)) + aesEntryFrame(t, strength); entry.CompressedSize64 != want {
				t.Errorf("the link entry is %d bytes, want %d at strength %d",
					entry.CompressedSize64, want, strength)
			}
			rc, oerr := entry.Open()
			if oerr != nil {
				t.Fatalf("opening the link entry: %v", oerr)
			}
			got, rerr := io.ReadAll(rc)
			if cerr := rc.Close(); cerr != nil {
				t.Fatalf("closing the link entry: %v", cerr)
			}
			if rerr != nil {
				t.Fatalf("reading the link entry: %v", rerr)
			}
			if string(got) != target {
				t.Errorf("the link target came back as %q, want %q", got, target)
			}
		})
	}

	t.Run("a strength nothing defines", func(t *testing.T) {
		var buf bytes.Buffer
		a := ArchiverCovNewArchiver(t, &buf, srcDir, WithArchiverPassword(password))
		if err := a.createSymlink(linkPath, fi, newLinkHeader(4)); err == nil {
			t.Fatal("a link entry was written at a key length WinZip AES does not define")
		}
		if buf.Len() != 0 {
			t.Errorf("%d bytes were written for an entry that was refused", buf.Len())
		}
	})
}

// TestAESArchiveExtractsItsSymlinks is the same round trip through the
// extractor, which is where a link that will not open is a link that is lost.
func TestAESArchiveExtractsItsSymlinks(t *testing.T) {
	const password = "pw"

	srcDir := t.TempDir()
	mustWriteFile(t, filepath.Join(srcDir, "target.txt"), []byte("body"), 0o600)
	if err := os.Symlink("target.txt", filepath.Join(srcDir, "link")); err != nil {
		t.Skipf("symlinks cannot be created here: %v", err)
	}

	zipPath := filepath.Join(t.TempDir(), "archive.zip")
	mustWriteFile(t, zipPath, ArchiverCovArchiveOne(t, srcDir, WithArchiverPassword(password)), 0o600)

	dstDir := t.TempDir()
	e, err := NewExtractor(zipPath, dstDir, WithExtractorPassword(password))
	if err != nil {
		t.Fatalf("building the extractor: %v", err)
	}
	closeAt(t, e)
	if err := e.Extract(context.Background()); err != nil {
		t.Fatalf("extracting: %v", err)
	}

	got, err := os.Readlink(filepath.Join(dstDir, "link"))
	if err != nil {
		t.Fatalf("the extracted link cannot be read: %v", err)
	}
	if got != "target.txt" {
		t.Errorf("the extracted link points at %q, want %q", got, "target.txt")
	}
}

// TestAESLeavesEntriesWithNoBytesUnmarked pins the other half of the rule. A
// hard link and a device node are their header and nothing else, so there is
// nothing to encrypt and nothing to mark: a frame of twenty eight bytes around
// no content is a promise with nothing behind it.
func TestAESLeavesEntriesWithNoBytesUnmarked(t *testing.T) {
	const password = "pw"

	for _, tc := range []struct {
		name  string
		write func(a *Archiver, hdr *FileHeader, fi os.FileInfo) error
	}{
		{"a hard link", func(a *Archiver, hdr *FileHeader, fi os.FileInfo) error {
			hdr.Linkname = "target.txt"
			return a.createHardlink(fi, hdr)
		}},
		{"a device node", func(a *Archiver, hdr *FileHeader, fi os.FileInfo) error {
			return a.createSpecialFile(fi, hdr)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			a := ArchiverCovNewArchiver(t, &buf, t.TempDir(), WithArchiverPassword(password))

			hdr, fi := ArchiverCovHeader("node", Store, 0)
			hdr.Password = password
			if err := tc.write(a, hdr, fi); err != nil {
				t.Fatalf("writing the entry: %v", err)
			}
			if err := a.Close(); err != nil {
				t.Fatalf("closing the archiver: %v", err)
			}

			zr := ArchiverCovRead(t, buf.Bytes(), password)
			entry := zr.File[0]
			if entry.Method != Store {
				t.Errorf("the entry uses method %d, want %d", entry.Method, Store)
			}
			if entry.Flags&0x1 != 0 {
				t.Errorf("the entry carries flags %#04x, and there is nothing here to encrypt", entry.Flags)
			}
			if _, ok := aesExtraStrength(entry.Extra); ok {
				t.Errorf("the entry carries an AES field over no bytes at all: extra %x", entry.Extra)
			}
			if entry.CompressedSize64 != 0 {
				t.Errorf("the entry is %d bytes, want none", entry.CompressedSize64)
			}

			rc, err := entry.Open()
			if err != nil {
				t.Fatalf("opening the entry: %v", err)
			}
			got, err := io.ReadAll(rc)
			if cerr := rc.Close(); cerr != nil {
				t.Fatalf("closing the entry: %v", cerr)
			}
			if err != nil {
				t.Fatalf("reading the entry: %v", err)
			}
			if len(got) != 0 {
				t.Errorf("the entry read back %d bytes", len(got))
			}
		})
	}
}

// TestAESHardLinkInATreeIsUnmarked is the same rule reached the way a caller
// reaches it, by archiving a directory that holds a hard link.
func TestAESHardLinkInATreeIsUnmarked(t *testing.T) {
	const password = "pw"

	srcDir := t.TempDir()
	target := filepath.Join(srcDir, "target.txt")
	mustWriteFile(t, target, []byte("body"), 0o600)
	if err := os.Link(target, filepath.Join(srcDir, "hard.txt")); err != nil {
		t.Skipf("hard links cannot be created here: %v", err)
	}

	archive := ArchiverCovArchiveOne(t, srcDir, WithArchiverPassword(password))
	zr := ArchiverCovRead(t, archive, password)

	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("entry %q: open: %v", f.Name, err)
		}
		_, err = io.Copy(io.Discard, rc)
		if cerr := rc.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			t.Fatalf("entry %q: read: %v", f.Name, err)
		}
		if f.Linkname != "" && f.Flags&0x1 != 0 {
			t.Errorf("the hard link entry %q is marked encrypted over no bytes", f.Name)
		}
	}
}

// TestDirectoryEntryWithAPasswordIsNotMarkedEncrypted pins the same rule in
// the writer, where any caller can reach it: a directory has no data, so a
// password put on its header has nothing to protect and must not leave the
// entry claiming otherwise.
func TestDirectoryEntryWithAPasswordIsNotMarkedEncrypted(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	fh := &FileHeader{Name: "folder/", Password: "pw", AESStrength: 3}
	if _, err := zw.CreateHeader(fh); err != nil {
		t.Fatalf("creating the directory entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the writer: %v", err)
	}

	if fh.Method != Store {
		t.Errorf("the directory entry uses method %d, want %d", fh.Method, Store)
	}
	if fh.Flags&0x1 != 0 {
		t.Errorf("the directory entry carries flags %#04x, and holds nothing to encrypt", fh.Flags)
	}
	if _, ok := aesExtraStrength(fh.Extra); ok {
		t.Errorf("the directory entry carries an AES field: extra %x", fh.Extra)
	}

	// The local header the archive holds says the same as the struct.
	entry, ok := findLocalEntry(t, buf.Bytes(), "folder/")
	if !ok {
		t.Fatal("the archive holds no folder/ entry")
	}
	if entry.method != Store {
		t.Errorf("the local header uses method %d, want %d", entry.method, Store)
	}
	raw := buf.Bytes()
	if flags := binary.LittleEndian.Uint16(raw[entry.headerOffset+6 : entry.headerOffset+8]); flags&0x1 != 0 {
		t.Errorf("the local header carries flags %#04x, which says the entry is encrypted", flags)
	}

	// A reader that was given no password at all opens it as what it is.
	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("reading the archive back: %v", err)
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("opening the directory entry without a password: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("closing the directory entry: %v", err)
	}
}
