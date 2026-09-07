package zip

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// Torrentzip's canonical form has no room for the WinZip AES record: the
// normalisation clears the extra field, forces method 8 and rewrites the flags,
// which is exactly what the AES record, the method 99 marker and the encryption
// bit would have to survive. Asking for both used to write AES ciphertext under
// a header saying "deflated, not encrypted" -- an entry no reader on earth,
// this one included, can get the content back out of. Found by fuzzing.
//
// The two are refused together instead, at the earliest point each API has.

// TestTorrentZipWithPasswordIsRefusedAtCreateHeader pins the refusal on the
// writer, before a byte of the entry is written.
func TestTorrentZipWithPasswordIsRefusedAtCreateHeader(t *testing.T) {
	for _, method := range []uint16{Store, Deflate} {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		w.SetTorrentZip(true)

		_, err := w.CreateHeader(&FileHeader{
			Name:        "a.txt",
			Method:      method,
			Password:    "pw",
			AESStrength: 3,
		})
		if err == nil {
			t.Fatalf("method %d: CreateHeader accepted a password in torrentzip mode", method)
		}
		if !strings.Contains(err.Error(), "torrentzip") || !strings.Contains(err.Error(), "password") {
			t.Errorf("method %d: the refusal names neither torrentzip nor the password: %v", method, err)
		}
		if buf.Len() != 0 {
			t.Errorf("method %d: %d bytes were written for an entry that was refused", method, buf.Len())
		}
	}
}

// TestTorrentZipWithPasswordWritesNoUnreadableEntry is the shape the defect was
// found in: whatever the writer decides to do, an entry that reaches the
// archive must read back.
func TestTorrentZipWithPasswordWritesNoUnreadableEntry(t *testing.T) {
	const password = "pw"
	body := []byte("content that was meant to be encrypted")

	for _, method := range []uint16{Store, Deflate} {
		var buf bytes.Buffer
		w := NewWriter(&buf)
		w.SetTorrentZip(true)

		fh := &FileHeader{
			Name:        "a.txt",
			Method:      method,
			Password:    password,
			AESStrength: 3,
		}
		fw, err := w.CreateHeader(fh)
		if err != nil {
			// Refusing the combination is the answer; the entry never exists.
			continue
		}
		if _, err := fw.Write(body); err != nil {
			t.Fatalf("method %d: write: %v", method, err)
		}
		if err := w.Close(); err != nil {
			continue
		}

		r, err := NewReaderWithPassword(bytes.NewReader(buf.Bytes()), int64(buf.Len()), password)
		if err != nil {
			t.Fatalf("method %d: the writer produced an archive the reader rejects: %v", method, err)
		}
		f := r.File[0]
		if !f.IsEncrypted() {
			t.Errorf("method %d: the entry was written with a password and is not marked encrypted", method)
		}
		rc, oerr := f.Open()
		if oerr != nil {
			t.Errorf("method %d: the writer produced an entry it cannot open: %v", method, oerr)
			continue
		}
		got, rerr := io.ReadAll(io.LimitReader(rc, int64(len(body))+1))
		cerr := rc.Close()
		if rerr != nil || cerr != nil {
			t.Errorf("method %d: the writer produced an entry it cannot read: %v / %v", method, rerr, cerr)
			continue
		}
		if !bytes.Equal(got, body) {
			t.Errorf("method %d: read back %d bytes, wrote %d", method, len(got), len(body))
		}
	}
}

// TestArchiverTorrentZipWithPasswordIsRefusedAtConstruction pins the other way
// in, which fails while the archive is still nothing but options.
func TestArchiverTorrentZipWithPasswordIsRefusedAtConstruction(t *testing.T) {
	var buf bytes.Buffer
	a, err := NewArchiver(&buf, t.TempDir(), WithArchiverTorrentZip(true), WithArchiverPassword("pw"))
	if err == nil {
		_ = a.Close()
		t.Fatal("NewArchiver accepted torrentzip together with a password")
	}
	if !strings.Contains(err.Error(), "torrentzip") || !strings.Contains(err.Error(), "password") {
		t.Errorf("the refusal names neither torrentzip nor the password: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("%d bytes were written for an archiver that was refused", buf.Len())
	}
}

// TestArchiverTorrentZipWithPasswordRefusedInAnyOrder pins that the refusal
// does not depend on which option came first.
func TestArchiverTorrentZipWithPasswordRefusedInAnyOrder(t *testing.T) {
	var buf bytes.Buffer
	if _, err := NewArchiver(&buf, t.TempDir(), WithArchiverPassword("pw"), WithArchiverTorrentZip(true)); err == nil {
		t.Fatal("NewArchiver accepted a password followed by torrentzip")
	}
}

// TestTorrentZipWithEncryptedDirectoryIsRefused pins the other half of the
// same contradiction: a torrentzip archive is canonical bytes with the
// directory's own checksum in its comment, which an encrypted directory
// cannot be. The setters answer nothing, so the writer weighs the two where
// the directory is about to be written.
func TestTorrentZipWithEncryptedDirectoryIsRefused(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)
	w.SetTorrentZip(true)
	w.SetEncryptCentralDirectory(true, "pw")

	fw, err := w.CreateHeader(&FileHeader{Name: "a.txt", Method: Deflate})
	if err != nil {
		t.Fatalf("CreateHeader: %v", err)
	}
	if _, err := fw.Write([]byte("body")); err != nil {
		t.Fatalf("write: %v", err)
	}
	err = w.Close()
	if err == nil {
		t.Fatal("Close wrote a torrentzip archive with an encrypted central directory")
	}
	if !strings.Contains(err.Error(), "torrentzip") {
		t.Errorf("the refusal does not name torrentzip: %v", err)
	}
}

// TestArchiverTorrentZipWithEncryptedDirectoryIsRefused pins it on the
// archiver, where both are options and neither has been acted on yet.
func TestArchiverTorrentZipWithEncryptedDirectoryIsRefused(t *testing.T) {
	var buf bytes.Buffer
	a, err := NewArchiver(&buf, t.TempDir(), WithArchiverTorrentZip(true), WithArchiverEncryptCD(true))
	if err == nil {
		_ = a.Close()
		t.Fatal("NewArchiver accepted torrentzip together with an encrypted central directory")
	}
	if !strings.Contains(err.Error(), "torrentzip") {
		t.Errorf("the refusal does not name torrentzip: %v", err)
	}
}

// TestTorrentZipAndPasswordSeparatelyStillWork keeps the refusal from growing
// into the two ordinary cases.
func TestTorrentZipAndPasswordSeparatelyStillWork(t *testing.T) {
	body := []byte("plain body")

	var tz bytes.Buffer
	w := NewWriter(&tz)
	w.SetTorrentZip(true)
	fw, err := w.CreateHeader(&FileHeader{Name: "a.txt", Method: Deflate})
	if err != nil {
		t.Fatalf("torrentzip without a password: CreateHeader: %v", err)
	}
	if _, err := fw.Write(body); err != nil {
		t.Fatalf("torrentzip without a password: write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("torrentzip without a password: close: %v", err)
	}
	if _, err := NewReader(bytes.NewReader(tz.Bytes()), int64(tz.Len())); err != nil {
		t.Fatalf("torrentzip without a password: the result does not read: %v", err)
	}

	var enc bytes.Buffer
	w = NewWriter(&enc)
	fw, err = w.CreateHeader(&FileHeader{Name: "a.txt", Method: Deflate, Password: "pw", AESStrength: 3})
	if err != nil {
		t.Fatalf("a password without torrentzip: CreateHeader: %v", err)
	}
	if _, err := fw.Write(body); err != nil {
		t.Fatalf("a password without torrentzip: write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("a password without torrentzip: close: %v", err)
	}
	r, err := NewReaderWithPassword(bytes.NewReader(enc.Bytes()), int64(enc.Len()), "pw")
	if err != nil {
		t.Fatalf("a password without torrentzip: the result does not read: %v", err)
	}
	if !r.File[0].IsEncrypted() {
		t.Fatal("a password without torrentzip: the entry is not marked encrypted")
	}
	rc, err := r.File[0].Open()
	if err != nil {
		t.Fatalf("a password without torrentzip: open: %v", err)
	}
	got, err := io.ReadAll(rc)
	if cerr := rc.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatalf("a password without torrentzip: read: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("a password without torrentzip: read back %q", got)
	}
}

// TestArchiverTorrentZipAndPasswordSeparatelyStillWork is the same guard on
// the archiver's construction.
func TestArchiverTorrentZipAndPasswordSeparatelyStillWork(t *testing.T) {
	var tz bytes.Buffer
	a, err := NewArchiver(&tz, t.TempDir(), WithArchiverTorrentZip(true))
	if err != nil {
		t.Fatalf("torrentzip without a password: %v", err)
	}
	if err := a.Close(); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("torrentzip without a password: close: %v", err)
	}

	var enc bytes.Buffer
	a, err = NewArchiver(&enc, t.TempDir(), WithArchiverPassword("pw"))
	if err != nil {
		t.Fatalf("a password without torrentzip: %v", err)
	}
	if err := a.Close(); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("a password without torrentzip: close: %v", err)
	}
}
