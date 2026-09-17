package zip

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	crand "crypto/rand"
	// #nosec G505 -- WinZip AES (APPNOTE 6.3.x) requires PBKDF2-HMAC-SHA1 and an HMAC-SHA1 authentication code; the tests below build the same bytes the format does
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/pbkdf2"
)

// errRegisterCovWrite is what RegisterCovShortWriter fails with once its
// budget is spent.
var errRegisterCovWrite = errors.New("no room left for this write")

// errRegisterCovRead is what the readers below fail with.
var errRegisterCovRead = errors.New("this source cannot be read")

// RegisterCovShortWriter takes budget bytes and refuses everything after them,
// which is what a full device does to a writer part way through a header.
type RegisterCovShortWriter struct {
	budget  int
	written int
}

func (w *RegisterCovShortWriter) Write(p []byte) (int, error) {
	room := w.budget - w.written
	if room <= 0 {
		return 0, errRegisterCovWrite
	}
	if len(p) > room {
		w.written = w.budget
		return room, errRegisterCovWrite
	}
	w.written += len(p)
	return len(p), nil
}

// RegisterCovFailingReaderAt refuses every read, which is what a handle does
// once the device behind it has gone away.
type RegisterCovFailingReaderAt struct{ err error }

func (r RegisterCovFailingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	return 0, r.err
}

// RegisterCovEmptyRandom has no randomness to give.
type RegisterCovEmptyRandom struct{}

func (RegisterCovEmptyRandom) Read(p []byte) (int, error) { return 0, errRegisterCovRead }

// RegisterCovEOFReaderAt reports io.EOF together with the last bytes of its
// data rather than on the read after them. io.ReaderAt allows either, and a
// caller has to cope with both.
type RegisterCovEOFReaderAt struct{ data []byte }

func (r RegisterCovEOFReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	if off+int64(n) >= int64(len(r.data)) {
		return n, io.EOF
	}
	return n, nil
}

// RegisterCovUseRandom replaces the source of randomness for the duration of
// the test and puts the real one back afterwards.
func RegisterCovUseRandom(t *testing.T, r io.Reader) {
	t.Helper()
	saved := crand.Reader
	t.Cleanup(func() { crand.Reader = saved })
	crand.Reader = r
}

// TestRegisterCovPooledFlateAfterClose: the pooled deflate wrappers hand their
// compressor back to the pool when they are closed, so every later call has to
// say so rather than touch a writer somebody else may already hold.
func TestRegisterCovPooledFlateAfterClose(t *testing.T) {
	payload := []byte(strings.Repeat("deflate round trip ", 32))

	buf := new(bytes.Buffer)
	w, ok := newFlateWriter(buf).(*pooledFlateWriter)
	if !ok {
		t.Fatal("newFlateWriter did not return a pooled deflate writer")
	}
	mustWrite(t, w, payload)
	if err := w.Close(); err != nil {
		t.Fatalf("close the deflate writer: %v", err)
	}
	// A closed wrapper has nothing left to reset, and saying so must not
	// reach into the compressor it gave up.
	w.ResetDict()
	if _, err := w.Write([]byte("more")); err == nil {
		t.Error("a write after Close was accepted")
	}
	if err := w.Flush(); err == nil {
		t.Error("a flush after Close was accepted")
	}

	r, ok := newFlateReader(bytes.NewReader(buf.Bytes())).(*pooledFlateReader)
	if !ok {
		t.Fatal("newFlateReader did not return a pooled deflate reader")
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read the compressed payload back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round trip returned %d bytes, want the %d written", len(got), len(payload))
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close the deflate reader: %v", err)
	}
	if _, err := r.Read(make([]byte, 1)); err == nil {
		t.Error("a read after Close was accepted")
	}
}

// TestRegisterCovPooledWritersWithoutAPool: a wrapper built without a pool of
// its own still compresses, and still returns its compressor when it is
// closed.
func TestRegisterCovPooledWritersWithoutAPool(t *testing.T) {
	payload := []byte(strings.Repeat("no pool of its own ", 32))

	t.Run("deflate", func(t *testing.T) {
		buf := new(bytes.Buffer)
		fw, err := flate.NewWriter(buf, flate.DefaultCompression)
		if err != nil {
			t.Fatalf("build a deflate writer: %v", err)
		}
		w := &pooledFlateWriter{fw: fw, w: buf}
		mustWrite(t, w, payload)
		if err := w.Close(); err != nil {
			t.Fatalf("close the deflate writer: %v", err)
		}

		rc := newFlateReader(bytes.NewReader(buf.Bytes()))
		closeAt(t, rc)
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read the compressed payload back: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("round trip returned %d bytes, want the %d written", len(got), len(payload))
		}
	})

	t.Run("zstd", func(t *testing.T) {
		buf := new(bytes.Buffer)
		enc, err := zstd.NewWriter(buf, zstd.WithEncoderCRC(false))
		if err != nil {
			t.Fatalf("build a zstd encoder: %v", err)
		}
		w := &pooledZstdWriter{enc: enc, w: buf}
		mustWrite(t, w, payload)
		if err := w.Close(); err != nil {
			t.Fatalf("close the zstd writer: %v", err)
		}

		rc := newZstdReader(bytes.NewReader(buf.Bytes()))
		closeAt(t, rc)
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read the compressed payload back: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("round trip returned %d bytes, want the %d written", len(got), len(payload))
		}
	})
}

// TestRegisterCovPooledZstdLifecycle: a flush has to push what has been
// written so far to the underlying writer, and once the wrapper is closed both
// writing and flushing have to report that the encoder is gone.
func TestRegisterCovPooledZstdLifecycle(t *testing.T) {
	payload := []byte(strings.Repeat("zstd flush and close ", 64))

	buf := new(bytes.Buffer)
	wc, err := newZstdWriter(buf)
	if err != nil {
		t.Fatalf("build a zstd writer: %v", err)
	}
	w, ok := wc.(*pooledZstdWriter)
	if !ok {
		t.Fatal("newZstdWriter did not return a pooled zstd writer")
	}
	mustWrite(t, w, payload)
	if err := w.Flush(); err != nil {
		t.Fatalf("flush the zstd writer: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("a flush left nothing in the underlying writer")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close the zstd writer: %v", err)
	}
	if _, err := w.Write(payload); err == nil {
		t.Error("a write after Close was accepted")
	}
	if err := w.Flush(); err == nil {
		t.Error("a flush after Close was accepted")
	}

	rc := newZstdReader(bytes.NewReader(buf.Bytes()))
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read the compressed payload back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round trip returned %d bytes, want the %d written", len(got), len(payload))
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close the zstd reader: %v", err)
	}
	if _, err := rc.Read(make([]byte, 1)); err == nil {
		t.Error("a read after Close was accepted")
	}
}

// RegisterCovBzip2Plain is what RegisterCovBzip2Stream decompresses to.
const RegisterCovBzip2Plain = "bzip2 stream inside a zip entry\n"

// RegisterCovBzip2Stream is RegisterCovBzip2Plain as bzip2 -9 wrote it. The
// package decompresses method 12 but cannot produce it, so the bytes have to
// be carried in the source.
const RegisterCovBzip2Stream = "425a6839314159265359cbadc544000004d98000104000100036235c30200" +
	"0314c001342269a6693469ea7872a0307155d7b529b895428606658fc5dc914e142432eb71510"

// TestRegisterCovBzip2Entry: an entry stored with method 12 is decompressed on
// the way out and its checksum still has to match.
func TestRegisterCovBzip2Entry(t *testing.T) {
	body, err := hex.DecodeString(RegisterCovBzip2Stream)
	if err != nil {
		t.Fatalf("decode the bzip2 stream: %v", err)
	}
	plain := []byte(RegisterCovBzip2Plain)

	buf := new(bytes.Buffer)
	zw := NewWriter(buf)
	w, err := zw.CreateRaw(&FileHeader{
		Name:               "bzip2.txt",
		Method:             BZIP2,
		CRC32:              crc32.ChecksumIEEE(plain),
		CompressedSize64:   uint64(len(body)),
		UncompressedSize64: uint64(len(plain)),
	})
	if err != nil {
		t.Fatalf("create the entry: %v", err)
	}
	mustWrite(t, w, body)
	if err := zw.Close(); err != nil {
		t.Fatalf("close the archive: %v", err)
	}

	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("open the archive: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("archive holds %d entries, want 1", len(zr.File))
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("open the entry: %v", err)
	}
	closeAt(t, rc)
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read the entry: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("entry holds %q, want %q", string(got), string(plain))
	}
}

// TestRegisterCovLZMAReaderRejectsBadProperties: method 14 puts a four byte
// version and property size in front of the LZMA properties, and every way
// that can be wrong has to come back as a reader that reports its own reason.
// A nil io.ReadCloser is not one of the answers: the caller cannot tell it
// from a working decompressor, so the entry would fail as a dereference
// instead.
func TestRegisterCovLZMAReaderRejectsBadProperties(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want string
	}{
		{
			"a header that stops inside the four leading bytes",
			[]byte{0x09, 0x00, 0x05},
			"ends inside its LZMA properties header",
		},
		{
			"a property size other than five",
			[]byte{0x09, 0x00, 0x04, 0x00, 0x5d, 0x00, 0x00, 0x00, 0x00},
			"declares 4 bytes of LZMA properties",
		},
		{
			"properties shorter than the size announced",
			[]byte{0x09, 0x00, 0x05, 0x00, 0x5d, 0x00},
			"ends inside its LZMA properties",
		},
		{
			"a properties byte no LZMA decoder accepts",
			[]byte{0x09, 0x00, 0x05, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00},
			"LZMA properties no decoder accepts",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc := newLZMAReader(bytes.NewReader(tc.in))
			if rc == nil {
				t.Fatal("a header it cannot decode was answered with a nil reader")
			}
			closeAt(t, rc)
			_, err := rc.Read(make([]byte, 8))
			if err == nil {
				t.Fatal("a header it cannot decode read as if it held data")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the entry failed with %q, want it to name %q", err, tc.want)
			}
			if !errors.Is(err, ErrFormat) {
				t.Errorf("the entry failed with %q, which is not an ErrFormat", err)
			}
		})
	}
}

// TestRegisterCovHeaderSwallower: the thirteen byte header the LZMA encoder
// writes for its own format is dropped however many writes it arrives in, and
// everything after it reaches the underlying writer untouched.
func TestRegisterCovHeaderSwallower(t *testing.T) {
	out := new(bytes.Buffer)
	s := &headerSwallower{w: out}

	// The header, in two writes that both stop inside it.
	mustWrite(t, s, make([]byte, 5))
	mustWrite(t, s, make([]byte, 8))
	if out.Len() != 0 {
		t.Fatalf("%d bytes of the header reached the underlying writer", out.Len())
	}

	// Everything from here on is payload.
	mustWrite(t, s, []byte("body"))
	if out.String() != "body" {
		t.Errorf("underlying writer holds %q, want %q", out.String(), "body")
	}
}

// TestRegisterCovLZMAWriterStopsOnAFailedHeaderWrite: the writer puts nine
// bytes of header out before it has an encoder, and a device that fills up
// part way through any of them has to stop the entry rather than leave a
// half written header behind a working encoder.
func TestRegisterCovLZMAWriterStopsOnAFailedHeaderWrite(t *testing.T) {
	for _, tc := range []struct {
		name   string
		budget int
	}{
		{"the version and property size", 0},
		{"the properties byte", 4},
		{"the dictionary size", 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wc, err := newLZMAWriter(&RegisterCovShortWriter{budget: tc.budget}, 5)
			if !errors.Is(err, errRegisterCovWrite) {
				t.Fatalf("got error %v, want the write failure", err)
			}
			if wc != nil {
				t.Error("a writer was handed back after the header could not be written")
			}
		})
	}
}

// TestRegisterCovLZMAWriterRejectsAnUnusableDictionarySize: the dictionary the
// writer asks for grows with the compression level, and a level whose
// dictionary does not fit the platform's int has to be refused rather than
// used at whatever the size wrapped to.
func TestRegisterCovLZMAWriterRejectsAnUnusableDictionarySize(t *testing.T) {
	if strconv.IntSize > 32 {
		t.Skip("every dictionary size this writer computes fits a 64 bit int")
	}
	wc, err := newLZMAWriter(new(bytes.Buffer), 13)
	if err == nil {
		t.Fatal("a dictionary size that does not fit an int was accepted")
	}
	if wc != nil {
		t.Error("a writer was handed back with an unusable dictionary")
	}
}

// TestRegisterCovZoneIdentifierWithoutABOM: Windows writes Zone.Identifier as
// UTF-16 with no byte order mark as readily as with one, and the zero bytes
// between the characters are what gives it away.
func TestRegisterCovZoneIdentifierWithoutABOM(t *testing.T) {
	const src = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=http://example.invalid/file.zip\r\n"
	// encodeUTF16LE leads with a byte order mark; drop it to get the form
	// that has to be recognised by its shape alone.
	got := sanitizeZoneIdentifier(encodeUTF16LE(src)[2:])
	want := encodeUTF16LE("[ZoneTransfer]\r\nZoneId=3\r\n")
	if !bytes.Equal(got, want) {
		t.Errorf("sanitized stream is %x, want %x", got, want)
	}
}

// TestRegisterCovParseNtfsAclOnMalformedExtra: the security descriptor is
// looked for in a field somebody else wrote, so a record whose length runs
// past the end of the field stops the walk, and a field without the tag
// yields nothing at all.
func TestRegisterCovParseNtfsAclOnMalformedExtra(t *testing.T) {
	// Tag 0x4453 announcing sixteen bytes with two behind it.
	overlong := []byte{0x53, 0x44, 0x10, 0x00, 0x01, 0x02}
	if sd := parseNtfsAcl(overlong); sd != nil {
		t.Errorf("a descriptor was read out of a record that ends before it: %x", sd)
	}

	// A well formed field that holds only the extended timestamp tag.
	other := []byte{0x55, 0x54, 0x02, 0x00, 0x01, 0x02}
	if sd := parseNtfsAcl(other); sd != nil {
		t.Errorf("a descriptor was found in a field without one: %x", sd)
	}
}

// RegisterCovAesParams returns the key and salt lengths WinZip AES defines for
// a strength byte.
func RegisterCovAesParams(t *testing.T, strength byte) (keyLen, saltLen int) {
	t.Helper()
	switch strength {
	case 1:
		return 16, 8
	case 2:
		return 24, 12
	case 3:
		return 32, 16
	}
	t.Fatalf("no WinZip AES parameters for strength %d", strength)
	return 0, 0
}

// RegisterCovAesInfo is the 0x9901 extra field an entry of the given strength
// carries.
func RegisterCovAesInfo(strength byte) *winzipAesInfo {
	return &winzipAesInfo{version: 2, strength: strength, actualMethod: Store}
}

// RegisterCovAesBody assembles what a WinZip AES entry holds on disk: the
// salt, the two byte password verification value, the CTR ciphertext and the
// authentication code. macBytes says how much of the ten byte code to append,
// so that a body that stops inside it can be built too.
func RegisterCovAesBody(t *testing.T, password string, strength byte, data []byte, macBytes int) []byte {
	t.Helper()
	keyLen, saltLen := RegisterCovAesParams(t, strength)

	salt := make([]byte, saltLen)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	keys := pbkdf2.Key([]byte(password), salt, 1000, keyLen*2+2, sha1.New)
	encKey := keys[:keyLen]
	authKey := keys[keyLen : 2*keyLen]
	pwVerif := keys[2*keyLen : 2*keyLen+2]

	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatalf("build a %d bit cipher: %v", keyLen*8, err)
	}
	iv := make([]byte, 16)
	iv[0] = 1
	cipherText := make([]byte, len(data))
	cipher.NewCTR(block, iv).XORKeyStream(cipherText, data)

	mac := hmac.New(sha1.New, authKey)
	mac.Write(cipherText)

	body := make([]byte, 0, saltLen+2+len(cipherText)+macBytes)
	body = append(body, salt...)
	body = append(body, pwVerif...)
	body = append(body, cipherText...)
	return append(body, mac.Sum(nil)[:macBytes]...)
}

// TestRegisterCovAesReaderRejects: everything the encryption header can be
// missing has to come back as a refusal, from both the stream reader and the
// seekable one.
func TestRegisterCovAesReaderRejects(t *testing.T) {
	const password = "aes-reader-pass"
	plain := []byte("payload behind the password")

	t.Run("no AES extra field", func(t *testing.T) {
		if _, _, err := newWinZipAesReader(bytes.NewReader(nil), password, nil, 0); err == nil {
			t.Error("a stream reader was built without the AES parameters")
		}
		if _, err := newWinZipAesReaderAt(bytes.NewReader(nil), password, nil, 0, true); err == nil {
			t.Error("a seekable reader was built without the AES parameters")
		}
	})

	t.Run("a body that stops inside the salt", func(t *testing.T) {
		body := []byte{1, 2, 3}
		if _, err := newWinZipAesReaderAt(bytes.NewReader(body), password, RegisterCovAesInfo(3), 64, true); err == nil {
			t.Error("a seekable reader was built on a body with no room for the salt")
		}
	})

	t.Run("a salt with no verification value behind it", func(t *testing.T) {
		body := RegisterCovAesBody(t, password, 1, plain, 10)[:8]
		if _, _, err := newWinZipAesReader(bytes.NewReader(body), password, RegisterCovAesInfo(1), int64(len(body))); err == nil {
			t.Error("a stream reader was built without a verification value to check")
		}
		if _, err := newWinZipAesReaderAt(bytes.NewReader(body), password, RegisterCovAesInfo(1), int64(len(body)), true); err == nil {
			t.Error("a seekable reader was built without a verification value to check")
		}
	})

	t.Run("the wrong password", func(t *testing.T) {
		body := RegisterCovAesBody(t, password, 3, plain, 10)
		_, err := newWinZipAesReaderAt(bytes.NewReader(body), "not the password", RegisterCovAesInfo(3), int64(len(body)), true)
		if !errors.Is(err, ErrPassword) {
			t.Errorf("got error %v, want a password mismatch", err)
		}
	})

	t.Run("a body with no room for the authentication code", func(t *testing.T) {
		body := RegisterCovAesBody(t, password, 1, nil, 0)
		if _, _, err := newWinZipAesReader(bytes.NewReader(body), password, RegisterCovAesInfo(1), int64(len(body))); err == nil {
			t.Error("a stream reader was built on a body too short to hold a code")
		}
		if _, err := newWinZipAesReaderAt(bytes.NewReader(body), password, RegisterCovAesInfo(1), int64(len(body)), true); err == nil {
			t.Error("a seekable reader was built on a body too short to hold a code")
		}
	})
}

// TestRegisterCovAesReaderTruncatedAuthenticationCode: the ten byte code
// closes an entry, so a body that stops in the middle of one is damaged rather
// than finished, and every read after the first has to keep saying so.
func TestRegisterCovAesReaderTruncatedAuthenticationCode(t *testing.T) {
	// #nosec G101 -- not a credential: the literal this test encrypts a fixture body with and then decrypts it again with, so it has to be in the source
	const password = "aes-mac-pass"
	plain := []byte("content followed by half a code")

	body := RegisterCovAesBody(t, password, 3, plain, 4)
	// The entry's recorded size counts the whole code, not the part of it
	// that is really there.
	size := int64(len(body) + 6)

	r, _, err := newWinZipAesReader(bytes.NewReader(body), password, RegisterCovAesInfo(3), size)
	if err != nil {
		t.Fatalf("build the reader: %v", err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("a body that stops inside the authentication code was read to the end without complaint")
	}
	if _, err := r.Read(make([]byte, 1)); err == nil {
		t.Error("a read after the failure was accepted")
	}
}

// TestRegisterCovAesReaderAtStrengths: the seekable reader has to decrypt at
// an arbitrary offset for each of the three key lengths, whether or not the
// offset falls on a cipher block boundary.
func TestRegisterCovAesReaderAtStrengths(t *testing.T) {
	// #nosec G101 -- not a credential: the literal this test encrypts a fixture body with and then decrypts it again with, so it has to be in the source
	const password = "aes-seekable-pass"
	plain := []byte("thirty two bytes of plain text..")

	for _, strength := range []byte{1, 2, 3} {
		t.Run(strconv.Itoa(int(strength)), func(t *testing.T) {
			_, saltLen := RegisterCovAesParams(t, strength)
			// The body stops at the end of the ciphertext while the entry's
			// recorded size counts the authentication code as well, so the
			// underlying source ends exactly where the data does.
			body := RegisterCovAesBody(t, password, strength, plain, 0)
			// The fixture carries no authentication code to check, and
			// what is under test here is the decryption at an offset:
			// the reader is built the way OpenSeekableUnverified builds
			// it.
			ar, err := newWinZipAesReaderAt(RegisterCovEOFReaderAt{data: body}, password, RegisterCovAesInfo(strength), int64(len(body)+10), false)
			if err != nil {
				t.Fatalf("build the reader: %v", err)
			}
			if ar.limit != int64(len(plain)) {
				t.Fatalf("reader covers %d bytes, want %d", ar.limit, len(plain))
			}
			if ar.baseOffset != int64(saltLen+2) {
				t.Fatalf("data starts at %d, want %d", ar.baseOffset, saltLen+2)
			}

			// An offset outside the data, either side.
			if _, err := ar.ReadAt(make([]byte, 4), -1); err != io.EOF {
				t.Errorf("a read before the start returned %v, want EOF", err)
			}
			if _, err := ar.ReadAt(make([]byte, 4), int64(len(plain))); err != io.EOF {
				t.Errorf("a read past the end returned %v, want EOF", err)
			}
			// Nothing asked for is nothing to report.
			if n, err := ar.ReadAt(nil, 0); n != 0 || err != nil {
				t.Errorf("an empty read returned %d, %v", n, err)
			}

			// A read that starts on a block boundary and ends at the end of
			// the data.
			out := make([]byte, 16)
			if n, err := ar.ReadAt(out, 16); err != nil || n != len(out) {
				t.Fatalf("read at 16 returned %d, %v", n, err)
			}
			if !bytes.Equal(out, plain[16:]) {
				t.Errorf("read at 16 gave %q, want %q", string(out), string(plain[16:]))
			}

			// A read that starts inside a block and asks for more than is
			// left.
			big := make([]byte, 64)
			n, err := ar.ReadAt(big, 24)
			if err != nil {
				t.Fatalf("read at 24 returned %v", err)
			}
			if !bytes.Equal(big[:n], plain[24:]) {
				t.Errorf("read at 24 gave %q, want %q", string(big[:n]), string(plain[24:]))
			}

			// A read that stops well before the end.
			head := make([]byte, 8)
			if n, err := ar.ReadAt(head, 0); err != nil || n != len(head) {
				t.Fatalf("read at 0 returned %d, %v", n, err)
			}
			if !bytes.Equal(head, plain[:8]) {
				t.Errorf("read at 0 gave %q, want %q", string(head), string(plain[:8]))
			}
		})
	}
}

// TestRegisterCovAesReaderAtFailures: the seekable reader builds its cipher
// and reaches for its bytes on every call, and neither a source that refuses
// nor a key the cipher will not take may become a panic.
func TestRegisterCovAesReaderAtFailures(t *testing.T) {
	t.Run("the source refuses the read", func(t *testing.T) {
		ar := &winZipAesReaderAt{
			r:          RegisterCovFailingReaderAt{err: errRegisterCovRead},
			baseOffset: 18,
			encKey:     make([]byte, 32),
			limit:      32,
		}
		if _, err := ar.ReadAt(make([]byte, 4), 0); !errors.Is(err, errRegisterCovRead) {
			t.Errorf("got error %v, want the read failure", err)
		}
	})

	t.Run("a key length the cipher does not take", func(t *testing.T) {
		ar := &winZipAesReaderAt{
			r:          bytes.NewReader(make([]byte, 64)),
			baseOffset: 18,
			encKey:     make([]byte, 17),
			limit:      32,
		}
		if _, err := ar.ReadAt(make([]byte, 4), 0); err == nil {
			t.Error("a seventeen byte key was accepted")
		}
	})
}

// TestRegisterCovAesWriter: the writer's own header has to round trip through
// the reader, an empty write has to leave the keystream alone, and a device
// that fills up or a source of randomness that dries up has to stop the entry.
func TestRegisterCovAesWriter(t *testing.T) {
	const password = "aes-writer-pass"
	plain := []byte("data the writer encrypts")

	t.Run("a 192 bit round trip", func(t *testing.T) {
		buf := new(bytes.Buffer)
		wc, err := newWinZipAesWriter(buf, password, 2, false)
		if err != nil {
			t.Fatalf("build the writer: %v", err)
		}
		if n, err := wc.Write(nil); n != 0 || err != nil {
			t.Fatalf("an empty write returned %d, %v", n, err)
		}
		mustWrite(t, wc, plain)
		if err := wc.Close(); err != nil {
			t.Fatalf("close the writer: %v", err)
		}

		r, method, err := newWinZipAesReader(bytes.NewReader(buf.Bytes()), password, RegisterCovAesInfo(2), int64(buf.Len()))
		if err != nil {
			t.Fatalf("read the entry back: %v", err)
		}
		if method != Store {
			t.Errorf("entry reports method %d, want %d", method, Store)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("decrypt the entry: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("decrypted %q, want %q", string(got), string(plain))
		}
	})

	t.Run("no room for the verification value", func(t *testing.T) {
		// The salt goes out first; the device fills up right behind it.
		_, saltLen := RegisterCovAesParams(t, 3)
		wc, err := newWinZipAesWriter(&RegisterCovShortWriter{budget: saltLen}, password, 3, false)
		if !errors.Is(err, errRegisterCovWrite) {
			t.Fatalf("got error %v, want the write failure", err)
		}
		if wc != nil {
			t.Error("a writer was handed back after the header could not be written")
		}
	})

	t.Run("no randomness for the salt", func(t *testing.T) {
		RegisterCovUseRandom(t, RegisterCovEmptyRandom{})
		wc, err := newWinZipAesWriter(new(bytes.Buffer), password, 3, false)
		if err == nil {
			t.Fatal("an entry was salted without any randomness")
		}
		if wc != nil {
			t.Error("a writer was handed back without a salt")
		}
	})
}

// registerCovPPMdArchive is a two entry archive another implementation wrote
// with PPMd, the method this package can read but has no compressor for. The
// entries were compressed at different model orders -- eight and two -- so the
// parameter word the reader takes them apart with is not the same for both.
// The bytes are carried here because nothing in this tree can produce them.
const registerCovPPMdArchive = "" +
	"UEsDBD8AAABiAJSbJl0BISABbwAAAOkBAAAFAAAAYS50eHQHAFQWO4tiMhmJJX2k9ZD9Ci1v" +
	"D6dRy6YhICH2oq9991+5Bt94dg1FMvNUNwutV57YEU3+Xh+cypGj1RSJ0mypqlFy7w3c2ISD" +
	"u6slKzj+24RFzLXQ29UUOY7cTV/+Zj9cPa56ZFEUkDrRYiQcOwBQSwMEPwAAAGIAlJsmXdTb" +
	"KyZ2AAAAHQEAAAUAAABiLnR4dAEAUxRKoN8a7eCV5BJ8BjyQgZRjxkH8lkYqUqDm0uWisCcU" +
	"94GfBjPJT2pMMXipdXdOGi4GxIKYfzuV7paaHPUeF7OYaKIGfX0CV8mZvfDBiAeU/hqx29dE" +
	"zn90J28M8AnyipBYRpqPhSW8srrantnv1h7aRQBQSwECPwA/AAAAYgCUmyZdASEgAW8AAADp" +
	"AQAABQAkAAAAAAAAACAAAAAAAAAAYS50eHQKACAAAAAAAAEAGACZMSAZ4j3dAQAAAAAAAAAA" +
	"AAAAAAAAAABQSwECPwA/AAAAYgCUmyZd1NsrJnYAAAAdAQAABQAkAAAAAAAAACAAAACSAAAA" +
	"Yi50eHQKACAAAAAAAAEAGADpYSgZ4j3dAQAAAAAAAAAAAAAAAAAAAABQSwUGAAAAAAIAAgCu" +
	"AAAAKwEAAAAA"

// registerCovPPMdWant is what those two entries held before they were
// compressed, spelled out rather than carried, so that a byte coming back
// wrong shows up as text.
func registerCovPPMdWant() map[string]string {
	var a, b strings.Builder
	a.WriteString("The quick brown fox jumps over the lazy dog.\n")
	for i := 1; i <= 6; i++ {
		fmt.Fprintf(&a, "PPMd round trip fixture line %d: the same words again and again and again.\n", i)
	}
	b.WriteString("Second entry, a different order and a smaller model.\n")
	for i := 1; i <= 4; i++ {
		fmt.Fprintf(&b, "entry two line %d: repetition helps the model settle down.\n", i)
	}
	return map[string]string{"a.txt": a.String(), "b.txt": b.String()}
}

func registerCovPPMdBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(registerCovPPMdArchive)
	if err != nil {
		t.Fatalf("decoding the archive: %v", err)
	}
	return raw
}

// TestRegisterCovPPMdIsRefused takes that archive through the two ways a
// caller reaches an entry and requires both to refuse it, at once and without
// handing back a byte.
//
// PPMd is a family rather than one algorithm. APPNOTE 5.10 gives method 98 as
// variant I revision 1; the decoder available here reads variant H, which .7z
// uses. Decoding one with the other produces bytes nobody wrote, so an entry
// like this has to be turned away rather than attempted -- and the reason it
// is turned away has to be legible as ErrAlgorithm, because that is what a
// caller tests for when it wants to know whether an archive is readable at
// all.
func TestRegisterCovPPMdIsRefused(t *testing.T) {
	raw := registerCovPPMdBytes(t)

	t.Run("through the reader", func(t *testing.T) {
		zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatalf("opening the archive: %v", err)
		}
		if len(zr.File) != len(registerCovPPMdWant()) {
			t.Fatalf("the archive holds %d entries, want %d", len(zr.File), len(registerCovPPMdWant()))
		}
		for _, f := range zr.File {
			// 98 is PPMd; the package has no name for it.
			if f.Method != 98 {
				t.Errorf("%s is stored with method %d, want PPMd", f.Name, f.Method)
				continue
			}
			rc, oerr := f.Open()
			if oerr != nil {
				t.Errorf("opening %s: %v", f.Name, oerr)
				continue
			}
			got, rerr := io.ReadAll(rc)
			closeAt(t, rc)
			if !errors.Is(rerr, ErrAlgorithm) {
				t.Errorf("reading %s gave %v, want it refused as an algorithm this package cannot read", f.Name, rerr)
			}
			if len(got) != 0 {
				t.Errorf("reading %s handed back %d bytes before refusing", f.Name, len(got))
			}
		}
	})

	t.Run("through the extractor", func(t *testing.T) {
		dst := t.TempDir()
		e, err := NewExtractorFromReader(bytes.NewReader(raw), int64(len(raw)), dst)
		if err != nil {
			t.Fatalf("building the extractor: %v", err)
		}
		closeAt(t, e)
		if err := e.Extract(context.Background()); !errors.Is(err, ErrAlgorithm) {
			t.Fatalf("extracting gave %v, want it refused as an algorithm this package cannot read", err)
		}
		for name := range registerCovPPMdWant() {
			if body, rerr := os.ReadFile(filepath.Join(dst, name)); rerr == nil && len(body) > 0 {
				t.Errorf("%s was written with %d bytes that were never decoded", name, len(body))
			}
		}
	})
}

// TestRegisterCovPPMdRefusalCostsNothing: the refusal is decided from the
// method alone, so none of the entry's own bytes are read and nothing the
// entry names is allocated. Method 98 puts two parameter bytes at the head of
// the data, one field of which is a model size in megabytes; taking that field
// at its word meant a hundred byte archive could ask for a hundred and
// twenty-eight megabytes per entry before a byte of it had been decoded or
// checksummed, and a payload that is not a PPMd stream could drive the decoder
// into a division by zero.
func TestRegisterCovPPMdRefusalCostsNothing(t *testing.T) {
	// The parameters are an order in the low four bits and a model size in
	// megabytes, less one, in the eight above them.
	largestModel := []byte{0x01, 0xff}

	archives := [][]byte{}
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"empty.bin", nil},
		{"model.bin", append(append([]byte(nil), largestModel...), bytes.Repeat([]byte{0x30}, 64)...)},
		{"garbage.bin", append([]byte{0x31, 0x30}, "\x00010000"...)},
	} {
		archives = append(archives, rawEntryArchive(t, &FileHeader{
			Name:               tc.name,
			Method:             98,
			CompressedSize64:   uint64(len(tc.body)),
			UncompressedSize64: 1 << 20,
		}, tc.body))
	}

	const budget = 32 << 20

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	for _, raw := range archives {
		zr := readerCovOpen(t, raw)
		rc, err := zr.File[0].Open()
		if err != nil {
			t.Fatalf("opening %s: %v", zr.File[0].Name, err)
		}
		got, rerr := io.ReadAll(rc)
		closeAt(t, rc)
		if !errors.Is(rerr, ErrAlgorithm) {
			t.Errorf("reading %s gave %v, want it refused as an algorithm this package cannot read", zr.File[0].Name, rerr)
		}
		if len(got) != 0 {
			t.Errorf("reading %s handed back %d bytes before refusing", zr.File[0].Name, len(got))
		}
	}

	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > budget {
		t.Errorf("three archives of a few hundred bytes allocated %d bytes, past the %d byte budget", allocated, budget)
	}
}
