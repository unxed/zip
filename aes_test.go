package zip

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	// #nosec G505 -- WinZip AES (APPNOTE 6.3.x) requires PBKDF2-HMAC-SHA1 and an HMAC-SHA1 authentication code; the test computes the same thing the format does
	"crypto/sha1"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func TestWinZipAES_Reader(t *testing.T) {
	password := "password123"
	data := []byte("highly confidential data")
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8} // 8 bytes for AES-128

	// 1. Prepare keys manually (imitating WinZip)
	// For AES-128 (strength 1): keyLen=16, saltLen=8
	keyLen := 16
	keys := pbkdf2.Key([]byte(password), salt, 1000, keyLen*2+2, sha1.New)
	encKey := keys[:keyLen]
	// authKey := keys[keyLen : 2*keyLen]
	pwVerif := keys[2*keyLen : 2*keyLen+2]

	// 2. Encrypt the data
	block, _ := aes.NewCipher(encKey)
	iv := make([]byte, 16)
	iv[0] = 1
	encrypter := cipher.NewCTR(block, iv)
	cipherText := make([]byte, len(data))
	encrypter.XORKeyStream(cipherText, data)

	// 3. Assemble the "raw" file stream inside the ZIP
	// Stream: [Salt] + [Verif] + [EncData] + [HMAC (10 bytes)]
	payload := new(bytes.Buffer)
	payload.Write(salt)
	payload.Write(pwVerif)
	payload.Write(cipherText)

	authKey := keys[keyLen : 2*keyLen]
	mac := hmac.New(sha1.New, authKey)
	mac.Write(cipherText)
	payload.Write(mac.Sum(nil)[:10])

	// 4. Test our aesReader
	info := &winzipAesInfo{
		version:      2,
		strength:     1, // AES-128
		actualMethod: Deflate,
	}

	totalCompressedSize := int64(payload.Len())
	r, method, err := newWinZipAesReader(payload, password, info, totalCompressedSize)
	if err != nil {
		t.Fatalf("failed to create AES reader: %v", err)
	}

	if method != Deflate {
		t.Errorf("expected original method Deflate, got %d", method)
	}

	decrypted, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}

	if !bytes.Equal(decrypted, data) {
		t.Errorf("decryption failed. expected %q, got %q", string(data), string(decrypted))
	}
}

func TestWinZipAES_FullCycle(t *testing.T) {
	password := "secure-password"
	data := []byte("this data is encrypted with AES-256")
	buf := new(bytes.Buffer)

	// 1. Write the encrypted file
	zw := NewWriter(buf)
	fh := &FileHeader{
		Name:        "secret.txt",
		Method:      Deflate,
		Password:    password,
		AESStrength: 3, // AES-256
	}
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatalf("CreateHeader failed: %v", err)
	}
	mustWrite(t, w, data)
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	// 2. Read and verify
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}
	zr.SetPassword(password)

	f := zr.File[0]
	if f.Method != winzipAesMethod {
		t.Errorf("expected method %d (AES), got %d", winzipAesMethod, f.Method)
	}

	rc, err := f.Open()
	if err != nil {
		t.Fatalf("f.Open failed: %v", err)
	}
	closeAt(t, rc)
	decrypted, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if !bytes.Equal(decrypted, data) {
		t.Errorf("content mismatch: expected %q, got %q", string(data), string(decrypted))
	}
}
func TestWinZipAES_StrengthsAndStore(t *testing.T) {
	testCases := []struct {
		name     string
		strength byte
		method   uint16
	}{
		{"AES128-Deflate", 1, Deflate},
		{"AES256-Store", 3, Store},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			password := "test-password"
			data := []byte("multi-strength test data")
			buf := new(bytes.Buffer)

			zw := NewWriter(buf)
			fh := &FileHeader{
				Name:        "test.bin",
				Method:      tc.method,
				Password:    password,
				AESStrength: tc.strength,
			}
			w := mustCreateHeader(t, zw, fh)
			mustWrite(t, w, data)
			if err := zw.Close(); err != nil {
				t.Fatalf("close writer: %v", err)
			}

			zr, _ := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			zr.SetPassword(password)
			rc, err := zr.File[0].Open()
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			closeAt(t, rc)
			decrypted, err := io.ReadAll(rc)
			if err != nil {
				t.Fatalf("ReadAll failed: %v", err)
			}

			if !bytes.Equal(decrypted, data) {
				t.Errorf("got %q, want %q", string(decrypted), string(data))
			}
		})
	}
}
func TestWinZipAES_CorruptedMAC(t *testing.T) {
	password := "secure-password"
	data := []byte("this data will be corrupted")
	buf := new(bytes.Buffer)

	zw := NewWriter(buf)
	fh := &FileHeader{
		Name:        "corrupted.txt",
		Method:      Deflate,
		Password:    password,
		AESStrength: 3,
	}
	w := mustCreateHeader(t, zw, fh)
	mustWrite(t, w, data)
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	raw := buf.Bytes()
	t.Logf("[DEBUG-TEST] Raw zip size: %d", len(raw))
	zr, _ := NewReader(bytes.NewReader(raw), int64(len(raw)))

	off, _ := zr.File[0].DataOffset()
	compSize, err := u64toi64(zr.File[0].CompressedSize64)
	if err != nil {
		t.Fatalf("compressed size of the entry just written: %v", err)
	}
	macOffset := off + compSize - 5
	t.Logf("[DEBUG-TEST] DataOffset: %d, CompressedSize64: %d, macOffset: %d", off, compSize, macOffset)
	t.Logf("[DEBUG-TEST] Bytes before corruption: %x", raw[macOffset-5:macOffset+5])
	raw[macOffset] ^= 0xFF
	t.Logf("[DEBUG-TEST] Bytes after corruption:  %x", raw[macOffset-5:macOffset+5])

	zr2, _ := NewReader(bytes.NewReader(raw), int64(len(raw)))
	zr2.SetPassword(password)

	f := zr2.File[0]
	rc, err := f.Open()
	if err != nil {
		t.Fatalf("f.Open failed: %v", err)
	}
	closeAt(t, rc)

	decrypted, err := io.ReadAll(rc)
	t.Logf("[DEBUG-TEST] ReadAll returned error: %v, decrypted len: %d", err, len(decrypted))
	if !errors.Is(err, ErrChecksum) || !errors.Is(err, ErrPassword) {
		t.Fatalf("Expected ErrChecksum wrapped as an encrypted-data error due to corrupted MAC, got: %v", err)
	}
}
func TestWinZipAES_Writer_BufResizing(t *testing.T) {
	// #nosec G101 -- not a credential: the literal the test encrypts a fixture archive with and then re-reads it with, so it has to be in the source
	password := "buf-resize-pass"
	buf := new(bytes.Buffer)

	zw := NewWriter(buf)
	fh := &FileHeader{
		Name:        "resize.txt",
		Method:      Store,
		Password:    password,
		AESStrength: 3,
	}
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatalf("CreateHeader failed: %v", err)
	}

	// Write 1: 5 bytes
	mustWrite(t, w, []byte("12345"))
	// Write 2: 20 bytes (triggers buf resizing)
	mustWrite(t, w, []byte("abcde12345abcde12345"))
	// Write 3: 2 bytes (tests reusing larger buffer)
	mustWrite(t, w, []byte("xy"))

	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	// Verify content is fully readable and decrypted correctly
	zr, _ := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	zr.SetPassword(password)
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	closeAt(t, rc)

	content, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	expected := "12345abcde12345abcde12345xy"
	if string(content) != expected {
		t.Errorf("expected %q, got %q", expected, string(content))
	}
}
func TestWinZipAES_Seekable(t *testing.T) {
	password := "seek-pass-123"
	// Generate enough data to cross multiple 16-byte blocks
	data := bytes.Repeat([]byte("1234567890ABCDEF"), 1000) // 16000 bytes

	buf := new(bytes.Buffer)
	zw := NewWriter(buf)

	// 1. Uncompressed (Store) with AES
	fh1 := &FileHeader{
		Name:        "store.bin",
		Method:      Store,
		Password:    password,
		AESStrength: 3,
	}
	w1 := mustCreateHeader(t, zw, fh1)
	mustWrite(t, w1, data)

	// 2. Compressed (Deflate) with AES + Seek Index
	fh2 := &FileHeader{
		Name:           "deflate.bin",
		Method:         Deflate,
		Password:       password,
		AESStrength:    3,
		SeekChunkSize:  1024,
		SeekContinuous: true,
	}
	w2 := mustCreateHeader(t, zw, fh2)
	mustWrite(t, w2, data)

	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	zr, _ := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	zr.SetPassword(password)

	// --- Test 1: Store (Direct O(1) AES-CTR mapping) ---
	f1 := zr.File[0]
	rs1, err := f1.OpenSeekable()
	if err != nil {
		t.Fatalf("OpenSeekable Store failed: %v", err)
	}

	// Seek to unaligned offset (17) which crosses the 16-byte block boundary
	if _, err := rs1.Seek(17, io.SeekStart); err != nil {
		t.Fatalf("Store seek failed: %v", err)
	}
	out := make([]byte, 16)
	if _, err := io.ReadFull(rs1, out); err != nil {
		t.Fatalf("Store read failed: %v", err)
	}
	if !bytes.Equal(out, data[17:33]) {
		t.Errorf("Store seek mismatch:\ngot  %q\nwant %q", string(out), string(data[17:33]))
	}

	// --- Test 2: Deflate + GZIDX + AES ---
	f2 := zr.File[1]
	rs2, err := f2.OpenSeekable()
	if err != nil {
		t.Fatalf("OpenSeekable Deflate failed: %v", err)
	}

	// Seek directly into the second chunk boundary where dictionary state is needed.
	// The AES decrypter should automatically shift the IV to match the start of the compressed chunk!
	if _, err := rs2.Seek(2048, io.SeekStart); err != nil {
		t.Fatalf("Deflate seek failed: %v", err)
	}
	out2 := make([]byte, 16)
	if _, err := io.ReadFull(rs2, out2); err != nil {
		t.Fatalf("Deflate read failed: %v", err)
	}
	if !bytes.Equal(out2, data[2048:2064]) {
		t.Errorf("Deflate seek mismatch:\ngot  %q\nwant %q", string(out2), string(data[2048:2064]))
	}
}
