package zip

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
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
	payload.Write(make([]byte, 10)) // HMAC dummy

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
		Name:     "secret.txt",
		Method:   Deflate,
		Password: password,
		AESStrength: 3, // AES-256
	}
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatalf("CreateHeader failed: %v", err)
	}
	w.Write(data)
	zw.Close()

	// 2. Read and verify
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}
	zr.SetPassword(password)

	f := zr.File[0]
	if f.Method != winzipAesExtraID {
		t.Errorf("expected method %d (AES), got %d", winzipAesExtraID, f.Method)
	}

	rc, err := f.Open()
	if err != nil {
		t.Fatalf("f.Open failed: %v", err)
	}
	decrypted, err := io.ReadAll(rc)
	rc.Close()

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
			w, _ := zw.CreateHeader(fh)
			w.Write(data)
			zw.Close()

			zr, _ := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			zr.SetPassword(password)
			rc, err := zr.File[0].Open()
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}
			decrypted, _ := io.ReadAll(rc)
			rc.Close()

			if !bytes.Equal(decrypted, data) {
				t.Errorf("got %q, want %q", string(decrypted), string(data))
			}
		})
	}
}
