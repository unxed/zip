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

	// 1. Подготавливаем ключи вручную (как это делает WinZip)
	// Для AES-128 (strength 1): keyLen=16, saltLen=8
	keyLen := 16
	keys := pbkdf2.Key([]byte(password), salt, 1000, keyLen*2+2, sha1.New)
	encKey := keys[:keyLen]
	// authKey := keys[keyLen : 2*keyLen]
	pwVerif := keys[2*keyLen : 2*keyLen+2]

	// 2. Шифруем данные
	block, _ := aes.NewCipher(encKey)
	iv := make([]byte, 16)
	iv[0] = 1
	encrypter := cipher.NewCTR(block, iv)
	cipherText := make([]byte, len(data))
	encrypter.XORKeyStream(cipherText, data)

	// 3. Собираем "сырой" поток файла внутри ZIP
	// Поток: [Salt] + [Verif] + [EncData] + [HMAC (10 bytes)]
	payload := new(bytes.Buffer)
	payload.Write(salt)
	payload.Write(pwVerif)
	payload.Write(cipherText)
	payload.Write(make([]byte, 10)) // HMAC dummy

	// 4. Тестируем наш aesReader
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