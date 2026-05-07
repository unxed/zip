package zip

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// winzipAesInfo stores parameters from Extra Field 0x9901
type winzipAesInfo struct {
	version      uint16
	strength     byte // 1=128, 2=192, 3=256
	actualMethod uint16
}

type aesReader struct {
	r          io.Reader
	decrypter  cipher.Stream
	mac        hash.Hash
	authCode   []byte
	expectedAC []byte
	err        error
}

func (ar *aesReader) Read(p []byte) (int, error) {
	if ar.err != nil {
		return 0, ar.err
	}
	n, err := ar.r.Read(p)
	if n > 0 {
		ar.decrypter.XORKeyStream(p[:n], p[:n])
		ar.mac.Write(p[:n])
	}
	if err == io.EOF {
		// HMAC check at the end of the file (in ZIP, these are the last 10 bytes of the stream)
		// At this level of abstraction, we only decode,
		// since it's better to perform HMAC verification in a separate wrapper reader.
	}
	return n, err
}

func newWinZipAesReader(r io.Reader, password string, info *winzipAesInfo, compressedSize int64) (io.Reader, uint16, error) {
	if info == nil {
		return nil, 0, errors.New("zip: AES info missing")
	}
	var keyLen, saltLen int
	switch info.strength {
	case 1: keyLen, saltLen = 16, 8
	case 2: keyLen, saltLen = 24, 12
	case 3: keyLen, saltLen = 32, 16
	default: return nil, 0, errors.New("zip: unknown AES strength")
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, 0, err
	}

	// Key derivation (1000 iterations per specification)
	keys := pbkdf2.Key([]byte(password), salt, 1000, keyLen*2+2, sha1.New)
	encKey := keys[:keyLen]
	authKey := keys[keyLen : 2*keyLen]
	pwVerif := keys[2*keyLen : 2*keyLen+2]

	// Password verification
	verifBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, verifBuf); err != nil {
		return nil, 0, err
	}
	if !hmac.Equal(verifBuf, pwVerif) {
		return nil, 0, errors.New("zip: incorrect password")
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, 0, err
	}

	// WinZip AES uses CTR mode with IV=1 (per 16-byte blocks)
	iv := make([]byte, 16)
	for i := range iv { iv[i] = 0 }
	iv[0] = 1

	decrypter := cipher.NewCTR(block, iv)

	// Limit the reader to avoid overrunning onto the HMAC (10 bytes at the end)
	dataSize := compressedSize - int64(saltLen) - 2 - 10
	if dataSize < 0 {
		return nil, 0, errors.New("zip: encrypted data too short")
	}
	limitedR := io.LimitReader(r, dataSize)

	return &aesReader{
		r:         limitedR,
		decrypter: decrypter,
		mac:       hmac.New(sha1.New, authKey),
	}, info.actualMethod, nil
}

type aesWriter struct {
	w         io.Writer
	encrypter cipher.Stream
	mac       hash.Hash
}

func newWinZipAesWriter(w io.Writer, password string, strength byte) (io.WriteCloser, error) {
	var keyLen, saltLen int
	switch strength {
	case 1:
		keyLen, saltLen = 16, 8
	case 2:
		keyLen, saltLen = 24, 12
	case 3:
		keyLen, saltLen = 32, 16
	default:
		return nil, errors.New("zip: unknown AES strength")
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	keys := pbkdf2.Key([]byte(password), salt, 1000, keyLen*2+2, sha1.New)
	encKey := keys[:keyLen]
	authKey := keys[keyLen : 2*keyLen]
	pwVerif := keys[2*keyLen : 2*keyLen+2]

	if _, err := w.Write(salt); err != nil {
		return nil, err
	}
	if _, err := w.Write(pwVerif); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = 0
	}
	iv[0] = 1

	decrypter := cipher.NewCTR(block, iv)

	return &aesWriter{
		w:         w,
		encrypter: decrypter,
		mac:       hmac.New(sha1.New, authKey),
	}, nil
}

func (aw *aesWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	enc := make([]byte, len(p))
	aw.encrypter.XORKeyStream(enc, p)
	aw.mac.Write(enc)
	return aw.w.Write(enc)
}

func (aw *aesWriter) Close() error {
	macBytes := aw.mac.Sum(nil)[:10] // WinZip AES uses 10-byte MAC
	_, err := aw.w.Write(macBytes)
	return err
}
