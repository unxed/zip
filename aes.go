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
	baseR      io.Reader
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
		ar.mac.Write(p[:n])
		ar.decrypter.XORKeyStream(p[:n], p[:n])
	}
	if err == io.EOF {
		expectedMAC := make([]byte, 10)
		if _, macErr := io.ReadFull(ar.baseR, expectedMAC); macErr != nil {
			ar.err = macErr
			return n, macErr
		}
		calculatedMAC := ar.mac.Sum(nil)[:10]
		if !hmac.Equal(calculatedMAC, expectedMAC) {
			ar.err = ErrChecksum
			return n, ErrChecksum
		}
		ar.err = io.EOF
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
		baseR:     r,
		decrypter: decrypter,
		mac:       hmac.New(sha1.New, authKey),
	}, info.actualMethod, nil
}
// addIVBigEndian adds a block offset to a 128-bit big-endian IV
func addIVBigEndian(baseIV []byte, offset uint64) []byte {
	iv := make([]byte, 16)
	copy(iv, baseIV)
	var carry uint64 = offset
	for i := 15; i >= 0 && carry > 0; i-- {
		sum := uint64(iv[i]) + (carry & 0xFF)
		iv[i] = byte(sum)
		carry = (carry >> 8) + (sum >> 8)
	}
	return iv
}

type winZipAesReaderAt struct {
	r          io.ReaderAt
	baseOffset int64
	encKey     []byte
	limit      int64
	iv         []byte
}

func newWinZipAesReaderAt(r io.ReaderAt, password string, info *winzipAesInfo, compressedSize int64) (*winZipAesReaderAt, error) {
	if info == nil {
		return nil, errors.New("zip: AES info missing")
	}
	var keyLen, saltLen int
	switch info.strength {
	case 1: keyLen, saltLen = 16, 8
	case 2: keyLen, saltLen = 24, 12
	case 3: keyLen, saltLen = 32, 16
	default: return nil, errors.New("zip: unknown AES strength")
	}

	salt := make([]byte, saltLen)
	if _, err := r.ReadAt(salt, 0); err != nil {
		return nil, err
	}

	keys := pbkdf2.Key([]byte(password), salt, 1000, keyLen*2+2, sha1.New)
	encKey := keys[:keyLen]
	pwVerif := keys[2*keyLen : 2*keyLen+2]

	verifBuf := make([]byte, 2)
	if _, err := r.ReadAt(verifBuf, int64(saltLen)); err != nil {
		return nil, err
	}
	if !hmac.Equal(verifBuf, pwVerif) {
		return nil, errors.New("zip: incorrect password")
	}

	limit := compressedSize - int64(saltLen) - 2 - 10
	if limit < 0 {
		return nil, errors.New("zip: encrypted data too short")
	}

	iv := make([]byte, 16)
	for i := range iv { iv[i] = 0 }
	iv[0] = 1

	return &winZipAesReaderAt{
		r:          r,
		baseOffset: int64(saltLen + 2),
		encKey:     encKey,
		limit:      limit,
		iv:         iv,
	}, nil
}

func (ar *winZipAesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= ar.limit {
		return 0, io.EOF
	}

	avail := ar.limit - off
	if int64(len(p)) > avail {
		p = p[:avail]
	}
	if len(p) == 0 {
		return 0, nil
	}

	blockOffset := uint64(off / 16)
	rem := int(off % 16)

	readSize := len(p) + rem
	encBuf := make([]byte, readSize)

	n, err := ar.r.ReadAt(encBuf, ar.baseOffset+off-int64(rem))
	if n == 0 && err != nil {
		return 0, err
	}

	encBuf = encBuf[:n]

	block, errC := aes.NewCipher(ar.encKey)
	if errC != nil {
		return 0, errC
	}

	ctrIV := addIVBigEndian(ar.iv, blockOffset)

	stream := cipher.NewCTR(block, ctrIV)
	decBuf := make([]byte, n)
	stream.XORKeyStream(decBuf, encBuf)

	copied := copy(p, decBuf[rem:])

	if err == io.EOF && copied == len(p) {
		return copied, nil
	}

	return copied, err
}

type aesWriter struct {
	w         io.Writer
	encrypter cipher.Stream
	mac       hash.Hash
	buf       []byte
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
	if cap(aw.buf) < len(p) {
		aw.buf = make([]byte, len(p))
	} else {
		aw.buf = aw.buf[:len(p)]
	}
	aw.encrypter.XORKeyStream(aw.buf, p)
	aw.mac.Write(aw.buf)
	return aw.w.Write(aw.buf)
}

func (aw *aesWriter) Close() error {
	macBytes := aw.mac.Sum(nil)[:10] // WinZip AES uses 10-byte MAC
	_, err := aw.w.Write(macBytes)
	return err
}
