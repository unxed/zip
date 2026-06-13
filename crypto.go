package zip

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

// F4CryptHeader represents the 93-byte binary header for encrypted streams
type F4CryptHeader struct {
	Version    uint8
	KdfAlgo    uint8
	Cipher     uint8
	Iterations uint32
	Salt       []byte
	IV         []byte
	MAC        []byte
}

func generateF4CryptHeader(password string, iterations int) (*F4CryptHeader, []byte, error) {
	if iterations == 0 {
		iterations = 600000
	}

	salt := make([]byte, 32)
	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	key := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)

	hdr := &F4CryptHeader{
		Version:    1,
		KdfAlgo:    1,
		Cipher:     1,
		Iterations: uint32(iterations),
		Salt:       salt,
		IV:         iv,
		MAC:        make([]byte, 32),
	}
	return hdr, key, nil
}

func parseF4CryptHeader(data []byte) (*F4CryptHeader, error) {
	if len(data) != 93 {
		return nil, errors.New("zip: invalid F4Crypt header size")
	}
	if string(data[0:6]) != "F4CRPT" {
		return nil, errors.New("zip: invalid F4Crypt magic signature")
	}
	if data[6] != 1 || data[7] != 1 || data[8] != 1 {
		return nil, errors.New("zip: unsupported F4Crypt algorithms")
	}

	hdr := &F4CryptHeader{
		Version:    data[6],
		KdfAlgo:    data[7],
		Cipher:     data[8],
		Iterations: binary.LittleEndian.Uint32(data[9:13]),
		Salt:       make([]byte, 32),
		IV:         make([]byte, 16),
		MAC:        make([]byte, 32),
	}
	copy(hdr.Salt, data[13:45])
	copy(hdr.IV, data[45:61])
	copy(hdr.MAC, data[61:93])

	return hdr, nil
}

func (h *F4CryptHeader) Encode() []byte {
	b := make([]byte, 93)
	copy(b[0:6], "F4CRPT")
	b[6] = h.Version
	b[7] = h.KdfAlgo
	b[8] = h.Cipher
	binary.LittleEndian.PutUint32(b[9:13], h.Iterations)
	copy(b[13:45], h.Salt)
	copy(b[45:61], h.IV)
	copy(b[61:93], h.MAC)
	return b
}

func (h *F4CryptHeader) DeriveKey(password string) []byte {
	return pbkdf2.Key([]byte(password), h.Salt, int(h.Iterations), 32, sha256.New)
}

type f4CryptWriter struct {
	w      io.Writer
	stream cipher.Stream
	mac    hash.Hash
}

func newF4CryptWriter(w io.Writer, key, iv []byte) (*f4CryptWriter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	mac := hmac.New(sha256.New, key)

	return &f4CryptWriter{
		w:      w,
		stream: stream,
		mac:    mac,
	}, nil
}

func (cw *f4CryptWriter) Write(p []byte) (int, error) {
	enc := make([]byte, len(p))
	cw.stream.XORKeyStream(enc, p)
	cw.mac.Write(enc)
	return cw.w.Write(enc)
}

func (cw *f4CryptWriter) MAC() []byte {
	return cw.mac.Sum(nil)
}

type f4CryptReaderAt struct {
	r   io.ReaderAt
	key []byte
	iv  []byte
}

func newF4CryptReaderAt(r io.ReaderAt, key, iv []byte) *f4CryptReaderAt {
	return &f4CryptReaderAt{r: r, key: key, iv: iv}
}

func (cr *f4CryptReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	blockOffset := uint64(off / 16)
	rem := int(off % 16)

	readSize := len(p) + rem
	encBuf := make([]byte, readSize)

	n, err := cr.r.ReadAt(encBuf, off-int64(rem))
	if n == 0 && err != nil {
		return 0, err
	}

	encBuf = encBuf[:n]

	c, errC := aes.NewCipher(cr.key)
	if errC != nil {
		return 0, errC
	}

	iv := make([]byte, 16)
	copy(iv, cr.iv)
	var carry uint64 = blockOffset
	for i := 15; i >= 0 && carry > 0; i-- {
		sum := uint64(iv[i]) + (carry & 0xFF)
		iv[i] = byte(sum)
		carry = (carry >> 8) + (sum >> 8)
	}

	stream := cipher.NewCTR(c, iv)

	decBuf := make([]byte, n)
	stream.XORKeyStream(decBuf, encBuf)

	copied := copy(p, decBuf[rem:])

	if err == io.EOF && copied == len(p) {
		return copied, nil
	}

	return copied, err
}

func encapsulateF4CryptZip(finalPath, tempPath, password string) error {
	out, err := os.Create(finalPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Stream 1: Plaintext Stub
	stubZip := NewWriter(out)
	stubMsg := []byte("This is an encrypted archive. Please use f4 or an F4SS-compatible tool to extract it.\n")
	w, _ := stubZip.CreateHeader(&FileHeader{Name: "README_ENCRYPTED.txt", Method: Store})
	w.Write(stubMsg)
	stubZip.Close()

	fi, _ := out.Stat()
	shadowStart := fi.Size()

	cHdr, key, err := generateF4CryptHeader(password, 600000)
	if err != nil {
		return err
	}

	// Stream 2: Encrypted Payload inside a ZIP container
	shadowZip := NewWriter(out)

	tempFi, err := os.Stat(tempPath)
	if err != nil {
		return err
	}

	// Payload
	pHdr := &FileHeader{Name: ".zipext/f4crypt/payload.enc", Method: Store}
	pHdr.UncompressedSize64 = uint64(tempFi.Size())
	pHdr.CompressedSize64 = pHdr.UncompressedSize64
	pw, _ := shadowZip.CreateRaw(pHdr)

	in, err := os.Open(tempPath)
	if err != nil {
		return err
	}
	cw, _ := newF4CryptWriter(pw, key, cHdr.IV)
	io.Copy(cw, in)
	in.Close()

	cHdr.MAC = cw.MAC()

	// Metadata
	mHdr := &FileHeader{Name: ".zipext/f4crypt/crypto.hdr", Method: Store}
	mHdr.UncompressedSize64 = 93
	mHdr.CompressedSize64 = 93
	mw, _ := shadowZip.CreateRaw(mHdr)
	mw.Write(cHdr.Encode())

	shadowZip.Close()

	fi, _ = out.Stat()
	shadowSize := fi.Size() - shadowStart

	// Stream 3: Magic Footer
	footer := make([]byte, 24)
	binary.LittleEndian.PutUint64(footer[0:8], uint64(shadowStart))
	binary.LittleEndian.PutUint64(footer[8:16], uint64(shadowSize))
	copy(footer[16:24], "F4IDX\x00\x00\x00")
	_, err = out.Write(footer)
	return err
}

func checkF4CryptZip(ra io.ReaderAt, size int64, password string) (io.ReaderAt, int64, error) {
	if size < 24 {
		return ra, size, nil
	}

	var footer [24]byte
	ra.ReadAt(footer[:], size-24)
	if string(footer[16:24]) != "F4IDX\x00\x00\x00" {
		return ra, size, nil
	}

	shadowStart := int64(binary.LittleEndian.Uint64(footer[0:8]))
	shadowSize := int64(binary.LittleEndian.Uint64(footer[8:16]))

	if shadowStart == 0 || shadowSize == 0 || shadowStart+shadowSize > size-24 {
		return ra, size, nil // Corrupt or invalid footer
	}

	sr := io.NewSectionReader(ra, shadowStart, shadowSize)
	zr, err := NewReader(sr, shadowSize)
	if err != nil {
		return ra, size, nil
	}

	var cHdr *F4CryptHeader
	var payloadFile *File

	for _, file := range zr.File {
		if file.Name == ".zipext/f4crypt/crypto.hdr" {
			rc, _ := file.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			cHdr, err = parseF4CryptHeader(data)
			if err != nil {
				return nil, 0, err
			}
		} else if file.Name == ".zipext/f4crypt/payload.enc" {
			payloadFile = file
		}
	}

	if cHdr == nil || payloadFile == nil {
		return ra, size, nil
	}

	if password == "" {
		return ra, size, nil // Return legacy unencrypted view of the stub (README)
	}

	key := cHdr.DeriveKey(password)

	// Open the payload stream directly
	pOff, _ := payloadFile.DataOffset()
	payloadSection := io.NewSectionReader(sr, pOff, int64(payloadFile.CompressedSize64))
	decReader := newF4CryptReaderAt(payloadSection, key, cHdr.IV)

	return decReader, int64(payloadFile.CompressedSize64), nil
}