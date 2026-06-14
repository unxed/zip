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
type XCryptHeader struct {
	Version    uint8
	KdfAlgo    uint8
	Cipher     uint8
	Iterations uint32
	Salt       []byte
	IV         []byte
	MAC        []byte
}

func generateXCryptHeader(password string, iterations int) (*XCryptHeader, []byte, error) {
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

	hdr := &XCryptHeader{
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

func parseXCryptHeader(data []byte) (*XCryptHeader, error) {
	if len(data) != 93 {
		return nil, errors.New("zip: invalid XCrypt header size")
	}
	if string(data[0:6]) != "XCRYPT" {
		return nil, errors.New("zip: invalid XCrypt magic signature")
	}
	if data[6] != 1 || data[7] != 1 || data[8] != 1 {
		return nil, errors.New("zip: unsupported XCrypt algorithms")
	}

	hdr := &XCryptHeader{
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

func (h *XCryptHeader) Encode() []byte {
	b := make([]byte, 93)
	copy(b[0:6], "XCRYPT")
	b[6] = h.Version
	b[7] = h.KdfAlgo
	b[8] = h.Cipher
	binary.LittleEndian.PutUint32(b[9:13], h.Iterations)
	copy(b[13:45], h.Salt)
	copy(b[45:61], h.IV)
	copy(b[61:93], h.MAC)
	return b
}

func (h *XCryptHeader) DeriveKey(password string) []byte {
	return pbkdf2.Key([]byte(password), h.Salt, int(h.Iterations), 32, sha256.New)
}

type xCryptWriter struct {
	w      io.Writer
	stream cipher.Stream
	mac    hash.Hash
}

func newXCryptWriter(w io.Writer, key, iv []byte) (*xCryptWriter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	mac := hmac.New(sha256.New, key)

	return &xCryptWriter{
		w:      w,
		stream: stream,
		mac:    mac,
	}, nil
}

func (cw *xCryptWriter) Write(p []byte) (int, error) {
	enc := make([]byte, len(p))
	cw.stream.XORKeyStream(enc, p)
	cw.mac.Write(enc)
	return cw.w.Write(enc)
}

func (cw *xCryptWriter) MAC() []byte {
	return cw.mac.Sum(nil)
}

type xCryptReaderAt struct {
	r   io.ReaderAt
	key []byte
	iv  []byte
}

func newXCryptReaderAt(r io.ReaderAt, key, iv []byte) *xCryptReaderAt {
	return &xCryptReaderAt{r: r, key: key, iv: iv}
}

func (cr *xCryptReaderAt) ReadAt(p []byte, off int64) (int, error) {
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

func encapsulateXCryptZip(finalPath, tempPath, password string) error {
	var out *os.File
	var err error
	if finalPath == "-" {
		out = os.Stdout
	} else {
		out, err = os.Create(finalPath)
		if err != nil {
			return err
		}
		defer out.Close()
	}

	zw := NewWriter(out)

	// Stub
	stubMsg := []byte("This is an encrypted archive. Please use f4 or an AXS-compatible tool to extract it.\n")
	w, _ := zw.CreateHeader(&FileHeader{Name: "README_ENCRYPTED.txt", Method: Store})
	w.Write(stubMsg)

	cHdr, key, err := generateXCryptHeader(password, 600000)
	if err != nil {
		return err
	}

	tempFi, err := os.Stat(tempPath)
	if err != nil {
		return err
	}

	// Payload
	pHdr := &FileHeader{Name: ".zipext/xcrypt/payload.enc", Method: Store}
	pHdr.UncompressedSize64 = uint64(tempFi.Size())
	pHdr.CompressedSize64 = pHdr.UncompressedSize64
	pHdr.Flags |= 0x1 // Mark as encrypted

	// Add standard Extra Field 0x7819 to identify it as XCrypt payload
	xcryptExtra := make([]byte, 4)
	binary.LittleEndian.PutUint16(xcryptExtra[0:2], xcryptExtraID)
	binary.LittleEndian.PutUint16(xcryptExtra[2:4], 0)
	pHdr.Extra = append(pHdr.Extra, xcryptExtra...)

	pw, _ := zw.CreateRaw(pHdr)

	in, err := os.Open(tempPath)
	if err != nil {
		return err
	}
	cw, _ := newXCryptWriter(pw, key, cHdr.IV)
	io.Copy(cw, in)
	in.Close()

	cHdr.MAC = cw.MAC()

	// Metadata
	mHdr := &FileHeader{Name: ".zipext/xcrypt/crypto.hdr", Method: Store}
	mHdr.UncompressedSize64 = 93
	mHdr.CompressedSize64 = 93
	mw, _ := zw.CreateRaw(mHdr)
	mw.Write(cHdr.Encode())

	return zw.Close()
}

func checkXCryptZip(ra io.ReaderAt, size int64, password string) (io.ReaderAt, int64, error) {
	if size < 22 {
		return ra, size, nil
	}

	zr := new(Reader)
	if err := zr.init(ra, size); err != nil {
		return ra, size, nil
	}

	var cHdr *XCryptHeader
	var payloadFile *File
	hasXcryptTag := false

	for _, file := range zr.File {
		if file.Name == ".zipext/xcrypt/crypto.hdr" {
			rc, _ := file.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			var err error
			cHdr, err = parseXCryptHeader(data)
			if err != nil {
				return nil, 0, err
			}
		} else if file.Name == ".zipext/xcrypt/payload.enc" {
			payloadFile = file
			for extra := readBuf(file.Extra); len(extra) >= 4; {
				tag := extra.uint16()
				sz := int(extra.uint16())
				if tag == xcryptExtraID {
					hasXcryptTag = true
					break
				}
				if len(extra) < sz {
					break
				}
				extra = extra[sz:]
			}
		}
	}

	if cHdr == nil || payloadFile == nil || !hasXcryptTag {
		return ra, size, nil
	}

	if password == "" {
		return ra, size, nil // Return legacy unencrypted view of the stub (README)
	}

	key := cHdr.DeriveKey(password)

	// Open the payload stream directly
	pOff, err := payloadFile.DataOffset()
	if err != nil {
		return nil, 0, err
	}
	payloadSection := io.NewSectionReader(ra, pOff, int64(payloadFile.CompressedSize64))
	decReader := newXCryptReaderAt(payloadSection, key, cHdr.IV)

	return decReader, int64(payloadFile.CompressedSize64), nil
}
