package zip

import (
	"hash/crc32"
)

var crc32Table = crc32.MakeTable(crc32.IEEE)

// Classic ZIP encryption algorithm (ZipCrypto).
type zipCrypto struct {
	keys [3]uint32
}

func (z *zipCrypto) updateKeys(b byte) {
	z.keys[0] = (z.keys[0] >> 8) ^ crc32Table[byte(z.keys[0])^b]
	z.keys[1] += z.keys[0] & 0xff
	z.keys[1] = z.keys[1]*134775813 + 1
	z.keys[2] = (z.keys[2] >> 8) ^ crc32Table[byte(z.keys[2])^byte(z.keys[1]>>24)]
}

func newZipCrypto(password []byte) *zipCrypto {
	z := &zipCrypto{
		keys: [3]uint32{0x12345678, 0x23456789, 0x34567890},
	}
	for _, b := range password {
		z.updateKeys(b)
	}
	return z
}

func (z *zipCrypto) decryptByte() byte {
	temp := uint16(z.keys[2]) | 2
	return byte((uint32(temp) * (uint32(temp) ^ 1)) >> 8)
}

func (z *zipCrypto) decrypt(b []byte) {
	for i, v := range b {
		c := v ^ z.decryptByte()
		z.updateKeys(c)
		b[i] = c
	}
}