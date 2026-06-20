package zip

import (
	"encoding/binary"
	"io"
)

var magicF4Recovery = []byte("F4RECOVERY\x00\x00\x00\x00\x00\x00")

func checkF4Recovery(ra io.ReaderAt, size int64) (io.ReaderAt, int64, error) {
	if size < 32 {
		return ra, size, nil
	}
	var footer [32]byte
	if _, err := ra.ReadAt(footer[:], size-32); err != nil {
		return ra, size, nil
	}
	if string(footer[16:32]) == string(magicF4Recovery) {
		origSize := int64(binary.LittleEndian.Uint64(footer[8:16]))
		if origSize < 0 || origSize > size {
			return ra, size, nil
		}
		return io.NewSectionReader(ra, 0, origSize), origSize, nil
	}
	return ra, size, nil
}
