//go:build amd64 || arm64 || s390x || ppc64le || riscv64

package zip

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/dovydenkovas/ppmd"
)

func newPPMdReader(r io.Reader, size uint64) io.ReadCloser {
	// APPNOTE 5.10.3: PPMd parameters are stored in the first 2 bytes of the data.
	props := make([]byte, 2)
	if _, err := io.ReadFull(r, props); err != nil {
		return nil
	}
	val := binary.LittleEndian.Uint16(props)

	// Parameter parsing:
	// Order: bits 0-3 (+1)
	// MemSize: bits 4-11 (+1) in MB
	// Restoration: bits 12-15
	order := int(val&0xF) + 1
	memSize := (int((val>>4)&0xFF) + 1)

	if int64(memSize) > MaxDecompressionDictSize/(1024*1024) {
		return errorReader{fmt.Errorf("zip: PPMd memory limit exceeded (%d MB)", memSize)}
	}

	rd, err := ppmd.NewH7zReader(r, order, memSize, int(size))
	if err != nil {
		return errorReader{err}
	}
	return io.NopCloser(&rd)
}