//go:build !amd64 && !arm64 && !s390x && !ppc64le && !riscv64

package zip

import (
	"errors"
	"io"
)

func newPPMdReader(r io.Reader, size uint64) io.ReadCloser {
	return errorReader{errors.New("zip: PPMd compression is not supported on 32-bit platforms")}
}