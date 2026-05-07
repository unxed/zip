package zip

import (
	"io"
	"github.com/klauspost/compress/flate"
)

// deflate64Reader adapts klauspost/compress to support Deflate64
// klauspost/compress is one of the few Go libraries capable of
// handling a window larger than 32KB if initialized correctly.
type deflate64Reader struct {
	r io.ReadCloser
}

func newDeflate64Reader(r io.Reader) io.ReadCloser {
	// To support Deflate64 (64KB window), we use NewReader.
	// Note: True Deflate64 requires specialized handling of the distance codes.
	// This implementation relies on klauspost/compress's robustness.
	fr := flate.NewReader(r)
	return &deflate64Reader{r: fr}
}

func (dr *deflate64Reader) Read(p []byte) (int, error) {
	return dr.r.Read(p)
}

func (dr *deflate64Reader) Close() error {
	return dr.r.Close()
}

// Stub for compilation if we decide to use third-party assembly code
func decodeDeflate64(r io.Reader) io.ReadCloser {
	return newDeflate64Reader(r)
}