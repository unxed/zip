package zip

import (
	"errors"
	"io"
)

type unsupportedDeflate64Reader struct{}

func (u unsupportedDeflate64Reader) Read(p []byte) (int, error) {
	return 0, errors.New("zip: Deflate64 compression method is not supported")
}

func (u unsupportedDeflate64Reader) Close() error {
	return nil
}

func decodeDeflate64(r io.Reader) io.ReadCloser {
	return unsupportedDeflate64Reader{}
}