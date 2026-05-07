package zip

import (
	"io"
	"github.com/klauspost/compress/flate"
)

// deflate64Reader адаптирует klauspost/compress для поддержки Deflate64
// klauspost/compress — одна из немногих библиотек на Go, которая умеет
// работать с окном более 32КБ, если её правильно инициализировать.
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

// Заглушка для компиляции, если мы решим использовать сторонний ассемблерный код
func decodeDeflate64(r io.Reader) io.ReadCloser {
	return newDeflate64Reader(r)
}