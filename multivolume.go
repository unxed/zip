package zip

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// multiVolumeReader joins multiple files into a single virtual ReaderAt stream.
type multiVolumeReader struct {
	files   []*os.File
	offsets []int64
	size    int64
}

func (m *multiVolumeReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 || off >= m.size {
		return 0, io.EOF
	}

	for i := range m.files {
		// Check if the offset falls within this file
		fileStart := m.offsets[i]
		fileEnd := m.size
		if i+1 < len(m.offsets) {
			fileEnd = m.offsets[i+1]
		}

		if off >= fileStart && off < fileEnd {
			relOff := off - fileStart
			canRead := fileEnd - off

			toRead := int64(len(p))
			if toRead > canRead {
				toRead = canRead
			}

			nPart, err := m.files[i].ReadAt(p[:toRead], relOff)
			n += nPart
			if err != nil && err != io.EOF {
				return n, err
			}

			if n < len(p) && nPart == int(toRead) {
				// Data continues in the next volume
				nextN, nextErr := m.ReadAt(p[n:], off+int64(nPart))
				return n + nextN, nextErr
			}
			return n, err
		}
	}
	return 0, io.EOF
}

func (m *multiVolumeReader) Close() error {
	var lastErr error
	for _, f := range m.files {
		if err := f.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// openMultiVolume looks for archive parts (.z01, .z02...) alongside the .zip file
func openMultiVolume(mainPath string) (io.ReaderAt, int64, io.Closer, error) {
	ext := filepath.Ext(mainPath)
	prefix := strings.TrimSuffix(mainPath, ext)

	var files []*os.File
	var offsets []int64
	var totalSize int64

	// Collect volumes in order: .z01, .z02...
	for i := 1; ; i++ {
		volPath := fmt.Sprintf("%s.z%02d", prefix, i)
		f, err := os.Open(volPath)
		if err != nil {
			break // No more volumes
		}
		fi, _ := f.Stat()
		offsets = append(offsets, totalSize)
		totalSize += fi.Size()
		files = append(files, f)
	}

	// The .zip file itself always comes last
	fMain, err := os.Open(mainPath)
	if err != nil {
		// Close already opened volumes on error
		for _, f := range files { f.Close() }
		return nil, 0, nil, err
	}
	fiMain, _ := fMain.Stat()
	offsets = append(offsets, totalSize)
	totalSize += fiMain.Size()
	files = append(files, fMain)

	if len(files) == 1 {
	// This is a regular single file
		return fMain, fiMain.Size(), fMain, nil
	}

	m := &multiVolumeReader{
		files:   files,
		offsets: offsets,
		size:    totalSize,
	}
	return m, totalSize, m, nil
}