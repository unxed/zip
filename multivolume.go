package zip

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MultiVolumeReader joins multiple files into a single virtual ReaderAt/WriterAt stream.
type MultiVolumeReader struct {
	files   []*os.File
	offsets []int64
	size    int64
}

func (m *MultiVolumeReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 || off >= m.size {
		return 0, io.EOF
	}
	for i := range m.files {
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
				nextN, nextErr := m.ReadAt(p[n:], off+int64(nPart))
				return n + nextN, nextErr
			}
			return n, err
		}
	}
	return 0, io.EOF
}

func (m *MultiVolumeReader) WriteAt(p []byte, off int64) (n int, err error) {
	if off < 0 || off >= m.size {
		return 0, fmt.Errorf("write out of bounds")
	}
	for i := range m.files {
		fileStart := m.offsets[i]
		fileEnd := m.size
		if i+1 < len(m.offsets) {
			fileEnd = m.offsets[i+1]
		}
		if off >= fileStart && off < fileEnd {
			relOff := off - fileStart
			canWrite := fileEnd - off
			toWrite := int64(len(p))
			if toWrite > canWrite {
				toWrite = canWrite
			}
			nPart, err := m.files[i].WriteAt(p[:toWrite], relOff)
			n += nPart
			if err != nil {
				return n, err
			}
			if n < len(p) && nPart == int(toWrite) {
				nextN, nextErr := m.WriteAt(p[n:], off+int64(nPart))
				return n + nextN, nextErr
			}
			return n, nil
		}
	}
	return 0, fmt.Errorf("write out of bounds")
}

func (m *MultiVolumeReader) Append(data []byte) error {
	lastFile := m.files[len(m.files)-1]
	if _, err := lastFile.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	n, err := lastFile.Write(data)
	if err == nil {
		m.size += int64(n)
	}
	return err
}

func (m *MultiVolumeReader) Close() error {
	var lastErr error
	for _, f := range m.files {
		if err := f.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// OpenMultiVolume looks for archive parts (.z01, .z02...) alongside the .zip file
func OpenMultiVolume(mainPath string, flag int) (*MultiVolumeReader, int64, error) {
	ext := strings.ToLower(filepath.Ext(mainPath))
	if ext != ".zip" && ext != ".zipx" {
		fMain, err := os.OpenFile(mainPath, flag, 0644)
		if err != nil {
			return nil, 0, err
		}
		fiMain, _ := fMain.Stat()
		return &MultiVolumeReader{files: []*os.File{fMain}, offsets: []int64{0}, size: fiMain.Size()}, fiMain.Size(), nil
	}

	prefix := mainPath[:len(mainPath)-len(ext)]

	var files []*os.File
	var offsets []int64
	var totalSize int64

	for i := 1; ; i++ {
		volPath := fmt.Sprintf("%s.z%02d", prefix, i)
		f, err := os.OpenFile(volPath, flag, 0644)
		if err != nil && os.IsNotExist(err) {
			volPathUpper := fmt.Sprintf("%s.Z%02d", prefix, i)
			f, err = os.OpenFile(volPathUpper, flag, 0644)
		}
		if err != nil {
			if os.IsNotExist(err) {
				break
			}
			for _, openedFile := range files {
				openedFile.Close()
			}
			return nil, 0, err
		}
		fi, _ := f.Stat()
		offsets = append(offsets, totalSize)
		totalSize += fi.Size()
		files = append(files, f)
	}

	fMain, err := os.OpenFile(mainPath, flag, 0644)
	if err != nil {
		for _, f := range files {
			f.Close()
		}
		return nil, 0, err
	}
	fiMain, _ := fMain.Stat()
	offsets = append(offsets, totalSize)
	totalSize += fiMain.Size()
	files = append(files, fMain)

	if len(files) == 1 {
		return &MultiVolumeReader{files: []*os.File{fMain}, offsets: []int64{0}, size: totalSize}, totalSize, nil
	}

	m := &MultiVolumeReader{
		files:   files,
		offsets: offsets,
		size:    totalSize,
	}
	return m, totalSize, nil
}

// MultiVolumeWriter transparently splits data across multiple files.
type MultiVolumeWriter struct {
	mainPath    string
	splitSize   int64
	currentFile *os.File
	volumeIndex int
	written     int64
}

func NewMultiVolumeWriter(mainPath string, splitSize int64) (*MultiVolumeWriter, error) {
	m := &MultiVolumeWriter{mainPath: mainPath, splitSize: splitSize}
	if err := m.openNextVolume(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *MultiVolumeWriter) openNextVolume() error {
	if m.currentFile != nil {
		if err := m.currentFile.Close(); err != nil {
			return err
		}
	}
	m.volumeIndex++
	ext := filepath.Ext(m.mainPath)
	prefix := m.mainPath[:len(m.mainPath)-len(ext)]
	volPath := fmt.Sprintf("%s.z%02d", prefix, m.volumeIndex)
	f, err := os.Create(volPath)
	if err != nil {
		return err
	}
	m.currentFile = f
	m.written = 0
	return nil
}

func (m *MultiVolumeWriter) Write(p []byte) (n int, err error) {
	total := 0
	for len(p) > 0 {
		room := m.splitSize - m.written
		if room <= 0 {
			if err := m.openNextVolume(); err != nil {
				return total, err
			}
			room = m.splitSize
		}
		chunk := int64(len(p))
		if chunk > room {
			chunk = room
		}
		wn, err := m.currentFile.Write(p[:chunk])
		total += wn
		m.written += int64(wn)
		if err != nil {
			return total, err
		}
		p = p[chunk:]
	}
	return total, nil
}

func (m *MultiVolumeWriter) Close() error {
	if m.currentFile == nil {
		return nil
	}
	err := m.currentFile.Close()
	if err != nil {
		return err
	}
	ext := filepath.Ext(m.mainPath)
	prefix := m.mainPath[:len(m.mainPath)-len(ext)]
	lastVolPath := fmt.Sprintf("%s.z%02d", prefix, m.volumeIndex)

	os.Remove(m.mainPath)
	if err := os.Rename(lastVolPath, m.mainPath); err != nil {
		return err
	}
	m.currentFile = nil
	return nil
}

func (m *MultiVolumeWriter) Sync() error {
	if m.currentFile != nil {
		return m.currentFile.Sync()
	}
	return nil
}

func (m *MultiVolumeWriter) Name() string {
	return m.mainPath
}
