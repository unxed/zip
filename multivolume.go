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

// VolumeStarts returns the offset at which each volume begins within the
// joined stream, in volume order. A ZIP split archive stores the offsets in
// its central directory relative to the volume an entry starts on, so a
// reader needs these to place the entries (APPNOTE 4.4.15, 4.4.16).
func (m *MultiVolumeReader) VolumeStarts() []int64 {
	starts := make([]int64, len(m.offsets))
	copy(starts, m.offsets)
	return starts
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

// OpenMultiVolume opens an archive that may be split into volumes, as one
// stream of bytes.
//
// NewMultiVolumeWriter numbers the volumes after the archive's name --
// archive.zip.001, archive.zip.002 and so on -- the way 7-Zip names the
// volumes of its -v switch and reads them back, and the way this project's
// tar volumes are named. They are opened by the name of the first volume, or
// by the archive's own name when no file has that name. Volumes this package
// wrote before took the ZIP split names instead, archive.z01, archive.z02 and
// so on with the last one named archive.zip, while holding the same plain
// split of one archive rather than the split format those names stand for;
// they are opened by the .zip name, as before.
func OpenMultiVolume(mainPath string, flag int) (*MultiVolumeReader, int64, error) {
	// A ZIP split archive keeps its central directory in the last volume,
	// the one named .zip, so opening it by one of the .z01, .z02, ... parts
	// means opening the whole set from that .zip.
	if main, ok := splitVolumeArchiveName(mainPath); ok {
		mainPath = main
	}
	if strings.HasSuffix(mainPath, ".001") {
		return openNumberedVolumes(strings.TrimSuffix(mainPath, ".001"), flag)
	}
	if _, err := os.Stat(mainPath); os.IsNotExist(err) {
		if _, err := os.Stat(mainPath + ".001"); err == nil {
			return openNumberedVolumes(mainPath, flag)
		}
	}

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
				// The volumes opened so far are being given up
				// because one of them could not be opened; that
				// is the error the caller gets.
				_ = openedFile.Close()
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
			// The volumes opened so far are being given up
			// because the main one could not be opened.
			_ = f.Close()
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

// openNumberedVolumes opens stem.001, stem.002 and so on up to the first
// number that is missing.
func openNumberedVolumes(stem string, flag int) (*MultiVolumeReader, int64, error) {
	var files []*os.File
	var offsets []int64
	var totalSize int64
	for i := 1; ; i++ {
		f, err := os.OpenFile(volumeName(stem, i), flag, 0644)
		if err != nil {
			if i > 1 && os.IsNotExist(err) {
				break
			}
			for _, opened := range files {
				// The volumes opened so far are given up because
				// this one could not be opened; that is the error
				// the caller gets.
				_ = opened.Close()
			}
			return nil, 0, err
		}
		fi, _ := f.Stat()
		offsets = append(offsets, totalSize)
		totalSize += fi.Size()
		files = append(files, f)
	}
	return &MultiVolumeReader{files: files, offsets: offsets, size: totalSize}, totalSize, nil
}

// volumeName is the name of volume i of the archive named stem.
func volumeName(stem string, i int) string {
	return fmt.Sprintf("%s.%03d", stem, i)
}

// MultiVolumeWriter transparently splits data across multiple files, named
// after the archive: mainPath.001, mainPath.002 and so on (see
// OpenMultiVolume). No file is written under mainPath itself.
type MultiVolumeWriter struct {
	mainPath    string
	splitSize   int64
	currentFile *os.File
	volumeIndex int
	written     int64
}

func NewMultiVolumeWriter(mainPath string, splitSize int64) (*MultiVolumeWriter, error) {
	// Write fills the current volume, opens the next one and carries on, so
	// a volume that holds nothing is a volume it opens for ever: with a
	// split size of zero it made a new empty part on every turn of the loop
	// and never wrote a byte of what it was given.
	if splitSize <= 0 {
		return nil, fmt.Errorf("zip: volume size %d is not a size", splitSize)
	}
	// An archive written under the same name before, in one piece, would
	// be what OpenMultiVolume opens by that name instead of these volumes.
	if err := os.Remove(mainPath); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
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
	f, err := os.Create(volumeName(m.mainPath, m.volumeIndex))
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
	if err := m.currentFile.Close(); err != nil {
		return err
	}
	m.currentFile = nil
	// Volumes past the last one, left by an archive of the same name that
	// took more of them, would be read as the rest of this one.
	for i := m.volumeIndex + 1; ; i++ {
		if err := os.Remove(volumeName(m.mainPath, i)); err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
	}
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

// splitVolumeArchiveName maps the name of a ZIP split volume -- archive.z01,
// archive.z02 and so on -- to the archive's own name, archive.zip, when that
// file is there beside it. Anything else is left alone.
func splitVolumeArchiveName(name string) (string, bool) {
	ext := strings.ToLower(filepath.Ext(name))
	if len(ext) < 4 || !strings.HasPrefix(ext, ".z") {
		return "", false
	}
	for _, c := range ext[2:] {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	stem := name[:len(name)-len(ext)]
	for _, mainExt := range []string{".zip", ".zipx"} {
		if _, err := os.Stat(stem + mainExt); err == nil {
			return stem + mainExt, true
		}
	}
	return "", false
}
