package zip

import (
	"encoding/binary"
	"hash/crc32"
	"testing"

	"golang.org/x/text/encoding/charmap"
)

// buildUnicodeExtra динамически собирает Info-ZIP Unicode Extra Field
func buildUnicodeExtra(raw []byte, utf8Str string) []byte {
	crc := crc32.ChecksumIEEE(raw)
	payload := make([]byte, 5+len(utf8Str))
	payload[0] = 1 // version
	binary.LittleEndian.PutUint32(payload[1:5], crc)
	copy(payload[5:], utf8Str)

	extra := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint16(extra[0:2], unicodePathExtraID)
	binary.LittleEndian.PutUint16(extra[2:4], uint16(len(payload)))
	copy(extra[4:], payload)
	return extra
}

func TestDecodeText(t *testing.T) {
	// Для целей теста переопределим дефолтные декодеры
	originalOEM := OEMDecoder
	originalANSI := ANSIDecoder
	OEMDecoder = charmap.CodePage866.NewDecoder()
	ANSIDecoder = charmap.Windows1251.NewDecoder()
	defer func() {
		OEMDecoder = originalOEM
		ANSIDecoder = originalANSI
	}()

	cp866Raw := []byte{0x8f, 0xe0, 0xa8, 0xa2, 0xa5, 0xe2, 0x2e, 0x74, 0x78, 0x74} // Привет.txt

	testCases := []struct {
		name      string
		raw       []byte
		isUTF8    bool
		packOS    byte
		packVer   uint16
		extra     []byte
		isComment bool
		expected  string
	}{
		{
			name:     "Explicit UTF-8 Flag",
			raw:      []byte("Привет.txt"),
			isUTF8:   true,
			packOS:   creatorFAT,
			packVer:  20,
			expected: "Привет.txt",
		},
		{
			name:     "Windows NTFS ANSI (Windows-1251)",
			raw:      []byte{0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2, 0x2e, 0x74, 0x78, 0x74},
			isUTF8:   false,
			packOS:   creatorNTFS,
			packVer:  20,
			expected: "Привет.txt",
		},
		{
			name:     "DOS FAT OEM (CP866)",
			raw:      cp866Raw,
			isUTF8:   false,
			packOS:   creatorFAT,
			packVer:  25,
			expected: "Привет.txt",
		},
		{
			name:     "Unicode Path Extra Field (Corrected)",
			raw:      cp866Raw,
			isUTF8:   false,
			packOS:   creatorFAT,
			packVer:  20,
			extra:    buildUnicodeExtra(cp866Raw, "Привет.txt"),
			expected: "Привет.txt",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := decodeText(tc.raw, tc.isUTF8, tc.packOS, tc.packVer, tc.extra, tc.isComment)
			if actual != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, actual)
			}
		})
	}
}