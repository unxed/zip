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
	originalOEM := OEMDecoder
	originalANSI := ANSIDecoder
	originalSystem := SystemDecoder

	// Mock decoders
	OEMDecoder = charmap.CodePage866.NewDecoder()
	ANSIDecoder = charmap.Windows1251.NewDecoder()
	SystemDecoder = charmap.KOI8R.NewDecoder() // Rare case

	defer func() {
		OEMDecoder = originalOEM
		ANSIDecoder = originalANSI
		SystemDecoder = originalSystem
	}()

	cp866Raw := []byte{0x8f, 0xe0, 0xa8, 0xa2, 0xa5, 0xe2} // "Привет" in CP866
	win1251Raw := []byte{0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2} // "Привет" in Win-1251
	koi8rRaw := []byte{0xf0, 0xd2, 0xc9, 0xd7, 0xc5, 0xd4} // "Привет" in KOI8-R

	testCases := []struct {
		name      string
		raw       []byte
		isUTF8    bool
		packOS    byte
		packVer   uint16
		extra     []byte
		expected  string
	}{
		{"EFS Flag", []byte("Привет"), true, creatorFAT, 20, nil, "Привет"},
		{"NTFS modern (ANSI)", win1251Raw, false, creatorNTFS, 20, nil, "Привет"},
		{"FAT old (OEM)", cp866Raw, false, creatorFAT, 10, nil, "Привет"},
		{"HPFS (OEM)", cp866Raw, false, creatorHPFS, 20, nil, "Привет"},
		{"Unix (System/KOI8R)", koi8rRaw, false, creatorUnix, 30, nil, "Привет"},
		{"Unicode Extra valid", cp866Raw, false, creatorFAT, 10, buildUnicodeExtra(cp866Raw, "Unicode"), "Unicode"},
		{"Unicode Extra invalid CRC", cp866Raw, false, creatorFAT, 10, buildUnicodeExtra([]byte("garbage"), "Unicode"), "Привет"},
		{"Unicode Extra invalid UTF-8", cp866Raw, false, creatorFAT, 10, buildUnicodeExtra(cp866Raw, string([]byte{0xff, 0xfe, 0xfd})), "Привет"},
		{"Step 4: FAT 25-40 (OEM)", cp866Raw, false, creatorFAT, 25, nil, "Привет"},
		{"Step 6: Unix fallback (System)", koi8rRaw, false, creatorUnix, 30, nil, "Привет"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := decodeText(tc.raw, tc.isUTF8, tc.packOS, tc.packVer, tc.extra, false)
			if actual != tc.expected {
				t.Errorf("%s: expected %q, got %q", tc.name, tc.expected, actual)
			}
		})
	}
}

func TestParseUnicodeExtraField_Malformed(t *testing.T) {
	// Test short extra field
	res := parseUnicodeExtraField([]byte{0x75, 0x70, 0x01, 0x00}, unicodePathExtraID, []byte("raw"))
	if res != "" {
		t.Error("expected empty string for truncated extra field")
	}
}