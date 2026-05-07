package zip

import (
	"encoding/binary"
	"hash/crc32"
	"testing"

	"golang.org/x/text/encoding/charmap"
)

// buildUnicodeExtra dynamically assembles Info-ZIP Unicode Extra Field
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

	defer func() {
		OEMDecoder = originalOEM
		ANSIDecoder = originalANSI
		SystemDecoder = originalSystem
	}()

	cp866Raw := []byte{0x8f, 0xe0, 0xa8, 0xa2, 0xa5, 0xe2} // "Привет" in CP866
	win1251Raw := []byte{0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2} // "Привет" in Win-1251

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
		{"Unicode Extra valid", cp866Raw, false, creatorFAT, 10, buildUnicodeExtra(cp866Raw, "Unicode"), "Unicode"},
		{"Unicode Extra invalid CRC", cp866Raw, false, creatorFAT, 10, buildUnicodeExtra([]byte("garbage"), "Unicode"), "Привет"},
		{"Unicode Extra invalid UTF-8", cp866Raw, false, creatorFAT, 10, buildUnicodeExtra(cp866Raw, string([]byte{0xff, 0xfe, 0xfd})), "Привет"},
		{"FAT 25-40 (OEM)", cp866Raw, false, creatorFAT, 25, nil, "Привет"},
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
func TestInitSystemLocales(t *testing.T) {
	// Save the original decoders
	origOEM := OEMDecoder
	origANSI := ANSIDecoder
	defer func() {
		OEMDecoder = origOEM
		ANSIDecoder = origANSI
	}()

	// Test Russian locale (CP866/Win1251)
	t.Setenv("LC_ALL", "ru_RU.UTF-8")
	initSystemLocales()

	// Verify that decoders have changed (comparison via Bytes)
	testStr := []byte{0x8f} // 'P' in CP866
	res, _ := OEMDecoder.Bytes(testStr)
	if string(res) != "П" {
		t.Errorf("expected CP866 decoder after setting ru_RU locale, got %s", string(res))
	}
}
func TestInitSystemLocales_Japanese(t *testing.T) {
	origOEM := OEMDecoder
	defer func() { OEMDecoder = origOEM }()

	// Test Japanese locale (Shift-JIS / CP932)
	t.Setenv("LC_ALL", "ja_JP.UTF-8")
	initSystemLocales()

	// "日" (Sun/Day) in Shift-JIS is 0x93FA
	sjisData := []byte{0x93, 0xFA}
	res, _ := OEMDecoder.Bytes(sjisData)
	if string(res) != "日" {
		t.Errorf("expected Shift-JIS decoder after setting ja_JP locale, got %s", string(res))
	}
}
func TestCharset_UnknownFallback(t *testing.T) {
	// Provide an encoding that is not in the mapping
	raw := []byte{0x41, 0x42, 0x43} // "ABC"
	// decodeText(raw, isUTF8Flag, packOS, packVer, extra, isComment)
	// Set flags so that Step 6 (System/Fallback) is triggered
	got := decodeText(raw, false, 99, 99, nil, false)
	if got != "ABC" {
		t.Errorf("expected raw string fallback, got %q", got)
	}
}

func TestParseUnicodeExtraField_Malformed(t *testing.T) {
	// Test short extra field
	res := parseUnicodeExtraField([]byte{0x75, 0x70, 0x01, 0x00}, unicodePathExtraID, []byte("raw"))
	if res != "" {
		t.Error("expected empty string for truncated extra field")
	}
}