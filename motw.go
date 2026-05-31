package zip

import (
	"bytes"
	"strings"
)

func sanitizeZoneIdentifier(data []byte) []byte {
	utf16 := isUTF16LE(data)
	var content string
	if utf16 {
		content = decodeUTF16LE(data)
	} else {
		content = string(data)
	}

	lines := strings.Split(content, "\n")
	zoneID := "3" // Default to Internet Zone (3) if parsing fails
	found := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ZoneId=") {
			val := strings.TrimPrefix(line, "ZoneId=")
			if len(val) > 0 && val[0] >= '0' && val[0] <= '4' {
				zoneID = string(val[0])
				found = true
			}
		}
	}
	if !found {
		return data
	}

	sanitized := "[ZoneTransfer]\r\nZoneId=" + zoneID + "\r\n"
	if utf16 {
		return encodeUTF16LE(sanitized)
	}
	return []byte(sanitized)
}

func isUTF16LE(data []byte) bool {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return true
	}
	if len(data) >= 4 && data[1] == 0 && data[3] == 0 {
		return true
	}
	return false
}

func decodeUTF16LE(data []byte) string {
	start := 0
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		start = 2
	}
	var b strings.Builder
	for i := start; i < len(data)-1; i += 2 {
		r := rune(data[i]) | (rune(data[i+1]) << 8)
		b.WriteRune(r)
	}
	return b.String()
}

func encodeUTF16LE(s string) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0xFF)
	buf.WriteByte(0xFE)
	for _, r := range s {
		buf.WriteByte(byte(r))
		buf.WriteByte(byte(r >> 8))
	}
	return buf.Bytes()
}