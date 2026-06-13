package zip

import (
	"strings"
	"unicode/utf8"
)

const MappedStringMark = '\uFFFE'
const MappedStringMarkStr = "\uFFFE"

func decodeUTF8OrMap(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	sb.WriteRune(MappedStringMark)
	for _, c := range b {
		sb.WriteRune(rune(0xE000) + rune(c))
	}
	return sb.String()
}

func encodeMappedString(s string) []byte {
	runes := []rune(s)
	if len(runes) > 0 && runes[0] == MappedStringMark {
		b := make([]byte, len(runes)-1)
		for i, r := range runes[1:] {
			b[i] = byte(r - 0xE000)
		}
		return b
	}
	return []byte(s)
}