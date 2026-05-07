package zip

import "testing"

func TestUnixExtraFields(t *testing.T) {
	uid, gid := 1001, 2002
	extra := appendUnixExtra(nil, uid, gid)

	parsedUID, parsedGID, ok := parseUnixExtra(extra)
	if !ok {
		t.Fatal("failed to parse unix extra fields")
	}
	if parsedUID != uid || parsedGID != gid {
		t.Errorf("metadata mismatch: got %d:%d, want %d:%d", parsedUID, parsedGID, uid, gid)
	}
}

func TestReadInt(t *testing.T) {
	cases := []struct {
		b     []byte
		want  int
	}{
		{[]byte{0x01, 0x00}, 1},
		{[]byte{0x01, 0x00, 0x00, 0x00}, 1},
		{[]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 1},
		{[]byte{0xFF}, 0}, // invalid length
	}
	for _, tc := range cases {
		if got := readInt(tc.b); got != tc.want {
			t.Errorf("readInt(%v) = %d, want %d", tc.b, got, tc.want)
		}
	}
}