package zip

import (
	"bytes"
	"encoding/binary"
	"io/fs"
	"math"
	"strings"
	"testing"
	"time"
)

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
		b    []byte
		want int
		ok   bool
	}{
		{[]byte{0x05}, 5, true},
		{[]byte{0xFF}, 255, true},
		{[]byte{0x01, 0x00}, 1, true},
		{[]byte{0x01, 0x00, 0x00, 0x00}, 1, true},
		{[]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 1, true},
		// The widest id every build this runs on can hold, in four
		// bytes and in eight.
		{[]byte{0xFF, 0xFF, 0xFF, 0x7F}, math.MaxInt32, true},
		{[]byte{0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00}, math.MaxInt32, true},
		// One past the widest id a uid_t holds, and the widest eight bytes
		// can name: both are refused rather than narrowed.
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, 0, false},
		{[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 0, false},
		{[]byte{0x01, 0x02, 0x03}, 0, false}, // invalid length (3 bytes)
	}
	for _, tc := range cases {
		got, ok := readInt(tc.b)
		if got != tc.want || ok != tc.ok {
			t.Errorf("readInt(%v) = %d, %t, want %d, %t", tc.b, got, ok, tc.want, tc.ok)
		}
	}
}

// TestReadIntNeverReturnsANegativeID pins the widest id the field can name.
// A 64-bit int holds 4294967295 and hands it back as it is; a 32-bit int does
// not, and narrowing it there would give -1, which is the number Lchown reads
// as "leave the owner alone". Either answer is fine, that one is not, and this
// is the same assertion on both.
func TestReadIntNeverReturnsANegativeID(t *testing.T) {
	for _, b := range [][]byte{
		{0xFF, 0xFF, 0xFF, 0xFF},
		{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00},
	} {
		got, ok := readInt(b)
		if !ok {
			continue
		}
		if got < 0 {
			t.Errorf("readInt(%v) = %d, which is not an id", b, got)
			continue
		}
		if int64(got) != int64(math.MaxUint32) {
			t.Errorf("readInt(%v) = %d, want the id itself", b, got)
		}
	}
}

// unixIDExtra builds a 0x7875 tag by hand. The tag holds a version byte and
// then each id preceded by one byte saying how many bytes it takes, and that
// width byte is what an archive gets to choose: it is passed separately here
// for the same reason.
func unixIDExtra(t *testing.T, uidWidth byte, uid []byte, gidWidth byte, gid []byte) []byte {
	t.Helper()
	payload := []byte{1} // version
	payload = append(payload, uidWidth)
	payload = append(payload, uid...)
	payload = append(payload, gidWidth)
	payload = append(payload, gid...)

	size, err := fitUint16(len(payload), "0x7875 payload")
	if err != nil {
		t.Fatalf("building the tag: %v", err)
	}
	extra := make([]byte, 4)
	binary.LittleEndian.PutUint16(extra[0:2], infoZipNewUnixExtraID)
	binary.LittleEndian.PutUint16(extra[2:4], size)
	return append(extra, payload...)
}

// TestParseUnixExtraRejectsIDsTooWideForAUid is the adversarial side of the
// bound in readInt. The width byte in the tag is one byte of the archive, so
// an entry can announce an eight-byte uid and put any number under it. Without
// the bound, the eight bytes below come back as -1 and 1, and the -1 is then
// what the extractor hands lchown as the owner the archive named.
func TestParseUnixExtraRejectsIDsTooWideForAUid(t *testing.T) {
	wide := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	narrow := []byte{0x01, 0x00, 0x00, 0x00}

	tests := []struct {
		name               string
		uidWidth, gidWidth byte
		uid, gid           []byte
	}{
		{"a uid no int holds", 8, 4, wide, narrow},
		{"a gid no int holds", 4, 8, narrow, wide},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extra := unixIDExtra(t, tt.uidWidth, tt.uid, tt.gidWidth, tt.gid)
			uid, gid, ok := parseUnixExtra(extra)
			if ok {
				t.Fatalf("the tag was accepted and gave %d:%d", uid, gid)
			}
			if uid != 0 || gid != 0 {
				t.Errorf("a refused tag still returned %d:%d", uid, gid)
			}
		})
	}
}

// TestParseUnixExtraRejectsMalformedTags walks the ways a 0x7875 tag can stop
// short of the ids it announces. Each of these is a tag an archive can carry,
// so each has to end as "no ids here" rather than as a read past what the tag
// holds.
func TestParseUnixExtraRejectsMalformedTags(t *testing.T) {
	tests := []struct {
		name  string
		extra []byte
	}{
		{"a tag longer than the extra field", []byte{0x75, 0x78, 20, 0, 0x01, 0x00}},
		{"a tag holding only the version byte", []byte{0x75, 0x78, 1, 0, 0x01}},
		{"a uid wider than the tag", []byte{0x75, 0x78, 3, 0, 0x01, 0x08, 0x00}},
		{"a tag that stops after the uid", []byte{0x75, 0x78, 3, 0, 0x01, 0x01, 0x2a}},
		{"a gid wider than the tag", []byte{0x75, 0x78, 4, 0, 0x01, 0x01, 0x2a, 0x04}},
		{"a version the tag has no layout for", []byte{0x75, 0x78, 3, 0, 0x02, 0x01, 0x2a}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uid, gid, ok := parseUnixExtra(tt.extra); ok {
				t.Errorf("the tag was accepted and gave %d:%d", uid, gid)
			}
		})
	}
}

// TestParseUnixOwnerNamesExtraRejectsMalformedTags is the same walk over the
// 0x7817 tag, whose two names are each preceded by a two-byte length that the
// tag's own length has to hold.
func TestParseUnixOwnerNamesExtraRejectsMalformedTags(t *testing.T) {
	tests := []struct {
		name  string
		extra []byte
	}{
		{"a tag longer than the extra field", []byte{0x17, 0x78, 20, 0, 0x00, 0x00}},
		{"a tag too short to hold two lengths", []byte{0x17, 0x78, 2, 0, 0x00, 0x00}},
		{"an owner name wider than the tag", []byte{0x17, 0x78, 4, 0, 10, 0, 0, 0}},
		{"a group name wider than the tag", []byte{0x17, 0x78, 6, 0, 1, 0, 'a', 10, 0, 0}},
		{"an extra field with no such tag in it", []byte{0x75, 0x78, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if uname, gname, ok := parseUnixOwnerNamesExtra(tt.extra); ok {
				t.Errorf("the tag was accepted and gave %q:%q", uname, gname)
			}
		})
	}
}

// TestParseUnixExtraAcceptsAnEightByteID keeps the bound from taking anything
// legitimate with it: an id that fits a uid_t is still read whatever width the
// tag chose to announce it in.
func TestParseUnixExtraAcceptsAnEightByteID(t *testing.T) {
	uid := []byte{0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00}
	gid := []byte{0xE9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	gotUID, gotGID, ok := parseUnixExtra(unixIDExtra(t, 8, uid, 8, gid))
	if !ok {
		t.Fatal("an eight-byte tag holding ids a uid_t fits was refused")
	}
	if gotUID != math.MaxInt32 || gotGID != 1001 {
		t.Errorf("got %d:%d, want %d:%d", gotUID, gotGID, math.MaxInt32, 1001)
	}
}

// TestAppendUnix000dExtraDevice covers the device half of the 0x000d tag,
// which is the only place the device number is written, and the times and the
// ids that go in the fixed part of the tag ahead of it.
func TestAppendUnix000dExtraDevice(t *testing.T) {
	hdr := &FileHeader{
		Name:     "dev/null",
		Uid:      1001,
		Gid:      2002,
		Devmajor: 1,
		Devminor: 3,
		Modified: time.Unix(1000000000, 0),
		Accessed: time.Unix(1000000001, 0),
	}
	hdr.SetMode(fs.ModeDevice | fs.ModeCharDevice | 0600)

	extra := appendUnix000dExtra(nil, hdr)
	if len(extra) != 24 {
		t.Fatalf("the tag is %d bytes, want 24: % x", len(extra), extra)
	}
	if tag := binary.LittleEndian.Uint16(extra[0:2]); tag != unixExtraID {
		t.Errorf("tag is %#04x, want %#04x", tag, unixExtraID)
	}
	if size := binary.LittleEndian.Uint16(extra[2:4]); size != 20 {
		t.Errorf("announced payload is %d bytes, want 20", size)
	}
	if at := binary.LittleEndian.Uint32(extra[4:8]); at != 1000000001 {
		t.Errorf("access time is %d, want 1000000001", at)
	}
	if mt := binary.LittleEndian.Uint32(extra[8:12]); mt != 1000000000 {
		t.Errorf("modification time is %d, want 1000000000", mt)
	}
	if uid := binary.LittleEndian.Uint16(extra[12:14]); uid != 1001 {
		t.Errorf("uid is %d, want 1001", uid)
	}
	if gid := binary.LittleEndian.Uint16(extra[14:16]); gid != 2002 {
		t.Errorf("gid is %d, want 2002", gid)
	}
	if major := binary.LittleEndian.Uint32(extra[16:20]); major != 1 {
		t.Errorf("major is %d, want 1", major)
	}
	if minor := binary.LittleEndian.Uint32(extra[20:24]); minor != 3 {
		t.Errorf("minor is %d, want 3", minor)
	}
}

// TestAppendUnix000dExtraLinkname covers the other half of the tag and the
// length it is written under, which is two bytes: a link target longer than
// the tag can announce leaves the tag out rather than going on disk under a
// length that has wrapped.
func TestAppendUnix000dExtraLinkname(t *testing.T) {
	hdr := &FileHeader{Name: "link", Linkname: "target.txt"}
	hdr.SetMode(fs.ModeSymlink | 0777)
	if extra := appendUnix000dExtra(nil, hdr); len(extra) != 26 {
		t.Errorf("a ten-byte target gave a %d-byte tag, want 26", len(extra))
	}

	hdr.Linkname = strings.Repeat("a", uint16max-11)
	if extra := appendUnix000dExtra([]byte("head"), hdr); string(extra) != "head" {
		t.Errorf("a target too long for the tag's length added %d bytes", len(extra)-4)
	}

	// Neither a link target nor a device: nothing to put in the tag.
	plain := &FileHeader{Name: "plain.txt"}
	plain.SetMode(0600)
	if extra := appendUnix000dExtra(nil, plain); extra != nil {
		t.Errorf("a plain file got a %d-byte 0x000d tag", len(extra))
	}
}

// TestHardLinkAttr covers the attribute bit fuse-zip and mount-zip need before
// they take the name in an entry's 0x000d tag for a hard link, read back out of
// the central directory the way they read it: set on a hard link made on Unix,
// and left off every entry that is not one, whose tag holds something other
// than a link name, or whose low attribute word means something else.
func TestHardLinkAttr(t *testing.T) {
	unixEntry := func(name, linkname string, mode fs.FileMode) func() *FileHeader {
		return func() *FileHeader {
			h := &FileHeader{Name: name, Linkname: linkname}
			h.SetMode(mode)
			return h
		}
	}
	tests := []struct {
		name     string
		hdr      func() *FileHeader
		wantFlag bool
	}{
		{"hard link to a regular file", unixEntry("hard.txt", "target.txt", 0644), true},
		{"hard link to a fifo", unixEntry("hard.fifo", "target.fifo", fs.ModeNamedPipe|0644), true},
		{"regular file", unixEntry("plain.txt", "", 0644), false},
		{"symlink", unixEntry("sym", "target.txt", fs.ModeSymlink|0777), false},
		{"character device", unixEntry("tty", "tty0", fs.ModeDevice|fs.ModeCharDevice|0600), false},
		{"target too long for the tag", unixEntry("hard.txt", strings.Repeat("a", uint16max-11), 0644), false},
		{"entry made on NTFS", func() *FileHeader {
			return &FileHeader{
				Name:           "hard.txt",
				Linkname:       "target.txt",
				CreatorVersion: creatorNTFS << 8,
				ExternalAttrs:  0x20,
			}
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hdr := tc.hdr()
			hdr.Method = Store
			wantMode := hdr.Mode()

			var buf bytes.Buffer
			zw := NewWriter(&buf)
			if _, err := zw.CreateHeader(hdr); err != nil {
				t.Fatal(err)
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}

			zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			if err != nil {
				t.Fatal(err)
			}
			if len(zr.File) != 1 {
				t.Fatalf("the archive holds %d entries, want 1", len(zr.File))
			}
			f := zr.File[0]
			if got := f.ExternalAttrs&pkwareHardLinkAttr != 0; got != tc.wantFlag {
				t.Errorf("hard link flag is %v, want %v (external attributes %#08x)", got, tc.wantFlag, f.ExternalAttrs)
			}
			if tc.wantFlag && f.Linkname != hdr.Linkname {
				t.Errorf("a flagged entry reads back with link target %q, want %q", f.Linkname, hdr.Linkname)
			}
			// On a Unix entry the bit lies outside the word the mode is
			// read from, so it changes nothing about what the entry is.
			if got := f.Mode(); got != wantMode {
				t.Errorf("mode reads back as %v, want %v", got, wantMode)
			}
		})
	}
}

func TestAppendXattrs(t *testing.T) {
	extra := appendXattrs(nil, map[string]string{"user.a": "1"})
	want := 4 + 2 + len("user.a") + 2 + len("1")
	if len(extra) != want {
		t.Fatalf("the tag is %d bytes, want %d: % x", len(extra), want, extra)
	}
	if tag := binary.LittleEndian.Uint16(extra[0:2]); tag != xattrExtraID {
		t.Errorf("tag is %#04x, want %#04x", tag, xattrExtraID)
	}
	if size := int(binary.LittleEndian.Uint16(extra[2:4])); size != want-4 {
		t.Errorf("announced payload is %d bytes, want %d", size, want-4)
	}

	if extra := appendXattrs([]byte("head"), nil); string(extra) != "head" {
		t.Errorf("an empty set added %d bytes", len(extra)-4)
	}
}

// TestAppendXattrsOverLongLengths covers the three lengths in the 0x7811 tag,
// each of which is two bytes: an attribute whose name or value does not fit is
// left out, and a set whose whole payload does not fit leaves the tag out.
func TestAppendXattrsOverLongLengths(t *testing.T) {
	long := strings.Repeat("x", uint16max+1)

	tests := []struct {
		name   string
		xattrs map[string]string
	}{
		{"a name longer than its length", map[string]string{"user." + long: "1"}},
		{"a value longer than its length", map[string]string{"user.a": long}},
		{
			"a payload longer than the tag's length",
			map[string]string{
				"user.a": strings.Repeat("x", 30000),
				"user.b": strings.Repeat("y", 30000),
				"user.c": strings.Repeat("z", 30000),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if extra := appendXattrs([]byte("head"), tt.xattrs); string(extra) != "head" {
				t.Errorf("the tag was written anyway, adding %d bytes", len(extra)-4)
			}
		})
	}
}

func TestUnixOwnerNamesExtra(t *testing.T) {
	extra := appendUnixOwnerNamesExtra(nil, "roma", "staff")
	uname, gname, ok := parseUnixOwnerNamesExtra(extra)
	if !ok {
		t.Fatal("failed to parse the owner name tag")
	}
	if uname != "roma" || gname != "staff" {
		t.Errorf("got %q:%q, want %q:%q", uname, gname, "roma", "staff")
	}
}

// TestAppendUnixOwnerNamesExtraOverLongNames covers the three lengths in the
// 0x7817 tag. A name that does not fit its own two-byte length, or a pair
// whose payload does not fit the tag's, leaves the tag out: the entry then
// carries only the numeric ids, which is what a reader that does not know the
// tag uses anyway.
func TestAppendUnixOwnerNamesExtraOverLongNames(t *testing.T) {
	long := strings.Repeat("n", uint16max+1)
	half := strings.Repeat("n", uint16max/2)

	tests := []struct {
		name         string
		uname, gname string
	}{
		{"an owner name longer than its length", long, "staff"},
		{"a group name longer than its length", "roma", long},
		{"two names that together overrun the tag", half, half},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extra := appendUnixOwnerNamesExtra([]byte("head"), tt.uname, tt.gname)
			if string(extra) != "head" {
				t.Errorf("the tag was written anyway, adding %d bytes", len(extra)-4)
			}
		})
	}
}
