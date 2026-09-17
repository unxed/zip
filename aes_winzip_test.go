package zip

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

// aesWinZipMessage is what both fixtures below hold, as msg.txt: 62 bytes,
// so the data runs past the first 16 byte CTR block.
const aesWinZipMessage = "WinZip AES counter check: this line is longer than one block.\n"

// aesWinZip7ZipFixture was written by 7-Zip 26.03
// (7zz a -tzip -mem=AES256 -mx0 -ppw): method 99, the 0x9901 field laid out
// as the WinZip AES specification has it, and the little-endian CTR counter.
var aesWinZip7ZipFixture = mustHex(
	"504b03043300010063001d03315d000000005a0000003e00000007000b006d73672e7478740199070002004145030000" +
		"2a836fdc4218f29a7e2064cf46ee815ff4e62dcb2896dc1e8f3b1e6fb4998c5d0a1894d0a2781072a2dde9db978ab1af" +
		"870a4950fec5012fe70382441d65bc47361bdde879fa6036b5e8dc3f13dc44673fb3aa4870a471eb0e91504b01023f03" +
		"3300010063001d03315d000000005a0000003e00000007002f000000000000002080a481000000006d73672e7478740a" +
		"0020000000000001001800dd5ad5f73a46dd01000000000000000000000000000000000199070002004145030000504b" +
		"05060000000001000100640000008a0000000000")

// aesWinZipLegacyFixture was written by this package before it wrote method
// 99 (zipper -m store -p pw): method 0x9901, the strength before the vendor
// ID, and the big-endian counter. Archives like it exist and have to open.
var aesWinZipLegacyFixture = mustHex(
	"504b03041400090001991c03315d000000000000000000000000070033006d73672e74787455540500015933ab6a7578" +
		"0b00010400000000040000000017780c000400726f6f740400726f6f740199070002000341450000060ccecbdefc97c2" +
		"42ecad229d908988e24263bcec6a449fa2a0ebb0b3af6f197e27d2d0333f24183812d1f6f3a16910e8a5b6e812946fe3" +
		"dda2fb0a3e4cb3e6cc61ffb2e7511bb39b5c3d0e838d7d67c144fe08055530ef1f80504b0708000000005a0000003e00" +
		"0000504b010214031400090001991c03315d000000005a0000003e000000070033000000000000000000a48100000000" +
		"6d73672e74787455540500015933ab6a75780b00010400000000040000000017780c000400726f6f740400726f6f7401" +
		"99070002000341450000504b0506000000000100010068000000c20000000000")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func aesWinZipReadAll(t *testing.T, raw []byte, password string) map[string][]byte {
	t.Helper()
	zr, err := NewReaderWithPassword(bytes.NewReader(raw), int64(len(raw)), password)
	if err != nil {
		t.Fatalf("open the archive: %v", err)
	}
	out := make(map[string][]byte)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		out[f.Name] = data
	}
	return out
}

// TestAesWinZip_Reads7ZipEntry: an entry 7-Zip encrypted decrypts to what it
// holds past its first block, read sequentially and from an offset inside the
// second block. With the big-endian counter this package ran before, every
// byte from the seventeenth on came out wrong and no error said so.
func TestAesWinZip_Reads7ZipEntry(t *testing.T) {
	got := aesWinZipReadAll(t, aesWinZip7ZipFixture, "pw")
	if string(got["msg.txt"]) != aesWinZipMessage {
		t.Fatalf("msg.txt decrypted to %q, want %q", got["msg.txt"], aesWinZipMessage)
	}

	zr, err := NewReaderWithPassword(bytes.NewReader(aesWinZip7ZipFixture), int64(len(aesWinZip7ZipFixture)), "pw")
	if err != nil {
		t.Fatalf("open the archive: %v", err)
	}
	rs, err := zr.File[0].OpenSeekable()
	if err != nil {
		t.Fatalf("open msg.txt for random access: %v", err)
	}
	if _, err := rs.Seek(20, io.SeekStart); err != nil {
		t.Fatalf("seek: %v", err)
	}
	tail, err := io.ReadAll(rs)
	if err != nil {
		t.Fatalf("read from offset 20: %v", err)
	}
	if string(tail) != aesWinZipMessage[20:] {
		t.Fatalf("from offset 20 msg.txt reads %q, want %q", tail, aesWinZipMessage[20:])
	}
}

// TestAesWinZip_ReadsLegacyEntry: an entry this package wrote under its old
// marking still decrypts, with the counter it was written with.
func TestAesWinZip_ReadsLegacyEntry(t *testing.T) {
	got := aesWinZipReadAll(t, aesWinZipLegacyFixture, "pw")
	if string(got["msg.txt"]) != aesWinZipMessage {
		t.Fatalf("msg.txt decrypted to %q, want %q", got["msg.txt"], aesWinZipMessage)
	}
}

// TestAesWinZip_WriterMarksEntriesAsTheSpecificationDoes: method 99, the
// 0x9901 field as version, "AE", strength, method, and an unencrypted
// directory; the body, longer than 256 blocks so the counter carries into its
// second byte, reads back.
func TestAesWinZip_WriterMarksEntriesAsTheSpecificationDoes(t *testing.T) {
	payload := make([]byte, 10000)
	for i := range payload {
		payload[i] = byte(i * 7 % 251)
	}
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	mustCreateHeader(t, zw, &FileHeader{Name: "dir/", Password: "pw"})
	w := mustCreateHeader(t, zw, &FileHeader{Name: "dir/data.bin", Method: Store, Password: "pw"})
	mustWrite(t, w, payload)
	if err := zw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	raw := buf.Bytes()

	zr, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("read the archive back: %v", err)
	}
	for _, f := range zr.File {
		field := aesWinZipField(f.Extra)
		switch f.Name {
		case "dir/":
			if f.Flags&0x1 != 0 || field != nil {
				t.Errorf("the directory is marked encrypted: flags %#04x, 0x9901 field %x", f.Flags, field)
			}
		case "dir/data.bin":
			if f.Method != winzipAesMethod {
				t.Errorf("method %d, want %d", f.Method, winzipAesMethod)
			}
			want := []byte{2, 0, 'A', 'E', 3, byte(Store), 0}
			if !bytes.Equal(field, want) {
				t.Errorf("0x9901 field %x, want %x", field, want)
			}
		}
	}

	got := aesWinZipReadAll(t, raw, "pw")
	if !bytes.Equal(got["dir/data.bin"], payload) {
		t.Fatalf("dir/data.bin did not read back as written")
	}
}

func aesWinZipField(extra []byte) []byte {
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra[0:2])
		size := int(binary.LittleEndian.Uint16(extra[2:4]))
		if 4+size > len(extra) {
			return nil
		}
		if id == winzipAesExtraID {
			return extra[4 : 4+size]
		}
		extra = extra[4+size:]
	}
	return nil
}

func TestAesWinZip_ParseExtra(t *testing.T) {
	for _, tc := range []struct {
		name     string
		payload  []byte
		ok       bool
		strength byte
	}{
		{"the specification's layout", []byte{2, 0, 'A', 'E', 3, 8, 0}, true, 3},
		{"the layout this package used to write", []byte{2, 0, 1, 'A', 'E', 8, 0}, true, 1},
		{"no vendor ID in either place", []byte{2, 0, 3, 0, 0, 8, 0}, false, 0},
		{"too short", []byte{2, 0, 'A', 'E', 3, 8}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, ok := parseWinZipAesExtra(tc.payload)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && (info.strength != tc.strength || info.actualMethod != Deflate || info.version != 2) {
				t.Errorf("parsed %+v, want version 2, strength %d, method %d", info, tc.strength, Deflate)
			}
		})
	}
}

// TestAesWinZip_InjectIsIdempotent: a header already marked gives back the
// method its 0x9901 field records and is not marked twice.
func TestAesWinZip_InjectIsIdempotent(t *testing.T) {
	fh := &FileHeader{Name: "a.txt", Method: Deflate, Password: "pw"}
	if got := fh.injectAutoExtras(); got != Deflate {
		t.Fatalf("first call gave method %d, want %d", got, Deflate)
	}
	if fh.Method != winzipAesMethod {
		t.Fatalf("the header carries method %d, want %d", fh.Method, winzipAesMethod)
	}
	if got := fh.injectAutoExtras(); got != Deflate {
		t.Fatalf("second call gave method %d, want %d", got, Deflate)
	}
	if n := strings.Count(string(fh.Extra), "\x01\x99\x07\x00"); n != 1 {
		t.Fatalf("the header carries %d 0x9901 fields, want 1", n)
	}
}

// TestAesWinZip_RawEntryRefusesUnknownStrength: a body the archiver encrypts
// itself is held to the three strengths the specification defines.
func TestAesWinZip_RawEntryRefusesUnknownStrength(t *testing.T) {
	var buf bytes.Buffer
	a, err := NewArchiver(&buf, t.TempDir(), WithArchiverPassword("pw"))
	if err != nil {
		t.Fatalf("building the archiver: %v", err)
	}
	hdr := &FileHeader{Name: "link", Password: "pw", AESStrength: 99}
	if err := a.writeRawEntry(nil, hdr, []byte("target")); err == nil {
		t.Fatal("an entry with AES strength 99 was written")
	}
}
