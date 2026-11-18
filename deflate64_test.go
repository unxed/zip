package zip

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/flate"
)

func TestDeflate64_Registration(t *testing.T) {
	// Verify that the method is registered in the global map
	dcomp := decompressor(Deflate64)
	if dcomp == nil {
		t.Fatal("Deflate64 decompressor not registered")
	}
}

func TestStaticBlockAfterDynamicBlockUsesTheFixedTable(t *testing.T) {
	stream, err := hex.DecodeString("727402108407a0000000008000000000" +
		"00000000000000000000000000000000" +
		"000000000000000000000000c88b888a" +
		"fdcfdd0300")
	if err != nil {
		t.Fatal(err)
	}

	// This fixed→dynamic→fixed stream used to overwrite the shared fixed
	// tables while building the dynamic block's tables.
	for i := 0; i < 2; i++ {
		r := newDeflate64Reader(bytes.NewReader(stream))
		got, err := io.ReadAll(r)
		closeAt(t, r)
		if err != nil {
			t.Fatalf("decode %d failed after %q: %v", i+1, got, err)
		}
		if want := "ABDEFGH"; string(got) != want {
			t.Fatalf("decode %d got %q, want %q", i+1, got, want)
		}
	}
}

func TestDeflate64_External7z(t *testing.T) {
	p7zPath, err := exec.LookPath("7z")
	if err != nil {
		t.Skip("7z utility not found, skipping external Deflate64 compression test")
	}

	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "test.txt")

	// Create content with repeating patterns to test huffman/LZ references
	var content bytes.Buffer
	for i := 0; i < 1000; i++ {
		content.WriteString("Deflate64 compression test data repeating multiple times to verify backreferences on larger streams. ")
	}
	err = os.WriteFile(srcFile, content.Bytes(), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	zipPath := filepath.Join(tmpDir, "deflate64_7z.zip")

	// Run 7z to compress to Deflate64 method
	cmd := exec.Command(p7zPath, "a", "-tzip", "-m0=deflate64", zipPath, srcFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("7z compression failed: %v, output: %s", err, string(output))
	}

	// Open with our library
	zr, err := OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open generated zip: %v", err)
	}
	closeAt(t, zr)

	if len(zr.File) == 0 {
		t.Fatal("no files in the zip archive")
	}

	f := zr.File[0]
	if f.Method != Deflate64 {
		t.Errorf("expected compression method Deflate64 (%d), got %d", Deflate64, f.Method)
	}

	rc, err := f.Open()
	if err != nil {
		t.Fatalf("failed to open file inside zip: %v", err)
	}
	closeAt(t, rc)

	decompressed, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("decompression failed: %v", err)
	}

	if !bytes.Equal(decompressed, content.Bytes()) {
		t.Error("decompressed content mismatch with original")
	}
}

// TestDeflate64_StoredBlock decodes an uncompressed (stored) block, the block
// type the encoder in this package never produces, and checks that a header
// whose length and one's complement disagree is rejected instead of being
// decoded as whatever the length happens to say.
func TestDeflate64_StoredBlock(t *testing.T) {
	payload := []byte("stored blocks carry their bytes verbatim")
	const payloadLen = 40
	if len(payload) != payloadLen {
		t.Fatalf("payload is %d bytes, the header below says %d", len(payload), payloadLen)
	}

	// First byte: bfinal = 1, btype = 00 (stored). The header is byte aligned
	// from there: LEN little endian, then its one's complement, then the bytes.
	storedBlock := func(nlenLo, nlenHi byte) io.Reader {
		return bytes.NewReader(append([]byte{0x01, payloadLen, 0x00, nlenLo, nlenHi}, payload...))
	}

	decoded, err := io.ReadAll(decodeDeflate64(storedBlock(0xD7, 0xFF)))
	if err != nil {
		t.Fatalf("decoding a stored block failed: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Errorf("decoded %q, want %q", decoded, payload)
	}

	if _, err := io.ReadAll(decodeDeflate64(storedBlock(0xD8, 0xFF))); !errors.Is(err, errDataError) {
		t.Errorf("a stored block whose length complement is off by one decoded with error %v, want %v", err, errDataError)
	}
}

// TestInputBuffer_CopyToDrainsBitBuffer covers the byte accurate hand off in
// copyTo. A block that ends on a byte boundary can leave whole bytes sitting
// in the bit accumulator, and the bytes a stored block copies out have to
// start with those rather than with the next unread input byte.
func TestInputBuffer_CopyToDrainsBitBuffer(t *testing.T) {
	in := newInputBuffer(bitsBuffer{}, []byte{0x11, 0x22, 0x33, 0x44})

	in.tryLoad16Bits() // pulls 0x11 and 0x22 into the accumulator
	if got := in.availableBits(); got != 16 {
		t.Fatalf("availableBits() = %d, want 16", got)
	}

	out := make([]byte, 4)
	if n := in.copyTo(out); n != len(out) {
		t.Fatalf("copyTo copied %d bytes, want %d", n, len(out))
	}
	if want := []byte{0x11, 0x22, 0x33, 0x44}; !bytes.Equal(out, want) {
		t.Errorf("copyTo produced %x, want %x", out, want)
	}
	if in.availableBits() != 0 {
		t.Errorf("copyTo left %d bits behind, want none", in.availableBits())
	}
	if in.readBytes != 4 {
		t.Errorf("copyTo accounted for %d read bytes, want 4", in.readBytes)
	}
}

// deflate64BitBuf lays out a deflate stream by hand: header fields go in
// least significant bit first, Huffman codes most significant bit first.
type deflate64BitBuf struct {
	out   []byte
	accum uint32
	nbits uint
}

// field writes count bits of value, low bit first, which is how the format
// spells everything that is not a Huffman code.
func (b *deflate64BitBuf) field(value uint32, count uint) {
	for i := uint(0); i < count; i++ {
		b.accum |= ((value >> i) & 1) << b.nbits
		b.nbits++
		if b.nbits == 8 {
			// #nosec G115 -- the accumulator is emitted a byte at a time, so taking its low eight bits is the operation itself
			b.out = append(b.out, byte(b.accum))
			b.accum, b.nbits = 0, 0
		}
	}
}

// code writes a Huffman code of count bits, high bit first.
func (b *deflate64BitBuf) code(value uint32, count uint) {
	for i := count; i > 0; i-- {
		b.field((value>>(i-1))&1, 1)
	}
}

func (b *deflate64BitBuf) bytes() []byte {
	if b.nbits > 0 {
		// #nosec G115 -- as above: the trailing partial byte is the low eight bits of the accumulator
		return append(b.out, byte(b.accum))
	}
	return b.out
}

// TestDeflate64_MatchBeforeTheStartOfTheOutputIsRefused: a match names how far
// back to copy from, and the window it copies out of is zeroed to begin with.
// A distance reaching past the start of the stream therefore used to produce
// zeros the stream never carried -- a file of plausible length, part of it
// invented, with nothing reported. The standard library's decoder refuses such
// a stream, and this is where.
func TestDeflate64_MatchBeforeTheStartOfTheOutputIsRefused(t *testing.T) {
	var b deflate64BitBuf
	b.field(1, 1) // final block
	b.field(1, 2) // fixed Huffman codes
	// One literal, 'A': the fixed table spells 0..143 in eight bits from
	// 0x30 up.
	b.code(0x30+'A', 8)
	// Length code 257, which is a match of three bytes and carries no extra
	// bits: the fixed table spells 256..279 in seven bits from zero up.
	b.code(257-256, 7)
	// Distance code 2, which is a distance of three -- two bytes further
	// back than the one byte produced so far. Distances are five bit codes.
	b.code(2, 5)
	b.code(endOfBlockCode-256, 7)
	raw := b.bytes()

	dec := decodeDeflate64(bytes.NewReader(raw))
	got, err := io.ReadAll(dec)
	if cerr := dec.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		t.Fatalf("a match reaching before the start of the stream produced %q and reported nothing", got)
	}
	if !errors.Is(err, errDataError) {
		t.Errorf("the stream was refused with %v, want %v", err, errDataError)
	}

	// The standard library's decoder is the second opinion on the same
	// bytes: they are an ordinary deflate stream, and it refuses them too.
	fr := flate.NewReader(bytes.NewReader(raw))
	_, ferr := io.ReadAll(fr)
	if cerr := fr.Close(); ferr == nil {
		ferr = cerr
	}
	if ferr == nil {
		t.Error("the standard library's decoder accepted the same stream")
	}
}

// TestDeflate64_MatchBeforeTheStartOfTheOutputIsRefusedInTheFastPath is the
// same stream where the decoder takes its unrolled path: with eight bytes of
// input still in hand and room in the window, a block is decoded by a loop
// that reads symbols without checking for more input between them, and the
// bound on how far back a match may reach has to hold there too.
func TestDeflate64_MatchBeforeTheStartOfTheOutputIsRefusedInTheFastPath(t *testing.T) {
	var b deflate64BitBuf
	b.field(1, 1) // final block
	b.field(1, 2) // fixed Huffman codes
	// Thirty literals, so that the loop below has produced something and
	// the input is still long enough to stay on the unrolled path.
	for i := 0; i < 30; i++ {
		b.code(0x30+'A', 8)
	}
	b.code(257-256, 7) // a match of three bytes, no extra bits
	b.code(10, 5)      // distance code 10, whose base is 33
	b.field(0, 4)      // its four extra bits, all zero: a distance of 33
	b.code(endOfBlockCode-256, 7)
	raw := b.bytes()
	// Trailing bytes nothing reads, so that the unrolled loop still sees
	// eight bytes of input when it reaches the match.
	raw = append(raw, make([]byte, 32)...)

	dec := decodeDeflate64(bytes.NewReader(raw))
	got, err := io.ReadAll(dec)
	if cerr := dec.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		t.Fatalf("a match reaching before the start of the stream produced %q and reported nothing", got)
	}
	if !errors.Is(err, errDataError) {
		t.Errorf("the stream was refused with %v, want %v", err, errDataError)
	}
}
