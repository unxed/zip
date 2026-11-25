package zip

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
)

// A fixed block, then a dynamic block, then a fixed block. Both fixed blocks
// must decode with the RFC 1951 fixed tables; the dynamic block's tables must
// not replace them for later blocks in this or any other stream.
var staticBlockAfterDynamicBlock = mustDecodeHex(
	"727402108407a0000000008000000000" +
		"00000000000000000000000000000000" +
		"000000000000000000000000c88b888a" +
		"fdcfdd0300")

func mustDecodeHex(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func TestFixedTableSurvivesRepeatedDecodes(t *testing.T) {
	for attempt := 0; attempt < 2; attempt++ {
		got, err := io.ReadAll(newDeflate64Reader(bytes.NewReader(staticBlockAfterDynamicBlock)))
		if err != nil {
			t.Fatalf("decode %d failed after %q: %v", attempt+1, got, err)
		}
		if want := "ABDEFGH"; string(got) != want {
			t.Fatalf("decode %d produced %q, want %q", attempt+1, got, want)
		}
	}
}
