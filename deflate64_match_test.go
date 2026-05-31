package zip

import (
	"bytes"
	"testing"
)

func TestMatchFinder_Basic(t *testing.T) {
	data := []byte("abcde_abcde_abcde")
	// Indices:       0123456789...
	// Second abcde starts at 6. Distance = 6. Length = 5.

	mf := newMatchFinder(true, 32)
	mf.reset(data)

	matchesBuf := make([]match, 0, 16)

	// Skip first 6 characters, updating hash chains.
	// findMatches() now automatically increments mf.pos on each step!
	for i := 0; i < 6; i++ {
		matchesBuf = mf.findMatches(matchesBuf)
	}

	// Now we are at position 6 (start of second "abcde")
	matchesBuf = mf.findMatches(matchesBuf)

	if len(matchesBuf) == 0 {
		t.Fatal("Expected to find a match, got 0 matches")
	}

	bestMatch := matchesBuf[len(matchesBuf)-1]
	if bestMatch.distance != 6 {
		t.Errorf("Expected distance 6, got %d", bestMatch.distance)
	}
	if bestMatch.length < 5 {
		t.Errorf("Expected length at least 5, got %d", bestMatch.length)
	}
}

func TestMatchFinder_LongMatchDeflate64(t *testing.T) {
	// Create a repeating pattern larger than 64KB
	pattern := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ") // 26 bytes
	var buf bytes.Buffer
	for buf.Len() < 100000 { // ~100 KB
		buf.Write(pattern)
	}
	data := buf.Bytes()

	mf := newMatchFinder(true, 256) // isDeflate64 = true
	mf.reset(data)

	matchesBuf := make([]match, 0, 32)

	// Fill history with the first pattern
	mf.skip(26)

	// Find matches. Since the pattern repeats to the end, length should hit maxMatchLength64 (65538)
	// or the remaining buffer limit.
	matchesBuf = mf.findMatches(matchesBuf)

	if len(matchesBuf) == 0 {
		t.Fatal("Expected matches")
	}

	bestMatch := matchesBuf[len(matchesBuf)-1]

	// Expect distance to equal the pattern length
	if bestMatch.distance != 26 {
		t.Errorf("Expected distance 26, got %d", bestMatch.distance)
	}

	// Expect match length to hit the Deflate64 limit (65538)
	if bestMatch.length != maxMatchLength64 {
		t.Errorf("Expected length to hit Deflate64 max limit 65538, got %d", bestMatch.length)
	}
}

func TestMatchFinder_Deflate32Limit(t *testing.T) {
	// Same, but for standard Deflate to verify limits
	pattern := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	var buf bytes.Buffer
	for buf.Len() < 10000 {
		buf.Write(pattern)
	}
	data := buf.Bytes()

	mf := newMatchFinder(false, 32) // isDeflate64 = false
	mf.reset(data)
	mf.skip(26)

	matchesBuf := make([]match, 0, 32)
	matchesBuf = mf.findMatches(matchesBuf)

	bestMatch := matchesBuf[len(matchesBuf)-1]

	// Expect length to hit standard Deflate limit (258)
	if bestMatch.length != maxMatchLength32 {
		t.Errorf("Expected length to hit Deflate max limit 258, got %d", bestMatch.length)
	}
}

func TestOptimalParser_Basic(t *testing.T) {
	// Non-trivial parsing choice:
	// Text: "ababcabcd"
	// A greedy algorithm would choose "ab" at pos 2, losing "abcd" later.
	// The optimal parser must construct a more efficient chain.
	data := []byte("ababcabcd")

	mf := newMatchFinder(true, 32)
	mf.reset(data)

	parser := newOptimalParser(mf)

	// Step 1: 'a' (literal)
	// getOptimal() automatically manages the mf.pos cursor
	length, distance := parser.getOptimal()
	if length != 1 || distance != 0 {
		t.Errorf("Expected literal, got len=%d, dist=%d", length, distance)
	}

	// Step 2: 'b' (literal)
	length, distance = parser.getOptimal()
	if length != 1 || distance != 0 {
		t.Errorf("Expected literal, got len=%d, dist=%d", length, distance)
	}

	// Next, the parser should efficiently match "abc" and "abcd"
	length, distance = parser.getOptimal()
	if length == 0 {
		t.Fatal("Parser stalled")
	}
}

func TestGetDistSlot(t *testing.T) {
	cases := []struct {
		dist uint32
		want uint32
	}{
		{1, 0},
		{4, 3},
		{5, 4},
		{6, 4},
		{7, 5},
		{8, 5},
		{9, 6},
		{32768, 29},
		{65536, 31},
	}
	for _, tc := range cases {
		if got := getDistSlot(tc.dist); got != tc.want {
			t.Errorf("getDistSlot(%d) = %d, want %d", tc.dist, got, tc.want)
		}
	}
}

func TestGetLenSlot(t *testing.T) {
	cases := []struct {
		length uint32
		want   uint32
	}{
		{3, 0},
		{11, 8},
		{12, 8},
		{13, 9},
		{257, 27},
		{258, 28},
		{10000, 28},
	}
	for _, tc := range cases {
		if got := getLenSlot(tc.length); got != tc.want {
			t.Errorf("getLenSlot(%d) = %d, want %d", tc.length, got, tc.want)
		}
	}
}