package zip

// Constants for Deflate and Deflate64
const (
	minMatch         = 3
	niceMatch        = 258   // Greedy matching threshold (similar to 7-Zip)
	maxMatchLength32 = 258   // Maximum match length for standard Deflate
	maxMatchLength64 = 65538 // Maximum match length for Deflate64

	windowSize32 = 32768 // Deflate window size (32 KB)
	windowSize64 = 65536 // Deflate64 window size (64 KB)
	windowMask64 = windowSize64 - 1

	// Map encoder constants with the decoder structures from deflate64.go
	kFixedMainTableSize = maxLiteralTreeElements // 288
	kDistTableSize64    = maxDistTreeElements    // 32
	kSymbolMatch        = 257

	// Minimum limit sizes according to PKWARE APPNOTE.TXT specification
	kNumLitLenCodesMin = 257
	kNumDistCodesMin   = 1
	kNumLevelCodesMin  = 4

	// Bit sizes for Deflate block headers
	kFinalBlockFieldSize    = 1
	kBlockTypeFieldSize     = 2
	kNumLenCodesFieldSize   = 5
	kNumDistCodesFieldSize  = 5
	kNumLevelCodesFieldSize = 4
	kLevelFieldSize         = 3
)

// lengthBase32 - base length values for standard Deflate (codes 257-285)
var lengthBase32 = []uint32{
	3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
	35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
}

// lengthExtraBits32 - number of extra bits for length codes (Deflate)
var lengthExtraBits32 = []uint8{
	0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
	3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
}

// In Deflate64, length codes 257-284 are identical.
// But code 285 has 16 extra bits and encodes lengths from 3 to 65538.
var lengthBase64 = append(lengthBase32[:28], 3)
var lengthExtraBits64 = append(lengthExtraBits32[:28], 16)

// distanceBase - base distance values (codes 0-31)
// Deflate uses 0-29. Deflate64 uses 0-31.
var distanceBase = []uint32{
	1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
	257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
	32769, 49153,
}

// distanceExtraBits - number of extra bits for distances
var distanceExtraBits = []uint8{
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
	7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
	14, 14,
}