package zip

import (
	"bufio"
	"io"
)

const (
	blockSizeLimit = 65532 // Keep safety margin under 64KB limit
)

// bitWriter implements high-performance LSB-first bit writing
type bitWriter struct {
	w     *bufio.Writer
	accum uint64
	nbits uint32
}

func newBitWriter(w io.Writer) *bitWriter {
	return &bitWriter{
		w: bufio.NewWriterSize(w, 1024*1024),
	}
}

func (bw *bitWriter) writeBits(value uint32, bits uint32) {
	bw.accum |= uint64(value) << bw.nbits
	bw.nbits += bits
	for bw.nbits >= 8 {
		bw.w.WriteByte(byte(bw.accum))
		bw.accum >>= 8
		bw.nbits -= 8
	}
}

func (bw *bitWriter) flushBits() error {
	if bw.nbits > 0 {
		bw.w.WriteByte(byte(bw.accum))
		bw.accum = 0
		bw.nbits = 0
	}
	return bw.w.Flush()
}

// deflate64Writer encodes an incoming data stream into Deflate64 format.
type deflate64Writer struct {
	w       *bitWriter
	mf      *matchFinder
	parser  *optimalParser
	dataBuf []byte // Accumulator buffer for the block (up to 64KB)
}

func newDeflate64Writer(w io.Writer) io.WriteCloser {
	mf := newMatchFinder(true, 64) // 64KB window, hash chain search depth of 64
	return &deflate64Writer{
		w:      newBitWriter(w),
		mf:     mf,
		parser: newOptimalParser(mf),
	}
}

func (dw *deflate64Writer) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		room := blockSizeLimit - len(dw.dataBuf)
		if room == 0 {
			if err := dw.flushBlock(false); err != nil {
				return total, err
			}
			room = blockSizeLimit
		}

		chunk := len(p)
		if chunk > room {
			chunk = room
		}

		dw.dataBuf = append(dw.dataBuf, p[:chunk]...)
		p = p[chunk:]
		total += chunk
	}
	return total, nil
}

func (dw *deflate64Writer) Close() error {
	// Flush the final block with bfinal = true
	if err := dw.flushBlock(true); err != nil {
		return err
	}
	return dw.w.flushBits()
}

type token struct {
	length   uint32
	distance uint32
}

// ensureAtLeastTwoFreqs ensures the frequency table has at least 2 active symbols.
// This is required to build a mathematically complete Huffman tree (RFC 1951 requirement).
func ensureAtLeastTwoFreqs(freqs []uint32) {
	count := 0
	for _, f := range freqs {
		if f > 0 {
			count++
		}
	}
	if count >= 2 {
		return
	}
	// If active codes count < 2, artificially insert dummies with frequency 1
	for i := range freqs {
		if freqs[i] == 0 {
			freqs[i] = 1
			count++
			if count >= 2 {
				break
			}
		}
	}
}

func (dw *deflate64Writer) flushBlock(bfinal bool) error {
	if len(dw.dataBuf) == 0 && !bfinal {
		return nil
	}

	dw.mf.reset(dw.dataBuf)
	dw.parser.resetPrices()

	// Collect LZ77 tokens and frequency statistics
	var tokens []token
	var litFreqs [kFixedMainTableSize]uint32
	var distFreqs [kDistTableSize64]uint32

	// Logical cursor for token assembly.
	// Physical cursor dw.mf.pos is managed solely by the parser.
	logicalPos := uint32(0)
	for logicalPos < uint32(len(dw.dataBuf)) {
		length, distance := dw.parser.getOptimal()
		if distance == 0 {
			lit := dw.dataBuf[logicalPos]
			// Store the original literal byte in the length field
			tokens = append(tokens, token{length: uint32(lit), distance: 0})
			litFreqs[lit]++
			logicalPos++
		} else {
			tokens = append(tokens, token{length: length, distance: distance})
			lenSlot := getLenSlot(length)
			distSlot := getDistSlot(distance)
			litFreqs[kSymbolMatch+lenSlot]++
			distFreqs[distSlot]++
			logicalPos += length
		}
	}
	litFreqs[endOfBlockCode]++ // End of block code is always present

	// Normalize frequencies before building trees
	ensureAtLeastTwoFreqs(litFreqs[:])
	ensureAtLeastTwoFreqs(distFreqs[:])

	// 1. Build Huffman trees
	var litLengths [kFixedMainTableSize]byte
	var distLengths [kDistTableSize64]byte
	buildHuffmanTree(litFreqs[:], 15, litLengths[:])
	buildHuffmanTree(distFreqs[:], 15, distLengths[:])

	// Find the count of active codes to write in the header
	numLitCodes := uint32(kFixedMainTableSize)
	for numLitCodes > kNumLitLenCodesMin && litLengths[numLitCodes-1] == 0 {
		numLitCodes--
	}
	numDistCodes := uint32(kDistTableSize64)
	for numDistCodes > kNumDistCodesMin && distLengths[numDistCodes-1] == 0 {
		numDistCodes--
	}

	// 2. Encode alphabets using RLE (codes 16, 17, 18)
	var clCodes []byte
	var clFreqs [numberOfCodeLengthTreeElements]uint32

	// Collect code lengths sequence
	allLengths := append(litLengths[:numLitCodes], distLengths[:numDistCodes]...)
	for i := 0; i < len(allLengths); {
		val := allLengths[i]
		run := 1
		for i+run < len(allLengths) && allLengths[i+run] == val {
			run++
		}

		if val == 0 {
			if run >= 11 {
				if run > 138 {
					run = 138
				}
				clCodes = append(clCodes, 18, byte(run-11))
				clFreqs[18]++
			} else if run >= 3 {
				clCodes = append(clCodes, 17, byte(run-3))
				clFreqs[17]++
			} else {
				for r := 0; r < run; r++ {
					clCodes = append(clCodes, 0)
					clFreqs[0]++
				}
			}
		} else {
			clCodes = append(clCodes, val)
			clFreqs[val]++

			// Code 16 repeats the PREVIOUS symbol. Number of repeats = run - 1
			dupCount := run - 1
			if dupCount >= 3 {
				if dupCount > 6 {
					dupCount = 6
				}
				clCodes = append(clCodes, 16, byte(dupCount-3))
				clFreqs[16]++
				run = 1 + dupCount
			} else {
				run = 1
			}
		}
		i += run
	}

	// Build the code length tree (max depth 7)
	var clTreeLengths [numberOfCodeLengthTreeElements]byte
	buildHuffmanTree(clFreqs[:], 7, clTreeLengths[:])

	numCLCodes := uint32(numberOfCodeLengthTreeElements)
	for numCLCodes > kNumLevelCodesMin && clTreeLengths[codeOrder[numCLCodes-1]] == 0 {
		numCLCodes--
	}

	// 3. Write block header
	var finalBit uint32 = 0
	if bfinal {
		finalBit = 1
	}
	dw.w.writeBits(finalBit, kFinalBlockFieldSize)
	dw.w.writeBits(uint32(blockTypeDynamic), kBlockTypeFieldSize)

	// Dynamic tables header
	dw.w.writeBits(numLitCodes-kNumLitLenCodesMin, kNumLenCodesFieldSize)
	dw.w.writeBits(numDistCodes-kNumDistCodesMin, kNumDistCodesFieldSize)
	dw.w.writeBits(numCLCodes-kNumLevelCodesMin, kNumLevelCodesFieldSize)

	// Write the code length tree (3 bits per symbol)
	for i := uint32(0); i < numCLCodes; i++ {
		dw.w.writeBits(uint32(clTreeLengths[codeOrder[i]]), kLevelFieldSize)
	}

	// Generate Huffman codes
	var clCodesMap [numberOfCodeLengthTreeElements]uint32
	generateCodes(clTreeLengths[:], clCodesMap[:])

	var litCodesMap [kFixedMainTableSize]uint32
	generateCodes(litLengths[:], litCodesMap[:])

	var distCodesMap [kDistTableSize64]uint32
	generateCodes(distLengths[:], distCodesMap[:])

	// Write RLE-compressed Huffman tables
	for i := 0; i < len(clCodes); {
		c := clCodes[i]
		dw.w.writeBits(clCodesMap[c], uint32(clTreeLengths[c]))
		i++
		if c >= 16 {
			extra := clCodes[i]
			extraBits := uint32(2)
			if c == 17 {
				extraBits = 3
			} else if c == 18 {
				extraBits = 7
			}
			dw.w.writeBits(uint32(extra), extraBits)
			i++
		}
	}

	// 4. Write compressed data (Tokens)
	for _, tok := range tokens {
		if tok.distance == 0 {
			lit := tok.length // Extract the original stored literal byte
			dw.w.writeBits(litCodesMap[lit], uint32(litLengths[lit]))
		} else {
			lenSlot := getLenSlot(tok.length)
			dw.w.writeBits(litCodesMap[kSymbolMatch+lenSlot], uint32(litLengths[kSymbolMatch+lenSlot]))
			if lengthExtraBits64[lenSlot] > 0 {
				extraLen := tok.length - lengthBase64[lenSlot]
				dw.w.writeBits(extraLen, uint32(lengthExtraBits64[lenSlot]))
			}

			distSlot := getDistSlot(tok.distance)
			dw.w.writeBits(distCodesMap[distSlot], uint32(distLengths[distSlot]))
			if distanceExtraBits[distSlot] > 0 {
				extraDist := tok.distance - distanceBase[distSlot]
				dw.w.writeBits(extraDist, uint32(distanceExtraBits[distSlot]))
			}
		}
	}

	// Write end of block marker
	dw.w.writeBits(litCodesMap[endOfBlockCode], uint32(litLengths[endOfBlockCode]))

	dw.dataBuf = dw.dataBuf[:0] // Reset buffer
	return nil
}
