package zip

import (
	"encoding/binary"
)

const (
	hashBits = 16
	hashSize = 1 << hashBits
)

// match represents a found dictionary match
type match struct {
	length   uint32
	distance uint32
}

// matchFinder implements a high-performance hash chain substring search.
// Optimized for Go: avoids allocations and array bounds-checking.
type matchFinder struct {
	head [hashSize]uint32
	prev [windowSize64]uint32

	data       []byte
	pos        uint32
	maxMatch   uint32
	windowSize uint32
	cycles     uint32 // Depth limit for search (comparable to 7-Zip: mc)
}

// newMatchFinder creates a new match finder.
// isDeflate64 = true uses a 64KB window and matches up to 65538.
func newMatchFinder(isDeflate64 bool, depthCycles uint32) *matchFinder {
	mf := &matchFinder{
		cycles: depthCycles,
	}
	if isDeflate64 {
		mf.maxMatch = maxMatchLength64
		mf.windowSize = windowSize64
	} else {
		mf.maxMatch = maxMatchLength32
		mf.windowSize = windowSize32
	}
	return mf
}

func (mf *matchFinder) reset(data []byte) {
	mf.data = data
	mf.pos = 0
	// Fast clear of head and prev arrays
	for i := range mf.head {
		mf.head[i] = 0
	}
	for i := range mf.prev {
		mf.prev[i] = 0
	}
}

// hash3 calculates a hash for 3 bytes.
// Prime multiplication provides excellent bit distribution.
func hash3(v uint32) uint32 {
	return ((v & 0xFFFFFF) * 0x1e35a7bd) >> (32 - hashBits)
}

// findMatches finds all possible match lengths at the current position.
// Results are appended to the dst slice (zero-allocation).
func (mf *matchFinder) findMatches(dst []match) []match {
	dst = dst[:0]

	if mf.pos+minMatch >= uint32(len(mf.data)) {
		mf.pos++ // Advance cursor even if EOF is reached
		return dst
	}

	// Read 4 bytes at once (compiles to a single CPU instruction)
	v := binary.LittleEndian.Uint32(mf.data[mf.pos:])
	h := hash3(v)

	// Get previous position with the same hash (1-based: 0 represents none)
	curMatch1 := mf.head[h]

	// Update chains: current position becomes head (+1 for 1-based)
	// Masking with windowMask64 eliminates bounds checking in Go
	mf.prev[mf.pos&windowMask64] = curMatch1
	mf.head[h] = mf.pos + 1

	mf.pos++ // Increment physical cursor of the MatchFinder

	if curMatch1 == 0 {
		return dst
	}
	curMatch := curMatch1 - 1

	// Since mf.pos is already incremented, calculate distance relative to mf.pos - 1
	if (mf.pos-1)-curMatch > mf.windowSize {
		return dst
	}

	bestLen := uint32(minMatch - 1)
	limit := (mf.pos - 1) + mf.maxMatch
	if limit > uint32(len(mf.data)) {
		limit = uint32(len(mf.data))
	}

	avail := limit - (mf.pos - 1)

	// Limit search depth to prevent DoS on highly redundant data
	cycles := mf.cycles

	for {
		distance := (mf.pos - 1) - curMatch
		if distance > mf.windowSize || cycles == 0 {
			break
		}
		cycles--

		// Fast check: do characters beyond the best length match?
		// This avoids expensive comparison loops for suboptimal matches.
		if mf.data[(mf.pos-1)+bestLen] == mf.data[curMatch+bestLen] && mf.data[mf.pos-1] == mf.data[curMatch] {

			// Calculate the exact match length
			l := uint32(0)
			for l < avail && mf.data[(mf.pos-1)+l] == mf.data[curMatch+l] {
				l++
			}

			if l > bestLen {
				bestLen = l
				dst = append(dst, match{length: l, distance: distance})
				// If match reaches available data limit OR niceMatch threshold,
				// stop hash chain search (greedy matching heuristic)
				if l == avail || l >= niceMatch {
					break
				}
			}
		}

		// Traverse to the next element in the hash chain (1-based)
		nextMatch1 := mf.prev[curMatch&windowMask64]
		if nextMatch1 == 0 || nextMatch1-1 >= curMatch {
			break // Guard against loops or empty chain
		}
		curMatch = nextMatch1 - 1
	}

	return dst
}

// skip advances the position by n bytes, updating hash chains
// without searching for matches (used when consuming tokens in the LZ77 loop).
func (mf *matchFinder) skip(n uint32) {
	limit := uint32(len(mf.data)) - minMatch
	for i := uint32(0); i < n; i++ {
		if mf.pos < limit {
			v := binary.LittleEndian.Uint32(mf.data[mf.pos:])
			h := hash3(v)
			mf.prev[mf.pos&windowMask64] = mf.head[h]
			mf.head[h] = mf.pos + 1
		}
		mf.pos++
	}
}