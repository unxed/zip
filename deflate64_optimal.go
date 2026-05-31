package zip

import (
	"math/bits"
)

const (
	optimalBufSize = 4096
	optimalMask    = optimalBufSize - 1
	infinityPrice  = 0xFFFFFFF
)

// optimalNode stores the best decision for transitioning to this position in the graph
type optimalNode struct {
	price    uint32 // Accumulated minimum bit price
	posPrev  uint16 // Index of the previous node in the circular decision buffer
	backPrev uint32 // LZ77 distance used to reach this position (0 if literal)
}

// optimalParser calculates optimal LZ77 transitions using dynamic programming.
type optimalParser struct {
	mf      *matchFinder
	nodes   [optimalBufSize]optimalNode
	matches []match // Buffer for MatchFinder results

	optStart uint32
	optEnd   uint32

	// Price tables (bits * 8 for fractional bit accuracy), calculated from Huffman frequencies
	literalPrices [256]uint32
	lenPrices     [256]uint32
	posPrices     [32]uint32
}

func newOptimalParser(mf *matchFinder) *optimalParser {
	op := &optimalParser{
		mf:      mf,
		matches: make([]match, 0, 128),
	}
	op.resetPrices()
	return op
}

// resetPrices initializes default prices (static estimation) when real Huffman trees are not built yet.
func (op *optimalParser) resetPrices() {
	// A literal costs 8 bits by default (8 * 8 = 64 score points)
	for i := range op.literalPrices {
		op.literalPrices[i] = 64
	}
	// Lengths default to an estimated average of 10 bits
	for i := range op.lenPrices {
		op.lenPrices[i] = 80
	}
	// Positions are estimated using log2(dist)
	for i := range op.posPrices {
		op.posPrices[i] = uint32(12 + i) * 4
	}
}

// getDistSlot finds the slot index for a distance (0-31)
func getDistSlot(dist uint32) uint32 {
	if dist <= 4 {
		return dist - 1
	}
	// Use high-speed CPU leading zeros instruction for log2 without loops
	msb := uint32(31 - bits.LeadingZeros32(dist-1))
	return (msb << 1) + uint32((dist-1)>>(msb-1)&1)
}

// getLenSlot finds the slot index for a length (0-28)
func getLenSlot(length uint32) uint32 {
	if length < 3 {
		return 0
	}
	// For Deflate64, lengths from 258 to 65538 are encoded in the last slot (28)
	if length >= 258 {
		return 28
	}
	// Binary search for short match lengths (faster than linear scan)
	low, high := uint32(0), uint32(28)
	for low < high {
		mid := (low + high) / 2
		if lengthBase64[mid] <= length {
			low = mid + 1
		} else {
			high = mid
		}
	}
	return low - 1
}

// calcMatchPrice returns the bit price (bits * 8) of a match for a given length and distance
func (op *optimalParser) calcMatchPrice(length, distance uint32) uint32 {
	lenSlot := getLenSlot(length)
	distSlot := getDistSlot(distance)

	price := op.lenPrices[lenSlot] + op.posPrices[distSlot]
	price += uint32(lengthExtraBits64[lenSlot]) * 8
	price += uint32(distanceExtraBits[distSlot]) * 8
	return price
}

// getOptimal performs lookahead and calculates the sequence of optimal decisions.
// Returns the best length and distance for the current position.
func (op *optimalParser) getOptimal() (uint32, uint32) {
	if op.optStart != op.optEnd {
		// Optimal path already built, return the next step from the queue
		node := &op.nodes[op.optStart&optimalMask]
		lenRes := uint32(node.posPrev) - op.optStart
		distRes := node.backPrev
		op.optStart = uint32(node.posPrev)
		return lenRes, distRes
	}

	op.optStart = 0
	op.optEnd = 0

	// Reset decisions buffer
	op.nodes[0].price = 0

	// Find matches for the current position
	op.matches = op.mf.findMatches(op.matches)

	if len(op.matches) == 0 {
		return 1, 0 // Literal only
	}

	bestMatch := op.matches[len(op.matches)-1]
	if bestMatch.length >= niceMatch {
		// Greedy optimization: if a match >= niceMatch is found, bypass the DP graph.
		// Consume the entire match (up to 65538 bytes) to guarantee O(N^2) protection on redundant data.
		op.mf.skip(bestMatch.length - 1)
		return bestMatch.length, bestMatch.distance
	}

	// Initialize transition prices from the start position in the graph
	for i := uint32(1); i <= bestMatch.length; i++ {
		op.nodes[i&optimalMask].price = infinityPrice
	}

	// 1. Estimate literal transition (mf.pos cursor was already advanced by 1 by the match finder)
	lit := op.mf.data[op.mf.pos-1]
	op.nodes[1].price = op.literalPrices[lit]
	op.nodes[1].posPrev = 0
	op.nodes[1].backPrev = 0

	// 2. Estimate transitions for all found matches
	matchIdx := 0
	for lenTest := uint32(minMatch); lenTest <= bestMatch.length; lenTest++ {
		dist := op.matches[matchIdx].distance
		price := op.calcMatchPrice(lenTest, dist)

		node := &op.nodes[lenTest&optimalMask]
		if price < node.price {
			node.price = price
			node.posPrev = 0
			node.backPrev = dist
		}
		if lenTest == op.matches[matchIdx].length {
			matchIdx++
		}
	}

	cur := uint32(0)
	for {
		cur++
		if cur == bestMatch.length || cur >= optimalBufSize-maxMatchLength32 {
			return op.backward(cur)
		}

		op.matches = op.mf.findMatches(op.matches)
		newLen := uint32(0)
		if len(op.matches) > 0 {
			newLen = op.matches[len(op.matches)-1].length
			if newLen >= niceMatch {
				lenRes, distRes := op.backward(cur)
				op.nodes[cur&optimalMask].backPrev = op.matches[len(op.matches)-1].distance
				op.optEnd = cur + newLen
				op.nodes[cur&optimalMask].posPrev = uint16(op.optEnd)
				op.mf.skip(newLen - 1)
				return lenRes, distRes
			}
		}

		curPrice := op.nodes[cur&optimalMask].price

		// Estimate literal transition (mf.pos is already advanced by cur+1)
		nextLit := op.mf.data[op.mf.pos-1]
		nextLitPrice := curPrice + op.literalPrices[nextLit]
		nextNode := &op.nodes[(cur+1)&optimalMask]
		if nextLitPrice < nextNode.price {
			nextNode.price = nextLitPrice
			nextNode.posPrev = uint16(cur)
			nextNode.backPrev = 0
		}

		if newLen == 0 {
			continue
		}

		// Initialize future nodes with infinity price
		for i := lenTestLimit(cur, bestMatch.length); i <= cur+newLen; i++ {
			op.nodes[i&optimalMask].price = infinityPrice
		}
		if cur+newLen > bestMatch.length {
			bestMatch.length = cur + newLen
		}

		// Estimate matches from the current position
		matchIdx = 0
		for lenTest := uint32(minMatch); lenTest <= newLen; lenTest++ {
			dist := op.matches[matchIdx].distance
			price := curPrice + op.calcMatchPrice(lenTest, dist)

			targetNode := &op.nodes[(cur+lenTest)&optimalMask]
			if price < targetNode.price {
				targetNode.price = price
				targetNode.posPrev = uint16(cur)
				targetNode.backPrev = dist
			}
			if lenTest == op.matches[matchIdx].length {
				matchIdx++
			}
		}
	}
}

func lenTestLimit(cur, bestLen uint32) uint32 {
	if bestLen > cur {
		return bestLen + 1
	}
	return cur + 1
}

// backward reconstructs the decision path from end to beginning, reversing it
func (op *optimalParser) backward(cur uint32) (uint32, uint32) {
	op.optEnd = cur
	posMem := uint32(op.nodes[cur&optimalMask].posPrev)
	backMem := op.nodes[cur&optimalMask].backPrev

	for {
		posPrev := posMem
		backCur := backMem

		backMem = op.nodes[posPrev&optimalMask].backPrev
		posMem = uint32(op.nodes[posPrev&optimalMask].posPrev)

		op.nodes[posPrev&optimalMask].backPrev = backCur
		op.nodes[posPrev&optimalMask].posPrev = uint16(cur)

		cur = posPrev
		if cur == 0 {
			break
		}
	}

	op.optStart = uint32(op.nodes[0].posPrev)
	return op.optStart, op.nodes[0].backPrev
}