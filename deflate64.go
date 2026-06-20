package zip

import (
	"errors"
	"io"
)

var (
	errDataNeeded = errors.New("zip: data needed")
	errDataError  = errors.New("zip: invalid deflate64 data")
)

// deflate64Reader implements a native Go decompressor for Deflate64 (Method 9).
type deflate64Reader struct {
	r        io.Reader
	im       *inflaterManaged
	bits     bitsBuffer
	inBuf    []byte
	inOffset int
	inLimit  int
	eof      bool
	err      error
}

func newDeflate64Reader(r io.Reader) io.ReadCloser {
	return &deflate64Reader{
		r:     r,
		im:    newInflaterManaged(),
		inBuf: make([]byte, 1024*1024), // 1MB read buffer for faster Deflate64 decoding
	}
}

func (dr *deflate64Reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if dr.err != nil {
		return 0, dr.err
	}

	bytesWritten := 0

	for bytesWritten < len(p) {
		if dr.im.output.availableBytes() > 0 {
			copied := dr.im.output.copyTo(p[bytesWritten:])
			bytesWritten += copied
			if bytesWritten == len(p) {
				return bytesWritten, nil
			}
		}

		if dr.im.state == stateDone && dr.im.output.availableBytes() == 0 {
			dr.err = io.EOF
			return bytesWritten, io.EOF
		}
		if dr.im.state == stateDataErrored {
			dr.err = errDataError
			return bytesWritten, errDataError
		}

		if dr.inOffset >= dr.inLimit {
			dr.inOffset = 0
			n, err := dr.r.Read(dr.inBuf)
			if n > 0 {
				dr.inLimit = n
				dr.eof = false
			} else {
				dr.inLimit = 0
			}
			if err != nil {
				if err == io.EOF {
					dr.eof = true
				} else {
					dr.err = err
					return bytesWritten, err
				}
			}
		}

		inputBytes := dr.inBuf[dr.inOffset:dr.inLimit]
		ib := newInputBuffer(dr.bits, inputBytes)

		err := dr.im.decode(ib)

		dr.bits = ib.bits
		dr.inOffset += ib.readBytes

		if err != nil {
			if err == errDataNeeded {
				if dr.eof && dr.inOffset >= dr.inLimit {
					dr.err = io.ErrUnexpectedEOF
					return bytesWritten, io.ErrUnexpectedEOF
				}
				continue
			}
			if err == errDataError {
				dr.im.state = stateDataErrored
				dr.err = errDataError
				return bytesWritten, errDataError
			}
			dr.err = err
			return bytesWritten, err
		}
	}

	return bytesWritten, nil
}

func (dr *deflate64Reader) Close() error {
	return nil
}

func decodeDeflate64(r io.Reader) io.ReadCloser {
	return newDeflate64Reader(r)
}

var (
	staticLiteralTree  = initStaticLiteralTree()
	staticDistanceTree = initStaticDistanceTree()
)

func initStaticLiteralTree() *huffmanTree {
	t := &huffmanTree{}
	lens := getStaticLiteralTreeLength()
	t.newInPlace(lens[:])
	return t
}

func initStaticDistanceTree() *huffmanTree {
	t := &huffmanTree{}
	lens := getStaticDistanceTreeLength()
	t.newInPlace(lens[:])
	return t
}

// --- Inline types and algorithms from deflate64-rs ---

// bitsBuffer represents the bit accumulator state.
type bitsBuffer struct {
	bitBuffer    uint32
	bitsInBuffer int32
}

// inputBuffer implements bit-level reading.
type inputBuffer struct {
	bits      bitsBuffer
	buffer    []byte
	readBytes int
}

func newInputBuffer(bits bitsBuffer, buffer []byte) *inputBuffer {
	return &inputBuffer{
		bits:   bits,
		buffer: buffer,
	}
}

func (in *inputBuffer) availableBits() int32 {
	return in.bits.bitsInBuffer
}

func (in *inputBuffer) availableBytes() int {
	return len(in.buffer) + int(in.bits.bitsInBuffer/8)
}

func (in *inputBuffer) ensureBitsAvailable(count int32) bool {
	if in.bits.bitsInBuffer < count {
		if len(in.buffer) == 0 {
			return false
		}
		in.bits.bitBuffer |= uint32(in.buffer[0]) << in.bits.bitsInBuffer
		in.buffer = in.buffer[1:]
		in.readBytes++
		in.bits.bitsInBuffer += 8

		if in.bits.bitsInBuffer < count {
			if len(in.buffer) == 0 {
				return false
			}
			in.bits.bitBuffer |= uint32(in.buffer[0]) << in.bits.bitsInBuffer
			in.buffer = in.buffer[1:]
			in.readBytes++
			in.bits.bitsInBuffer += 8
		}
	}
	return true
}

func (in *inputBuffer) tryLoad16Bits() uint32 {
	if in.bits.bitsInBuffer < 8 {
		if len(in.buffer) > 1 {
			in.bits.bitBuffer |= uint32(in.buffer[0]) << in.bits.bitsInBuffer
			in.bits.bitBuffer |= uint32(in.buffer[1]) << (in.bits.bitsInBuffer + 8)
			in.buffer = in.buffer[2:]
			in.readBytes += 2
			in.bits.bitsInBuffer += 16
		} else if len(in.buffer) > 0 {
			in.bits.bitBuffer |= uint32(in.buffer[0]) << in.bits.bitsInBuffer
			in.buffer = in.buffer[1:]
			in.readBytes++
			in.bits.bitsInBuffer += 8
		}
	} else if in.bits.bitsInBuffer < 16 && len(in.buffer) > 0 {
		in.bits.bitBuffer |= uint32(in.buffer[0]) << in.bits.bitsInBuffer
		in.buffer = in.buffer[1:]
		in.readBytes++
		in.bits.bitsInBuffer += 8
	}
	return in.bits.bitBuffer
}

func (in *inputBuffer) getBitMask(count int32) uint32 {
	return (1 << count) - 1
}

func (in *inputBuffer) getBits(count int32) (uint16, error) {
	if !in.ensureBitsAvailable(count) {
		return 0, errDataNeeded
	}
	result := uint16(in.bits.bitBuffer & in.getBitMask(count))
	in.bits.bitBuffer >>= count
	in.bits.bitsInBuffer -= count
	return result, nil
}

func (in *inputBuffer) load16BitsAssumeInput() uint32 {
	if in.bits.bitsInBuffer < 16 {
		if len(in.buffer) >= 2 {
			word := uint32(in.buffer[0]) | (uint32(in.buffer[1]) << 8)
			in.bits.bitBuffer |= word << in.bits.bitsInBuffer
			in.buffer = in.buffer[2:]
			in.readBytes += 2
		}
		in.bits.bitsInBuffer += 16
	}
	return in.bits.bitBuffer
}

func (in *inputBuffer) getBitsAssumeInput(count int32) uint32 {
	result := in.load16BitsAssumeInput() & in.getBitMask(count)
	in.bits.bitBuffer >>= count
	in.bits.bitsInBuffer -= count
	return result
}

func (in *inputBuffer) copyTo(output []byte) int {
	bytesFromBitBuffer := 0
	for in.bits.bitsInBuffer > 0 && len(output) > 0 {
		output[0] = byte(in.bits.bitBuffer)
		output = output[1:]
		in.bits.bitBuffer >>= 8
		in.bits.bitsInBuffer -= 8
		bytesFromBitBuffer++
	}
	if len(output) == 0 {
		return bytesFromBitBuffer
	}
	length := len(output)
	if len(in.buffer) < length {
		length = len(in.buffer)
	}
	copy(output[:length], in.buffer[:length])
	in.buffer = in.buffer[length:]
	in.readBytes += length
	return bytesFromBitBuffer + length
}

func (in *inputBuffer) skipBits(n int32) {
	in.bits.bitBuffer >>= n
	in.bits.bitsInBuffer -= n
}

func (in *inputBuffer) skipToByteBoundary() {
	in.bits.bitBuffer >>= in.bits.bitsInBuffer % 8
	in.bits.bitsInBuffer -= in.bits.bitsInBuffer % 8
}

// outputWindow maintains the circular output history window.
const (
	windowSize = 131072
	windowMask = 131071
)

type outputWindow struct {
	window    [windowSize]byte
	end       int
	bytesUsed int
}

func newOutputWindow() *outputWindow {
	return &outputWindow{}
}

func (ow *outputWindow) writeByte(b byte) {
	ow.window[ow.end] = b
	ow.end = (ow.end + 1) & windowMask
	ow.bytesUsed++
}

func (ow *outputWindow) writeLengthDistance(length, distance int) {
	ow.bytesUsed += length
	from := (ow.end - distance) & windowMask
	to := ow.end

	for i := 0; i < length; i++ {
		ow.window[to] = ow.window[from]
		to = (to + 1) & windowMask
		from = (from + 1) & windowMask
	}
	ow.end = to
}

func (ow *outputWindow) copyFrom(input *inputBuffer, length int) int {
	avail := length
	if windowSize-ow.bytesUsed < avail {
		avail = windowSize - ow.bytesUsed
	}
	if input.availableBytes() < avail {
		avail = input.availableBytes()
	}
	copied := 0

	tailLen := windowSize - ow.end
	if avail > tailLen {
		copied = input.copyTo(ow.window[ow.end : ow.end+tailLen])
		if copied == tailLen {
			copied += input.copyTo(ow.window[:avail-tailLen])
		}
	} else {
		copied = input.copyTo(ow.window[ow.end : ow.end+avail])
	}

	ow.end = (ow.end + copied) & windowMask
	ow.bytesUsed += copied
	return copied
}

func (ow *outputWindow) freeBytes() int {
	return windowSize - ow.bytesUsed
}

func (ow *outputWindow) availableBytes() int {
	return ow.bytesUsed
}

func (ow *outputWindow) copyTo(output []byte) int {
	var copyEnd int
	var outLen int
	if len(output) > ow.bytesUsed {
		copyEnd = ow.end
		outLen = ow.bytesUsed
	} else {
		copyEnd = (ow.end - ow.bytesUsed + len(output)) & windowMask
		outLen = len(output)
	}

	copied := outLen

	if outLen > copyEnd {
		tailLen := outLen - copyEnd
		copy(output[:tailLen], ow.window[windowSize-tailLen:windowSize])
		copy(output[tailLen:tailLen+copyEnd], ow.window[:copyEnd])
	} else {
		copy(output[:outLen], ow.window[copyEnd-outLen:copyEnd])
	}

	ow.bytesUsed -= copied
	return copied
}

// Huffman Tree Constants and structures
const (
	symbolBits                     = 9
	symbolMask                     = (1 << symbolBits) - 1 // 0x1FF
	maxCodeLengths                 = 288
	tableBits                      = 9
	tableBitsMask                  = (1 << tableBits) - 1
	maxLiteralTreeElements         = 288
	maxDistTreeElements            = 32
	endOfBlockCode                 = 256
	numberOfCodeLengthTreeElements = 19
)

func pack(symbol int16, codeLen byte) int16 {
	return symbol | (int16(codeLen) << symbolBits)
}

func unpack(entry int16) (uint16, int32) {
	return uint16(entry & symbolMask), int32(entry >> symbolBits)
}

type huffmanTree struct {
	codeLengthsLength uint16
	table             [1 << tableBits]int16
	nodes             [maxCodeLengths * 4]int16
	codeLengthArray   [maxCodeLengths]byte
}

func newHuffmanTreeInvalid() *huffmanTree {
	return &huffmanTree{}
}

func newHuffmanTreeStaticLiteral() *huffmanTree {
	return staticLiteralTree
}

func newHuffmanTreeStaticDistance() *huffmanTree {
	return staticDistanceTree
}

func getStaticLiteralTreeLength() [maxLiteralTreeElements]byte {
	var literalTreeLength [maxLiteralTreeElements]byte
	for i := 0; i < 144; i++ {
		literalTreeLength[i] = 8
	}
	for i := 144; i < 256; i++ {
		literalTreeLength[i] = 9
	}
	for i := 256; i < 280; i++ {
		literalTreeLength[i] = 7
	}
	for i := 280; i < 288; i++ {
		literalTreeLength[i] = 8
	}
	return literalTreeLength
}

func getStaticDistanceTreeLength() [maxDistTreeElements]byte {
	var dist [maxDistTreeElements]byte
	for i := 0; i < maxDistTreeElements; i++ {
		dist[i] = 5
	}
	return dist
}

func bitReverse(code uint32, length int) uint32 {
	rev := uint32(0)
	for i := 0; i < length; i++ {
		rev |= (code & 1) << (length - 1 - i)
		code >>= 1
	}
	return rev
}

func (ht *huffmanTree) calculateHuffmanCode() [maxLiteralTreeElements]uint32 {
	codeLengths := ht.codeLengthArray[:ht.codeLengthsLength]
	var bitLengthCount [17]uint32
	for _, codeLength := range codeLengths {
		bitLengthCount[codeLength]++
	}
	bitLengthCount[0] = 0

	var nextCode [17]uint32
	tempCode := uint32(0)
	for bits := 1; bits <= 16; bits++ {
		tempCode = (tempCode + bitLengthCount[bits-1]) << 1
		nextCode[bits] = tempCode
	}

	var code [maxLiteralTreeElements]uint32
	for i, lenVal := range codeLengths {
		if lenVal > 0 {
			code[i] = bitReverse(nextCode[lenVal], int(lenVal))
			nextCode[lenVal]++
		}
	}
	return code
}

func (ht *huffmanTree) newInPlace(codeLengths []byte) error {
	for i := range ht.table {
		ht.table[i] = 0
	}
	for i := range ht.nodes {
		ht.nodes[i] = 0
	}
	ht.codeLengthsLength = uint16(len(codeLengths))
	copy(ht.codeLengthArray[:], codeLengths)
	for i := len(codeLengths); i < len(ht.codeLengthArray); i++ {
		ht.codeLengthArray[i] = 0
	}
	return ht.createTable()
}

func (ht *huffmanTree) createTable() error {
	codeArray := ht.calculateHuffmanCode()
	codeLengthsLen := int(ht.codeLengthsLength)

	avail := int16(1)

	for ch, lenVal := range ht.codeLengthArray[:codeLengthsLen] {
		if lenVal > 0 {
			start := int(codeArray[ch])

			if lenVal <= tableBits {
				increment := 1 << lenVal
				if start >= increment {
					return errDataError
				}

				locs := 1 << (tableBits - lenVal)
				for i := 0; i < locs; i++ {
					ht.table[start] = pack(int16(ch), lenVal)
					start += increment
				}
			} else {
				overflowBits := lenVal - tableBits
				codeBitMask := int(1 << tableBits)

				index := start & tableBitsMask
				value := &ht.table[index]

				for {
					if *value == 0 {
						*value = -(avail * 2)
						avail++
					}

					if *value > 0 {
						return errDataError
					}

					leftChild := int(-*value)
					bitSet := 0
					if (start & codeBitMask) != 0 {
						bitSet = 1
					}
					index = leftChild + bitSet

					if index >= len(ht.nodes) {
						return errDataError
					}
					value = &ht.nodes[index]

					codeBitMask <<= 1
					overflowBits--

					if overflowBits == 0 {
						break
					}
				}
				*value = pack(int16(ch), lenVal)
			}
		}
	}
	return nil
}

func (ht *huffmanTree) getNextSymbol(input *inputBuffer) (uint16, error) {
	bitBuffer := input.tryLoad16Bits()
	if input.availableBits() == 0 {
		return 0, errDataNeeded
	}

	entry := ht.table[bitBuffer&tableBitsMask]
	bits := bitBuffer >> tableBits
	for entry < 0 {
		childIndex := int(-entry) + int(bits&1)
		entry = ht.nodes[childIndex]
		bits >>= 1
	}

	symbol, codeLength := unpack(entry)
	if codeLength <= 0 || codeLength > 16 {
		return 0, errDataError
	}

	if codeLength > input.availableBits() {
		return 0, errDataNeeded
	}

	input.skipBits(codeLength)
	return symbol, nil
}

func (ht *huffmanTree) getNextSymbolAssumeInput(input *inputBuffer) (uint16, error) {
	bitBuffer := input.load16BitsAssumeInput()
	entry := ht.table[bitBuffer&tableBitsMask]
	bits := bitBuffer >> tableBits
	for entry < 0 {
		childIndex := int(-entry) + int(bits&1)
		entry = ht.nodes[childIndex]
		bits >>= 1
	}
	symbol, codeLength := unpack(entry)
	if codeLength == 0 {
		return 0, errDataError
	}
	input.skipBits(codeLength)
	return symbol, nil
}

func (ht *huffmanTree) codeLengths() []byte {
	return ht.codeLengthArray[:ht.codeLengthsLength]
}

// State machine management and table tables
type inflaterState int

const (
	stateReadingBFinal inflaterState = iota
	stateReadingBType
	stateReadingNumLitCodes
	stateReadingNumDistCodes
	stateReadingNumCodeLengthCodes
	stateReadingCodeLengthCodes
	stateReadingTreeCodesBefore
	stateReadingTreeCodesAfter
	stateDecodeTop
	stateHaveInitialLength
	stateHaveFullLength
	stateHaveDistCode
	stateUncompressedAligning
	stateUncompressedByte1
	stateUncompressedByte2
	stateUncompressedByte3
	stateUncompressedByte4
	stateDecodingUncompressed
	stateDone
	stateDataErrored
)

type blockType int

const (
	blockTypeUncompressed blockType = 0
	blockTypeStatic       blockType = 1
	blockTypeDynamic      blockType = 2
)

type inflaterManaged struct {
	output                   *outputWindow
	bits                     bitsBuffer
	literalLengthTree        *huffmanTree
	distanceTree             *huffmanTree
	state                    inflaterState
	bfinal                   bool
	blockType                blockType
	blockLengthBuffer        [4]byte
	blockLength              int
	length                   int
	distanceCode             uint16
	extraBits                int32
	loopCounter              uint32
	literalLengthCodeCount   uint32
	distanceCodeCount        uint32
	codeLengthCodeCount      uint32
	codeArraySize            uint32
	lengthCode               uint16
	codeList                 [maxLiteralTreeElements + maxDistTreeElements]byte
	codeLengthTreeCodeLength [numberOfCodeLengthTreeElements]byte
	deflate64                bool
	codeLengthTree           *huffmanTree
}

func newInflaterManaged() *inflaterManaged {
	return &inflaterManaged{
		output:            newOutputWindow(),
		bits:              bitsBuffer{},
		literalLengthTree: newHuffmanTreeInvalid(),
		distanceTree:      newHuffmanTreeInvalid(),
		codeLengthTree:    newHuffmanTreeInvalid(),
		state:             stateReadingBFinal,
		deflate64:         true,
	}
}

func (im *inflaterManaged) decode(input *inputBuffer) error {
	var eob bool
	var err error

	if im.state == stateDataErrored {
		return errDataError
	} else if im.state == stateDone {
		return nil
	}

	if im.state == stateReadingBFinal {
		bits, err := input.getBits(1)
		if err != nil {
			return err
		}
		im.bfinal = bits != 0
		im.state = stateReadingBType
	}

	if im.state == stateReadingBType {
		bits, err := input.getBits(2)
		if err != nil {
			return err
		}
		im.blockType = blockType(bits)
		switch im.blockType {
		case blockTypeDynamic:
			im.state = stateReadingNumLitCodes
		case blockTypeStatic:
			im.literalLengthTree = newHuffmanTreeStaticLiteral()
			im.distanceTree = newHuffmanTreeStaticDistance()
			im.state = stateDecodeTop
		case blockTypeUncompressed:
			im.state = stateUncompressedAligning
		default:
			return errDataError
		}
	}

	if im.blockType == blockTypeDynamic {
		if im.state < stateDecodeTop {
			err = im.decodeDynamicBlockHeader(input)
		} else {
			err = im.decodeBlock(input, &eob)
		}
	} else if im.blockType == blockTypeStatic {
		err = im.decodeBlock(input, &eob)
	} else if im.blockType == blockTypeUncompressed {
		err = im.decodeUncompressedBlock(input, &eob)
	} else {
		err = errDataError
	}

	if err != nil {
		return err
	}

	if eob && im.bfinal {
		im.state = stateDone
	}
	return nil
}

func (im *inflaterManaged) decodeUncompressedBlock(input *inputBuffer, endOfBlock *bool) error {
	*endOfBlock = false
	for {
		switch im.state {
		case stateUncompressedAligning:
			input.skipToByteBoundary()
			im.state = stateUncompressedByte1
			continue
		case stateUncompressedByte1, stateUncompressedByte2, stateUncompressedByte3, stateUncompressedByte4:
			bits, err := input.getBits(8)
			if err != nil {
				return err
			}
			idx := im.state - stateUncompressedByte1
			im.blockLengthBuffer[idx] = byte(bits)
			if im.state == stateUncompressedByte4 {
				im.blockLength = int(im.blockLengthBuffer[0]) + int(im.blockLengthBuffer[1])*256
				blockLengthComplement := int32(im.blockLengthBuffer[2]) + int32(im.blockLengthBuffer[3])*256

				if uint16(im.blockLength) != uint16(^blockLengthComplement) {
					return errDataError
				}
			}
			switch im.state {
			case stateUncompressedByte1:
				im.state = stateUncompressedByte2
			case stateUncompressedByte2:
				im.state = stateUncompressedByte3
			case stateUncompressedByte3:
				im.state = stateUncompressedByte4
			case stateUncompressedByte4:
				im.state = stateDecodingUncompressed
			}
		case stateDecodingUncompressed:
			bytesCopied := im.output.copyFrom(input, im.blockLength)
			im.blockLength -= bytesCopied

			if im.blockLength == 0 {
				im.state = stateReadingBFinal
				*endOfBlock = true
				return nil
			}

			if im.output.freeBytes() == 0 {
				return nil
			}
			return errDataNeeded
		default:
			panic("UnknownState")
		}
	}
}

func (im *inflaterManaged) decodeBlock(input *inputBuffer, endOfBlockCodeSeen *bool) error {
	*endOfBlockCodeSeen = false

	if im.state == stateDecodeTop {
		written, eob, err := im.decodeBlockFastInnerLoop(input)
		if err != nil {
			return err
		}
		if eob {
			*endOfBlockCodeSeen = true
			im.state = stateReadingBFinal
			return nil
		}
		if written > 0 {
			return nil
		}
	}

	freeBytes := im.output.freeBytes()
	for freeBytes >= tableLookupLengthMax {
		switch im.state {
		case stateDecodeTop:
			symbol, err := im.literalLengthTree.getNextSymbol(input)
			if err != nil {
				return err
			}

			if symbol < 256 {
				im.output.writeByte(byte(symbol))
				freeBytes--
			} else if symbol == 256 {
				*endOfBlockCodeSeen = true
				im.state = stateReadingBFinal
				return nil
			} else {
				symbol -= 257
				if symbol < 8 {
					symbol += 3
					im.extraBits = 0
				} else if !im.deflate64 && symbol == 28 {
					symbol = 258
					im.extraBits = 0
				} else {
					if int(symbol) >= len(extraLengthBits) {
						return errDataError
					}
					im.extraBits = int32(extraLengthBits[symbol])
				}
				im.length = int(symbol)
				im.state = stateHaveInitialLength
				continue
			}
		case stateHaveInitialLength:
			if im.extraBits > 0 {
				bits, err := input.getBits(im.extraBits)
				if err != nil {
					return err
				}
				if im.length >= len(lengthBase) {
					return errDataError
				}
				im.length = int(lengthBase[im.length]) + int(bits)
			}
			im.state = stateHaveFullLength
			continue
		case stateHaveFullLength:
			if im.blockType == blockTypeDynamic {
				bits, err := im.distanceTree.getNextSymbol(input)
				if err != nil {
					return err
				}
				im.distanceCode = bits
			} else {
				bits, err := input.getBits(5)
				if err != nil {
					return err
				}
				im.distanceCode = uint16(staticDistanceTreeTable[bits])
			}
			im.state = stateHaveDistCode
			continue
		case stateHaveDistCode:
			var offset int
			if im.distanceCode > 3 {
				if int(im.distanceCode) >= len(distanceBasePosition) {
					return errDataError
				}
				im.extraBits = int32((im.distanceCode - 2) >> 1)
				bits, err := input.getBits(im.extraBits)
				if err != nil {
					return err
				}
				offset = int(distanceBasePosition[im.distanceCode]) + int(bits)
			} else {
				offset = int(im.distanceCode + 1)
			}

			if im.length > tableLookupLengthMax || offset > tableLookupDistanceMax {
				return errDataError
			}

			im.output.writeLengthDistance(im.length, offset)
			freeBytes -= im.length
			im.state = stateDecodeTop
		default:
			panic("UnknownState")
		}
	}

	return nil
}

func (im *inflaterManaged) decodeBlockFastInnerLoop(input *inputBuffer) (int, bool, error) {
	initialFree := im.output.freeBytes()

	for {
		if im.output.freeBytes() < tableLookupLengthMax || input.availableBytes() < 8 {
			return initialFree - im.output.freeBytes(), false, nil
		}

		symbol, err := im.literalLengthTree.getNextSymbolAssumeInput(input)
		if err != nil {
			return 0, false, err
		}

		switch {
		case symbol < 256:
			im.output.writeByte(byte(symbol))
		case symbol == 256:
			return initialFree - im.output.freeBytes(), true, nil
		case symbol >= 257 && symbol <= 285:
			lengthIndex := int(symbol - 257)
			var length int
			if lengthIndex < 8 {
				length = lengthIndex + 3
			} else {
				extraBits := int32(extraLengthBits[lengthIndex])
				bits := input.getBitsAssumeInput(extraBits)
				length = int(lengthBase[lengthIndex]) + int(bits)
			}

			var distanceCode int
			if im.blockType == blockTypeDynamic {
				bits, err := im.distanceTree.getNextSymbolAssumeInput(input)
				if err != nil {
					return 0, false, err
				}
				distanceCode = int(bits)
			} else {
				distanceCode = int(staticDistanceTreeTable[input.getBitsAssumeInput(5)])
			}

			var offset int
			if distanceCode <= 3 {
				offset = distanceCode + 1
			} else {
				extraBits := int32((distanceCode - 2) >> 1)
				bits := input.getBitsAssumeInput(extraBits)
				if distanceCode >= len(distanceBasePosition) {
					return 0, false, errDataError
				}
				offset = int(distanceBasePosition[distanceCode]) + int(bits)
			}

			if length > tableLookupLengthMax || offset > tableLookupDistanceMax {
				return 0, false, errDataError
			}
			im.output.writeLengthDistance(length, offset)
		default:
			return 0, false, errDataError
		}
	}
}

func (im *inflaterManaged) decodeDynamicBlockHeader(input *inputBuffer) error {
loop:
	for {
		switch im.state {
		case stateReadingNumLitCodes:
			bits, err := input.getBits(5)
			if err != nil {
				return err
			}
			im.literalLengthCodeCount = uint32(bits) + 257
			im.state = stateReadingNumDistCodes
			continue loop
		case stateReadingNumDistCodes:
			bits, err := input.getBits(5)
			if err != nil {
				return err
			}
			im.distanceCodeCount = uint32(bits) + 1
			im.state = stateReadingNumCodeLengthCodes
			continue loop
		case stateReadingNumCodeLengthCodes:
			bits, err := input.getBits(4)
			if err != nil {
				return err
			}
			im.codeLengthCodeCount = uint32(bits) + 4
			im.loopCounter = 0
			im.state = stateReadingCodeLengthCodes
			continue loop
		case stateReadingCodeLengthCodes:
			for im.loopCounter < im.codeLengthCodeCount {
				bits, err := input.getBits(3)
				if err != nil {
					return err
				}
				im.codeLengthTreeCodeLength[codeOrder[im.loopCounter]] = byte(bits)
				im.loopCounter++
			}

			for _, codeOder := range codeOrder[im.codeLengthCodeCount:] {
				im.codeLengthTreeCodeLength[codeOder] = 0
			}

			err := im.codeLengthTree.newInPlace(im.codeLengthTreeCodeLength[:])
			if err != nil {
				return err
			}
			im.codeArraySize = im.literalLengthCodeCount + im.distanceCodeCount
			im.loopCounter = 0

			im.state = stateReadingTreeCodesBefore
			continue loop
		case stateReadingTreeCodesBefore, stateReadingTreeCodesAfter:
			for im.loopCounter < im.codeArraySize {
				if im.state == stateReadingTreeCodesBefore {
					symbol, err := im.codeLengthTree.getNextSymbol(input)
					if err != nil {
						return err
					}
					im.lengthCode = symbol
				}

				if im.lengthCode <= 15 {
					im.codeList[im.loopCounter] = byte(im.lengthCode)
					im.loopCounter++
				} else {
					var repeatCount uint32
					if im.lengthCode == 16 {
						im.state = stateReadingTreeCodesAfter
						if im.loopCounter == 0 {
							return errDataError
						}

						bits, err := input.getBits(2)
						if err != nil {
							return err
						}

						previousCode := im.codeList[im.loopCounter-1]
						repeatCount = uint32(bits) + 3

						if im.loopCounter+repeatCount > im.codeArraySize {
							return errDataError
						}

						for i := uint32(0); i < repeatCount; i++ {
							im.codeList[im.loopCounter] = previousCode
							im.loopCounter++
						}
					} else if im.lengthCode == 17 {
						im.state = stateReadingTreeCodesAfter
						bits, err := input.getBits(3)
						if err != nil {
							return err
						}

						repeatCount = uint32(bits) + 3

						if im.loopCounter+repeatCount > im.codeArraySize {
							return errDataError
						}

						for i := uint32(0); i < repeatCount; i++ {
							im.codeList[im.loopCounter] = 0
							im.loopCounter++
						}
					} else {
						im.state = stateReadingTreeCodesAfter
						bits, err := input.getBits(7)
						if err != nil {
							return err
						}

						repeatCount = uint32(bits) + 11

						if im.loopCounter+repeatCount > im.codeArraySize {
							return errDataError
						}

						for i := uint32(0); i < repeatCount; i++ {
							im.codeList[im.loopCounter] = 0
							im.loopCounter++
						}
					}
				}
				im.state = stateReadingTreeCodesBefore
			}
			break loop
		default:
			panic("InvalidDataException: UnknownState")
		}
	}

	var literalTreeCodeLength [maxLiteralTreeElements]byte
	var distanceTreeCodeLength [maxDistTreeElements]byte

	copy(literalTreeCodeLength[:im.literalLengthCodeCount], im.codeList[:im.literalLengthCodeCount])
	copy(distanceTreeCodeLength[:im.distanceCodeCount], im.codeList[im.literalLengthCodeCount:im.literalLengthCodeCount+im.distanceCodeCount])

	if literalTreeCodeLength[endOfBlockCode] == 0 {
		return errDataError
	}

	err := im.literalLengthTree.newInPlace(literalTreeCodeLength[:])
	if err != nil {
		return err
	}
	err = im.distanceTree.newInPlace(distanceTreeCodeLength[:])
	if err != nil {
		return err
	}
	im.state = stateDecodeTop
	return nil
}

// Static mapping arrays
var extraLengthBits = []byte{
	0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16,
}

var lengthBase = []byte{
	3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
	163, 195, 227, 3,
}

var distanceBasePosition = []uint16{
	1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
	2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153,
}

var codeOrder = []byte{
	16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
}

var staticDistanceTreeTable = []byte{
	0x00, 0x10, 0x08, 0x18, 0x04, 0x14, 0x0c, 0x1c, 0x02, 0x12, 0x0a, 0x1a, 0x06, 0x16, 0x0e, 0x1e,
	0x01, 0x11, 0x09, 0x19, 0x05, 0x15, 0x0d, 0x1d, 0x03, 0x13, 0x0b, 0x1b, 0x07, 0x17, 0x0f, 0x1f,
}

const (
	tableLookupLengthMax   = 65538
	tableLookupDistanceMax = 65536
)
