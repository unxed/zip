package zip

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestReadDirectory64End_V2_SES(t *testing.T) {
	// Подготавливаем структуру Zip64 EOCD Record Version 2 (SES)
	// Спецификация 4.3.14 + 7.3.4
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(directory64EndSignature))
	binary.Write(buf, binary.LittleEndian, uint64(44+24))    // Size (56-12 + 24)
	binary.Write(buf, binary.LittleEndian, uint16(45))       // Version made
	binary.Write(buf, binary.LittleEndian, uint16(45))       // Version needed
	binary.Write(buf, binary.LittleEndian, uint32(0))        // Disk numbers...
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint64(10))       // Records on disk
	binary.Write(buf, binary.LittleEndian, uint64(10))       // Total records
	binary.Write(buf, binary.LittleEndian, uint64(500))      // Dir size
	binary.Write(buf, binary.LittleEndian, uint64(1000))     // Dir offset

	// SES Extension (Version 2 fields)
	binary.Write(buf, binary.LittleEndian, uint16(8))        // Compression (Deflate)
	binary.Write(buf, binary.LittleEndian, uint64(500))      // Compressed size
	binary.Write(buf, binary.LittleEndian, uint64(1000))     // Original size
	binary.Write(buf, binary.LittleEndian, uint16(sesAES256)) // AlgId
	binary.Write(buf, binary.LittleEndian, uint16(256))       // BitLen
	binary.Write(buf, binary.LittleEndian, uint16(0x0001))   // Flags (bit 0 = encrypted)

	data := buf.Bytes()
	ra := bytes.NewReader(data)

	d := &directoryEnd{}
	err := readDirectory64End(ra, 0, d)
	if err != nil {
		t.Fatalf("failed to read V2 EOCD: %v", err)
	}

	if !d.encrypted {
		t.Error("expected encrypted flag to be true")
	}
	if d.algId != sesAES256 || d.bitLen != 256 {
		t.Errorf("incorrect SES params: alg=%x, bits=%d", d.algId, d.bitLen)
	}
}