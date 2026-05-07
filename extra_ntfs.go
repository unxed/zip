package zip

import "encoding/binary"

// appendNtfsAcl записывает Windows Security Descriptor в тег 0x4453
func appendNtfsAcl(extra []byte, sd []byte) []byte {
	if len(sd) == 0 {
		return extra
	}
	// Формат 0x4453: [ID 2b] [Size 2b] [Data...]
	buf := make([]byte, 4+len(sd))
	binary.LittleEndian.PutUint16(buf[0:2], ntfsAclExtraID)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(sd)))
	copy(buf[4:], sd)
	return append(extra, buf...)
}

// parseNtfsAcl извлекает Security Descriptor
func parseNtfsAcl(extra []byte) []byte {
	for len(extra) >= 4 {
		tag := binary.LittleEndian.Uint16(extra[:2])
		size := binary.LittleEndian.Uint16(extra[2:4])
		extra = extra[4:]
		if int(size) > len(extra) {
			break
		}
		if tag == ntfsAclExtraID {
			sd := make([]byte, size)
			copy(sd, extra[:size])
			return sd
		}
		extra = extra[size:]
	}
	return nil
}