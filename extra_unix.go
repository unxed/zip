package zip

import "encoding/binary"

const infoZipNewUnixExtraID = 0x7875

func appendUnixExtra(extra []byte, uid, gid int) []byte {
	var buf [15]byte
	binary.LittleEndian.PutUint16(buf[0:2], infoZipNewUnixExtraID)
	binary.LittleEndian.PutUint16(buf[2:4], 11)
	buf[4] = 1 // version
	buf[5] = 4 // uid size
	binary.LittleEndian.PutUint32(buf[6:10], uint32(uid))
	buf[10] = 4 // gid size
	binary.LittleEndian.PutUint32(buf[11:15], uint32(gid))
	return append(extra, buf[:]...)
}

func parseUnixExtra(extra []byte) (uid, gid int, ok bool) {
	for len(extra) >= 4 {
		tag := binary.LittleEndian.Uint16(extra[:2])
		size := binary.LittleEndian.Uint16(extra[2:4])
		extra = extra[4:]
		if int(size) > len(extra) {
			break
		}
		if tag == infoZipNewUnixExtraID && size >= 1 {
			version := extra[0]
			if version == 1 {
				offset := 1
				// uid
				if offset >= int(size) { break }
				uidSize := int(extra[offset])
				offset++
				if offset+uidSize > int(size) { break }
				uid = readInt(extra[offset : offset+uidSize])
				offset += uidSize

				// gid
				if offset >= int(size) { break }
				gidSize := int(extra[offset])
				offset++
				if offset+gidSize > int(size) { break }
				gid = readInt(extra[offset : offset+gidSize])
				return uid, gid, true
			}
		}
		extra = extra[size:]
	}
	return 0, 0, false
}

func readInt(b []byte) int {
	switch len(b) {
	case 2:
		return int(binary.LittleEndian.Uint16(b))
	case 4:
		return int(binary.LittleEndian.Uint32(b))
	case 8:
		return int(binary.LittleEndian.Uint64(b))
	}
	return 0
}