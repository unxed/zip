package zip

import (
	"encoding/binary"
	"io/fs"
)

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

func appendUnix000dExtra(extra []byte, hdr *FileHeader) []byte {
	varData := []byte{}
	if hdr.Linkname != "" {
		varData = []byte(hdr.Linkname)
	} else if hdr.Mode()&(fs.ModeDevice|fs.ModeCharDevice) != 0 {
		varData = make([]byte, 8)
		binary.LittleEndian.PutUint32(varData[0:4], uint32(hdr.Devmajor))
		binary.LittleEndian.PutUint32(varData[4:8], uint32(hdr.Devminor))
	}

	if len(varData) == 0 {
		return extra
	}

	buf := make([]byte, 16+len(varData))
	binary.LittleEndian.PutUint16(buf[0:2], unixExtraID)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(12+len(varData)))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(hdr.Accessed.Unix()))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(hdr.Modified.Unix()))
	binary.LittleEndian.PutUint16(buf[12:14], uint16(hdr.Uid))
	binary.LittleEndian.PutUint16(buf[14:16], uint16(hdr.Gid))
	copy(buf[16:], varData)
	return append(extra, buf...)
}

func appendXattrs(extra []byte, xattrs map[string]string) []byte {
	if len(xattrs) == 0 {
		return extra
	}
	var payload []byte
	for k, v := range xattrs {
		var kv [4]byte
		binary.LittleEndian.PutUint16(kv[0:2], uint16(len(k)))
		binary.LittleEndian.PutUint16(kv[2:4], uint16(len(v)))
		payload = append(payload, kv[0:2]...)
		payload = append(payload, k...)
		payload = append(payload, kv[2:4]...)
		payload = append(payload, v...)
	}
	var head [4]byte
	binary.LittleEndian.PutUint16(head[0:2], xattrExtraID)
	binary.LittleEndian.PutUint16(head[2:4], uint16(len(payload)))
	extra = append(extra, head[:]...)
	return append(extra, payload...)
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
				if offset >= int(size) {
					break
				}
				uidSize := int(extra[offset])
				offset++
				if offset+uidSize > int(size) {
					break
				}
				uid = readInt(extra[offset : offset+uidSize])
				offset += uidSize

				// gid
				if offset >= int(size) {
					break
				}
				gidSize := int(extra[offset])
				offset++
				if offset+gidSize > int(size) {
					break
				}
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
	case 1:
		return int(b[0])
	case 2:
		return int(binary.LittleEndian.Uint16(b))
	case 4:
		return int(binary.LittleEndian.Uint32(b))
	case 8:
		return int(binary.LittleEndian.Uint64(b))
	}
	return 0
}

func appendUnixOwnerNamesExtra(extra []byte, uname, gname string) []byte {
	payloadSize := 4 + len(uname) + len(gname)
	buf := make([]byte, 4+payloadSize)
	binary.LittleEndian.PutUint16(buf[0:2], unixOwnerNameExtraID)
	binary.LittleEndian.PutUint16(buf[2:4], uint16(payloadSize))
	binary.LittleEndian.PutUint16(buf[4:6], uint16(len(uname)))
	copy(buf[6:6+len(uname)], uname)
	binary.LittleEndian.PutUint16(buf[6+len(uname):8+len(uname)], uint16(len(gname)))
	copy(buf[8+len(uname):], gname)
	return append(extra, buf...)
}

func parseUnixOwnerNamesExtra(extra []byte) (uname, gname string, ok bool) {
	for len(extra) >= 4 {
		tag := binary.LittleEndian.Uint16(extra[:2])
		size := binary.LittleEndian.Uint16(extra[2:4])
		extra = extra[4:]
		if int(size) > len(extra) {
			break
		}
		if tag == unixOwnerNameExtraID {
			if size < 4 {
				break
			}
			ulen := binary.LittleEndian.Uint16(extra[:2])
			if 4+int(ulen) > int(size) {
				break
			}
			uname = string(extra[2 : 2+ulen])
			glen := binary.LittleEndian.Uint16(extra[2+ulen : 4+ulen])
			if 4+int(ulen)+int(glen) > int(size) {
				break
			}
			gname = string(extra[4+ulen : 4+ulen+glen])
			return uname, gname, true
		}
		extra = extra[size:]
	}
	return "", "", false
}
