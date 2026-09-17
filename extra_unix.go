package zip

import (
	"encoding/binary"
	"io/fs"
	"math"
)

const infoZipNewUnixExtraID = 0x7875

func appendUnixExtra(extra []byte, uid, gid int) []byte {
	var buf [15]byte
	binary.LittleEndian.PutUint16(buf[0:2], infoZipNewUnixExtraID)
	binary.LittleEndian.PutUint16(buf[2:4], 11)
	buf[4] = 1 // version
	buf[5] = 4 // uid size
	// #nosec G115 -- the byte above announces a four-byte uid and a uid_t is thirty-two unsigned bits, so four bytes is the whole width an id has
	binary.LittleEndian.PutUint32(buf[6:10], uint32(uid))
	buf[10] = 4 // gid size
	// #nosec G115 -- the byte above announces a four-byte gid and a gid_t is thirty-two unsigned bits, so four bytes is the whole width an id has
	binary.LittleEndian.PutUint32(buf[11:15], uint32(gid))
	return append(extra, buf[:]...)
}

// pkwareHardLinkAttr is the bit in the low word of the external file
// attributes that fuse-zip and mount-zip read as PKZIP's hard link flag: on an
// entry that has it they resolve the name in its 0x000d tag as the file it is
// a hard link to, and any other entry is the empty regular file its mode and
// size describe. APPNOTE 6.3.10 does not define the bit: 4.4.15 leaves the
// attributes to the host system, and 4.5.7 gives the tag one field for the
// target of "hard or symbolic links" with nothing to say which.
const pkwareHardLinkAttr = 0x800

// marksHardLink reports whether the entry is a hard link that is to carry
// pkwareHardLinkAttr. The low word holds MS-DOS attributes on FAT and NTFS
// hosts, where 0x800 is FILE_ATTRIBUTE_COMPRESSED and 7-Zip takes the word for
// Windows attributes, so only an entry made on Unix gets it. A device's 0x000d
// tag holds its device number rather than a name, and a symlink's target is
// its body, which is how this package reads both back, so neither is flagged;
// fuse-zip ignores the bit on devices too.
func (h *FileHeader) marksHardLink() bool {
	if h.Linkname == "" || h.CreatorVersion>>8 != creatorUnix {
		return false
	}
	switch h.Mode().Type() {
	case 0, fs.ModeNamedPipe, fs.ModeSocket:
		return true
	}
	return false
}

// appendUnix000dExtra writes the 0x000d tag, which carries either a link
// target or a device number. Its length, like every extra field's, is two
// bytes of the header, so a link target longer than that leaves the tag out
// rather than going on disk under a length that has wrapped: the entry keeps
// its data and loses only a tag no reader has to understand.
func appendUnix000dExtra(extra []byte, hdr *FileHeader) []byte {
	varData := []byte{}
	if hdr.Linkname != "" {
		varData = []byte(hdr.Linkname)
	} else if hdr.Mode()&(fs.ModeDevice|fs.ModeCharDevice) != 0 {
		varData = make([]byte, 8)
		// #nosec G115 -- the 0x000d tag holds each half of the device number in four bytes and that is the whole width the field has
		binary.LittleEndian.PutUint32(varData[0:4], uint32(hdr.Devmajor))
		// #nosec G115 -- the 0x000d tag holds each half of the device number in four bytes and that is the whole width the field has
		binary.LittleEndian.PutUint32(varData[4:8], uint32(hdr.Devminor))
	}

	if len(varData) == 0 {
		return extra
	}

	size, err := fitUint16(12+len(varData), "unix extra field (0x000d)")
	if err != nil {
		return extra
	}

	buf := make([]byte, 16+len(varData))
	binary.LittleEndian.PutUint16(buf[0:2], unixExtraID)
	binary.LittleEndian.PutUint16(buf[2:4], size)
	// #nosec G115 -- the 0x000d tag holds each time in four bytes of Unix time and this is the whole of the field
	binary.LittleEndian.PutUint32(buf[4:8], uint32(hdr.Accessed.Unix()))
	// #nosec G115 -- the 0x000d tag holds each time in four bytes of Unix time and this is the whole of the field
	binary.LittleEndian.PutUint32(buf[8:12], uint32(hdr.Modified.Unix()))
	// #nosec G115 -- the 0x000d tag holds the uid in two bytes and that is the whole width the field has; the full id travels in the 0x7875 tag
	binary.LittleEndian.PutUint16(buf[12:14], uint16(hdr.Uid))
	// #nosec G115 -- the 0x000d tag holds the gid in two bytes and that is the whole width the field has; the full id travels in the 0x7875 tag
	binary.LittleEndian.PutUint16(buf[14:16], uint16(hdr.Gid))
	copy(buf[16:], varData)
	return append(extra, buf...)
}

// appendXattrs writes the extended attributes to the 0x7811 tag. Every length
// in the tag is two bytes: an attribute whose name or value is longer than
// that is left out, and a set whose whole payload is longer than that leaves
// the tag out. Writing either under a wrapped length would put a header on
// disk announcing len&0xffff bytes ahead of the full string, which is not an
// archive a reader can walk.
func appendXattrs(extra []byte, xattrs map[string]string) []byte {
	if len(xattrs) == 0 {
		return extra
	}
	var payload []byte
	for k, v := range xattrs {
		klen, err := fitUint16(len(k), "extended attribute name")
		if err != nil {
			continue
		}
		vlen, err := fitUint16(len(v), "extended attribute value")
		if err != nil {
			continue
		}
		var kv [4]byte
		binary.LittleEndian.PutUint16(kv[0:2], klen)
		binary.LittleEndian.PutUint16(kv[2:4], vlen)
		payload = append(payload, kv[0:2]...)
		payload = append(payload, k...)
		payload = append(payload, kv[2:4]...)
		payload = append(payload, v...)
	}
	if len(payload) == 0 {
		return extra
	}
	size, err := fitUint16(len(payload), "extended attribute extra field")
	if err != nil {
		return extra
	}
	var head [4]byte
	binary.LittleEndian.PutUint16(head[0:2], xattrExtraID)
	binary.LittleEndian.PutUint16(head[2:4], size)
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
				var idOK bool
				// uid
				if offset >= int(size) {
					break
				}
				uidSize := int(extra[offset])
				offset++
				if offset+uidSize > int(size) {
					break
				}
				if uid, idOK = readInt(extra[offset : offset+uidSize]); !idOK {
					break
				}
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
				if gid, idOK = readInt(extra[offset : offset+gidSize]); !idOK {
					break
				}
				return uid, gid, true
			}
		}
		extra = extra[size:]
	}
	return 0, 0, false
}

// readInt reads a uid or a gid out of the 0x7875 tag in the width the tag
// announces for it. That width is one byte of the archive, so it can name an
// eight-byte field, and eight bytes hold numbers no int holds: converting one
// of those turns it negative, and a negative uid is not the owner the archive
// named -- it is whatever lchown makes of the wrapped value. A uid_t and a
// gid_t are thirty-two unsigned bits on every Unix, so a wider number is not
// an id at all. Such a field is refused rather than narrowed, as is a width
// the tag has no encoding for.
func readInt(b []byte) (int, bool) {
	var v uint64
	switch len(b) {
	case 1:
		v = uint64(b[0])
	case 2:
		v = uint64(binary.LittleEndian.Uint16(b))
	case 4:
		v = uint64(binary.LittleEndian.Uint32(b))
	case 8:
		v = binary.LittleEndian.Uint64(b)
	default:
		return 0, false
	}
	// Two bounds, and the second is not the first on every build. A uid_t
	// or a gid_t is 32 unsigned bits, so a wider value is not an id at
	// all. And where an int is 32 bits, an id the field can perfectly well
	// name still has no int to be put in: narrowing 4294967295 there gives
	// -1, which is the number Lchown reads as "leave this alone".
	if v > math.MaxUint32 || v > math.MaxInt {
		return 0, false
	}
	return int(v), true
}

// appendUnixOwnerNamesExtra writes the owner and the group name to the 0x7817
// tag. The tag's own length and the length of each name in it are two bytes,
// so a name longer than that leaves the tag out rather than going on disk
// under a length that has wrapped. The entry then carries only the numeric
// ids, which is what a reader that does not know the tag uses anyway.
func appendUnixOwnerNamesExtra(extra []byte, uname, gname string) []byte {
	ulen, err := fitUint16(len(uname), "unix owner name")
	if err != nil {
		return extra
	}
	glen, err := fitUint16(len(gname), "unix group name")
	if err != nil {
		return extra
	}
	payloadSize := 4 + len(uname) + len(gname)
	size, err := fitUint16(payloadSize, "unix owner name extra field (0x7817)")
	if err != nil {
		return extra
	}
	buf := make([]byte, 4+payloadSize)
	binary.LittleEndian.PutUint16(buf[0:2], unixOwnerNameExtraID)
	binary.LittleEndian.PutUint16(buf[2:4], size)
	binary.LittleEndian.PutUint16(buf[4:6], ulen)
	copy(buf[6:6+len(uname)], uname)
	binary.LittleEndian.PutUint16(buf[6+len(uname):8+len(uname)], glen)
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
