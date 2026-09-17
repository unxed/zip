package zip

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"
)

// Compression methods.
const (
	Store     uint16 = 0 // no compression
	Deflate   uint16 = 8 // DEFLATE compressed
	Deflate64 uint16 = 9
	BZIP2     uint16 = 12
	LZMA      uint16 = 14
	ZSTD      uint16 = 93 // Zstandard compressed
)

const (
	fileHeaderSignature      = 0x04034b50
	directoryHeaderSignature = 0x02014b50
	directoryEndSignature    = 0x06054b50
	directory64LocSignature  = 0x07064b50
	directory64EndSignature  = 0x06064b50
	dataDescriptorSignature  = 0x08074b50 // de-facto standard; required by OS X Finder
	splitSignature           = 0x08074b50 // Signature of the first volume of a multi-volume archive
	splitAltSignature        = 0x30304b50 // Alternative signature (STPAN)
	fileHeaderLen            = 30         // + filename + extra
	directoryHeaderLen       = 46         // + filename + extra + comment
	directoryEndLen          = 22         // + comment
	dataDescriptorLen        = 16         // four uint32: descriptor signature, crc32, compressed size, size
	dataDescriptor64Len      = 24         // two uint32: signature, crc32 | two uint64: compressed size, size
	directory64LocLen        = 20         //
	directory64EndLen        = 56         // + extra

	// Constants for the first byte in CreatorVersion.
	creatorFAT    = 0
	creatorUnix   = 3
	creatorHPFS   = 6
	creatorNTFS   = 11
	creatorVFAT   = 14
	creatorMacOSX = 19

	// Version numbers.
	zipVersion20 = 20 // 2.0
	zipVersion45 = 45 // 4.5 (reads and writes zip64 archives)

	// Limits for non zip64 files.
	uint16max = (1 << 16) - 1
	uint32max = (1 << 32) - 1

	// Extra header IDs.
	zip64ExtraID          = 0x0001 // Zip64 extended information
	ntfsExtraID           = 0x000a // NTFS
	unixExtraID           = 0x000d // UNIX
	ntfsAclExtraID        = 0x4453 // Windows NT Security Descriptor (ACL)
	extTimeExtraID        = 0x5455 // Extended timestamp
	infoZipUnixExtraID    = 0x5855 // Info-ZIP Unix extension
	unicodeCommentExtraID = 0x6375 // Info-ZIP Unicode Comment Extra Field
	unicodePathExtraID    = 0x7075 // Info-ZIP Unicode Path Extra Field
	//                      0x756e // ASi UNIX
	//                             // 0x756f..0x7810 unused
	xattrExtraID = 0x7811 // f4 extensions: Xattrs
	//                      0x7812 // Reserved for further f4 extensions versions
	//                      0x7813 // Reserved for further f4 extensions versions
	//                      0x7814 // Reserved for further f4 extensions versions
	//                      0x7815 // Reserved for further f4 extensions versions
	//                      0x7816 // Reserved for further f4 extensions versions
	unixOwnerNameExtraID = 0x7817 // f4 extensions: Unix owner/group string names
	xcryptExtraID        = 0x7819 // f4 extensions: XCrypt encryption extra field
	//                             // 0x781a..0x7854 unused
	//                      0x7855 // Info-ZIP UNIX (new)
	//                      0x7875 // Info-ZIP UNIX (newer UID/GID)
	winzipAesExtraID = 0x9901 // WinZip AES encryption extra field
)

// winzipAesMethod is the compression method code that marks an entry as
// WinZip AES encrypted, used together with the 0x9901 extra field that holds
// the method the data was actually compressed with (APPNOTE 4.4.5 and
// APPENDIX E; WinZip AES specification, section II.B).
const winzipAesMethod = 99

// isWinZipAesMethod reports whether an entry's method code marks it as
// WinZip AES. Besides 99 it accepts 0x9901, the extra field ID, which this
// package wrote into the method field of the entries it encrypted before
// it wrote 99: those archives still have to open.
func isWinZipAesMethod(method uint16) bool {
	return method == winzipAesMethod || method == winzipAesExtraID
}

// parseWinZipAesExtra reads the payload of a 0x9901 extra field. The
// specification lays it out as vendor version (2 bytes), vendor ID "AE"
// (2 bytes), strength (1 byte), actual compression method (2 bytes), and
// allows the payload to grow past 7 bytes. This package used to write the
// strength before the vendor ID; the two layouts are told apart by where
// "AE" stands, since a strength is never the byte 'A'. A payload with "AE"
// in neither place is not a WinZip AES field.
func parseWinZipAesExtra(b []byte) (info winzipAesInfo, ok bool) {
	if len(b) < 7 {
		return winzipAesInfo{}, false
	}
	info.version = binary.LittleEndian.Uint16(b[0:2])
	info.actualMethod = binary.LittleEndian.Uint16(b[5:7])
	switch {
	case b[2] == 'A' && b[3] == 'E':
		info.strength = b[4]
	case b[3] == 'A' && b[4] == 'E':
		info.strength = b[2]
	default:
		return winzipAesInfo{}, false
	}
	return info, true
}

// Abstraction hooks for NTFS security and stream operations to support unit testing on non-Windows platforms.
var (
	getFileSecurityFunc           = getFileSecurity
	applyNtfsAclFunc              = applyNtfsAcl
	getAlternativeDataStreamsFunc = getAlternativeDataStreams
)

const (
	// Strong Encryption (SES) Algorithm IDs
	sesDES     = 0x6601
	sesRC2old  = 0x6602
	ses3DES168 = 0x6603
	ses3DES112 = 0x6609
	sesAES128  = 0x660E
	sesAES192  = 0x660F
	sesAES256  = 0x6610
)

// ConfigIncludePlatformMetadata defines if FileInfoHeader should automatically
// include OS-specific metadata (like UID/GID on Unix).
// Enabled by default to match system archivers behavior.
var ConfigIncludePlatformMetadata = true

type gzPoint struct {
	compOffset   uint64
	uncompOffset uint64
	bits         uint8
	hasData      uint8
	window       []byte
}

// FileHeader describes a file within a ZIP file.
type FileHeader struct {
	Name               string
	Comment            string
	NonUTF8            bool // If set, disables automatic UTF-8 flag encoding
	RecoveryPct        int  // Уровень избыточности PAR2 для всего архива
	RecoveryFile       *os.File
	CreatorVersion     uint16
	ReaderVersion      uint16
	Flags              uint16
	Method             uint16
	Modified           time.Time
	Accessed           time.Time
	Created            time.Time
	ModifiedTime       uint16 // Deprecated
	ModifiedDate       uint16 // Deprecated
	CRC32              uint32
	CompressedSize     uint32 // Deprecated: Use CompressedSize64
	UncompressedSize   uint32 // Deprecated: Use UncompressedSize64
	CompressedSize64   uint64
	UncompressedSize64 uint64
	Extra              []byte
	ExternalAttrs      uint32
	// UNIX attributes
	Uid      int
	Gid      int
	OwnerSet bool
	Uname    string // User name of owner
	Gname    string // Group name of owner
	// Hardlinks & Devices
	Devmajor int64
	Devminor int64
	Linkname string
	// Xattrs
	Xattrs map[string]string
	// NTFS Attributes
	Acl []byte // Windows Security Descriptor (ACL)

	// Seek Index (SOZip / GZIDX Hidden files)
	SeekChunkSize  uint32    // Uncompressed block size (e.g. 1MB)
	SeekIndex      []uint64  // SOZip compressed offsets
	GzidxPoints    []gzPoint // GZIDX stateful points
	SeekContinuous bool      // If true, generate GZIDX instead of SOZip

	// WinZip AES encryption
	Password    string
	AESStrength byte // 1 = 128, 2 = 192, 3 = 256. Defaults to 3 (AES-256) if Password != ""
	Level       int
}

func (h *FileHeader) SetComment(comment string) {
	h.Comment = comment
}

func (h *FileHeader) FileInfo() fs.FileInfo {
	return headerFileInfo{h}
}

type headerFileInfo struct {
	fh *FileHeader
}

func (fi headerFileInfo) Name() string { return path.Base(fi.fh.Name) }
func (fi headerFileInfo) Size() int64 {
	if fi.fh.UncompressedSize64 > 0 {
		// #nosec G115 -- headers read from an archive are held to UncompressedSize64 <= MaxInt64 by readDirectoryHeader; a header built in this process carries the caller's own number
		return int64(fi.fh.UncompressedSize64)
	}
	return int64(fi.fh.UncompressedSize)
}
func (fi headerFileInfo) IsDir() bool                { return fi.Mode().IsDir() }
func (fi headerFileInfo) ModTime() time.Time         { return fi.fh.Modified.UTC() }
func (fi headerFileInfo) Mode() fs.FileMode          { return fi.fh.Mode() }
func (fi headerFileInfo) Type() fs.FileMode          { return fi.fh.Mode().Type() }
func (fi headerFileInfo) Sys() any                   { return fi.fh }
func (fi headerFileInfo) Info() (fs.FileInfo, error) { return fi, nil }
func (fi headerFileInfo) String() string             { return fs.FormatFileInfo(fi) }

func FileInfoHeader(fi fs.FileInfo) (*FileHeader, error) {
	size := fi.Size()
	// fs.FileInfo is an interface, so the size is whatever the caller's
	// implementation returns. A negative one read as unsigned becomes a
	// header announcing about 2^64 bytes, which is the size the archive
	// would then be trusted to hold.
	if size < 0 {
		return nil, fmt.Errorf("zip: %s reports a size of %d bytes", fi.Name(), size)
	}
	fh := &FileHeader{
		Name:               fi.Name(),
		UncompressedSize64: uint64(size),
	}
	fh.SetModTime(fi.ModTime())
	fh.SetMode(fi.Mode())
	if fh.UncompressedSize64 > uint32max {
		fh.UncompressedSize = uint32max
	} else {
		fh.UncompressedSize = uint32(fh.UncompressedSize64)
	}

	// Automatically try to extract OS-specific metadata if enabled globally
	appendPlatformExtra(fi, fh, ConfigIncludePlatformMetadata)

	return fh, nil
}

type directoryEnd struct {
	diskNbr            uint32
	dirDiskNbr         uint32
	dirRecordsThisDisk uint64
	directoryRecords   uint64
	directorySize      uint64
	directoryOffset    uint64
	commentLen         uint16
	comment            string

	// SES (Strong Encryption) fields
	encrypted bool
	algId     uint16
	bitLen    uint16
}

func timeZone(offset time.Duration) *time.Location {
	const minOffset = -12 * time.Hour
	const maxOffset = +14 * time.Hour
	const offsetAlias = 15 * time.Minute
	offset = offset.Round(offsetAlias)
	if offset < minOffset || maxOffset < offset {
		offset = 0
	}
	return time.FixedZone("", int(offset/time.Second))
}

func msDosTimeToTime(dosDate, dosTime uint16) time.Time {
	return time.Date(
		int(dosDate>>9+1980),
		time.Month(dosDate>>5&0xf),
		int(dosDate&0x1f),
		int(dosTime>>11),
		int(dosTime>>5&0x3f),
		int(dosTime&0x1f*2),
		0, time.UTC,
	)
}

func timeToMsDosTime(t time.Time) (fDate uint16, fTime uint16) {
	// #nosec G115 -- APPNOTE 4.4.6: the MS-DOS date is a 16-bit field holding day, month and year-1980, and a year outside 1980-2107 has no spelling in it at all
	fDate = uint16(t.Day() + int(t.Month())<<5 + (t.Year()-1980)<<9)
	// #nosec G115 -- APPNOTE 4.4.6: the MS-DOS time is a 16-bit field holding two-second units, minutes and hours, all of which fit by construction
	fTime = uint16(t.Second()/2 + t.Minute()<<5 + t.Hour()<<11)
	return
}

// validateName reports whether name can be written as it stands.
//
// A reader rewrites every backslash in a name to a forward slash, which is the
// right thing for the separators a Windows archive carries inside a path. At
// the end of a name it changes what the entry is: a trailing forward slash is
// how the format says "directory", so an entry named `a\` comes back as the
// directory `a/` and its content is refused. Nothing tells it apart from a
// directory entry afterwards -- the rewrite has already happened by the time
// anything looks -- so the name is turned away here instead.
func validateName(name string) error {
	if strings.HasSuffix(name, `\`) {
		return fmt.Errorf("zip: file name %q ends in a backslash, which a reader reads as the separator that marks a directory entry: %w", name, ErrFormat)
	}
	return nil
}

// validateExtra reports whether extra is a well formed run of extra field
// records -- a two byte id, a two byte length, and that many bytes -- which is
// what the format says the area is and what a reader walks it as.
//
// A write path appends records of its own behind the caller's bytes: the
// WinZip AES record that names the salt and the strength an entry was
// encrypted under, the zip64 record that carries the real sizes of an entry
// over four gigabytes, the timestamps. A reader stops at the first record
// whose header or length does not fit, so a caller's stray byte hides
// everything written behind it -- and the entry comes back marked encrypted
// with nothing to describe how, its payload unrecoverable, with no error
// reported on the way out.
func validateExtra(extra []byte) error {
	for i := 0; i < len(extra); {
		if len(extra)-i < 4 {
			return fmt.Errorf("zip: extra field ends %d bytes into the four an extra field record begins with: %w", len(extra)-i, ErrFormat)
		}
		id := binary.LittleEndian.Uint16(extra[i : i+2])
		size := int(binary.LittleEndian.Uint16(extra[i+2 : i+4]))
		if rest := len(extra) - i - 4; rest < size {
			return fmt.Errorf("zip: extra field record %#04x declares %d bytes and %d are left: %w", id, size, rest, ErrFormat)
		}
		i += 4 + size
	}
	return nil
}

func (fh *FileHeader) injectAutoExtras() uint16 {
	// 1. Handle Method 99 (AES) recovery and idempotency
	originalMethod := fh.Method
	if isWinZipAesMethod(fh.Method) {
		// Already injected, try to recover original method from extra field
		for eb := readBuf(fh.Extra); len(eb) >= 4; {
			tag := eb.uint16()
			size := int(eb.uint16())
			if len(eb) < size {
				break
			}
			if tag == winzipAesExtraID {
				if info, ok := parseWinZipAesExtra(eb[:size]); ok {
					originalMethod = info.actualMethod
				}
				break
			}
			eb = eb[size:]
		}
	}

	// 2. Timestamps (0x5455)
	var extTimeFlags uint8
	if !fh.Modified.IsZero() {
		fh.ModifiedDate, fh.ModifiedTime = timeToMsDosTime(fh.Modified)
		extTimeFlags |= 1
	}
	if !fh.Accessed.IsZero() {
		extTimeFlags |= 2
	}
	if !fh.Created.IsZero() {
		extTimeFlags |= 4
	}

	// Helper to check or remove tags
	findTag := func(id uint16) (int, int) {
		offset := 0
		for eb := readBuf(fh.Extra); len(eb) >= 4; {
			tag := eb.uint16()
			size := int(eb.uint16())
			if tag == id {
				return offset, 4 + size
			}
			if len(eb) < size {
				break
			}
			eb = eb[size:]
			offset += 4 + size
		}
		return -1, 0
	}

	/*
		removeTag := func(id uint16) {
			off, size := findTag(id)
			if off >= 0 {
				newExtra := make([]byte, 0, len(fh.Extra)-size)
				newExtra = append(newExtra, fh.Extra[:off]...)
				newExtra = append(newExtra, fh.Extra[off+size:]...)
				fh.Extra = newExtra
			}
		}
	*/

	hasTag := func(id uint16) bool {
		off, _ := findTag(id)
		return off >= 0
	}

	if extTimeFlags > 0 && !hasTag(extTimeExtraID) {
		var size uint16 = 1
		if extTimeFlags&1 != 0 {
			size += 4
		}
		if extTimeFlags&2 != 0 {
			size += 4
		}
		if extTimeFlags&4 != 0 {
			size += 4
		}

		buf := make([]byte, 4+size)
		eb := writeBuf(buf)
		eb.uint16(extTimeExtraID)
		eb.uint16(size)
		eb.uint8(extTimeFlags)
		// The extended timestamp (Info-ZIP 0x5455) holds each time as
		// four bytes of Unix time, so what is written is the low 32 bits
		// whatever the time is; a reader of the tag puts them back the
		// same way. Nothing wider exists in the tag to write instead.
		if extTimeFlags&1 != 0 {
			// #nosec G115 -- Info-ZIP 0x5455: the field is four bytes of Unix time and this is the whole of it
			eb.uint32(uint32(fh.Modified.Unix()))
		}
		if extTimeFlags&2 != 0 {
			// #nosec G115 -- Info-ZIP 0x5455: the field is four bytes of Unix time and this is the whole of it
			eb.uint32(uint32(fh.Accessed.Unix()))
		}
		if extTimeFlags&4 != 0 {
			// #nosec G115 -- Info-ZIP 0x5455: the field is four bytes of Unix time and this is the whole of it
			eb.uint32(uint32(fh.Created.Unix()))
		}
		fh.Extra = append(fh.Extra, buf...)
	}

	// 3. Unix IDs (0x7875)
	if fh.OwnerSet && !hasTag(infoZipNewUnixExtraID) {
		fh.Extra = appendUnixExtra(fh.Extra, fh.Uid, fh.Gid)
	}

	// 3.1 Hardlinks & Devices (0x000d)
	if (fh.Linkname != "" || fh.Mode()&(fs.ModeDevice|fs.ModeCharDevice) != 0) && !hasTag(unixExtraID) {
		fh.Extra = appendUnix000dExtra(fh.Extra, fh)
	}
	// The flag goes on only once the tag is there: a flagged entry whose
	// target was left out for being too long is a link to nothing, while
	// the same entry unflagged is still an empty file.
	if fh.marksHardLink() && hasTag(unixExtraID) {
		fh.ExternalAttrs |= pkwareHardLinkAttr
	}

	// 3.2 Xattrs (0x7811)
	if len(fh.Xattrs) > 0 && !hasTag(xattrExtraID) {
		fh.Extra = appendXattrs(fh.Extra, fh.Xattrs)
	}

	// 3.3 NTFS ACLs (0x4453)
	if len(fh.Acl) > 0 && !hasTag(ntfsAclExtraID) {
		fh.Extra = appendNtfsAcl(fh.Extra, fh.Acl)
	}

	// 3.4 Unix Owner/Group Strings (0x7812)
	if (fh.Uname != "" || fh.Gname != "") && !hasTag(unixOwnerNameExtraID) {
		fh.Extra = appendUnixOwnerNamesExtra(fh.Extra, fh.Uname, fh.Gname)
	}

	// 3.5 Unicode Comment (0x6375)
	if fh.Comment != "" && !hasTag(unicodeCommentExtraID) {
		commentBytes := []byte(fh.Comment)
		crc := crc32.ChecksumIEEE([]byte(fh.Comment))

		payload := make([]byte, 5+len(commentBytes))
		payload[0] = 1 // Version
		binary.LittleEndian.PutUint32(payload[1:5], crc)
		copy(payload[5:], commentBytes)

		// A comment with no room left for the five bytes of header the
		// tag carries is left out of the extra field: the comment
		// itself is still written to the entry, and a length that has
		// wrapped would make every following tag unreadable.
		if payloadLen, err := fitUint16(len(payload), "Unicode comment extra field"); err == nil {
			buf := make([]byte, 4+len(payload))
			binary.LittleEndian.PutUint16(buf[0:2], unicodeCommentExtraID)
			binary.LittleEndian.PutUint16(buf[2:4], payloadLen)
			copy(buf[4:], payload)
			fh.Extra = append(fh.Extra, buf...)
		}
	}

	// 4. AES Encryption (0x9901)
	//
	// A directory holds no data to encrypt and is left unmarked, as the
	// WinZip AES specification recommends (section V.A) and as 7-Zip writes
	// it; a zero-length file is encrypted like any other.
	if fh.Password != "" && !isWinZipAesMethod(fh.Method) && !strings.HasSuffix(fh.Name, "/") {
		fh.Flags |= 0x1 // Set Encryption bit
		if fh.AESStrength == 0 {
			fh.AESStrength = 3
		}
		fh.Method = winzipAesMethod
		buf := make([]byte, 11)
		binary.LittleEndian.PutUint16(buf[0:2], winzipAesExtraID)
		binary.LittleEndian.PutUint16(buf[2:4], 7)
		binary.LittleEndian.PutUint16(buf[4:6], 2) // vendor version: AE-2
		// vendor ID
		buf[6], buf[7] = 'A', 'E'
		buf[8] = fh.AESStrength
		binary.LittleEndian.PutUint16(buf[9:11], originalMethod)
		fh.Extra = append(fh.Extra, buf...)
	}
	return originalMethod
}
func (h *FileHeader) ModTime() time.Time {
	return msDosTimeToTime(h.ModifiedDate, h.ModifiedTime)
}

func (h *FileHeader) SetModTime(t time.Time) {
	t = t.UTC()
	h.Modified = t
	h.ModifiedDate, h.ModifiedTime = timeToMsDosTime(t)
}

const (
	s_IFMT   = 0xf000
	s_IFSOCK = 0xc000
	s_IFLNK  = 0xa000
	s_IFREG  = 0x8000
	s_IFBLK  = 0x6000
	s_IFDIR  = 0x4000
	s_IFCHR  = 0x2000
	s_IFIFO  = 0x1000
	s_ISUID  = 0x800
	s_ISGID  = 0x400
	s_ISVTX  = 0x200

	msdosDir      = 0x10
	msdosReadOnly = 0x01
)

func (h *FileHeader) Mode() (mode fs.FileMode) {
	switch h.CreatorVersion >> 8 {
	case creatorUnix, creatorMacOSX:
		mode = unixModeToFileMode(h.ExternalAttrs >> 16)
	case creatorNTFS, creatorVFAT, creatorFAT:
		mode = msdosModeToFileMode(h.ExternalAttrs)
	}
	if len(h.Name) > 0 && h.Name[len(h.Name)-1] == '/' {
		mode |= fs.ModeDir
	}
	return mode
}

func (h *FileHeader) SetMode(mode fs.FileMode) {
	h.CreatorVersion = h.CreatorVersion&0xff | creatorUnix<<8
	h.ExternalAttrs = fileModeToUnixMode(mode) << 16
	if mode&fs.ModeDir != 0 {
		h.ExternalAttrs |= msdosDir
	}
	if mode&0200 == 0 {
		h.ExternalAttrs |= msdosReadOnly
	}
}

func (h *FileHeader) isZip64() bool {
	return h.CompressedSize64 >= uint32max || h.UncompressedSize64 >= uint32max
}

func (h *FileHeader) hasDataDescriptor() bool {
	return h.Flags&0x8 != 0
}
func (h *FileHeader) IsEncrypted() bool {
	return h.Flags&0x1 != 0
}

func msdosModeToFileMode(m uint32) (mode fs.FileMode) {
	if m&msdosDir != 0 {
		mode = fs.ModeDir | 0777
	} else {
		mode = 0666
	}
	if m&msdosReadOnly != 0 {
		mode &^= 0222
	}
	return mode
}

func fileModeToUnixMode(mode fs.FileMode) uint32 {
	var m uint32
	switch mode & fs.ModeType {
	default:
		m = s_IFREG
	case fs.ModeDir:
		m = s_IFDIR
	case fs.ModeSymlink:
		m = s_IFLNK
	case fs.ModeNamedPipe:
		m = s_IFIFO
	case fs.ModeSocket:
		m = s_IFSOCK
	case fs.ModeDevice:
		m = s_IFBLK
	case fs.ModeDevice | fs.ModeCharDevice:
		m = s_IFCHR
	}
	if mode&fs.ModeSetuid != 0 {
		m |= s_ISUID
	}
	if mode&fs.ModeSetgid != 0 {
		m |= s_ISGID
	}
	if mode&fs.ModeSticky != 0 {
		m |= s_ISVTX
	}
	return m | uint32(mode&0777)
}

func unixModeToFileMode(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0777)
	switch m & s_IFMT {
	case s_IFBLK:
		mode |= fs.ModeDevice
	case s_IFCHR:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case s_IFDIR:
		mode |= fs.ModeDir
	case s_IFIFO:
		mode |= fs.ModeNamedPipe
	case s_IFLNK:
		mode |= fs.ModeSymlink
	case s_IFREG:
	case s_IFSOCK:
		mode |= fs.ModeSocket
	}
	if m&s_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if m&s_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if m&s_ISVTX != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}
