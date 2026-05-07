package zip

import (
	"io/fs"
	"encoding/binary"
	"path"
	"time"
)

// Compression methods.
const (
	Store     uint16 = 0 // no compression
	Deflate   uint16 = 8 // DEFLATE compressed
	Deflate64 uint16 = 9
	BZIP2     uint16 = 12
	LZMA    uint16 = 14
	ZSTD    uint16 = 93 // Zstandard compressed
)

const (
	fileHeaderSignature      = 0x04034b50
	directoryHeaderSignature = 0x02014b50
	directoryEndSignature    = 0x06054b50
	directory64LocSignature  = 0x07064b50
	directory64EndSignature  = 0x06064b50
	dataDescriptorSignature  = 0x08074b50 // de-facto standard; required by OS X Finder
	splitSignature           = 0x08074b50 // Сигнатура первого тома многотомного архива
	splitAltSignature        = 0x30304b50 // Альтернативная сигнатура (STPAN)
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
	extTimeExtraID        = 0x5455 // Extended timestamp
	infoZipUnixExtraID    = 0x5855 // Info-ZIP Unix extension
	unicodePathExtraID    = 0x7075 // Info-ZIP Unicode Path Extra Field
	unicodeCommentExtraID = 0x6375 // Info-ZIP Unicode Comment Extra Field
	winzipAesExtraID      = 0x9901 // WinZip AES encryption extra field
	ntfsAclExtraID        = 0x4453 // Windows NT Security Descriptor (ACL)
)
const (
	// Strong Encryption (SES) Algorithm IDs
	sesDES    = 0x6601
	sesRC2old = 0x6602
	ses3DES168 = 0x6603
	ses3DES112 = 0x6609
	sesAES128  = 0x660E
	sesAES192  = 0x660F
	sesAES256  = 0x6610
)
// ConfigIncludePlatformMetadata defines if FileInfoHeader should automatically
// include OS-specific metadata (like UID/GID on Unix).
// Disabled by default to ensure archive portability.
var ConfigIncludePlatformMetadata = false

// FileHeader describes a file within a ZIP file.
type FileHeader struct {
	Name               string
	Comment            string
	NonUTF8            bool // If set, disables automatic UTF-8 flag encoding
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
	// NTFS Attributes
	Acl      []byte // Windows Security Descriptor (ACL)

	// WinZip AES encryption
	Password    string
	AESStrength byte // 1 = 128, 2 = 192, 3 = 256. Defaults to 3 (AES-256) if Password != ""
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
		return int64(fi.fh.UncompressedSize64)
	}
	return int64(fi.fh.UncompressedSize)
}
func (fi headerFileInfo) IsDir() bool        { return fi.Mode().IsDir() }
func (fi headerFileInfo) ModTime() time.Time { return fi.fh.Modified.UTC() }
func (fi headerFileInfo) Mode() fs.FileMode  { return fi.fh.Mode() }
func (fi headerFileInfo) Type() fs.FileMode  { return fi.fh.Mode().Type() }
func (fi headerFileInfo) Sys() any           { return fi.fh }
func (fi headerFileInfo) Info() (fs.FileInfo, error) { return fi, nil }
func (fi headerFileInfo) String() string { return fs.FormatFileInfo(fi) }

func FileInfoHeader(fi fs.FileInfo) (*FileHeader, error) {
	size := fi.Size()
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
	encrypted          bool
	algId              uint16
	bitLen             uint16
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
	fDate = uint16(t.Day() + int(t.Month())<<5 + (t.Year()-1980)<<9)
	fTime = uint16(t.Second()/2 + t.Minute()<<5 + t.Hour()<<11)
	return
}

func (fh *FileHeader) injectAutoExtras() uint16 {
	// 1. Handle Method 99 (AES) recovery and idempotency
	originalMethod := fh.Method
	if fh.Method == winzipAesExtraID {
		// Already injected, try to recover original method from extra field
		for eb := readBuf(fh.Extra); len(eb) >= 4; {
			tag := eb.uint16()
			size := int(eb.uint16())
			if len(eb) < size {
				break
			}
			if tag == winzipAesExtraID && size >= 7 {
				eb.uint16() // version
				eb.uint8()  // strength
				eb.uint16() // vendor
				originalMethod = eb.uint16()
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

	// Simple check to avoid duplicate tag injection
	hasTag := func(id uint16) bool {
		for eb := readBuf(fh.Extra); len(eb) >= 4; {
			tag := eb.uint16()
			size := int(eb.uint16())
			if tag == id {
				return true
			}
			if len(eb) < size {
				break
			}
			eb = eb[size:]
		}
		return false
	}

	if extTimeFlags > 0 && !hasTag(extTimeExtraID) {
		var size uint16 = 1
		if extTimeFlags&1 != 0 { size += 4 }
		if extTimeFlags&2 != 0 { size += 4 }
		if extTimeFlags&4 != 0 { size += 4 }

		buf := make([]byte, 4+size)
		eb := writeBuf(buf)
		eb.uint16(extTimeExtraID)
		eb.uint16(size)
		eb.uint8(extTimeFlags)
		if extTimeFlags&1 != 0 { eb.uint32(uint32(fh.Modified.Unix())) }
		if extTimeFlags&2 != 0 { eb.uint32(uint32(fh.Accessed.Unix())) }
		if extTimeFlags&4 != 0 { eb.uint32(uint32(fh.Created.Unix())) }
		fh.Extra = append(fh.Extra, buf...)
	}

	// 3. Unix IDs (0x7875)
	if fh.OwnerSet && !hasTag(infoZipNewUnixExtraID) {
		fh.Extra = appendUnixExtra(fh.Extra, fh.Uid, fh.Gid)
	}

	// 3.1 NTFS ACLs (0x4453)
	if len(fh.Acl) > 0 && !hasTag(ntfsAclExtraID) {
		fh.Extra = appendNtfsAcl(fh.Extra, fh.Acl)
	}

	// 4. AES Encryption (0x9901)
	if fh.Password != "" && fh.Method != winzipAesExtraID {
		fh.Flags |= 0x1 // Set Encryption bit
		if fh.AESStrength == 0 {
			fh.AESStrength = 3
		}
		fh.Method = winzipAesExtraID
		buf := make([]byte, 11)
		binary.LittleEndian.PutUint16(buf[0:2], winzipAesExtraID)
		binary.LittleEndian.PutUint16(buf[2:4], 7)
		binary.LittleEndian.PutUint16(buf[4:6], 2) // AE-2
		buf[6] = fh.AESStrength
		binary.LittleEndian.PutUint16(buf[7:9], 0x4541)
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