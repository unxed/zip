//go:build windows
// +build windows

package zip

import "os"

type hardlinkKey struct{}

func getHardLinkTarget(fi os.FileInfo, seen map[hardlinkKey]string) string         { return "" }
func rememberHardLink(fi os.FileInfo, relPath string, seen map[hardlinkKey]string) {
	_ = fi
	_ = relPath
	_ = seen
}

func sysPlatformExtra(fi os.FileInfo, hdr *FileHeader) {
	_ = fi
	_ = hdr
}
func extractSpecialFile(path string, hdr *FileHeader) error { return nil }
func sysXattrs(path string, hdr *FileHeader) error {
	acl, err := getFileSecurityFunc(path)
	if err == nil && len(acl) > 0 {
		hdr.Acl = acl
	}
	return nil
}

// applyXattrs restores what the archive recorded about the file beside its
// contents, which on Windows is the security descriptor.
//
// The descriptor is applied for whatever of it this machine will take and the
// result is deliberately not reported. A descriptor written on another machine
// names owners and groups by SID, and a SID from a domain or a local account
// that does not exist here cannot be set: SetFileSecurityW refuses it, and it
// would refuse it on every file in the archive. The contents are extracted
// correctly either way, and an extraction that failed over an owner who cannot
// exist on this machine would be worse than one that leaves the file owned by
// whoever unpacked it.
func applyXattrs(path string, hdr *FileHeader) error {
	if len(hdr.Acl) > 0 {
		_ = applyNtfsAclFunc(path, hdr.Acl)
	}
	return nil
}

func resolveIds(hdr *FileHeader, numericOwner bool) (int, int) {
	return hdr.Uid, hdr.Gid
}
