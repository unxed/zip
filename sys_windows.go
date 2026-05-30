//go:build windows
// +build windows

package zip

import "os"

type hardlinkKey struct{}

func getHardLinkTarget(fi os.FileInfo, seen map[hardlinkKey]string) string { return "" }
func rememberHardLink(fi os.FileInfo, relPath string, seen map[hardlinkKey]string) {}

func sysPlatformExtra(fi os.FileInfo, hdr *FileHeader) {}
func extractSpecialFile(path string, hdr *FileHeader) error { return nil }
func sysXattrs(path string, hdr *FileHeader) error {
	acl, err := getFileSecurityFunc(path)
	if err == nil && len(acl) > 0 {
		hdr.Acl = acl
	}
	return nil
}
func applyXattrs(path string, hdr *FileHeader) error {
	if len(hdr.Acl) > 0 {
		applyNtfsAclFunc(path, hdr.Acl)
	}
	return nil
}

func resolveIds(hdr *FileHeader, numericOwner bool) (int, int) {
	return hdr.Uid, hdr.Gid
}
