//go:build !linux && !freebsd && !darwin && !windows
// +build !linux,!freebsd,!darwin,!windows

package zip

import "os"

type hardlinkKey struct{}

func getHardLinkTarget(fi os.FileInfo, seen map[hardlinkKey]string) string { return "" }
func rememberHardLink(fi os.FileInfo, relPath string, seen map[hardlinkKey]string) {}

func sysPlatformExtra(fi os.FileInfo, hdr *FileHeader) {}
func extractSpecialFile(path string, hdr *FileHeader) error { return nil }
func sysXattrs(path string, hdr *FileHeader) error { return nil }
func applyXattrs(path string, hdr *FileHeader) error { return nil }