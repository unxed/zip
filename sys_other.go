//go:build !linux && !freebsd && !darwin && !windows
// +build !linux,!freebsd,!darwin,!windows

package zip

import "os"

func sysPlatformExtra(fi os.FileInfo, hdr *FileHeader) {}
func extractSpecialFile(path string, hdr *FileHeader) error { return nil }
func sysXattrs(path string, hdr *FileHeader) error { return nil }
func applyXattrs(path string, hdr *FileHeader) error { return nil }