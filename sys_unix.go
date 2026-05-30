//go:build !windows
// +build !windows

package zip

import (
	"os"
	"syscall"
)

type hardlinkKey struct {
	dev uint64
	ino uint64
}

func getHardLinkTarget(fi os.FileInfo, seen map[hardlinkKey]string) string {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || sys.Nlink <= 1 {
		return ""
	}
	key := hardlinkKey{dev: uint64(sys.Dev), ino: uint64(sys.Ino)}
	if target, exists := seen[key]; exists {
		return target
	}
	return ""
}

func rememberHardLink(fi os.FileInfo, relPath string, seen map[hardlinkKey]string) {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || sys.Nlink <= 1 {
		return
	}
	key := hardlinkKey{dev: uint64(sys.Dev), ino: uint64(sys.Ino)}
	if _, exists := seen[key]; !exists {
		seen[key] = relPath
	}
}

func resolveIds(hdr *FileHeader, numericOwner bool) (int, int) {
	return hdr.Uid, hdr.Gid
}
