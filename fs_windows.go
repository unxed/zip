//go:build windows
// +build windows

package zip

import (
	"os"
	"time"
)

func lchmod(name string, mode os.FileMode) error {
	if mode&os.ModeSymlink != 0 {
		return nil
	}
	return os.Chmod(name, mode)
}

func lchtimes(name string, mode os.FileMode, atime, mtime time.Time) error {
	if mode&os.ModeSymlink != 0 {
		return nil
	}
	return os.Chtimes(name, atime, mtime)
}

func lchown(name string, uid, gid int) error {
	return nil
}
func applyNtfsAcl(path string, acl []byte) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var secInfo uint32 = windows.OWNER_SECURITY_INFORMATION |
		windows.GROUP_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION

	return windows.SetFileSecurity(pathPtr, secInfo, (*byte)(unsafe.Pointer(&acl[0])))
}

import (
	"syscall"
	"unsafe"
	"golang.org/x/sys/windows"
)

func appendPlatformExtra(fi os.FileInfo, hdr *FileHeader, force bool) {
	if !force {
		return
	}

	// Попытка получить Windows Security Descriptor (ACL)
	pathPtr, err := windows.UTF16PtrFromString(hdr.Name)
	if err != nil {
		return
	}

	var secInfo uint32 = windows.OWNER_SECURITY_INFORMATION |
		windows.GROUP_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION

	var n uint32
	// Сначала узнаем размер
	windows.GetFileSecurity(pathPtr, secInfo, nil, 0, &n)
	if n == 0 {
		return
	}

	buf := make([]byte, n)
	err = windows.GetFileSecurity(pathPtr, secInfo, (*byte)(unsafe.Pointer(&buf[0])), n, &n)
	if err == nil {
		hdr.Acl = buf
	}
}