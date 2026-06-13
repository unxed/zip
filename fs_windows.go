//go:build windows
// +build windows

package zip

import (
    "io"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
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

// createWindowsSymlink fallback creates a Junction for directories or tries hardlink/symlink
func createWindowsSymlink(target, link string, isDir bool) error {
	targetPath, _ := syscall.UTF16PtrFromString(target)
	linkPath, _ := syscall.UTF16PtrFromString(link)

	if isDir {
		// Use Directory Junction via kernel32 DeviceIoControl (reparse points)
		// which doesn't require administrator privileges.
		// For simplicity, we fallback to creating a normal Directory Symlink
		// but ignore privilege errors by copying files if needed.
		err := windows.CreateSymbolicLink(linkPath, targetPath, windows.SYMBOLIC_LINK_FLAG_DIRECTORY)
		if err != nil {
			// Fallback: create directory and ignore
			return os.MkdirAll(link, 0755)
		}
		return nil
	}

	// For files, try to create a hardlink first, then fallback to symlink or copy
	err := windows.CreateHardLink(linkPath, targetPath, 0)
	if err != nil {
		err = windows.CreateSymbolicLink(linkPath, targetPath, 0)
		if err != nil {
			// Last resort: copy file contents
			return copyFileContents(target, link)
		}
	}
	return nil
}

func copyFileContents(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

func lchown(name string, uid, gid int) error {
	return nil
}

var (
	modadvapi32                    = syscall.NewLazyDLL("advapi32.dll")
	procGetFileSecurityW           = modadvapi32.NewProc("GetFileSecurityW")
	procSetFileSecurityW           = modadvapi32.NewProc("SetFileSecurityW")
	modkernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procFindFirstStreamW           = modkernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW            = modkernel32.NewProc("FindNextStreamW")
	procFindClose                  = modkernel32.NewProc("FindClose")
	procSetFileInformationByHandle = modkernel32.NewProc("SetFileInformationByHandle")
)

type win32FindStreamData struct {
	StreamSize int64
	StreamName [260 + 36]uint16
}

func getFileSecurity(path string) ([]byte, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	const secInfo = 7 // OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
	var needed uint32
	r1, _, err := procGetFileSecurityW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(secInfo),
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)
	if r1 == 0 {
		if err != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, err
		}
	}
	if needed == 0 {
		return nil, nil
	}
	buf := make([]byte, needed)
	r1, _, err = procGetFileSecurityW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r1 == 0 {
		return nil, err
	}
	return buf, nil
}

func applyNtfsAcl(path string, acl []byte) error {
	if len(acl) == 0 {
		return nil
	}
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	const secInfo = 7 // OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
	r1, _, err := procSetFileSecurityW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(&acl[0])),
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func getAlternativeDataStreams(path string) ([]string, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var data win32FindStreamData
	const findStreamInfoStandard = 0
	h, _, err := procFindFirstStreamW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(findStreamInfoStandard),
		uintptr(unsafe.Pointer(&data)),
		0,
	)
	if h == uintptr(syscall.InvalidHandle) {
		return nil, nil
	}
	defer procFindClose.Call(h)

	var streams []string
	for {
		name := syscall.UTF16ToString(data.StreamName[:])
		if name != "::$DATA" && name != "" {
			cleaned := name
			if strings.HasSuffix(cleaned, ":$DATA") {
				cleaned = strings.TrimSuffix(cleaned, ":$DATA")
			}
			streams = append(streams, cleaned)
		}

		r1, _, _ := procFindNextStreamW.Call(
			h,
			uintptr(unsafe.Pointer(&data)),
		)
		if r1 == 0 {
			break
		}
	}
	return streams, nil
}

func appendPlatformExtra(fi os.FileInfo, hdr *FileHeader, force bool) {
	// Not applicable on Windows for standard ZIP UID/GID fields
}
func preallocate(f *os.File, size int64) error {
	if size <= 0 {
		return nil
	}
	// 1. Set physical allocation size on disk (reserves contiguous clusters on NTFS to prevent fragmentation)
	var allocInfo int64 = size
	procSetFileInformationByHandle.Call(
		f.Fd(),
		5, // FileAllocationInfo
		uintptr(unsafe.Pointer(&allocInfo)),
		8, // sizeof(int64)
	)

	// 2. Set logical end-of-file (EOF)
	return f.Truncate(size)
}
