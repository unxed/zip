//go:build windows
// +build windows

package zip

import (
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

func lchown(name string, uid, gid int) error {
	return nil
}

var (
	modadvapi32          = syscall.NewLazyDLL("advapi32.dll")
	procGetFileSecurityW = modadvapi32.NewProc("GetFileSecurityW")
	procSetFileSecurityW = modadvapi32.NewProc("SetFileSecurityW")
	modkernel32          = syscall.NewLazyDLL("kernel32.dll")
	procFindFirstStreamW = modkernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW  = modkernel32.NewProc("FindNextStreamW")
	procFindClose        = modkernel32.NewProc("FindClose")
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
	return f.Truncate(size) // On Windows, Truncate physically extends the file and allocates space
}
