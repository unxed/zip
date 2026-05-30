//go:build freebsd
// +build freebsd

package zip

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func sysPlatformExtra(fi os.FileInfo, hdr *FileHeader) {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}

	switch fi.Mode() & os.ModeType {
	case os.ModeDevice | os.ModeCharDevice:
		hdr.Devmajor = int64(unix.Major(uint64(sys.Rdev)))
		hdr.Devminor = int64(unix.Minor(uint64(sys.Rdev)))
	case os.ModeDevice:
		hdr.Devmajor = int64(unix.Major(uint64(sys.Rdev)))
		hdr.Devminor = int64(unix.Minor(uint64(sys.Rdev)))
	}
}

func mknod(name string, mode uint32, dev uint64) error {
	return unix.Mknod(name, mode, dev)
}

func extractSpecialFile(path string, hdr *FileHeader) error {
	os.Remove(path) // Ignore error
	mode := uint32(hdr.Mode()) & 0777
	if hdr.Mode()&os.ModeCharDevice != 0 {
		mode |= unix.S_IFCHR
	} else if hdr.Mode()&os.ModeDevice != 0 {
		mode |= unix.S_IFBLK
	} else if hdr.Mode()&os.ModeNamedPipe != 0 {
		mode |= unix.S_IFIFO
	}
	dev := unix.Mkdev(uint32(hdr.Devmajor), uint32(hdr.Devminor))
	return mknod(path, mode, dev)
}

func sysXattrs(path string, hdr *FileHeader) error {
	namespaces := []struct {
		ns     int
		prefix string
	}{
		{unix.EXTATTR_NAMESPACE_USER, "user."},
		{unix.EXTATTR_NAMESPACE_SYSTEM, "system."},
	}

	for _, n := range namespaces {
		// 1. Query size of list (passing 0 and 0 under FreeBSD API)
		sz, err := unix.ExtattrListLink(path, n.ns, 0, 0)
		if err != nil || sz <= 0 {
			continue
		}

		buf := make([]byte, sz)
		sz, err = unix.ExtattrListLink(path, n.ns, uintptr(unsafe.Pointer(&buf[0])), len(buf))
		if err != nil {
			continue
		}

		if hdr.Xattrs == nil {
			hdr.Xattrs = make(map[string]string)
		}

		for i := 0; i < sz; {
			l := int(buf[i])
			i++
			if i+l > sz {
				break
			}
			key := string(buf[i : i+l])
			i += l

			// 2. Query size of attribute value
			valSz, err := unix.ExtattrGetLink(path, n.ns, key, 0, 0)
			if err != nil || valSz <= 0 {
				continue
			}

			val := make([]byte, valSz)
			valSz, err = unix.ExtattrGetLink(path, n.ns, key, uintptr(unsafe.Pointer(&val[0])), len(val))
			if err == nil {
				hdr.Xattrs[n.prefix+key] = string(val[:valSz])
			}
		}
	}
	return nil
}

func applyXattrs(path string, hdr *FileHeader) error {
	if len(hdr.Xattrs) == 0 {
		return nil
	}
	for k, v := range hdr.Xattrs {
		ns := unix.EXTATTR_NAMESPACE_USER
		attrName := k
		if len(k) > 7 && k[:7] == "system." {
			ns = unix.EXTATTR_NAMESPACE_SYSTEM
			attrName = k[7:]
		} else if len(k) > 5 && k[:5] == "user." {
			attrName = k[5:]
		}

		var ptr uintptr
		if len(v) > 0 {
			bytesVal := []byte(v)
			ptr = uintptr(unsafe.Pointer(&bytesVal[0]))
		}

		unix.ExtattrSetLink(path, ns, attrName, ptr, len(v))
	}
	return nil
}
