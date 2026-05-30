//go:build darwin
// +build darwin

package zip

import (
	"os"
	"syscall"

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
	return unix.Mknod(name, mode, int(dev))
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
	sz, err := unix.Llistxattr(path, nil)
	if err != nil || sz <= 0 {
		return nil
	}
	buf := make([]byte, sz)
	sz, err = unix.Llistxattr(path, buf)
	if err != nil {
		return nil
	}

	var keys []string
	for i, j := 0, 0; i < sz; i++ {
		if buf[i] == 0 {
			keys = append(keys, string(buf[j:i]))
			j = i + 1
		}
	}

	if len(keys) > 0 && hdr.Xattrs == nil {
		hdr.Xattrs = make(map[string]string)
	}

	for _, key := range keys {
		valSz, err := unix.Lgetxattr(path, key, nil)
		if err != nil || valSz <= 0 {
			continue
		}
		val := make([]byte, valSz)
		sz, err = unix.Lgetxattr(path, key, val)
		if err == nil {
			hdr.Xattrs[key] = string(val[:sz])
		}
	}
	return nil
}

func applyXattrs(path string, hdr *FileHeader) error {
	if len(hdr.Xattrs) == 0 {
		return nil
	}
	for k, v := range hdr.Xattrs {
		unix.Lsetxattr(path, k, []byte(v), 0)
	}
	return nil
}