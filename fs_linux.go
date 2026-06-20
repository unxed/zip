//go:build linux
// +build linux

package zip

import (
	"golang.org/x/sys/unix"
	"os"
)

func preallocate(f *os.File, size int64) error {
	if size <= 0 {
		return nil
	}
	err := unix.Fallocate(int(f.Fd()), 0, 0, size)
	if err != nil {
		// Ignore filesystem-unsupported errors as preallocation is a performance optimization
		if err == unix.EOPNOTSUPP || err == unix.ENOSYS || err == unix.ENOTTY || err == unix.EINVAL {
			return nil
		}
	}
	return err
}
