//go:build linux
// +build linux

package zip

import (
	"os"
	"golang.org/x/sys/unix"
)

func preallocate(f *os.File, size int64) error {
	if size <= 0 {
		return nil
	}
	return unix.Fallocate(int(f.Fd()), 0, 0, size)
}