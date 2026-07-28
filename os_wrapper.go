package zip

import (
	"path/filepath"
	"runtime"
	"strings"
)

// fixOSPath adds the \\?\ prefix on Windows to prevent the Win32 API
// from automatically stripping trailing dots and spaces from file names.
func fixOSPath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	if p == "" {
		return p
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if strings.HasPrefix(abs, `\\?\`) {
		return abs
	}
	if strings.HasPrefix(abs, `\\`) {
		return `\\?\UNC\` + abs[2:]
	}
	return `\\?\` + abs
}