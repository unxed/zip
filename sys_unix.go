//go:build !windows
// +build !windows

package zip

import (
	"os"
	"strings"
)

func initSystemLocales() {
	lc := os.Getenv("LC_ALL")
	if lc == "" {
		lc = os.Getenv("LC_CTYPE")
	}
	if lc == "" {
		lc = os.Getenv("LANG")
	}
	if lc == "" || lc == "C" || lc == "POSIX" {
		return
	}

	lcBase := lc
	if idx := strings.IndexByte(lcBase, '.'); idx != -1 {
		lcBase = lcBase[:idx]
	}

	if oem, ok := lcToOemTable[lcBase]; ok {
		if enc := getEncodingByName(oem); enc != nil {
			OEMDecoder = enc.NewDecoder()
			SystemDecoder = OEMDecoder
		}
	}
	if ansi, ok := lcToAnsiTable[lcBase]; ok {
		if enc := getEncodingByName(ansi); enc != nil {
			ANSIDecoder = enc.NewDecoder()
		}
	}
}