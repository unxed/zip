//go:build windows
// +build windows

package zip

import (
	"fmt"
	"syscall"

	"golang.org/x/text/encoding/htmlindex"
)

func initSystemLocales() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getACP := kernel32.NewProc("GetACP")
	getOEMCP := kernel32.NewProc("GetOEMCP")

	if acp, _, _ := getACP.Call(); acp != 0 {
		if enc, err := htmlindex.Get(fmt.Sprintf("windows-%d", acp)); err == nil {
			ANSIDecoder = enc.NewDecoder()
		}
	}
	if oemcp, _, _ := getOEMCP.Call(); oemcp != 0 {
		if enc, err := htmlindex.Get(fmt.Sprintf("cp%d", oemcp)); err == nil {
			OEMDecoder = enc.NewDecoder()
			SystemDecoder = OEMDecoder
		}
	}
}