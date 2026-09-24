//go:build windows

package zip

import "testing"

func TestCoverageWindowsNoopMetadataHelpers(t *testing.T) {
	rememberHardLink(nil, "path", map[hardlinkKey]string{})
	sysPlatformExtra(nil, &FileHeader{})
}