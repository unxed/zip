//go:build !windows
// +build !windows

package zip

import (
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"sync"

	"golang.org/x/sys/unix"
)

func lchmod(name string, mode os.FileMode) error {
	var flags int
	if runtime.GOOS == "linux" {
		if mode&os.ModeSymlink != 0 {
			return nil
		}
	} else {
		flags = unix.AT_SYMLINK_NOFOLLOW
	}

	err := unix.Fchmodat(unix.AT_FDCWD, name, uint32(mode), flags)
	if err != nil {
		return &os.PathError{Op: "lchmod", Path: name, Err: err}
	}
	return nil
}

func lchtimes(name string, mode os.FileMode, atime, mtime time.Time) error {
	at := unix.NsecToTimeval(atime.UnixNano())
	mt := unix.NsecToTimeval(mtime.UnixNano())
	tv := [2]unix.Timeval{at, mt}

	err := unix.Lutimes(name, tv[:])
	if err != nil {
		return &os.PathError{Op: "lchtimes", Path: name, Err: err}
	}
	return nil
}

func lchown(name string, uid, gid int) error {
	return os.Lchown(name, uid, gid)
}
func applyNtfsAcl(path string, acl []byte) error {
	return nil // No-op on Unix
}
func getFileSecurity(path string) ([]byte, error) {
	return nil, nil
}
func getAlternativeDataStreams(path string) ([]string, error) {
	return nil, nil
}

var (
	userCache   = make(map[uint32]string)
	groupCache  = make(map[uint32]string)
	idCacheLock sync.RWMutex
)

func getUsername(uid uint32) string {
	idCacheLock.RLock()
	name, ok := userCache[uid]
	idCacheLock.RUnlock()
	if ok {
		return name
	}
	idCacheLock.Lock()
	defer idCacheLock.Unlock()
	if name, ok := userCache[uid]; ok {
		return name
	}
	if u, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
		userCache[uid] = u.Username
		return u.Username
	}
	userCache[uid] = ""
	return ""
}

func getGroupname(gid uint32) string {
	idCacheLock.RLock()
	name, ok := groupCache[gid]
	idCacheLock.RUnlock()
	if ok {
		return name
	}
	idCacheLock.Lock()
	defer idCacheLock.Unlock()
	if name, ok := groupCache[gid]; ok {
		return name
	}
	if g, err := user.LookupGroupId(strconv.Itoa(int(gid))); err == nil {
		groupCache[gid] = g.Name
		return g.Name
	}
	groupCache[gid] = ""
	return ""
}
func appendPlatformExtra(fi os.FileInfo, hdr *FileHeader, force bool) {
	if !force {
		return
	}
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		hdr.Uid = int(stat.Uid)
		hdr.Gid = int(stat.Gid)
		hdr.OwnerSet = true
		if uname := getUsername(stat.Uid); uname != "" {
			hdr.Uname = uname
		}
		if gname := getGroupname(stat.Gid); gname != "" {
			hdr.Gname = gname
		}
	}
	sysPlatformExtra(fi, hdr)
}
