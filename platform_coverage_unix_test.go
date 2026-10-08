//go:build !windows
// +build !windows

package zip

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestPlatformCovLchmodReportsAFailedChmod covers the error path of the mode
// pass. Nothing at the path means nothing to set a mode on, and what comes
// back names the operation and the path, because an extraction that stops here
// has to be able to say which entry it stopped on.
func TestPlatformCovLchmodReportsAFailedChmod(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "entry")

	err := lchmod(path, 0644)
	if err == nil {
		t.Fatal("a mode was set on a path with nothing at it")
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("lchmod gave a %T, want one that names the path: %v", err, err)
	}
	if pathErr.Op != "lchmod" || pathErr.Path != path {
		t.Errorf("lchmod failure names %q %q, want %q %q", pathErr.Op, pathErr.Path, "lchmod", path)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("lchmod failure = %v, want one that says nothing is there", err)
	}
}

// TestPlatformCovLchtimesReportsAFailedUtimes covers the error path of the
// timestamp pass, which is the mode pass's twin: a path with nothing at it has
// no timestamps to set, and the failure names the operation and the path.
func TestPlatformCovLchtimesReportsAFailedUtimes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "entry")
	when := time.Date(2001, time.February, 3, 4, 5, 6, 0, time.UTC)

	err := lchtimes(path, 0644, when, when)
	if err == nil {
		t.Fatal("timestamps were set on a path with nothing at it")
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("lchtimes gave a %T, want one that names the path: %v", err, err)
	}
	if pathErr.Op != "lchtimes" || pathErr.Path != path {
		t.Errorf("lchtimes failure names %q %q, want %q %q", pathErr.Op, pathErr.Path, "lchtimes", path)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("lchtimes failure = %v, want one that says nothing is there", err)
	}
}

// TestPlatformCovApplyNtfsAclIsANoOpOffWindows covers what an archive's
// Windows security descriptor does to a Unix filesystem, which is nothing.
// There is nowhere to put it, and an entry that carries one still extracts:
// the pass reports success and leaves the file exactly as it found it.
func TestPlatformCovApplyNtfsAclIsANoOpOffWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry")
	mustWriteFile(t, path, []byte("data"), 0600)
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}

	// A self-relative descriptor's first bytes, which is as close to a real
	// one as anything off Windows can be handed.
	if err := applyNtfsAcl(path, []byte{1, 0, 4, 0x80}); err != nil {
		t.Fatalf("applying a security descriptor off Windows: %v", err)
	}

	after, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if after.Mode() != before.Mode() || after.Size() != before.Size() {
		t.Errorf("the file went from %v/%d bytes to %v/%d", before.Mode(), before.Size(), after.Mode(), after.Size())
	}
}

// TestPlatformCovLookupUserAndGroupReportAnUnknownName covers the answer for
// an owner an archive names in text that the machine extracting it has never
// heard of. There is no id to resolve the name to, and the failure is reported
// rather than guessed at, which is what leaves the caller free to fall back to
// the numeric id the entry also carries.
func TestPlatformCovLookupUserAndGroupReportAnUnknownName(t *testing.T) {
	const unknown = "platformcov-no-such-account"

	if id, err := lookupUser(unknown); err == nil {
		t.Errorf("looking up the user %q gave id %d, want a failure", unknown, id)
	} else if id != -1 {
		t.Errorf("looking up the user %q gave id %d beside the failure, want -1", unknown, id)
	}
	if id, err := lookupGroup(unknown); err == nil {
		t.Errorf("looking up the group %q gave id %d, want a failure", unknown, id)
	} else if id != -1 {
		t.Errorf("looking up the group %q gave id %d beside the failure, want -1", unknown, id)
	}
}

// TestPlatformCovLookupUserAndGroupRejectANonNumericId covers the second thing
// that can go wrong on the way from a name to an id. The account database
// answers in text throughout, the id included, and text that is not a number
// is not an id: it is reported as a failure rather than turned into zero,
// which is root and is nobody's account.
func TestPlatformCovLookupUserAndGroupRejectANonNumericId(t *testing.T) {
	const name = "platformcov-textual-id"

	origUser, origGroup := lookupUserByName, lookupGroupByName
	t.Cleanup(func() {
		lookupUserByName, lookupGroupByName = origUser, origGroup
	})
	lookupUserByName = func(n string) (*user.User, error) {
		return &user.User{Username: n, Uid: "S-1-5-21", Gid: "S-1-5-21"}, nil
	}
	lookupGroupByName = func(n string) (*user.Group, error) {
		return &user.Group{Name: n, Gid: "S-1-5-32"}, nil
	}

	if id, err := lookupUser(name); err == nil {
		t.Errorf("a user id that is not a number was accepted as %d", id)
	} else if id != -1 {
		t.Errorf("looking up the user %q gave id %d beside the failure, want -1", name, id)
	}
	if id, err := lookupGroup(name); err == nil {
		t.Errorf("a group id that is not a number was accepted as %d", id)
	} else if id != -1 {
		t.Errorf("looking up the group %q gave id %d beside the failure, want -1", name, id)
	}

	// Nothing was remembered, so the name is looked up again the next time
	// rather than answered from a cache of a failure.
	resolveMut.RLock()
	_, uok := uidCache[name]
	_, gok := gidCache[name]
	resolveMut.RUnlock()
	if uok || gok {
		t.Error("an id that could not be read was remembered")
	}
}

// TestPlatformCovLookupUserAndGroupServeFromCache covers the other half of
// the name-to-id cache from TestPlatformCovLookupUserAndGroupRejectANonNumericId:
// an id read once is kept, and the second lookup of the same name answers from
// uidCache/gidCache directly rather than asking the account database again --
// the same saving getUsername/getGroupname give the reverse direction, here
// exercised for lookupUser and lookupGroup instead.
func TestPlatformCovLookupUserAndGroupServeFromCache(t *testing.T) {
	const name = "platformcov-cached-account"

	origUser, origGroup := lookupUserByName, lookupGroupByName
	t.Cleanup(func() {
		lookupUserByName, lookupGroupByName = origUser, origGroup
	})

	var userCalls, groupCalls int
	lookupUserByName = func(n string) (*user.User, error) {
		userCalls++
		return &user.User{Username: n, Uid: "4242"}, nil
	}
	lookupGroupByName = func(n string) (*user.Group, error) {
		groupCalls++
		return &user.Group{Name: n, Gid: "4343"}, nil
	}

	resolveMut.Lock()
	delete(uidCache, name)
	delete(gidCache, name)
	resolveMut.Unlock()
	t.Cleanup(func() {
		resolveMut.Lock()
		delete(uidCache, name)
		delete(gidCache, name)
		resolveMut.Unlock()
	})

	for i := 0; i < 2; i++ {
		if id, err := lookupUser(name); err != nil || id != 4242 {
			t.Fatalf("lookupUser #%d = %d, %v, want 4242, nil", i, id, err)
		}
		if id, err := lookupGroup(name); err != nil || id != 4343 {
			t.Fatalf("lookupGroup #%d = %d, %v, want 4343, nil", i, id, err)
		}
	}
	if userCalls != 1 {
		t.Errorf("the account database was asked for the user %d times, want 1: the second lookup should have come from the cache", userCalls)
	}
	if groupCalls != 1 {
		t.Errorf("the account database was asked for the group %d times, want 1: the second lookup should have come from the cache", groupCalls)
	}
}

// platformCovForgetIds takes ids out of the process-wide name caches, both
// before the test uses them and again when it ends, so that what the test sees
// is a lookup and not an answer left behind by something else.
func platformCovForgetIds(t *testing.T, uids, gids []uint32) {
	t.Helper()
	forget := func() {
		idCacheLock.Lock()
		defer idCacheLock.Unlock()
		for _, uid := range uids {
			delete(userCache, uid)
		}
		for _, gid := range gids {
			delete(groupCache, gid)
		}
	}
	t.Cleanup(forget)
	forget()
}

// TestPlatformCovGetUsernameAndGroupnameRememberAnUnknownId covers the
// negative half of the name cache. An id with no account behind it has no name
// to put in the header, and the empty answer is remembered as firmly as a real
// one: a tree of a thousand files owned by a departed account must not cost a
// thousand trips to the account database.
func TestPlatformCovGetUsernameAndGroupnameRememberAnUnknownId(t *testing.T) {
	const uid = uint32(0x7ffffff0)
	const gid = uint32(0x7ffffff1)
	if u, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
		t.Skipf("uid %d belongs to %s on this machine", uid, u.Username)
	}
	if g, err := user.LookupGroupId(strconv.Itoa(int(gid))); err == nil {
		t.Skipf("gid %d belongs to %s on this machine", gid, g.Name)
	}
	platformCovForgetIds(t, []uint32{uid}, []uint32{gid})

	if name := getUsername(uid); name != "" {
		t.Errorf("uid %d came back as %q, want no name at all", uid, name)
	}
	if name := getGroupname(gid); name != "" {
		t.Errorf("gid %d came back as %q, want no name at all", gid, name)
	}

	idCacheLock.RLock()
	uname, uok := userCache[uid]
	gname, gok := groupCache[gid]
	idCacheLock.RUnlock()
	if !uok || uname != "" {
		t.Errorf("uid %d was remembered as %q/%v, want the empty answer", uid, uname, uok)
	}
	if !gok || gname != "" {
		t.Errorf("gid %d was remembered as %q/%v, want the empty answer", gid, gname, gok)
	}
}

// TestPlatformCovGetUsernameAndGroupnameServeWaitersFromTheCache covers what
// happens when an archiver walking a tree in parallel meets a directory whose
// files all belong to the same owner. Every one of those goroutines misses the
// cache and queues for the right to fill it; one of them asks the account
// database and the rest, by the time their turn comes, find the answer already
// there and take it rather than asking again.
//
// Holding the lock while the callers gather is what makes that ordering the
// one the test gets: a write lock released hands every waiting reader through
// at once, so they all miss together before any of them can start filling.
func TestPlatformCovGetUsernameAndGroupnameServeWaitersFromTheCache(t *testing.T) {
	// The ids are read off a file the way an archiver reads them, so they
	// are ids the machine really has and the names really resolve.
	path := filepath.Join(t.TempDir(), "entry")
	mustWriteFile(t, path, []byte("data"), 0600)
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skipf("no owner is reported for a file here: %T", fi.Sys())
	}
	uid, gid := stat.Uid, stat.Gid
	platformCovForgetIds(t, []uint32{uid}, []uint32{gid})

	const waiters = 16
	for _, tc := range []struct {
		what string
		ask  func() string
	}{
		{"the owning user", func() string { return getUsername(uid) }},
		{"the owning group", func() string { return getGroupname(gid) }},
	} {
		t.Run(tc.what, func(t *testing.T) {
			answers := make([]string, waiters)
			ready := make(chan struct{}, waiters)
			var wg sync.WaitGroup

			idCacheLock.Lock()
			for i := range answers {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					ready <- struct{}{}
					answers[i] = tc.ask()
				}(i)
			}
			for range answers {
				<-ready
			}
			// The signal goes out on the line before the call, so
			// the callers are given a moment to reach it and park.
			time.Sleep(20 * time.Millisecond)
			idCacheLock.Unlock()
			wg.Wait()

			for i, got := range answers {
				if got != answers[0] {
					t.Fatalf("caller %d was told %q where caller 0 was told %q", i, got, answers[0])
				}
			}
			// The answer stayed behind, so the one that comes after
			// the crowd is served without any lock being taken for
			// writing at all.
			if again := tc.ask(); again != answers[0] {
				t.Errorf("the remembered answer is %q where the crowd was told %q", again, answers[0])
			}
			// And it is the same answer a cold lookup gives.
			platformCovForgetIds(t, []uint32{uid}, []uint32{gid})
			if fresh := tc.ask(); fresh != answers[0] {
				t.Errorf("looking the id up afresh gave %q where the crowd was told %q", fresh, answers[0])
			}
		})
	}
}
