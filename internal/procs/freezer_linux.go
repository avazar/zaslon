package procs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const cgroupMount = "/sys/fs/cgroup"

func unifiedGroup(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		path, ok := strings.CutPrefix(line, "0::")
		if ok && filepath.IsAbs(path) && path == filepath.Clean(path) {
			return filepath.Join(cgroupMount, path), nil
		}
	}
	return "", errors.New("no accessible unified cgroup")
}

func groupPrefix(p Proc) string { return fmt.Sprintf(".zaslon-%d-", p.PID) }

func groupInode(path string) (uint64, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return 0, err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return 0, errors.New("not cgroup v2")
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) {
		return 0, errors.New("not a private cgroup of this user")
	}
	return st.Ino, nil
}

func (g *FreezerGroup) check(p Proc) error {
	if !strings.HasPrefix(g.Path, cgroupMount+"/") || filepath.Clean(g.Path) != g.Path ||
		!strings.HasPrefix(filepath.Base(g.Path), groupPrefix(p)) {
		return errors.New("invalid freezer group in journal")
	}
	inode, err := groupInode(g.Path)
	if err != nil {
		return err
	}
	if inode != g.Inode {
		return errors.New("freezer group was replaced")
	}
	return nil
}

func groupWrite(dir, file, value string) error {
	f, err := os.OpenFile(filepath.Join(dir, file), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(value)
	return err
}

func groupMembers(dir string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	return strings.Fields(string(b)), err
}

func exclusive(dir string, pid int) bool {
	members, err := groupMembers(dir)
	return err == nil && len(members) == 1 && members[0] == strconv.Itoa(pid)
}

func waitFrozen(dir string) error {
	deadline := time.Now().Add(250 * time.Millisecond)
	for {
		b, err := os.ReadFile(filepath.Join(dir, "cgroup.events"))
		if err != nil {
			return err
		}
		if strings.Contains("\n"+string(b), "\nfrozen 1\n") {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("freezer did not confirm suspension")
		}
		time.Sleep(time.Millisecond)
	}
}

// cgroup.procs accepts a numeric PID. Check both birth and source membership
// immediately before migration, then verify arrival before freezing the leaf.
func moveMember(p Proc, from, to string) error {
	actual, err := unifiedGroup(p.PID)
	if err != nil {
		return err
	}
	born, err := processIdentity(p.PID)
	if err != nil {
		return err
	}
	if actual != from || born != p.Created {
		return errors.New("process or cgroup identity changed")
	}
	return groupWrite(to, "cgroup.procs", strconv.Itoa(p.PID))
}

// Return inherited children as well if one forked during the narrow interval
// between migration and the kernel confirming the freeze. No SIGCONT is sent.
func (g *FreezerGroup) restore(p Proc) error {
	if err := g.check(p); err != nil {
		return err
	}
	if err := groupWrite(g.Path, "cgroup.freeze", "0"); err != nil {
		return err
	}
	parent := filepath.Dir(g.Path)
	for attempt := 0; attempt < 4; attempt++ {
		members, err := groupMembers(g.Path)
		if err != nil {
			return err
		}
		for _, member := range members {
			pid, err := strconv.Atoi(member)
			if err != nil {
				return err
			}
			birth, err := processIdentity(pid)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			if err := moveMember(Proc{PID: pid, Created: birth}, g.Path, parent); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ESRCH) {
				return err
			}
		}
		err = os.Remove(g.Path)
		if !errors.Is(err, unix.EBUSY) && !errors.Is(err, unix.ENOTEMPTY) {
			return err
		}
	}
	return errors.New("could not empty private freezer group")
}

func (c *osController) FreezeTracked(p Proc, remember func(*FreezerGroup) error) (*FreezerGroup, error) {
	var used *FreezerGroup
	err := withUnixSignalTarget(p, openUnixSignalTarget, func(target unixSignalTarget, stopped bool) error {
		if stopped {
			return errors.Join(ErrNotApplied, ErrAlreadyStopped)
		}
		fallback := func() error { return sendUnixSignal(target, syscall.SIGSTOP) }
		parent, err := unifiedGroup(p.PID)
		if err != nil || strings.HasPrefix(filepath.Base(parent), ".zaslon-") {
			return fallback()
		}
		// Never change the host's delegation or controller settings.
		var fs unix.Statfs_t
		if unix.Statfs(parent, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
			return fallback()
		}
		dir, err := os.MkdirTemp(parent, groupPrefix(p))
		if err != nil {
			return fallback()
		}
		inode, err := groupInode(dir)
		if err != nil {
			_ = os.Remove(dir)
			return fallback()
		}
		group := &FreezerGroup{Path: dir, Inode: inode}
		if err := groupWrite(dir, "cgroup.freeze", "0"); err != nil {
			_ = os.Remove(dir)
			return fallback()
		}
		if err := remember(group); err != nil {
			_ = os.Remove(dir)
			return errors.Join(ErrNotApplied, err)
		}
		if err := moveMember(p, parent, dir); err != nil {
			_ = os.Remove(dir)
			return fallback()
		}
		born, nowStopped, err := target.snapshot()
		if err == nil && born == p.Created && !nowStopped && exclusive(dir, p.PID) {
			if groupWrite(dir, "cgroup.freeze", "1") == nil && waitFrozen(dir) == nil && exclusive(dir, p.PID) {
				used = group
				return nil
			}
		}
		// Install the strict stop on the original pidfd before removing any
		// temporary freezer hold. A fork or a failed freezer must not fail open.
		var stopErr error
		if nowStopped {
			stopErr = errors.Join(ErrNotApplied, ErrAlreadyStopped)
		} else {
			stopErr = fallback()
		}
		if err := group.restore(p); err != nil {
			return fmt.Errorf("freezer rollback: %v (signal: %v)", err, stopErr)
		}
		return stopErr
	})
	if err == nil && used == nil && c.fallbackNotice != nil {
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p.PID))
		fields := strings.Fields(string(b)[strings.LastIndexByte(string(b), ')')+1:])
		if len(fields) > 4 && fields[4] != "0" {
			c.noticeOnce.Do(c.fallbackNotice)
		}
	}
	return used, err
}

func (c *osController) ReleaseGroup(p Proc, g *FreezerGroup) error {
	if err := g.check(p); err != nil {
		return errors.Join(ErrNotApplied, err)
	}
	if !exclusive(g.Path, p.PID) {
		// An exited process can leave an empty leaf before the next prune.
		if err := c.ForgetGroup(p, g); err == nil {
			return nil
		}
		return errors.Join(ErrNotApplied, errors.New("unexpected freezer group membership"))
	}
	born, err := processIdentity(p.PID)
	if err != nil || born != p.Created {
		return errors.Join(ErrNotApplied, errors.New("freezer process identity changed"), err)
	}
	return g.restore(p)
}

func (c *osController) ForgetGroup(p Proc, g *FreezerGroup) error {
	err := g.check(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// rmdir only succeeds for an empty group. Never thaw a populated orphan.
	return os.Remove(g.Path)
}
