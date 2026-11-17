package procs

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

type cached struct {
	start      int64
	path, args string
	control    controlRole
}

type osController struct {
	mu    sync.Mutex
	cache map[int]cached // pid -> exec path; keyed with start time so a reused pid is re-read
	own   string
}

func New() Controller { return &osController{cache: map[int]cached{}, own: executablePath()} }

func (c *osController) List() ([]Proc, error) {
	kps, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := make(map[int]bool, len(kps))
	out := make([]Proc, 0, len(kps))
	for i := range kps {
		kp := &kps[i]
		pid := int(kp.Proc.P_pid)
		if pid <= 0 {
			continue
		}
		seen[pid] = true
		start := kp.Proc.P_starttime.Sec*1_000_000 + int64(kp.Proc.P_starttime.Usec)
		ce, ok := c.cache[pid]
		if !ok || ce.start != start {
			// procargs2 is readable for our own user's processes, which is what we protect.
			path, argv := procArguments(pid)
			ce = cached{start: start, path: path, args: joinArgs(argv), control: ownRole(path, c.own, argv)}
			c.cache[pid] = ce
		}
		if ce.control != notControl {
			// An exec can retain PID and birth: do not exempt a replacement image.
			path, argv := procArguments(pid)
			ce.path, ce.args, ce.control = path, joinArgs(argv), ownRole(path, c.own, argv)
			c.cache[pid] = ce
		}
		name := filepath.Base(ce.path)
		if ce.path == "" {
			name = unix.ByteSliceToString(kp.Proc.P_comm[:])
		}
		p := Proc{PID: pid, Created: strconv.FormatInt(start, 10), PPID: int(kp.Eproc.Ppid), Name: name, Path: ce.path}
		p.control, p.Control = ce.control, ce.control != notControl
		if isInterpreter(name) {
			p.Args = ce.args
		}
		out = append(out, p)
	}
	for pid := range c.cache {
		if !seen[pid] {
			delete(c.cache, pid)
		}
	}
	parents := make(map[int]Proc, len(out))
	for _, p := range out {
		parents[p.PID] = p
	}
	for i, p := range out {
		parent := parents[p.PPID]
		if !darwinProbePath(p.Path) || parent.control != guardControl || !parent.Control {
			continue
		}
		// Read the actual image/argv again: exec can preserve PID and birth.
		path, argv := procArguments(p.PID)
		if darwinProbeHelper(parent, p, path, argv) {
			if birth, err := processIdentity(p.PID); err == nil && birth == p.Created {
				out[i].Control = true
			}
		}
	}
	return out, nil
}

func processIdentity(pid int) (string, error) {
	identity, _, err := processState(pid)
	return identity, err
}

func processState(pid int) (string, bool, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return "", false, err
	}
	if kp == nil || kp.Proc.P_pid != int32(pid) || kp.Proc.P_starttime.Sec == 0 {
		return "", false, os.ErrNotExist
	}
	return strconv.FormatInt(kp.Proc.P_starttime.Sec*1_000_000+int64(kp.Proc.P_starttime.Usec), 10), kp.Proc.P_stat == 4, nil // SSTOP in sys/proc.h
}

// procArgs reads kern.procargs2: argc (int32), exec path, NUL padding, argv..., env...
func procArgs(pid int) (path, args string) {
	path, argv := procArguments(pid)
	return path, joinArgs(argv)
}

func procArguments(pid int) (path string, argv []string) {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(buf) < 4 {
		return "", nil
	}
	argc := int(binary.LittleEndian.Uint32(buf[:4]))
	rest := buf[4:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return "", nil
	}
	path = string(rest[:i])
	rest = rest[i:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	for n := 0; n < argc && len(rest) > 0; n++ {
		j := bytes.IndexByte(rest, 0)
		if j < 0 {
			j = len(rest)
		}
		argv = append(argv, string(rest[:j]))
		if j == len(rest) {
			break
		}
		rest = rest[j+1:]
	}
	return path, argv
}

func joinArgs(argv []string) string {
	var b bytes.Buffer
	for i, a := range argv {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(a)
	}
	return b.String()
}
