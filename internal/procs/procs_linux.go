package procs

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type osController struct {
	own            string
	fallbackNotice func()
	noticeOnce     sync.Once
}

func (c *osController) OnTerminalFallback(notice func()) { c.fallbackNotice = notice }

func New() Controller { return &osController{own: executablePath()} }

func (c *osController) List() ([]Proc, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make([]Proc, 0, len(ents))
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := "/proc/" + e.Name()
		// Capture birth before attributes. If the PID is recycled during these
		// reads, a later operation rejects the replacement instead of binding
		// an old executable name to the replacement's new birth identity.
		born, _ := processIdentity(pid)
		path, _ := os.Readlink(dir + "/exe")
		path = strings.TrimSuffix(path, " (deleted)")
		name := filepath.Base(path)
		if path == "" {
			comm, _ := os.ReadFile(dir + "/comm")
			name = strings.TrimSpace(string(comm))
		}
		p := Proc{PID: pid, Created: born, PPID: parentPID(dir), Name: name, Path: path}
		if isInterpreter(name) {
			raw, _ := os.ReadFile(dir + "/cmdline")
			p.Args = strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
		}
		if sameExecutable(path, c.own) && born != "" {
			raw, _ := os.ReadFile(dir + "/cmdline")
			argv := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
			p.control = ownRole(path, c.own, argv)
			p.Control = p.control != notControl
		}
		out = append(out, p)
	}
	return out, nil
}

func processIdentity(pid int) (string, error) {
	identity, _, err := processState(pid)
	return identity, err
}

func processState(pid int) (string, bool, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", false, err
	}
	f := strings.Fields(string(b)[strings.LastIndexByte(string(b), ')')+1:])
	if len(f) < 20 {
		return "", false, os.ErrInvalid
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", false, err
	}
	return strings.TrimSpace(string(boot)) + ":" + f[19], f[0] == "T" || f[0] == "t", nil
}

// parentPID reads the 4th field of /proc/<pid>/stat; the 2nd (comm) may contain spaces and ")".
func parentPID(dir string) int {
	b, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(f[1])
	return n
}
