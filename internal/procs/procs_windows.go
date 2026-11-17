package procs

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ntdll            = windows.NewLazySystemDLL("ntdll.dll")
	ntSuspendProcess = ntdll.NewProc("NtSuspendProcess")
	ntResumeProcess  = ntdll.NewProc("NtResumeProcess")
	user32           = windows.NewLazySystemDLL("user32.dll")
	enumWindows      = user32.NewProc("EnumWindows")
	getWindowPID     = user32.NewProc("GetWindowThreadProcessId")
	postMessage      = user32.NewProc("PostMessageW")
)

const (
	processSuspendResume = 0x0800
	wmClose              = 0x0010
)

type cached struct {
	created            int64
	path, args, script string
	argsRead           bool
	ownImage           bool
	control            controlRole
}

type osController struct {
	mu    sync.Mutex
	cache map[int]cached
	own   string
}

func New() Controller { return &osController{cache: map[int]cached{}, own: executablePath()} }

func (c *osController) List() ([]Proc, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[int]bool{}
	var out []Proc
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		pid := int(e.ProcessID)
		if pid == 0 {
			continue
		}
		seen[pid] = true
		out = append(out, c.processInfo(e))
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, err
	}
	for pid := range c.cache {
		if !seen[pid] {
			delete(c.cache, pid)
		}
	}
	markPanelMembers(out)
	return out, nil
}

// Identity, image path and command line come from one handle, so a reused PID
// cannot contribute another process's arguments to the cached identity.
func (c *osController) processInfo(e windows.ProcessEntry32) Proc {
	p := Proc{PID: int(e.ProcessID), PPID: int(e.ParentProcessID), Name: windows.UTF16ToString(e.ExeFile[:])}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, e.ProcessID)
	if err != nil {
		delete(c.cache, p.PID)
		return p
	}
	defer windows.CloseHandle(h)
	var born, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &born, &exited, &kernel, &user) != nil || born.Nanoseconds() == 0 {
		delete(c.cache, p.PID)
		return p
	}
	created := born.Nanoseconds()
	p.Created = strconv.FormatInt(created, 10)
	ce, ok := c.cache[p.PID]
	if !ok || ce.created != created {
		ce = cached{created: created}
	}
	if ce.path == "" {
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
			ce.path = windows.UTF16ToString(buf[:n])
			ce.ownImage = sameExecutable(ce.path, c.own)
			if !ce.ownImage {
				// Windows can report the 8.3 spelling used to launch the image.
				// Expand it for identity comparison only; app rules use ce.path.
				n, err := windows.GetLongPathName(&buf[0], &buf[0], uint32(len(buf)))
				if err == nil && n > 0 && n < uint32(len(buf)) {
					ce.ownImage = sameExecutable(windows.UTF16ToString(buf[:n]), c.own)
				}
			}
		}
	}
	p.Path = ce.path
	if p.Path != "" {
		p.Name = filepath.Base(p.Path)
	}
	if isInterpreter(p.Name) {
		if !ce.argsRead {
			// A denied/early query stays retryable. Never guess that every node/bun
			// process belongs to a protected CLI when its command line is hidden.
			if args, err := queryProcessCommandLine(h); err == nil {
				ce.args, ce.script, ce.argsRead = args, windowsInterpreterScript(p.Name, args), args != ""
			}
		}
		p.Args, p.ScriptPath = ce.args, ce.script
	}
	if ce.ownImage {
		if line, err := queryProcessCommandLine(h); err == nil {
			if argv, err := windows.DecomposeCommandLine(line); err == nil {
				ce.control = controlMode(argv)
			}
		}
	}
	p.control, p.Control = ce.control, ce.control != notControl && p.Created != ""
	c.cache[p.PID] = ce
	return p
}

func withHandle(p Proc, access uint32, fn func(windows.Handle) error) error {
	if p.Created == "" || p.PID <= 0 {
		return errors.Join(ErrNotApplied, errors.New("missing process identity"))
	}
	h, err := windows.OpenProcess(access|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.PID))
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil // already gone
		}
		return errors.Join(ErrNotApplied, err)
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return errors.Join(ErrNotApplied, err)
	}
	if strconv.FormatInt(created.Nanoseconds(), 10) != p.Created {
		return nil
	} // original process is gone
	return fn(h)
}

func ntCall(proc *windows.LazyProc, p Proc) error {
	return withHandle(p, processSuspendResume, func(h windows.Handle) error {
		if err := proc.Find(); err != nil {
			return errors.Join(ErrNotApplied, fmt.Errorf("process control API: %w", err))
		}
		if st, _, _ := proc.Call(uintptr(h)); st != 0 {
			return windows.NTStatus(st)
		}
		return nil
	})
}

func (c *osController) Freeze(p Proc) error { return ntCall(ntSuspendProcess, p) }
func (c *osController) Resume(p Proc) error { return ntCall(ntResumeProcess, p) }

func (c *osController) Kill(p Proc) error {
	return withHandle(p, windows.PROCESS_TERMINATE, func(h windows.Handle) error {
		return windows.TerminateProcess(h, 1)
	})
}

// EnumWindows callbacks can't be freed (Windows allows ~1000 per process),
// so there is one, and the target pid is passed through a guarded variable.
var (
	closeMu     sync.Mutex
	closeTarget uint32
	closeCB     = windows.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		var pid uint32
		getWindowPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid == closeTarget {
			postMessage.Call(hwnd, wmClose, 0, 0)
		}
		return 1
	})
)

// Close resumes the process and posts WM_CLOSE to its windows. Apps without
// windows (or that hide to the tray) are force-closed after close_timeout.
func (c *osController) Close(p Proc) error {
	_ = c.Resume(p)
	closeMu.Lock()
	defer closeMu.Unlock()
	closeTarget = uint32(p.PID)
	enumWindows.Call(closeCB, 0)
	return nil
}
