package procs

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	controlKernel      = windows.NewLazySystemDLL("kernel32.dll")
	createControlJob   = controlKernel.NewProc("CreateJobObjectW")
	openControlJob     = controlKernel.NewProc("OpenJobObjectW")
	isControlJobMember = controlKernel.NewProc("IsProcessInJob")
)

func panelJobName(p Proc) string {
	birth, err := strconv.ParseInt(p.Created, 10, 64)
	if p.PID <= 0 || err != nil || birth <= 0 {
		return ""
	}
	return fmt.Sprintf("Local\\Zaslon.Panel.%d.%d", p.PID, birth)
}

func createPanelJob(owner Proc) (windows.Handle, error) {
	name := panelJobName(owner)
	if name == "" {
		return 0, errors.New("panel owner identity unavailable")
	}
	u, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, _, callErr := createControlJob.Call(0, uintptr(unsafe.Pointer(u)))
	if h == 0 {
		return 0, callErr
	}
	if errors.Is(callErr, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(windows.Handle(h))
		return 0, errors.New("panel process already owns a session")
	}
	return windows.Handle(h), nil
}

// NewPanelJob gives the dedicated browser a kernel-owned identity that the
// worker can query across processes. No user's ordinary browser joins this job.
func NewPanelJob() (windows.Handle, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(os.Getpid()))
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var born, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &born, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return createPanelJob(Proc{PID: os.Getpid(), Created: strconv.FormatInt(born.Nanoseconds(), 10)})
}

func markPanelMembers(all []Proc) {
	var jobs []windows.Handle
	panels := map[int]Proc{}
	for _, p := range all {
		if p.control != panelControl || !p.Control {
			continue
		}
		panels[p.PID] = p
		name := panelJobName(p)
		if name == "" {
			continue
		}
		u, _ := windows.UTF16PtrFromString(name)
		h, _, _ := openControlJob.Call(0x0004, 0, uintptr(unsafe.Pointer(u))) // JOB_OBJECT_QUERY
		if h != 0 {
			jobs = append(jobs, windows.Handle(h))
		}
	}
	defer func() {
		for _, job := range jobs {
			windows.CloseHandle(job)
		}
	}()
	for i, p := range all {
		if p.Control || p.Created == "" {
			continue
		}
		// CreateProcess exposes a suspended direct child just before assignment
		// to the job. Cover only that Edge child of a verified panel owner,
		// with a birth later than its parent; never an arbitrary guard subtree.
		if owner, ok := panels[p.PPID]; ok && strings.EqualFold(p.Name, "msedge.exe") {
			if owner.Sequence != 0 && owner.Sequence == p.parentSequence && p.Sequence > owner.Sequence {
				all[i].Control = true
				continue
			}
		}
		if len(jobs) == 0 {
			continue
		}
		_ = withHandle(p, 0, func(h windows.Handle) error {
			for _, job := range jobs {
				var member int32
				ok, _, _ := isControlJobMember.Call(uintptr(h), uintptr(job), uintptr(unsafe.Pointer(&member)))
				if ok != 0 && member != 0 {
					all[i].Control = true
					break
				}
			}
			return nil
		})
	}
}
