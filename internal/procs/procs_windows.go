package procs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ntdll             = windows.NewLazySystemDLL("ntdll.dll")
	ntSuspendProcess  = ntdll.NewProc("NtSuspendProcess")
	ntResumeProcess   = ntdll.NewProc("NtResumeProcess")
	user32            = windows.NewLazySystemDLL("user32.dll")
	enumWindows       = user32.NewProc("EnumWindows")
	getWindowPID      = user32.NewProc("GetWindowThreadProcessId")
	postMessage       = user32.NewProc("PostMessageW")
	isProcessCritical = controlKernel.NewProc("IsProcessCritical")
)

const (
	processSuspendResume = 0x0800
	wmClose              = 0x0010
)

type cached struct {
	created            int64
	sequence           uint64
	path, args, script string
	argsRead           bool
	ownImage           bool
	control            controlRole
}

type osController struct {
	mu             sync.Mutex
	cache          map[int]cached
	own            string
	snapshot       []byte // reused only while holding mu
	legacySnapshot bool
}

func New() Controller { return &osController{cache: map[int]cached{}, own: executablePath()} }

func (c *osController) List() ([]Proc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.listSnapshot()
	if err != nil {
		return nil, err
	}
	for i, p := range out {
		out[i] = c.processInfo(p)
	}
	seen := verifyWindowsParents(out)
	for pid := range c.cache {
		if _, ok := seen[pid]; !ok {
			delete(c.cache, pid)
		}
	}
	markPanelMembers(out)
	return out, nil
}

// SYSTEM_BASICPROCESS_INFORMATION, available on newer Windows 11 builds.
type basicProcessRecord struct {
	next        uint32
	pid, parent uintptr
	sequence    uint64
	image       windows.NTUnicodeString
}

func (c *osController) listSnapshot() ([]Proc, error) {
	if len(c.snapshot) == 0 {
		c.snapshot = make([]byte, 1<<20)
	}
	const systemBasicProcessInformation = 252
	var used uint32
	for {
		class := int32(systemBasicProcessInformation)
		if c.legacySnapshot {
			class = windows.SystemProcessInformation
		}
		err := windows.NtQuerySystemInformation(class, unsafe.Pointer(&c.snapshot[0]), uint32(len(c.snapshot)), &used)
		if err == nil {
			break
		}
		if !c.legacySnapshot && (err == windows.STATUS_INVALID_INFO_CLASS || err == windows.STATUS_NOT_IMPLEMENTED) {
			c.legacySnapshot = true
			continue
		}
		if err != windows.STATUS_INFO_LENGTH_MISMATCH {
			return nil, err
		}
		size := max(uint64(used), 2*uint64(len(c.snapshot)))
		if size > 256<<20 {
			return nil, errors.New("process snapshot exceeds size limit")
		}
		c.snapshot = make([]byte, size)
	}
	if uint64(used) > uint64(len(c.snapshot)) {
		return nil, errors.New("invalid process snapshot length")
	}
	var out []Proc
	header := uint32(unsafe.Sizeof(basicProcessRecord{}))
	if c.legacySnapshot {
		header = uint32(unsafe.Sizeof(windows.SYSTEM_PROCESS_INFORMATION{}))
	}
	for data := c.snapshot[:used]; len(data) >= int(header); {
		var p Proc
		var next uint32
		if c.legacySnapshot {
			e := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&data[0]))
			next = e.NextEntryOffset
			p = Proc{PID: int(e.UniqueProcessID), Name: e.ImageName.String()}
			if e.CreateTime > 0 {
				ft := windows.Filetime{LowDateTime: uint32(e.CreateTime), HighDateTime: uint32(e.CreateTime >> 32)}
				p.Created = strconv.FormatInt(ft.Nanoseconds(), 10)
			}
		} else {
			e := (*basicProcessRecord)(unsafe.Pointer(&data[0]))
			next = e.next
			p = Proc{PID: int(e.pid), PPID: int(e.parent), Sequence: e.sequence, Name: e.image.String()}
		}
		if p.PID != 0 {
			out = append(out, p)
		}
		if next == 0 {
			return out, nil
		}
		if next < header || uint64(next) > uint64(len(data)) {
			break
		}
		data = data[next:]
	}
	return nil, errors.New("truncated process snapshot")
}

// Windows retains a creator's numeric PID after its exit. Only expose an edge
// when the current holder was already alive at the child's creation. A missing
// intermediate identity must also cut inheritance to its entire subtree.
func verifyWindowsParents(all []Proc) map[int]uint64 {
	instances := make(map[int]uint64, len(all))
	for _, p := range all {
		instances[p.PID] = p.Sequence
	}
	for i, p := range all {
		parent := instances[p.PPID]
		all[i].parentSequence = 0
		if parent == 0 || p.Sequence <= parent {
			all[i].PPID = 0
		} else {
			all[i].parentSequence = parent
		}
	}
	return instances
}

func processSequence(h windows.Handle) (uint64, error) {
	var seq uint64
	err := windows.NtQueryInformationProcess(h, windows.ProcessSequenceNumber, unsafe.Pointer(&seq), uint32(unsafe.Sizeof(seq)), nil)
	if err == windows.STATUS_INVALID_INFO_CLASS || err == windows.STATUS_NOT_IMPLEMENTED {
		seq, err = telemetrySequence(h)
	}
	if err == nil && seq == 0 {
		err = errors.New("process sequence unavailable")
	}
	return seq, err
}

// Earlier Windows 10 versions expose the same sequence in the telemetry
// header. The variable-length payload can also contain sensitive strings;
// only the fixed sequence field is used.
func telemetrySequence(h windows.Handle) (uint64, error) {
	var used uint32
	buf := make([]byte, 512)
	for {
		err := windows.NtQueryInformationProcess(h, windows.ProcessTelemetryIdInformation, unsafe.Pointer(&buf[0]), uint32(len(buf)), &used)
		if commandLineSizeError(err) && used > uint32(len(buf)) && used <= 1<<20 {
			buf = make([]byte, used)
			continue
		}
		if err != nil {
			return 0, err
		}
		const sequenceEnd = 48
		if used < sequenceEnd || used > uint32(len(buf)) || binary.LittleEndian.Uint32(buf) < sequenceEnd {
			return 0, errors.New("missing process sequence in telemetry header")
		}
		return binary.LittleEndian.Uint64(buf[40:sequenceEnd]), nil
	}
}

func processParent(h windows.Handle) (int, error) {
	var info windows.PROCESS_BASIC_INFORMATION
	if err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), nil); err != nil {
		return 0, err
	}
	return int(info.InheritedFromUniqueProcessId), nil
}

// Recheck a live creator's instance. If it exited after our snapshot, the
// already observed relationship to this exact child is still valid.
func (c *osController) verifyLiveParent(p Proc) error {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.PPID))
	if err == windows.ERROR_INVALID_PARAMETER {
		return nil
	}
	if err == windows.ERROR_ACCESS_DENIED {
		// A protected creator can still be identified from a kernel snapshot.
		c.mu.Lock()
		defer c.mu.Unlock()
		if !c.legacySnapshot {
			all, err := c.listSnapshot()
			if err != nil {
				return err
			}
			for _, current := range all {
				if current.PID == p.PPID && current.Sequence != p.parentSequence {
					return errors.New("creator PID has been reused")
				}
			}
			return nil
		}
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	seq, err := processSequence(h)
	if err != nil {
		return err
	}
	if seq != p.parentSequence {
		return errors.New("creator PID has been reused")
	}
	return nil
}

// Only enrich the snapshot if the handle still refers to that instance.
func (c *osController) processInfo(p Proc) Proc {
	snapshotTime := p.Created
	p.Created = "" // fill only for a positively identified instance
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.PID))
	if err != nil {
		delete(c.cache, p.PID)
		return p
	}
	defer windows.CloseHandle(h)
	var born, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &born, &exited, &kernel, &user) != nil {
		delete(c.cache, p.PID)
		return p
	}
	created := born.Nanoseconds()
	stamp := strconv.FormatInt(created, 10)
	seq, err := processSequence(h)
	if err != nil || (c.legacySnapshot && snapshotTime != stamp) || (!c.legacySnapshot && p.Sequence != seq) {
		delete(c.cache, p.PID)
		return p
	}
	if c.legacySnapshot {
		// The enumeration only located this PID. Read the creator and image
		// from the same object as the sequence, even for identical wall times.
		p.PPID, _ = processParent(h)
		p.Name = ""
	}
	p.Created, p.Sequence = stamp, seq
	ce, ok := c.cache[p.PID]
	if !ok || ce.created != created || ce.sequence != seq {
		ce = cached{created: created, sequence: seq}
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
			return ErrProcessGone
		}
		return errors.Join(ErrNotApplied, err)
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return errors.Join(ErrNotApplied, err)
	}
	if exited != (windows.Filetime{}) || strconv.FormatInt(created.Nanoseconds(), 10) != p.Created {
		return ErrProcessGone
	}
	if p.Sequence != 0 {
		seq, err := processSequence(h)
		if err != nil {
			return errors.Join(ErrNotApplied, err)
		}
		if seq != p.Sequence {
			return ErrProcessGone
		}
	}
	return fn(h)
}

// Release and explicit recovery are idempotent after the original exits.
func ignoreGone(err error) error {
	if err == ErrProcessGone {
		return nil
	}
	return err
}

func ntCall(proc *windows.LazyProc, h windows.Handle) error {
	if err := proc.Find(); err != nil {
		return errors.Join(ErrNotApplied, fmt.Errorf("process control API: %w", err))
	}
	if st, _, _ := proc.Call(uintptr(h)); st != 0 {
		if windows.NTStatus(st) == windows.STATUS_PROCESS_IS_TERMINATING {
			return ErrProcessGone
		}
		return windows.NTStatus(st)
	}
	return nil
}

func (c *osController) Freeze(p Proc) error {
	if p.Sequence == 0 {
		return errors.Join(ErrNotApplied, errors.New("missing Windows process sequence"))
	}
	return withHandle(p, processSuspendResume, func(h windows.Handle) error {
		if p.PPID != 0 {
			parent, err := processParent(h)
			if err != nil {
				return errors.Join(ErrNotApplied, fmt.Errorf("verify process parent: %w", err))
			}
			if parent != p.PPID || p.parentSequence == 0 || p.parentSequence >= p.Sequence {
				return errors.Join(ErrNotApplied, errors.New("process parent differs from snapshot"))
			}
			if err := c.verifyLiveParent(p); err != nil {
				return errors.Join(ErrNotApplied, err)
			}
		}
		var critical int32
		if err := isProcessCritical.Find(); err != nil {
			return errors.Join(ErrNotApplied, err)
		}
		ok, _, err := isProcessCritical.Call(uintptr(h), uintptr(unsafe.Pointer(&critical)))
		if err := checkCriticalResult(ok, critical, err); err != nil {
			return err
		}
		return ntCall(ntSuspendProcess, h)
	})
}

func checkCriticalResult(ok uintptr, critical int32, err error) error {
	if ok == 0 {
		return errors.Join(ErrNotApplied, fmt.Errorf("check critical process: %w", err))
	}
	if critical != 0 {
		return errors.Join(ErrNotApplied, errors.New("cannot suspend a critical Windows process"))
	}
	return nil
}

func (c *osController) Resume(p Proc) error {
	return ignoreGone(withHandle(p, processSuspendResume, func(h windows.Handle) error {
		return ntCall(ntResumeProcess, h)
	}))
}

func (c *osController) Kill(p Proc) error {
	return ignoreGone(withHandle(p, windows.PROCESS_TERMINATE, func(h windows.Handle) error {
		return windows.TerminateProcess(h, 1)
	}))
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
	return ignoreGone(withHandle(p, processSuspendResume, func(h windows.Handle) error {
		if err := ntCall(ntResumeProcess, h); err != nil {
			return err
		}
		// Keep the verified process object referenced through window enumeration
		// and posting. Windows cannot recycle its PID while this handle is open.
		closeMu.Lock()
		defer closeMu.Unlock()
		closeTarget = uint32(p.PID)
		if ok, _, err := enumWindows.Call(closeCB, 0); ok == 0 {
			return err
		}
		return nil
	}))
}
