package procs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func fixtureJob(t *testing.T) windows.Handle {
	t.Helper()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.TerminateJobObject(job, 1); windows.CloseHandle(job) })
	return job
}

func controlFixture(t *testing.T, job windows.Handle, exe, mode string) (*exec.Cmd, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "heartbeat")
	cmd := exec.Command(exe, mode)
	cmd.Env = append(os.Environ(), "ZASLON_HELPER="+file)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	err = windows.AssignProcessToJobObject(job, h)
	windows.CloseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for lines(t, file) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("fixture did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cmd, file
}

func TestPrivatePanelJobExemptsOnlyItsOwnProcesses(t *testing.T) {
	bounded := fixtureJob(t)
	// Exercise both spellings on volumes that provide DOS short names.
	exe := executablePath()
	path, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	panelExe := exe
	if n, err := windows.GetShortPathName(path, &buf[0], uint32(len(buf))); err == nil && n > 0 && n < uint32(len(buf)) {
		panelExe = windows.UTF16ToString(buf[:n])
	}
	owner, _ := controlFixture(t, bounded, panelExe, "panel")
	worker, _ := controlFixture(t, bounded, exe, "headless")
	member, memberFile := controlFixture(t, bounded, exe, "ordinary-fixture")
	user, userFile := controlFixture(t, bounded, exe, "ordinary-fixture")
	c := New()
	all, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	find := func(ps []Proc, pid int) Proc {
		for _, p := range ps {
			if p.PID == pid {
				return p
			}
		}
		t.Fatalf("fixture PID %d missing", pid)
		return Proc{}
	}
	ownerProc := find(all, owner.Process.Pid)
	workerProc := find(all, worker.Process.Pid)
	if ownerProc.control != panelControl || workerProc.control != guardControl {
		t.Fatalf("own executable %q: panel %q role=%d, supervisor %q role=%d",
			c.(*osController).own, ownerProc.Path, ownerProc.control, workerProc.Path, workerProc.control)
	}
	panelJob, err := createPanelJob(ownerProc)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(panelJob)
	if other, err := createPanelJob(ownerProc); err == nil {
		windows.CloseHandle(other)
		t.Fatal("adopted an existing session job")
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(member.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	err = windows.AssignProcessToJobObject(panelJob, h)
	windows.CloseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	all, err = c.List()
	if err != nil {
		t.Fatal(err)
	}
	ownMember, userProc := find(all, member.Process.Pid), find(all, user.Process.Pid)
	if !ownMember.Control || userProc.Control {
		t.Fatal("private panel membership confused with ordinary traffic")
	}
	selection := Filter([]Proc{ownerProc, find(all, worker.Process.Pid), ownMember, userProc},
		[]Target{{ID: "fixture", Name: "fixture", Rule: Rule{Names: []string{userProc.Name}}}}, os.Getpid())
	if len(selection) != 1 || selection[0].PID != userProc.PID {
		t.Fatalf("wrong protection selection: %v", selection)
	}
	stale := ownMember
	stale.Control = false
	stale.Created = "1"
	check := []Proc{ownerProc, stale}
	markPanelMembers(check)
	if check[1].Control {
		t.Fatal("a stale PID/birth pair acquired panel exemption")
	}
	if err = c.Freeze(userProc); err != nil {
		t.Fatal(err)
	}
	held := true
	defer func() {
		if held {
			_ = c.Resume(userProc)
		}
	}()
	time.Sleep(80 * time.Millisecond)
	beforeUser, beforeMember := lines(t, userFile), lines(t, memberFile)
	time.Sleep(160 * time.Millisecond)
	if lines(t, userFile) != beforeUser || lines(t, memberFile) <= beforeMember {
		t.Fatal("own panel paused or ordinary fixture escaped suspension")
	}
	if err = c.Resume(userProc); err != nil {
		t.Fatal(err)
	}
	held = false
	time.Sleep(80 * time.Millisecond)
	if lines(t, userFile) <= beforeUser {
		t.Fatal("ordinary fixture did not resume")
	}
}

func TestDirectPanelChildRequiresOwnerRoleAndBirthOrder(t *testing.T) {
	for _, tc := range []struct {
		role          controlRole
		parent, child string
		want          bool
	}{
		{panelControl, "100", "101", true},
		{panelControl, "100", "99", false},
		{guardControl, "100", "101", false},
	} {
		parentSeq, _ := strconv.ParseUint(tc.parent, 10, 64)
		childSeq, _ := strconv.ParseUint(tc.child, 10, 64)
		owner := Proc{PID: 2000000000, Created: "100", Sequence: parentSeq, Control: true, control: tc.role}
		child := Proc{PID: 2000000001, PPID: owner.PID, Created: "100", Sequence: childSeq, Name: "msedge.exe"}
		ps := []Proc{owner, child}
		verifyWindowsParents(ps)
		markPanelMembers(ps)
		if ps[1].Control != tc.want {
			t.Fatalf("role=%v birth=%s/%s: control=%v", tc.role, tc.parent, tc.child, ps[1].Control)
		}
	}
	a := Proc{PID: 42, Created: strconv.FormatInt(time.Now().UnixNano(), 10)}
	b := a
	b.Created = "1"
	if panelJobName(a) == panelJobName(b) {
		t.Fatal("job identity ignored process birth")
	}
}
