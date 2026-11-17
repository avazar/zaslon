package guard

import (
	"errors"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/procs"
)

type failingProcs struct {
	*fakeProcs
	resumeErr, freezeErr, killErr, listErr error
	resumes                                int
}

func (p *failingProcs) Resume(pr procs.Proc) error {
	p.resumes++
	if p.resumeErr != nil {
		return p.resumeErr
	}
	return p.fakeProcs.Resume(pr)
}
func (p *failingProcs) Freeze(pr procs.Proc) error {
	if p.freezeErr != nil {
		return p.freezeErr
	}
	return p.fakeProcs.Freeze(pr)
}
func (p *failingProcs) Kill(pr procs.Proc) error {
	if p.killErr != nil {
		return p.killErr
	}
	return p.fakeProcs.Kill(pr)
}
func (p *failingProcs) List() ([]procs.Proc, error) {
	if p.listErr != nil {
		return nil, p.listErr
	}
	return p.fakeProcs.List()
}

func TestStartupDoesNotBlindlyResumeMatchedProcesses(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	p := &failingProcs{fakeProcs: h.p}
	h.g.d.Procs = p
	h.step(0)
	if p.resumes != 0 {
		t.Fatal("startup resumed processes it did not suspend")
	}
}

func TestFailedResumeRemainsTrackedAndRetried(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	p := &failingProcs{fakeProcs: h.p}
	h.g.d.Procs = p
	h.step(0)
	p.resumeErr = errors.New("access denied")
	h.probe("1.2.3.4", "NL")
	s := h.g.Snapshot(h.now)
	if s.Frozen != 1 || len(s.Errors) == 0 || s.Allowed() {
		t.Fatal("failed resume reported as success")
	}
	if h.had(EvResumed) {
		t.Fatal("announced a resume that failed")
	}
	p.resumeErr = nil
	h.step(time.Second)
	s = h.g.Snapshot(h.now)
	if s.Frozen != 0 || len(s.Errors) != 0 || h.p.frozen[claude.PID] {
		t.Fatal("resume was not retried")
	}
	if !h.had(EvResumed) {
		t.Fatal("successful retry was not logged")
	}
}

func TestFrozenChildSurvivesParentExitInRecoveryTracking(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	child := procs.Proc{PID: 101, PPID: claude.PID, Name: "helper.exe"}
	h.p.procs = append(h.p.procs, child)
	h.step(0)
	h.p.remove(claude.PID)
	h.step(time.Second)
	if h.g.Snapshot(h.now).Frozen != 1 {
		t.Fatal("forgot orphaned frozen child")
	}
	h.g.Shutdown()
	if h.p.frozen[child.PID] {
		t.Fatal("orphan left frozen")
	}
}

func TestTerminationIsNeverAttemptedByGuard(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	p := &failingProcs{fakeProcs: h.p, killErr: errors.New("denied")}
	h.g.d.Procs = p
	h.step(0)
	h.probe("5.6.7.8", "DE")
	h.step(21 * time.Second)
	s := h.g.Snapshot(h.now)
	if s.Frozen != 1 || len(s.Errors) != 0 || !h.p.frozen[claude.PID] || h.p.closed[claude.PID] {
		t.Fatal("guard attempted termination")
	}
	p.killErr = nil
	h.step(time.Second)
	if h.p.killed[claude.PID] || h.g.Snapshot(h.now).Frozen != 1 {
		t.Fatal("guard did not keep the process suspended")
	}
}

func TestProcessFailuresAreVisible(t *testing.T) {
	for _, op := range []string{"freeze", "list"} {
		t.Run(op, func(t *testing.T) {
			h := newHarness(t, "1.2.3.4")
			p := &failingProcs{fakeProcs: h.p}
			h.g.d.Procs = p
			if op == "freeze" {
				p.freezeErr = errors.New("denied")
			} else {
				p.listErr = errors.New("snapshot failed")
			}
			h.step(0)
			if len(h.g.Snapshot(h.now).Errors) == 0 || !h.had(EvProcessError) {
				t.Fatal("process error hidden")
			}
		})
	}
}

func TestFailedFreezeErrorIsPrunedOnlyAfterConfirmedExit(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	h.p.procs[0].Created = "original-birth"
	p := &failingProcs{fakeProcs: h.p, freezeErr: errors.New("access denied")}
	h.g.d.Procs = p
	h.step(0)
	if len(h.g.Snapshot(h.now).Errors) != 1 {
		t.Fatal("missing initial freeze error")
	}
	h.p.procs[0].Created = "" // identity inaccessible: cannot confirm exit
	h.probe("1.2.3.4", "NL")
	h.step(time.Millisecond)
	if len(h.g.Snapshot(h.now).Errors) != 1 {
		t.Fatal("unreadable identity discarded the error")
	}
	h.p.remove(claude.PID)
	p.listErr = errors.New("snapshot unavailable")
	h.step(time.Millisecond)
	if len(h.g.Snapshot(h.now).Errors) != 2 {
		t.Fatal("failed snapshot discarded the process error")
	}
	p.listErr = nil
	h.step(time.Millisecond)
	if len(h.g.Snapshot(h.now).Errors) != 0 {
		t.Fatal("confirmed process exit left stale errors")
	}
}

func TestFailedFreezeErrorDoesNotFollowReusedPID(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	h.p.procs[0].Created = "old-birth"
	p := &failingProcs{fakeProcs: h.p, freezeErr: errors.New("access denied")}
	h.g.d.Procs = p
	h.step(0)
	h.p.procs[0].Created = "new-birth"
	p.freezeErr = nil
	h.step(time.Millisecond)
	if len(h.g.Snapshot(h.now).Errors) != 0 || !h.p.frozen[claude.PID] {
		t.Fatal("old error survived PID reuse or new process escaped suspension")
	}
}

func TestReusedPIDGetsItsOwnSuspension(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	h.p.procs[0].Created = "old-birth"
	h.step(0)
	h.probe("5.6.7.8", "DE")
	h.step(21 * time.Second)
	h.p.frozen[claude.PID] = false
	h.p.procs[0].Created = "new-birth"
	h.step(500 * time.Millisecond)
	if !h.p.frozen[claude.PID] || h.p.killed[claude.PID] {
		t.Fatal("new process did not get its own suspension")
	}
}
