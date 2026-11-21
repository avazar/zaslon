package procs

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsParentEvidence(t *testing.T) {
	targets := []Target{
		{ID: "chatgpt", Name: "ChatGPT", Rule: ParseMatch([]string{"ChatGPT"})},
		{ID: "codex", Name: "Codex", Rule: ParseMatch([]string{"codex"})},
	}
	for _, serviceSeq := range []uint64{20, 0, 100} {
		all := []Proc{
			{PID: 10, Name: "ChatGPT.exe", Created: "100", Sequence: 100},
			{PID: 11, PPID: 10, Name: "wininit.exe", Created: "200", Sequence: serviceSeq},
			{PID: 12, PPID: 11, Name: "services.exe", Created: "201", Sequence: 101},
			{PID: 13, PPID: 12, Name: "svchost.exe", Created: "201", Sequence: 120},
			{PID: 14, PPID: 10, Name: "worker.exe", Created: "100", Sequence: 102},
			{PID: 15, PPID: 14, Name: "worker.exe", Created: "90", Sequence: 104},
			{PID: 16, PPID: 11, Name: "codex.exe", Created: "130", Sequence: 130},
		}
		verifyWindowsParents(all)
		var pids []int
		for _, p := range Filter(all, targets, 999) {
			pids = append(pids, p.PID)
			if p.PID == 16 && !slices.Equal(p.PolicyIDs, []string{"codex"}) {
				t.Fatalf("Codex inherited an unverified policy: %+v", p)
			}
		}
		if !slices.Equal(pids, []int{10, 14, 15, 16}) {
			t.Fatalf("service sequence %d: selected %v", serviceSeq, pids)
		}
	}
}

func TestWindowsSequenceSources(t *testing.T) {
	seq, err := processSequence(windows.CurrentProcess())
	if err != nil || seq == 0 {
		t.Fatalf("sequence query: %d, %v", seq, err)
	}
	telemetry, err := telemetrySequence(windows.CurrentProcess())
	if err != nil || telemetry != seq {
		t.Fatalf("telemetry sequence %d, want %d: %v", telemetry, seq, err)
	}
	for _, legacy := range []bool{false, true} {
		c := New().(*osController)
		c.legacySnapshot = legacy
		ps, err := c.List()
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(ps, func(p Proc) bool { return p.PID == os.Getpid() })
		if i < 0 || ps[i].Sequence != seq || ps[i].Created == "" {
			t.Fatalf("legacy=%v: own instance missing from snapshot", legacy)
		}
	}
}

func TestWindowsCriticalProcessRefusal(t *testing.T) {
	if !errors.Is(checkCriticalResult(1, 1, nil), ErrNotApplied) ||
		!errors.Is(checkCriticalResult(0, 0, windows.ERROR_ACCESS_DENIED), ErrNotApplied) ||
		checkCriticalResult(1, 0, nil) != nil {
		t.Fatal("only a confirmed non-critical process may be suspended")
	}
}

func TestWindowsFreezeChecksLiveCreator(t *testing.T) {
	ticks := filepath.Join(t.TempDir(), "ticks")
	child := hiddenCLIFixture(exec.Command(os.Args[0], "-test.run=^$"))
	child.Env = append(os.Environ(), "ZASLON_HELPER="+ticks)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Process.Kill(); child.Wait() })
	waitCLIFixture(t, "helper startup", func() bool { return lines(t, ticks) > 0 })
	c := New()
	all, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	idx := slices.IndexFunc(all, func(p Proc) bool { return p.PID == child.Process.Pid })
	if idx < 0 || all[idx].PPID != os.Getpid() || all[idx].parentSequence == 0 {
		t.Fatal("test child's creator was not identified")
	}
	p := all[idx]
	wrong := p
	wrong.PPID = child.Process.Pid
	if err := c.Freeze(wrong); !errors.Is(err, ErrNotApplied) {
		t.Fatalf("wrong creator PID: %v", err)
	}
	wrong = p
	wrong.parentSequence--
	if err := c.Freeze(wrong); !errors.Is(err, ErrNotApplied) {
		t.Fatalf("correct creator PID but wrong instance: %v", err)
	}
	if err := c.Freeze(p); err != nil {
		t.Fatal(err)
	}
	before := lines(t, ticks)
	time.Sleep(160 * time.Millisecond)
	if after := lines(t, ticks); after != before {
		t.Fatalf("suspended child continued writing: %d -> %d", before, after)
	}
	if err := c.Resume(p); err != nil {
		t.Fatal(err)
	}
	waitCLIFixture(t, "helper resume", func() bool { return lines(t, ticks) > before })
}
