//go:build linux || darwin

package recovery

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/procs"
)

func TestAlreadyStoppedChildIsNotAdoptedOrResumed(t *testing.T) {
	dir := t.TempDir()
	heartbeat := filepath.Join(dir, "ticks")
	child := exec.Command(os.Args[0], "-test.run=^$")
	child.Env = append(os.Environ(), "ZASLON_RECOVERY_TEST_ROLE=heartbeat", "ZASLON_RECOVERY_TEST_FILE="+heartbeat)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	size := func() int64 {
		st, _ := os.Stat(heartbeat)
		if st == nil {
			return 0
		}
		return st.Size()
	}
	deadline := time.Now().Add(5 * time.Second)
	for size() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if size() == 0 {
		t.Fatal("test child did not finish starting")
	}
	backend := procs.New()
	var p procs.Proc
	all, err := backend.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range all {
		if candidate.PID == child.Process.Pid && candidate.PPID == os.Getpid() {
			p = candidate
		}
	}
	if p.Created == "" {
		t.Fatal("test child identity unavailable")
	}
	if err := syscall.Kill(p.PID, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		stopped, err := fixtureStopped(p.PID)
		if err != nil {
			t.Fatal(err)
		}
		if stopped {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("test child did not enter its external stop")
		}
		time.Sleep(10 * time.Millisecond)
	}
	c, err := Open(dir, backend)
	if err != nil {
		t.Fatal(err)
	}
	err = c.Freeze(p)
	if !errors.Is(err, procs.ErrNotApplied) || !errors.Is(err, procs.ErrAlreadyStopped) {
		t.Fatalf("external stop claimed: %v", err)
	}
	if len(c.Entries()) != 0 {
		t.Fatal("external stop entered recovery journal")
	}
	if err := c.Recover(false); err != nil {
		t.Fatal(err)
	}
	before := size()
	time.Sleep(150 * time.Millisecond)
	if size() != before {
		t.Fatal("recovery resumed another owner's stop")
	}
	// Only this fixture, which owns the external stop, releases it.
	if err := syscall.Kill(p.PID, syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for size() == before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if size() <= before {
		t.Fatal("test owner's resume did not restart the child")
	}
}
