package procs

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPidfdDoesNotSignalAfterOriginalChildExits(t *testing.T) {
	child := exec.Command(os.Args[0], "-test.run=^$")
	child.Env = append(os.Environ(), "ZASLON_HELPER="+filepath.Join(t.TempDir(), "ticks"))
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	identity, err := processIdentity(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	target, err := openUnixSignalTarget(Proc{PID: child.Process.Pid, Created: identity})
	if err != nil {
		t.Fatal(err)
	}
	defer target.close()
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	// Even after reaping, the descriptor refers to the original task, not
	// whatever task might later acquire its numeric PID.
	if err := target.send(syscall.SIGSTOP); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("stale pidfd signal: %v", err)
	}
}
