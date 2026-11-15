package procs

import (
	"errors"
	"os"
	"syscall"
)

type darwinSignalTarget struct{ process Proc }

func openUnixSignalTarget(p Proc) (unixSignalTarget, error) {
	return &darwinSignalTarget{process: p}, nil
}
func (t *darwinSignalTarget) snapshot() (string, bool, error) { return processState(t.process.PID) }
func (t *darwinSignalTarget) send(sig syscall.Signal) error {
	// Darwin's POSIX API has no pidfd. Recheck directly before each signal;
	// the check-to-kill race and independent SIGSTOP ownership remain limits.
	identity, stopped, err := processState(t.process.PID)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if err != nil {
		return err
	}
	if identity != t.process.Created {
		return nil
	}
	if sig == syscall.SIGSTOP && stopped {
		return ErrAlreadyStopped
	}
	return syscall.Kill(t.process.PID, sig)
}
func (*darwinSignalTarget) close() {}
