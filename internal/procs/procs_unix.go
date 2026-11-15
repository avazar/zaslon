//go:build darwin || linux

package procs

import (
	"errors"
	"os"
	"syscall"
)

type unixSignalTarget interface {
	snapshot() (identity string, stopped bool, err error)
	send(syscall.Signal) error
	close()
}

func withUnixSignalTarget(p Proc, open func(Proc) (unixSignalTarget, error), operation func(unixSignalTarget, bool) error) error {
	if p.Created == "" || p.PID <= 0 {
		return errors.Join(ErrNotApplied, errors.New("missing process identity"))
	}
	target, err := open(p)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrNotApplied, err)
	}
	defer target.close()
	born, stopped, err := target.snapshot()
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrNotApplied, err)
	}
	if born != p.Created {
		return nil
	}
	return operation(target, stopped)
}

func sendUnixSignal(target unixSignalTarget, sig syscall.Signal) error {
	err := target.send(sig)
	if errors.Is(err, syscall.ESRCH) {
		return nil // already gone
	}
	if err != nil {
		return errors.Join(ErrNotApplied, err)
	}
	return nil
}

func (c *osController) Freeze(p Proc) error {
	return withUnixSignalTarget(p, openUnixSignalTarget, func(target unixSignalTarget, stopped bool) error {
		if stopped {
			return errors.Join(ErrNotApplied, ErrAlreadyStopped)
		}
		return sendUnixSignal(target, syscall.SIGSTOP)
	})
}
func (c *osController) Resume(p Proc) error {
	return withUnixSignalTarget(p, openUnixSignalTarget, func(target unixSignalTarget, _ bool) error { return sendUnixSignal(target, syscall.SIGCONT) })
}
func (c *osController) Kill(p Proc) error {
	return withUnixSignalTarget(p, openUnixSignalTarget, func(target unixSignalTarget, _ bool) error { return sendUnixSignal(target, syscall.SIGKILL) })
}

// Close sends SIGTERM and then SIGCONT: a stopped process only handles
// the pending SIGTERM once it runs again, and quits instead of carrying on.
func (c *osController) Close(p Proc) error {
	return withUnixSignalTarget(p, openUnixSignalTarget, func(target unixSignalTarget, _ bool) error {
		if err := sendUnixSignal(target, syscall.SIGTERM); err != nil {
			return err
		}
		return sendUnixSignal(target, syscall.SIGCONT)
	})
}
