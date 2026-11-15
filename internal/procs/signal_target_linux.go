package procs

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

type linuxSignalTarget struct{ pid, fd int }

func openUnixSignalTarget(p Proc) (unixSignalTarget, error) {
	fd, err := unix.PidfdOpen(p.PID, 0)
	if err != nil {
		return nil, fmt.Errorf("pidfd_open for PID %d (required; no PID-only fallback): %w", p.PID, err)
	}
	return &linuxSignalTarget{pid: p.PID, fd: fd}, nil
}
func (t *linuxSignalTarget) snapshot() (string, bool, error) { return processState(t.pid) }
func (t *linuxSignalTarget) send(sig syscall.Signal) error {
	return unix.PidfdSendSignal(t.fd, unix.Signal(sig), nil, 0)
}
func (t *linuxSignalTarget) close() { _ = unix.Close(t.fd) }
