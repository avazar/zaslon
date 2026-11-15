//go:build linux || darwin

package procs

import (
	"errors"
	"syscall"
	"testing"
)

type fixtureSignalTarget struct {
	identity                 string
	stopped, closed          bool
	signals                  []syscall.Signal
	snapshotError, sendError error
}

func (t *fixtureSignalTarget) snapshot() (string, bool, error) {
	return t.identity, t.stopped, t.snapshotError
}
func (t *fixtureSignalTarget) send(s syscall.Signal) error {
	t.signals = append(t.signals, s)
	return t.sendError
}
func (t *fixtureSignalTarget) close() { t.closed = true }

func TestUnixSignalTargetIdentityAndErrors(t *testing.T) {
	p := Proc{PID: 123, Created: "expected"}
	for _, tc := range []struct {
		name, identity           string
		snapshotError, sendError error
		wantSignals              int
		wantError                bool
	}{
		{"matching", "expected", nil, nil, 1, false},
		{"reused-pid", "replacement", nil, nil, 0, false},
		{"gone", "", syscall.ESRCH, nil, 0, false},
		{"inaccessible", "", syscall.EPERM, nil, 0, true},
		{"send-denied", "expected", nil, syscall.EPERM, 1, true},
		{"exited-after-snapshot", "expected", nil, syscall.ESRCH, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := &fixtureSignalTarget{identity: tc.identity, snapshotError: tc.snapshotError, sendError: tc.sendError}
			err := withUnixSignalTarget(p, func(Proc) (unixSignalTarget, error) { return target, nil }, func(target unixSignalTarget, _ bool) error { return sendUnixSignal(target, syscall.SIGSTOP) })
			if (err != nil) != tc.wantError || len(target.signals) != tc.wantSignals || !target.closed {
				t.Fatalf("signals=%v closed=%v err=%v", target.signals, target.closed, err)
			}
			if tc.wantError && !errors.Is(err, ErrNotApplied) {
				t.Fatal("operation failure lost its no-effect classification")
			}
		})
	}
	called := false
	err := withUnixSignalTarget(p, func(Proc) (unixSignalTarget, error) { return nil, syscall.ENOSYS }, func(unixSignalTarget, bool) error { called = true; return nil })
	if !errors.Is(err, ErrNotApplied) || called {
		t.Fatal("unsupported stable process handle used a fallback operation")
	}
}
