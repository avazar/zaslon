package recovery

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/avazar/zaslon/internal/procs"
)

func TestConfirmedSuspensionsPreserveUnknownOutcomes(t *testing.T) {
	for _, mode := range []string{"freezing", "resuming", "identity"} {
		t.Run(mode, func(t *testing.T) {
			c, f, dir := fixture(t)
			if err := c.Freeze(testProc); err != nil {
				t.Fatal(err)
			}
			if mode == "identity" {
				f.all[0].Created = ""
			} else {
				e := c.entries[testProc.PID]
				e.Phase = mode
				c.entries[testProc.PID] = e
				if err := c.save(); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(filepath.Join(dir, FileName))
			if err != nil {
				t.Fatal(err)
			}
			if ps, err := c.ConfirmedSuspensions(); err == nil || len(ps) != 0 {
				t.Fatal("adopted uncertain operation")
			}
			after, _ := os.ReadFile(filepath.Join(dir, FileName))
			if string(before) != string(after) || f.count[testProc.PID] != 1 || f.resumes != 0 || f.kills != 0 {
				t.Fatal("adoption modified uncertain state")
			}
		})
	}
}

func TestRememberFrozenPoliciesIsDurableAndWriteFailureIsReversible(t *testing.T) {
	c, f, dir := fixture(t)
	p := testProc
	p.AppID = "one"
	p.PolicyIDs = []string{"one"}
	if err := c.Freeze(p); err != nil {
		t.Fatal(err)
	}
	p.PolicyIDs = []string{"one", "two"}
	p.Args = "secret"
	p.ScriptPath = "private"
	c.write = func(string, []byte) error { return errors.New("disk full") }
	second := p
	second.PolicyIDs = []string{"one", "three"}
	if err := c.RememberFrozen([]procs.Proc{p, second}); err == nil {
		t.Fatal("lost policy write failure")
	}
	if len(c.Entries()[0].Process.PolicyIDs) != 1 {
		t.Fatal("failed metadata write changed ownership")
	}
	c.write = writeAtomic
	if err := c.RememberFrozen([]procs.Proc{p}); err != nil {
		t.Fatal(err)
	}
	p.PolicyIDs[1] = "mutated"
	read, err := Open(dir, f)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := read.ConfirmedSuspensions()
	if err != nil || len(ps) != 1 || ps[0].PolicyIDs[1] != "two" || ps[0].Args != "" || ps[0].ScriptPath != "" {
		t.Fatal("policy metadata was lost or persisted command lines")
	}
	ps[0].PolicyIDs[1] = "changed externally"
	if read.Entries()[0].Process.PolicyIDs[1] != "two" || f.freezes != 1 || f.resumes != 0 {
		t.Fatal("policy update changed suspension ownership")
	}
}
