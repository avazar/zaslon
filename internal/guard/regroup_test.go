package guard

import (
	"errors"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/procs"
	"github.com/avazar/zaslon/internal/recovery"
)

func TestRegroupTransfersEachSuspensionToExactlyOneOwner(t *testing.T) {
	for _, direction := range []string{"shared-to-app", "app-to-shared"} {
		t.Run(direction, func(t *testing.T) {
			h := newHarness(t, "1.2.3.4")
			h.p.procs[0].Created = "parent-birth"
			child := procs.Proc{PID: 101, PPID: claude.PID, Created: "child-birth", Name: "helper.exe"}
			h.p.procs = append(h.p.procs, child)
			ledger, err := recovery.Open(t.TempDir(), h.p)
			if err != nil {
				t.Fatal(err)
			}
			h.g.d.Procs = ledger
			if direction == "app-to-shared" {
				c := h.g.cfg.Clone()
				c.AppRules = map[string]config.Allow{"claude": {IPs: []string{"1.2.3.4"}}}
				h.g.SetConfig(h.now, c)
			}
			h.step(0)
			h.probe("1.2.3.4", "NL")
			c := h.g.cfg.Clone()
			if direction == "shared-to-app" {
				c.AppRules = map[string]config.Allow{"claude": {IPs: []string{"9.9.9.9"}}}
			} else {
				c.AppRules = nil
				c.Allow.IPs = []string{"9.9.9.9"}
			}
			h.g.SetConfig(h.now, c)
			assertFrozen := func() {
				t.Helper()
				for _, pid := range []int{claude.PID, child.PID} {
					owners := 0
					for _, gr := range h.g.groups {
						if _, ok := gr.frozen[pid]; ok {
							owners++
						}
					}
					if owners != 1 || !h.p.frozen[pid] {
						t.Fatalf("PID %d: owners=%d, suspended=%t", pid, owners, h.p.frozen[pid])
					}
				}
				if len(ledger.Entries()) != 2 {
					t.Fatal("regrouping lost recovery ownership")
				}
			}
			assertFrozen()
			h.probe("1.2.3.4", "NL")
			h.step(time.Second)
			assertFrozen()
			h.probe("9.9.9.9", "NL")
			if h.p.frozen[claude.PID] || h.p.frozen[child.PID] || len(ledger.Entries()) != 0 {
				t.Fatal("allowed result did not release the transferred suspensions")
			}
		})
	}
}

func TestReaddingAppReclaimsPendingReleaseBeforeFreshCheck(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	h.p.procs[0].Created = "parent-birth"
	p := &failingProcs{fakeProcs: h.p}
	ledger, err := recovery.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	h.g.d.Procs = ledger
	h.step(0)
	p.resumeErr = errors.Join(procs.ErrNotApplied, errors.New("access denied"))
	c := h.g.cfg.Clone()
	c.Apps = nil
	h.g.SetConfig(h.now, c)
	if len(h.g.releasing) != 1 {
		t.Fatal("failed release was not retained")
	}
	c.Apps = []string{"claude"}
	h.g.SetConfig(h.now, c)
	p.resumeErr = nil
	h.step(time.Millisecond)
	if len(h.g.releasing) != 0 || !h.p.frozen[claude.PID] || len(ledger.Entries()) != 1 {
		t.Fatal("re-added app was released before checking its current rules")
	}
	h.probe("1.2.3.4", "NL")
	if h.p.frozen[claude.PID] || len(ledger.Entries()) != 0 {
		t.Fatal("fresh allowed check failed to release the reclaimed suspension")
	}
}
