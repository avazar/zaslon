package guard

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestParentPolicyHoldAndReleaseAreLoggedOncePerBatch(t *testing.T) {
	h := domainHarness(t)
	h.p.procs[2].PPID = 100 // A directly matched Cursor and its worker both inherit Claude's policy.
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	h.events = nil
	failed := domainReply(h, "", "198.51.100.20")
	failed.Domains["claude"][0].Error = "context deadline exceeded"
	h.probeFull(failed)
	if !h.p.frozen[200] || !h.p.frozen[201] {
		t.Fatal("parent denial did not hold the child and grandchild")
	}
	checkBatch := func(kind EventKind) {
		t.Helper()
		batches := 0
		for _, e := range h.events {
			if e.Kind == kind && slices.Contains(e.Apps, "Cursor") {
				batches++
				if e.Reason != ProcessPolicyDenied || !slices.Contains(e.Details, "processes=2") {
					t.Fatalf("incorrect child operation: %+v", e)
				}
				if kind == EvFrozen && !slices.Contains(e.HeldBy, "Claude") {
					t.Fatalf("missing parent policy: %+v", e)
				}
				if kind == EvResumed && (e.PauseMin < time.Second || e.PauseMax > time.Second+time.Millisecond) {
					t.Fatalf("wrong duration of the inherited pause: %+v", e)
				}
			}
		}
		if batches != 1 {
			t.Fatalf("kind %d: %d Cursor batches; want 1 (%+v)", kind, batches, h.events)
		}
	}
	checkBatch(EvFrozen)
	h.events = nil
	h.now = h.now.Add(time.Second)
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	h.step(time.Millisecond)
	if h.p.frozen[200] || h.p.frozen[201] {
		t.Fatal("fresh parent proof did not release the child and grandchild")
	}
	checkBatch(EvResumed)
}

func TestEmptyOrFailedSuspensionNeverReportsFreeze(t *testing.T) {
	for _, failed := range []bool{false, true} {
		name := "no matching processes"
		if failed {
			name = "suspension refused"
		}
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "203.0.113.10")
			if failed {
				h.g.d.Procs = &failingProcs{fakeProcs: h.p, freezeErr: errors.New("access denied")}
			} else {
				h.p.remove(claude.PID)
			}
			h.step(0)
			h.probe("198.51.100.20", "NL")
			if h.had(EvFrozen) || h.had(EvHoldReason) || h.g.Snapshot(h.now).Counters.Freezes != 0 {
				t.Fatalf("reported a suspension that never happened: %+v", h.events)
			}
			if failed && !h.had(EvProcessError) {
				t.Fatal("the process control error was not logged")
			}
		})
	}
}

func TestManualReleaseIsLoggedWithoutClaimingAllowedIP(t *testing.T) {
	h := newHarness(t, "203.0.113.10")
	h.step(0)
	h.events = nil
	h.g.Pause(h.now, time.Minute)
	h.step(time.Second)
	if h.p.frozen[claude.PID] || h.g.Snapshot(h.now).Counters.Saves != 0 {
		t.Fatal("manual pause did not release the fixture independently of IP verification")
	}
	count := 0
	for _, e := range h.events {
		if e.Kind == EvResumed {
			count++
			if e.Notify || e.IP != "" || !slices.Contains(e.Details, "processes=1; cause=protection paused") {
				t.Fatalf("wrong account of manual release: %+v", e)
			}
		}
	}
	if count != 1 {
		t.Fatalf("logged %d manual releases; want 1", count)
	}
}

func TestStartupOperationsReachLateListener(t *testing.T) {
	h := newHarness(t, "203.0.113.10")
	h.g.OnChange(nil)
	h.step(0)
	h.g.OnChange(func(_ Snapshot, evs []Event) { h.events = append(h.events, evs...) })
	h.probe("198.51.100.20", "NL")
	if !h.had(EvFrozen) || !h.had(EvHoldReason) {
		t.Fatalf("startup operation or subsequent hold reason lost: %+v", h.events)
	}
}
