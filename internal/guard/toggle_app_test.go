package guard

import (
	"slices"
	"testing"
	"time"
)

func TestMenuSelectionAlreadyAppliedLeavesProtectionAlone(t *testing.T) {
	h := domainHarness(t)
	for _, enabled := range []bool{false, true} {
		if err := h.g.SetAppEnabled(h.now, "claude", enabled); err != nil {
			t.Fatal(err)
		}
		probe := h.g.probeID
		h.saved = nil
		if err := h.g.SetAppEnabled(h.now, "claude", enabled); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(h.g.cfg.Apps, "claude") != enabled || h.saved != nil || h.g.probeID != probe {
			t.Fatal("stale menu click reversed the choice or restarted verification")
		}
	}
}

func TestToggleAppKeepsIndependentProtectionCurrent(t *testing.T) {
	for _, domains := range []bool{false, true} {
		name := "shared"
		if domains {
			name = "domain"
		}
		t.Run(name, func(t *testing.T) {
			h := domainHarness(t)
			c := h.g.cfg.Clone()
			c.DomainChecksEnabled["claude"] = domains
			c.DomainChecksEnabled["cursor"] = domains
			h.g.SetConfig(h.now, c)
			allowed := func() ProbeResult {
				r := domainReply(h, "203.0.113.10", "198.51.100.20")
				r.IP, r.Country, r.Votes, r.Err = "203.0.113.10", "NL", 2, nil
				return r
			}
			h.probeFull(allowed())
			h.g.ToggleApp(h.now, "claude")
			if h.p.frozen[100] || h.p.frozen[101] || h.p.frozen[200] || h.p.frozen[201] {
				t.Fatal("disabling an app interrupted an allowed process")
			}
			h.g.CheckNow(h.now)
			h.step(0)
			previous := h.g.probeID
			h.g.ToggleApp(h.now, "claude")
			if h.g.probeID == previous || !h.p.frozen[100] || !h.p.frozen[101] || h.p.frozen[200] || h.p.frozen[201] {
				t.Fatal("only the newly enabled process tree should wait for a new check")
			}
			snap := h.g.Snapshot(h.now)
			if snap.FrozenApps["claude"] != 2 || snap.FrozenApps["cursor"] != 0 {
				t.Fatalf("wrong per-app suspension counts: %v", snap.FrozenApps)
			}
			stale := allowed()
			stale.ID = previous
			h.g.HandleProbe(h.now, stale)
			if !h.p.frozen[100] || !h.p.frozen[101] {
				t.Fatal("pre-toggle proof released a newly enabled process")
			}
			h.probeFull(allowed())
			if h.g.Snapshot(h.now).Frozen != 0 {
				t.Fatal("fresh allowed result did not release the newly enabled tree")
			}
		})
	}
}

func TestToggleAppFollowsAncestorAndCurrentNetwork(t *testing.T) {
	h := domainHarness(t)
	h.p.procs[2].PPID = 100
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	h.g.ToggleApp(h.now, "claude")
	h.g.ToggleApp(h.now, "claude")
	if !h.p.frozen[200] || !h.p.frozen[201] {
		t.Fatal("direct matches must still wait for the newly enabled ancestor's check")
	}
	h.now = h.now.Add(time.Millisecond)
	h.revision++
	h.g.ToggleApp(h.now, "claude")
	if !h.p.frozen[200] || !h.p.frozen[201] {
		t.Fatal("a simultaneous network change must invalidate even the remaining app's allowed result")
	}
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	if h.p.frozen[200] || h.p.frozen[201] {
		t.Fatal("fresh current-network result did not release the remaining app")
	}
}
