package guard

import (
	"errors"
	"testing"
	"time"
)

func TestRouteEventFreezesBeforeProbeWithUnchangedAddresses(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	h.step(0)
	h.probe("1.2.3.4", "NL")
	h.onProbe = func() {
		if !h.p.frozen[claude.PID] {
			t.Fatal("probe started before apps were suspended")
		}
	}
	h.revision++ // OS route notification, no change to the address fingerprint
	h.step(time.Millisecond)
	h.want(Suspect)
	if h.g.Snapshot(h.now).Allowed() {
		t.Fatal("old verified IP still presented as allowed")
	}
	h.probe("1.2.3.4", "NL")
	h.want(OK)
}

func TestQueuedOldSuccessCannotWinRaceWithNetworkEvent(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	h.step(0)
	h.probe("1.2.3.4", "NL")
	h.g.CheckNow(h.now)
	h.step(0)
	oldID := h.g.probeID
	h.revision++ // callback happened, but the runner hasn't consumed its event
	h.g.HandleProbe(h.now, ProbeResult{ID: oldID, IP: "1.2.3.4", Votes: 2})
	if !h.p.frozen[claude.PID] || h.g.probeID == oldID || !h.g.probing {
		t.Fatal("stale success escaped event invalidation")
	}
	h.probe("5.6.7.8", "DE")
	h.want(Suspect)
}

func TestCallbackDuringFingerprintInvalidatesCompletedProbe(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	h.step(0)
	id := h.g.probeID
	before := h.cancelled
	h.g.d.Fingerprint = func() string {
		h.revision++ // route-only callback while adapter addresses are being read
		h.g.d.Fingerprint = func() string { return h.fp }
		return h.fp
	}
	h.g.HandleProbe(h.now, ProbeResult{ID: id, IP: "1.2.3.4", Votes: 2})
	if !h.p.frozen[claude.PID] || h.g.probeID == id || h.cancelled != before+1 {
		t.Fatal("callback during enumeration allowed a stale result to resume apps")
	}
	h.probe("1.2.3.4", "NL")
	if h.p.frozen[claude.PID] {
		t.Fatal("fresh result failed to resume apps")
	}
}

func TestLateAndDuplicateProbeResultsCannotResume(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	h.step(0)
	oldID := h.g.probeID
	before := h.cancelled
	h.revision++
	h.step(time.Millisecond)
	if h.cancelled != before+1 {
		t.Fatal("superseded check was not cancelled")
	}
	newID := h.g.probeID
	h.g.HandleProbe(h.now, ProbeResult{ID: oldID, IP: "1.2.3.4", Votes: 2})
	if !h.g.probing || h.g.probeID != newID || !h.p.frozen[claude.PID] {
		t.Fatal("old result changed current check")
	}
	h.g.HandleProbe(h.now, ProbeResult{ID: newID, Err: errors.New("timeout")})
	h.g.HandleProbe(h.now, ProbeResult{ID: newID, IP: "1.2.3.4", Votes: 2})
	if !h.p.frozen[claude.PID] {
		t.Fatal("duplicate completion resumed after failure")
	}
}

func TestSettingsEditWhileCheckingCannotUsePreviousAllowedIP(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	h.step(0)
	h.probe("1.2.3.4", "NL")
	h.revision++
	h.step(time.Millisecond)
	oldID := h.g.probeID
	c := h.g.cfg.Clone()
	c.Notifications = false
	h.g.SetConfig(h.now, c)
	if !h.p.frozen[claude.PID] {
		t.Fatal("settings edit resumed using a cached IP")
	}
	h.g.HandleProbe(h.now, ProbeResult{ID: oldID, IP: "1.2.3.4", Votes: 2})
	if !h.p.frozen[claude.PID] {
		t.Fatal("pre-edit result accepted")
	}
	h.probe("1.2.3.4", "NL")
	if h.p.frozen[claude.PID] {
		t.Fatal("fresh allowed result failed to resume")
	}
}

func TestPauseExpiryRequiresFreshCheckEvenWhenOffline(t *testing.T) {
	for _, manual := range []bool{false, true} {
		h := newHarness(t, "1.2.3.4")
		h.step(0)
		h.probe("1.2.3.4", "NL")
		h.g.Pause(h.now, time.Second)
		h.offline()
		if manual {
			h.g.Unpause(h.now)
		} else {
			h.step(2 * time.Second)
		}
		if !h.p.frozen[claude.PID] {
			t.Fatal("pause ended with apps running before a new check")
		}
		h.probe("1.2.3.4", "NL")
		if h.p.frozen[claude.PID] {
			t.Fatal("fresh check failed to resume")
		}
	}
}

func TestFingerprintChangeBeforeResultAndNoInterfaces(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	h.fp = ""
	h.step(0)
	id := h.g.probeID
	h.fp = "ethernet=192.168.1.5"
	h.g.HandleProbe(h.now, ProbeResult{ID: id, IP: "1.2.3.4", Votes: 2})
	if !h.p.frozen[claude.PID] || h.g.probeID == id {
		t.Fatal("empty fingerprint was mistaken for uninitialized state")
	}
}

func TestNetworkSubscriptionFailureCannotReleaseApps(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	h.step(0)
	h.probe("1.2.3.4", "NL")
	h.g.CheckNow(h.now)
	h.step(0)
	id := h.g.probeID
	h.g.d.NetworkError = func() error { return errors.New("subscription lost") }
	h.g.HandleProbe(h.now, ProbeResult{ID: id, IP: "1.2.3.4", Votes: 2})
	if !h.p.frozen[claude.PID] || h.g.Snapshot(h.now).Allowed() || len(h.g.Snapshot(h.now).Errors) == 0 {
		t.Fatal("monitor failure silently allowed apps")
	}
}

func TestProbeStartedBySettingsBeforeFirstTickStillHasNetworkBaseline(t *testing.T) {
	h := newHarness(t, "1.2.3.4")
	h.g.SetConfig(h.now, h.g.cfg.Clone())
	id := h.g.probeID
	h.revision++
	h.g.HandleProbe(h.now, ProbeResult{ID: id, IP: "1.2.3.4", Votes: 2})
	if !h.p.frozen[claude.PID] || h.g.probeID == id {
		t.Fatal("first settings-triggered probe lost its network baseline")
	}
}

func TestInconclusiveIPv6CannotResumeOnAllowedIPv4(t *testing.T) {
	h := newHarness(t, "1.2.3.4", "2001:db8::/64")
	h.step(0)
	h.probeFull(ProbeResult{IP: "1.2.3.4", Votes: 2, IP6: "2001:db9::1"})
	h.want(Suspect)
	h.probeFull(ProbeResult{IP: "1.2.3.4", Votes: 2, IPv6Unknown: true})
	if !h.p.frozen[claude.PID] || h.g.Snapshot(h.now).Reason != IPv6Unconfirmed {
		t.Fatal("IPv6 failure treated as no IPv6")
	}
	h.probeFull(ProbeResult{IP: "1.2.3.4", Votes: 2, IP6: "2001:db8::1"})
	h.want(OK)
}

func TestConflictingIPv6CannotResumeOnAllowedWinningAddress(t *testing.T) {
	h := newHarness(t, "203.0.113.10", "2001:db8::/64")
	h.step(0)
	h.probeFull(ProbeResult{IP: "203.0.113.10", Votes: 2, IP6: "2001:db8::1", IPv6Unknown: true})
	if !h.p.frozen[claude.PID] || h.g.Snapshot(h.now).Reason != IPv6Unconfirmed {
		t.Fatal("an allowed IPv6 winner hid a conflicting exit")
	}
	h.probeFull(ProbeResult{IP: "203.0.113.10", Votes: 2, IP6: "2001:db8::1"})
	h.want(OK)
	if h.p.frozen[claude.PID] {
		t.Fatal("fresh conclusive IPv6 check did not release the pause")
	}
}
