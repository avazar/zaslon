package guard

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/procs"
)

func TestKnownUnsafeGeneralExitSurvivesIgnoredFailure(t *testing.T) {
	for _, family := range []string{"v4", "v6", "v6-conflict", "v4-conflict", "quorum"} {
		t.Run(family, func(t *testing.T) {
			h := newHarness(t, "203.0.113.10", "2001:db8::/64")
			c := h.g.cfg.Clone()
			c.DNSCheck = "off"
			c.IPUnavailableAction, c.IPv6UnavailableAction = config.IgnoreFailure, config.IgnoreFailure
			h.g.SetConfig(h.now, c)
			bad := ProbeResult{IP: "203.0.113.10", Votes: 2}
			switch family {
			case "v4":
				bad.IP = "192.0.2.99"
			case "v6":
				bad.IP6 = "2001:db9::1"
			case "v6-conflict":
				bad.IP6, bad.IPv6Conflicting = "2001:db8::1", true
			case "v4-conflict":
				bad.Others = []string{"192.0.2.99"}
			case "quorum":
				bad.Votes = 1
			}
			h.probeFull(bad)
			if !h.p.frozen[100] {
				t.Fatal("known denial did not suspend fixture")
			}
			for range 3 {
				r := ProbeResult{IP: "203.0.113.10", Votes: 2, IPv6Unknown: true, IPv6Possible: true}
				if family == "v4" || family == "v4-conflict" || family == "quorum" {
					r = ProbeResult{Err: errors.New("timeout"), IPv6Unknown: true, IPv6Possible: true}
				}
				h.probeFull(r)
				if !h.p.frozen[100] {
					t.Fatal("a failed check erased known unsafe evidence")
				}
			}
			h.probeFull(ProbeResult{IP: "203.0.113.10", Votes: 2, IP6: "2001:db8::1"})
			h.want(OK)
			if h.p.frozen[100] {
				t.Fatal("fresh permitted proof did not release the fixture")
			}
		})
	}
}

func TestKnownDomainDenialSurvivesFailureIndependently(t *testing.T) {
	for _, family := range []string{"v4", "v6"} {
		t.Run(family, func(t *testing.T) {
			h := domainHarness(t)
			c := h.g.cfg.Clone()
			c.IPUnavailableAction, c.IPv6UnavailableAction = config.IgnoreFailure, config.IgnoreFailure
			h.g.SetConfig(h.now, c)
			bad := domainReply(h, "203.0.113.10", "198.51.100.20")
			if family == "v4" {
				bad.Domains["claude"][0].IP = "192.0.2.99"
			} else {
				bad.Domains["claude"][0].IP6 = "2001:db9::1"
			}
			h.probeFull(bad)
			failed := domainReply(h, "203.0.113.10", "198.51.100.20")
			if family == "v4" {
				failed.Domains["claude"][0].IP, failed.Domains["claude"][0].Error = "", "HTTP 403"
			} else {
				failed.Domains["claude"][0].IPv6Error = "timeout"
			}
			h.probeFull(failed)
			if !h.p.frozen[100] || !h.p.frozen[101] || h.p.frozen[200] || h.p.frozen[201] {
				t.Fatalf("independent retained decisions lost: %v", h.p.frozen)
			}
			h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
			h.want(OK) // fresh successful absence of endpoint IPv6 is conclusive
		})
	}
}

func TestInvalidDomainReplyCannotEraseKnownDenial(t *testing.T) {
	for _, mode := range []string{"duplicate", "unexpected", "stale", "future", "missing"} {
		t.Run(mode, func(t *testing.T) {
			h := domainHarness(t)
			h.g.Update(h.now, func(c *config.Config) { c.IPUnavailableAction = config.IgnoreFailure })
			h.probeFull(domainReply(h, "192.0.2.99", "198.51.100.20"))
			r := domainReply(h, "203.0.113.10", "198.51.100.20")
			switch mode {
			case "duplicate":
				r.Domains["claude"] = append(r.Domains["claude"], r.Domains["claude"][0])
			case "unexpected":
				r.Domains["claude"] = append(r.Domains["claude"], DomainResult{Endpoint: "https://other.example/cdn-cgi/trace", CheckedAt: h.now})
			case "stale":
				r.Domains["claude"][0].CheckedAt = h.now.Add(-time.Second)
			case "future":
				r.Domains["claude"][0].CheckedAt = h.now.Add(time.Second)
			case "missing":
				delete(r.Domains, "claude")
			}
			h.probeFull(r)
			failed := domainReply(h, "", "198.51.100.20")
			failed.Domains["claude"][0].Error = "HTTP 403"
			h.probeFull(failed)
			if !h.p.frozen[100] || !h.p.frozen[101] || h.p.frozen[200] {
				t.Fatal("invalid reply erased the denial before a later ignored error")
			}
			h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
			h.want(OK)
		})
	}
}

func TestRemovingDomainCheckDiscardsOnlyItsEvidence(t *testing.T) {
	h := domainHarness(t)
	h.g.Update(h.now, func(c *config.Config) { c.IPUnavailableAction = config.IgnoreFailure })
	h.probeFull(domainReply(h, "192.0.2.99", "192.0.2.98"))
	h.g.Update(h.now, func(c *config.Config) { c.DomainChecksEnabled["claude"] = false })
	h.g.Update(h.now, func(c *config.Config) { c.DomainChecksEnabled["claude"] = true })
	r := domainReply(h, "", "")
	r.Domains["claude"][0].Error, r.Domains["cursor"][0].Error = "HTTP 403", "HTTP 403"
	h.probeFull(r)
	if h.p.frozen[100] || h.p.frozen[101] || !h.p.frozen[200] || !h.p.frozen[201] {
		t.Fatal("explicit check removal failed to discard only that app's evidence")
	}
}

func TestExplicitPolicyChangesReevaluateRememberedExit(t *testing.T) {
	h := newHarness(t, "203.0.113.10")
	c := h.g.cfg.Clone()
	c.IPv6UnavailableAction = config.IgnoreFailure
	h.g.SetConfig(h.now, c)
	h.probeFull(ProbeResult{IP: "203.0.113.10", Votes: 2, IP6: "2001:db9::1"})
	h.probeFull(ProbeResult{IP: "203.0.113.10", Votes: 2, IPv6Unknown: true})
	if !h.p.frozen[100] {
		t.Fatal("lost known IPv6 denial")
	}
	h.g.Update(h.now, func(c *config.Config) { c.CheckIPv6 = false })
	h.probeFull(ProbeResult{IP: "203.0.113.10", Votes: 2})
	h.want(OK)
	h.g.Update(h.now, func(c *config.Config) { c.CheckIPv6 = true })
	h.probeFull(ProbeResult{IP: "203.0.113.10", Votes: 2, IPv6Unknown: true})
	h.want(OK) // explicit disabling discarded the old family observation
}

func TestAllowCountryNeverAddsTheOtherIPv6Country(t *testing.T) {
	h := newHarness(t)
	h.step(0)
	h.probeFull(ProbeResult{IP: "203.0.113.10", Country: "NL", Votes: 2, IP6: "2001:db9::1", Country6: "RU"})
	if !h.g.AllowCurrentCountry(h.now) {
		t.Fatal("country not added")
	}
	if !slices.Equal(h.saved.Allow.Countries, []string{"NL"}) {
		t.Fatalf("unexpected countries: %v", h.saved.Allow.Countries)
	}
	h.probeFull(ProbeResult{IP: "203.0.113.10", Country: "NL", Votes: 2, IP6: "2001:db9::1", Country6: "RU"})
	if !h.p.frozen[100] {
		t.Fatal("IPv6 country was implicitly allowed")
	}
}

func TestExpiredGeneralResultCannotResumeOrReplaceEvidence(t *testing.T) {
	h := newHarness(t, "203.0.113.10")
	h.step(0)
	h.probe("192.0.2.99", "RU")
	h.g.CheckNow(h.now)
	h.step(0)
	id := h.g.probeID
	h.now = h.now.Add(MaxProbeAge)
	h.g.HandleProbe(h.now, ProbeResult{ID: id, IP: "203.0.113.10", Votes: 2})
	if !h.p.frozen[100] || h.g.probeID == id || h.g.lastIPv4.ip != "192.0.2.99" {
		t.Fatal("expired success erased the denial or resumed the fixture")
	}
	h.probe("203.0.113.10", "NL")
	h.want(OK)
}

func TestProbeFreshnessIncludesWallClockAndRejectsFuture(t *testing.T) {
	start := time.Now()
	for _, now := range []time.Time{start.Add(-time.Second), start.Add(MaxProbeAge), start.Add(time.Hour), start.Round(0).Add(time.Hour)} {
		if freshProbe(start, now) {
			t.Fatalf("accepted invalid timestamp: %v", now)
		}
	}
	if !freshProbe(start, start.Add(time.Second)) {
		t.Fatal("fresh result rejected")
	}
}

func TestControlExemptionDoesNotHideOrdinaryDescendants(t *testing.T) {
	p := newFakeProcs(
		procs.Proc{PID: 100, Created: "app", Name: "claude"},
		procs.Proc{PID: 200, Created: "own", PPID: 100, Name: "zaslon", Control: true},
		procs.Proc{PID: 201, Created: "panel", PPID: 200, Name: "msedge", Control: true},
		procs.Proc{PID: 202, Created: "worker", PPID: 200, Name: "ordinary-network-worker"},
	)
	c := config.Default()
	c.Apps = []string{"claude"}
	g := New(c, Deps{Self: 200, Procs: p, Fingerprint: func() string { return "fixture" },
		StartProbe: func(*config.Config, uint64, ProbePlan) func() { return nil }})
	g.Step(time.Now())
	if p.frozen[200] || p.frozen[201] || !p.frozen[100] || !p.frozen[202] {
		t.Fatalf("control exception was too broad: %v", p.frozen)
	}
}

func TestFormerlyHeldControlIsReleasedWithoutReleasingApps(t *testing.T) {
	h := newHarness(t)
	h.step(0)
	h.p.procs[0].Control = true
	h.step(time.Millisecond)
	if h.p.frozen[100] {
		t.Fatal("positively identified own control remained held")
	}
	if len(h.g.groups[0].frozen) != 0 {
		t.Fatal("control stayed in protection ownership")
	}
}

func TestTrustConfirmationRejectsAnotherRouter(t *testing.T) {
	h := newHarness(t, "203.0.113.10")
	h.step(0)
	h.probeFull(ProbeResult{IP: "203.0.113.10", Votes: 2, NetID: "router-a"})
	if h.g.TrustNetwork(h.now, "router-b", "Office") || h.saved != nil {
		t.Fatal("trusted a network not shown in confirmation")
	}
	if !h.g.TrustNetwork(h.now, "router-a", "Office") {
		t.Fatal("matching router confirmation rejected")
	}
}
