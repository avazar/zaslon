package guard

import (
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
)

func timedOutReply(h *harness, ipv6 bool) ProbeResult {
	r := domainReply(h, "203.0.113.10", "198.51.100.20")
	d := &r.Domains["claude"][0]
	if ipv6 {
		d.IPv6Error, d.IPv6Timeout = "TLS handshake timeout", true
	} else {
		d.IP, d.Error, d.Timeout = "", "context deadline exceeded", true
	}
	return r
}

// Family samples are delivered before the worker repeats the single request.
func timeoutDecision(h *harness, r ProbeResult, ipv6 bool) bool {
	reply := make(chan bool, 1)
	h.g.HandleProbe(h.now, ProbeResult{ID: r.ID, Part: DomainFamily, Sample: r.Domains["claude"][0], SampleIPv6: ipv6, Retry: reply})
	return <-reply
}

func TestDomainTimeoutRetriesOnlyWhileHeldAndRearmsAfterSuccess(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		h := domainHarness(t)
		good := func() ProbeResult { return domainReply(h, "203.0.113.10", "198.51.100.20") }
		h.probeFull(good())
		h.step(DomainInterval)
		r := timedOutReply(h, ipv6)
		r.ID = h.g.probeID
		if !timeoutDecision(h, r, ipv6) || !h.p.frozen[100] || !h.p.frozen[101] || h.p.frozen[200] || h.p.frozen[201] {
			t.Fatal("targeted retry requires the affected tree to be held")
		}
		if timeoutDecision(h, r, ipv6) {
			t.Fatal("retry loop")
		}
		h.probeFull(r)
		h.step(DomainInterval)
		r.ID = h.g.probeID
		if timeoutDecision(h, r, ipv6) {
			t.Fatal("uninterrupted failure rearmed retry")
		}
		success := good()
		h.g.HandleProbe(h.now, ProbeResult{Part: DomainGroup, ID: r.ID, Domains: success.Domains})
		h.probeFull(success)
		if h.p.frozen[100] {
			t.Fatal("fresh success did not resume application")
		}
		h.step(DomainInterval)
		r = timedOutReply(h, ipv6)
		r.ID = h.g.probeID
		if !timeoutDecision(h, r, ipv6) {
			t.Fatal("new timeout did not retry")
		}
	}
}

func TestDomainTimeoutRetryHonoursFailurePoliciesAndEvidence(t *testing.T) {
	for _, mode := range []string{"ignore-ip", "ignore-ipv6", "403", "stale", "network-change", "no-processes", "denied"} {
		t.Run(mode, func(t *testing.T) {
			h := domainHarness(t)
			if mode == "ignore-ip" {
				h.g.cfg.IPUnavailableAction = config.IgnoreFailure
			}
			if mode == "ignore-ipv6" {
				h.g.cfg.IPv6UnavailableAction = config.IgnoreFailure
			}
			good := domainReply(h, "203.0.113.10", "198.51.100.20")
			if mode == "denied" {
				good.Domains["claude"][0].IP = "192.0.2.99"
			}
			h.probeFull(good)
			h.step(DomainInterval)
			v6 := mode == "ignore-ipv6"
			r := timedOutReply(h, v6)
			r.ID = h.g.probeID
			switch mode {
			case "403":
				r.Domains["claude"][0].Timeout = false
				r.Domains["claude"][0].Error = "HTTP 403"
			case "stale":
				r.Domains["claude"][0].CheckedAt = h.now.Add(-time.Hour)
			case "network-change":
				h.revision++
			case "no-processes":
				h.p.remove(100)
				h.p.remove(101)
			}
			if timeoutDecision(h, r, v6) {
				t.Fatal("unexpected retry")
			}
		})
	}
}

func TestTargetedRetryStillRequiresSiblingAndAncestorPolicies(t *testing.T) {
	h := domainHarness(t)
	h.p.procs[2].PPID = 100
	cfg := h.g.cfg.Clone()
	cfg.DomainChecks["claude"] = append(cfg.DomainChecks["claude"], "second")
	h.g.SetConfig(h.now, cfg)
	r := timedOutReply(h, false)
	r.ID = h.g.probeID
	if !timeoutDecision(h, r, false) {
		t.Fatal("missing retry")
	}
	allowed := domainReply(h, "203.0.113.10", "192.0.2.99")
	allowed.ID = r.ID
	h.g.HandleProbe(h.now, ProbeResult{ID: r.ID, Part: DomainGroup, Domains: allowed.Domains})
	if !h.p.frozen[100] || !h.p.frozen[200] {
		t.Fatal("partial group released process")
	}
	allowed.Domains["claude"] = append(allowed.Domains["claude"], DomainResult{Endpoint: "second", IP: "203.0.113.10", CheckedAt: h.now})
	h.probeFull(allowed)
	if h.p.frozen[100] || !h.p.frozen[200] || !h.p.frozen[201] {
		t.Fatal("retry bypassed child policy")
	}
}

func TestIdleAppRelaunchRequiresNewDomainProbe(t *testing.T) {
	h := domainHarness(t)
	h.g.cfg.CheckInterval = config.Duration(time.Minute)
	good := func() ProbeResult { return domainReply(h, "203.0.113.10", "198.51.100.20") }
	h.probeFull(good())
	generalAt := h.g.measuredAt
	oldProcs := append(h.p.procs[:0:0], h.p.procs...)
	h.step(DomainInterval)
	old := h.g.probeID
	h.p.procs = nil
	h.step(time.Millisecond)
	h.p.procs = oldProcs[:2]
	h.step(time.Millisecond)
	if !h.p.frozen[100] {
		t.Fatal("relaunched app reused previous proof")
	}
	r := good()
	r.ID = old
	h.g.HandleProbe(h.now, r)
	if !h.p.frozen[100] {
		t.Fatal("old in-flight reply released new session")
	}
	h.step(0)
	if h.g.plan.General || len(h.g.plan.Apps) != 1 || !h.g.plan.Apps["claude"] {
		t.Fatalf("wrong sources: %+v", h.g.plan)
	}
	h.probeFull(good())
	if h.p.frozen[100] || h.g.measuredAt != generalAt {
		t.Fatal("domain-only result did not release or changed general IP")
	}
	h.p.procs = nil
	h.step(time.Millisecond)
	h.step(DomainInterval)
	if h.g.probing {
		t.Fatal("idle apps scheduled a domain check")
	}
	h.step(time.Minute)
	if !h.g.plan.General || len(h.g.plan.Apps) != 0 {
		t.Fatal("general IP should run alone")
	}
}

func TestSecondEndpointAttributedToHold(t *testing.T) {
	h := domainHarness(t)
	c := h.g.cfg.Clone()
	c.DomainChecks["claude"] = append(c.DomainChecks["claude"], "https://api.claude.example/check")
	h.g.SetConfig(h.now, c)
	r := domainReply(h, "203.0.113.10", "198.51.100.20")
	failed := DomainResult{Endpoint: c.DomainChecks["claude"][1], Timeout: true, Error: "deadline", CheckedAt: h.now}
	r.Domains["claude"] = append(r.Domains["claude"], failed)
	h.probeFull(r)
	for _, gr := range h.g.Snapshot(h.now).Groups {
		if gr.Key == "claude" && (len(gr.Issues) != 1 || gr.Issues[0].Endpoint != failed.Endpoint || !gr.Issues[0].Timeout) {
			t.Fatalf("wrong culprit: %+v", gr.Issues)
		}
	}
}

func TestReplacedProcessTreeCannotUseInflightDomainPermission(t *testing.T) {
	h := domainHarness(t)
	good := func() ProbeResult { return domainReply(h, "203.0.113.10", "198.51.100.20") }
	h.probeFull(good())
	h.step(DomainInterval)
	h.p.procs[0].Created = "new instance"
	h.p.procs[1].Created = "new child"
	h.step(time.Millisecond)
	h.probeFull(good())
	if !h.p.frozen[100] || h.p.frozen[200] {
		t.Fatal("process replacement reused old proof or affected independent app")
	}
	h.step(time.Millisecond)
	h.probeFull(good())
	if h.p.frozen[100] {
		t.Fatal("new verification did not release replacement")
	}
}
