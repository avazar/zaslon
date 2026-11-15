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

func TestDomainTimeoutRetriesAfterFreezeAndRequiresFreshSuccess(t *testing.T) {
	h := domainHarness(t)
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	var ids []uint64
	var requested []bool
	requireHeld := false
	h.g.d.StartProbe = func(_ *config.Config, id uint64, domains bool) func() {
		if requireHeld && (!h.p.frozen[100] || !h.p.frozen[101] || h.p.frozen[200] || h.p.frozen[201]) {
			t.Error("retry started before freezing the affected tree or froze another app")
		}
		ids = append(ids, id)
		requested = append(requested, domains)
		return func() {}
	}
	h.step(DomainInterval)
	oldID := h.g.probeID
	h.step(4 * time.Second)
	requireHeld = true
	r := timedOutReply(h, false)
	r.ID = oldID
	h.g.HandleProbe(h.now, r)
	if len(ids) != 2 || !requested[1] || ids[1] == oldID || h.g.probeStarted != h.now {
		t.Fatal("timeout did not start an immediate, separately numbered domain check")
	}
	// The former request cannot release this hold after its retry has started.
	stale := domainReply(h, "203.0.113.10", "198.51.100.20")
	stale.ID = oldID
	h.g.HandleProbe(h.now, stale)
	if !h.p.frozen[100] || !h.p.frozen[101] || len(ids) != 2 {
		t.Fatal("stale success resumed processes or duplicated the retry")
	}
	// Even a new result must obey all domains and the app's allow-list.
	bad := domainReply(h, "192.0.2.99", "198.51.100.20")
	bad.ID = h.g.probeID
	h.g.HandleProbe(h.now, bad)
	if !h.p.frozen[100] || !h.p.frozen[101] {
		t.Fatal("retry resumed a forbidden exit")
	}
	requireHeld = false
	h.step(DomainInterval)
	fresh := domainReply(h, "203.0.113.10", "198.51.100.20")
	fresh.ID = h.g.probeID
	h.g.HandleProbe(h.now, fresh)
	if h.p.frozen[100] || h.p.frozen[101] {
		t.Fatal("verified retry-cycle result did not resume tree")
	}
}

func TestDomainTimeoutImmediateRetryIsBoundedAndRearmsOnSuccess(t *testing.T) {
	h := domainHarness(t)
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	h.step(DomainInterval)
	r := timedOutReply(h, false)
	r.ID = h.g.probeID
	h.g.HandleProbe(h.now, r)
	retryID := h.g.probeID
	r = timedOutReply(h, false)
	r.ID = retryID
	h.g.HandleProbe(h.now, r)
	if h.g.probing || h.g.probeID != retryID || !h.p.frozen[100] || !h.p.frozen[101] {
		t.Fatal("failed retry looped or resumed the app")
	}
	h.step(FastCheck)
	if h.g.checkingDomains {
		t.Fatal("failed immediate retry bypassed normal domain cadence again")
	}
	g := ProbeResult{ID: h.g.probeID}
	h.g.HandleProbe(h.now, g)
	if !h.p.frozen[100] {
		t.Fatal("general check bypassed domain failure")
	}
	h.step(DomainInterval)
	fresh := domainReply(h, "203.0.113.10", "198.51.100.20")
	fresh.ID = h.g.probeID
	h.g.HandleProbe(h.now, fresh)
	h.step(DomainInterval)
	id := h.g.probeID
	r = timedOutReply(h, false)
	r.ID = id
	h.g.HandleProbe(h.now, r)
	if !h.g.probing || !h.g.checkingDomains || h.g.probeID != id+1 {
		t.Fatal("verified success did not rearm the next suspension's retry")
	}
}

func TestDomainTimeoutRetryHonoursFailurePoliciesAndEvidence(t *testing.T) {
	for _, mode := range []string{"ipv6", "ignore-ipv6", "ignore-ip", "403", "forbidden-other-domain", "missing", "stale-timeout", "network-change", "no-processes"} {
		t.Run(mode, func(t *testing.T) {
			h := domainHarness(t)
			if mode == "ignore-ip" {
				h.g.cfg.IPUnavailableAction = config.IgnoreFailure
			}
			if mode == "ignore-ipv6" {
				h.g.cfg.IPv6UnavailableAction = config.IgnoreFailure
			}
			h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
			h.step(DomainInterval)
			id := h.g.probeID
			r := timedOutReply(h, mode == "ipv6" || mode == "ignore-ipv6")
			r.ID = id
			d := &r.Domains["claude"][0]
			switch mode {
			case "403":
				d.Error, d.Timeout = "HTTP 403", false
			case "forbidden-other-domain":
				h.g.cfg.DomainChecks["claude"] = append(h.g.cfg.DomainChecks["claude"], "https://other.example/cdn-cgi/trace")
				r.Domains["claude"] = append(r.Domains["claude"], DomainResult{Endpoint: "https://other.example/cdn-cgi/trace", IP: "192.0.2.99", CheckedAt: h.now})
			case "missing":
				delete(r.Domains, "claude")
			case "stale-timeout":
				d.CheckedAt = h.now.Add(-time.Hour)
			case "network-change":
				h.revision++
			case "no-processes":
				h.p.remove(100)
				h.p.remove(101)
			}
			h.g.HandleProbe(h.now, r)
			wantRetry := mode == "ipv6"
			if mode == "network-change" { // only the new network's own check may exist
				if !h.p.frozen[100] || h.g.domains["claude"] != nil {
					t.Fatal("old network's timeout crossed revision")
				}
				return
			}
			if (h.g.probeID == id+1) != wantRetry {
				t.Fatalf("mode=%s retry=%v", mode, h.g.probeID != id)
			}
			if wantRetry && (!h.p.frozen[100] || !h.p.frozen[101]) {
				t.Fatal("IPv6 retry did not keep tree suspended")
			}
		})
	}
}

func TestDomainRetryRequiresEveryDomainAndCurrentNetwork(t *testing.T) {
	for _, mode := range []string{"missing-domain", "old-domain", "network-change"} {
		t.Run(mode, func(t *testing.T) {
			h := domainHarness(t)
			other := "https://second.example/cdn-cgi/trace"
			c := h.g.cfg.Clone()
			c.DomainChecks["claude"] = append(c.DomainChecks["claude"], other)
			h.g.SetConfig(h.now, c)
			complete := func() ProbeResult {
				r := domainReply(h, "203.0.113.10", "198.51.100.20")
				r.Domains["claude"] = append(r.Domains["claude"], DomainResult{Endpoint: other, IP: "203.0.113.10", CheckedAt: h.now})
				return r
			}
			h.probeFull(complete())
			h.step(DomainInterval)
			r := complete()
			r.Domains["claude"][0].Error, r.Domains["claude"][0].Timeout = "deadline", true
			r.ID = h.g.probeID
			h.g.HandleProbe(h.now, r)
			r = complete()
			r.ID = h.g.probeID
			switch mode {
			case "missing-domain":
				r.Domains["claude"] = r.Domains["claude"][:1]
			case "old-domain":
				r.Domains["claude"][1].CheckedAt = h.now.Add(-time.Second)
			case "network-change":
				h.revision++
			}
			h.g.HandleProbe(h.now, r)
			if !h.p.frozen[100] || !h.p.frozen[101] {
				t.Fatal("incomplete or old-network retry success resumed processes")
			}
			if mode != "network-change" {
				h.step(DomainInterval)
			}
			r = complete()
			r.ID = h.g.probeID
			h.g.HandleProbe(h.now, r)
			if h.p.frozen[100] || h.p.frozen[101] {
				t.Fatal("complete current-network success did not resume processes")
			}
		})
	}
}

func TestDomainRetrySuccessStillObeysChildPolicy(t *testing.T) {
	h := domainHarness(t)
	h.p.procs[2].PPID = 100
	h.step(0)
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	h.step(DomainInterval)
	r := timedOutReply(h, false)
	r.ID = h.g.probeID
	h.g.HandleProbe(h.now, r)
	for _, pid := range []int{100, 101, 200, 201} {
		if !h.p.frozen[pid] {
			t.Fatal("parent timeout failed to hold descendant")
		}
	}
	r = domainReply(h, "203.0.113.10", "192.0.2.99")
	r.ID = h.g.probeID
	h.g.HandleProbe(h.now, r)
	if h.p.frozen[100] || h.p.frozen[101] || !h.p.frozen[200] || !h.p.frozen[201] {
		t.Fatal("successful parent retry bypassed the child's separate policy")
	}
}
