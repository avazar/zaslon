package guard

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
)

func TestUnavailablePoliciesAndKnownUnsafeEvidence(t *testing.T) {
	suspend, ignore := config.SuspendOnFailure, config.IgnoreFailure
	good := ProbeResult{IP: "203.0.113.10", Votes: 2}
	tests := []struct {
		name     string
		ip, v6   config.FailureAction
		r        ProbeResult
		reason   Reason
		warnings []Reason
	}{
		{"offline-strict", suspend, suspend, ProbeResult{Err: errors.New("offline")}, Offline, nil},
		{"offline-ignore", ignore, suspend, ProbeResult{Err: errors.New("offline")}, NoReason, []Reason{Offline}},
		{"v6-strict", suspend, suspend, ProbeResult{IP: good.IP, Votes: 2, IPv6Unknown: true}, IPv6Unconfirmed, nil},
		{"v6-ignore", suspend, ignore, ProbeResult{IP: good.IP, Votes: 2, IPv6Unknown: true}, NoReason, []Reason{IPv6Unconfirmed}},
		{"both-strict-v6", ignore, suspend, ProbeResult{Err: errors.New("offline"), IPv6Unknown: true}, IPv6Unconfirmed, nil},
		{"both-strict-v4", suspend, ignore, ProbeResult{Err: errors.New("offline"), IPv6Unknown: true}, Offline, nil},
		{"both-ignore", ignore, ignore, ProbeResult{Err: errors.New("offline"), IPv6Unknown: true}, NoReason, []Reason{Offline, IPv6Unconfirmed}},
		{"bad-v4", ignore, ignore, ProbeResult{IP: "192.0.2.99", Votes: 2, IPv6Unknown: true}, IPNotAllowed, nil},
		{"bad-v6", ignore, ignore, ProbeResult{IP: good.IP, Votes: 2, IP6: "2001:db9::1"}, IPv6Leak, nil},
		{"offline-bad-v6", ignore, ignore, ProbeResult{Err: errors.New("offline"), IP6: "2001:db9::1"}, IPv6Leak, nil},
		{"v6-conflict", ignore, ignore, ProbeResult{IP: good.IP, Votes: 2, IP6: "2001:db8::1", IPv6Conflicting: true}, IPv6Conflict, nil},
		{"offline-v6-conflict", ignore, ignore, ProbeResult{Err: errors.New("offline"), IP6: "2001:db8::1", IPv6Conflicting: true}, IPv6Conflict, nil},
		{"v4-conflict", ignore, ignore, ProbeResult{IP: good.IP, Votes: 2, Others: []string{"192.0.2.99"}}, Unconfirmed, nil},
		{"low-quorum", ignore, ignore, ProbeResult{IP: good.IP, Votes: 1}, Unconfirmed, nil},
		{"good", ignore, ignore, good, NoReason, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, good.IP, "2001:db8::/64")
			c := h.g.cfg.Clone()
			c.IPUnavailableAction, c.IPv6UnavailableAction = tc.ip, tc.v6
			h.g.SetConfig(h.now, c)
			if !h.p.frozen[100] {
				t.Fatal("policy skipped the initial current-network check")
			}
			h.probeFull(tc.r)
			s := h.g.Snapshot(h.now)
			if tc.reason == NoReason {
				h.want(OK)
			} else {
				h.want(Suspect)
				if s.Reason != tc.reason {
					t.Fatalf("reason %v, want %v", s.Reason, tc.reason)
				}
			}
			if h.p.frozen[100] != (tc.reason != NoReason) {
				t.Fatal("process suspension disagrees with verdict")
			}
			var warnings []Reason
			for _, w := range s.Warnings {
				warnings = append(warnings, w.Reason)
			}
			if !reflect.DeepEqual(warnings, tc.warnings) {
				t.Fatalf("warnings %v, want %v", warnings, tc.warnings)
			}
			if len(warnings) > 0 && s.Allowed() {
				t.Fatal("ignored proof was presented as a verified allowed exit")
			}
		})
	}
}

func TestIgnoredFailureStillInvalidatesOnNetworkAndSettingsChanges(t *testing.T) {
	h := newHarness(t, "203.0.113.10")
	c := h.g.cfg.Clone()
	c.IPv6UnavailableAction = config.IgnoreFailure
	h.g.SetConfig(h.now, c)
	r := ProbeResult{IP: "203.0.113.10", Votes: 2, IPv6Unknown: true}
	h.probeFull(r)
	h.want(OK)
	oldID := h.g.probeID
	h.revision++
	h.step(time.Second)
	if !h.p.frozen[100] {
		t.Fatal("ignored result crossed a network event")
	}
	r.ID = oldID
	h.g.HandleProbe(h.now, r)
	if !h.p.frozen[100] {
		t.Fatal("stale result resumed apps")
	}
	h.probeFull(r)
	h.want(OK)
	c.IPv6UnavailableAction = config.SuspendOnFailure
	h.g.SetConfig(h.now, c)
	if !h.p.frozen[100] {
		t.Fatal("stricter policy did not freeze immediately")
	}
	h.probeFull(r)
	h.want(Suspect)
	h.probe("203.0.113.10", "NL")
	h.want(OK)
	if len(h.g.Snapshot(h.now).Warnings) != 0 {
		t.Fatal("warning survived a successful check")
	}
}

func TestDomainPoliciesApplyToEachEndpointAndBothFamilies(t *testing.T) {
	for _, mode := range []string{"v6-error", "v4-error", "v4-error-v6-error", "v4-error-v6-bad", "other-endpoint-bad", "expired"} {
		t.Run(mode, func(t *testing.T) {
			h := domainHarness(t)
			c := h.g.cfg.Clone()
			c.IPUnavailableAction, c.IPv6UnavailableAction = config.IgnoreFailure, config.IgnoreFailure
			h.g.SetConfig(h.now, c)
			r := domainReply(h, "203.0.113.10", "198.51.100.20")
			d := r.Domains["claude"][0]
			switch mode {
			case "v6-error":
				d.IPv6Error = "timeout"
			case "v4-error":
				d.IP, d.Error = "", "HTTP 403"
			case "v4-error-v6-error":
				d.IP, d.Error, d.IPv6Error = "", "timeout", "timeout"
			case "v4-error-v6-bad":
				d.IP, d.Error, d.IP6 = "", "timeout", "2001:db9::1"
			case "other-endpoint-bad":
				c.DomainChecks["claude"] = append(c.DomainChecks["claude"], "https://second.example/cdn-cgi/trace")
				h.g.SetConfig(h.now, c)
				d.IP, d.Error = "", "timeout"
				r.Domains["claude"] = append(r.Domains["claude"], DomainResult{Endpoint: c.DomainChecks["claude"][1], IP: "192.0.2.99", CheckedAt: h.now})
			case "expired":
				d.CheckedAt = h.now.Add(-DomainMaxAge)
			}
			r.Domains["claude"][0] = d
			h.probeFull(r)
			bad := mode == "v4-error-v6-bad" || mode == "other-endpoint-bad"
			if h.p.frozen[100] != bad || h.p.frozen[101] != bad || h.p.frozen[200] {
				t.Fatalf("wrong independent decisions: %v", h.p.frozen)
			}
			if !bad && len(h.g.Snapshot(h.now).Warnings) == 0 {
				t.Fatal("missing warning")
			}
		})
	}
}

func TestIPFailurePolicyDoesNotIgnoreDomainIPv6Failure(t *testing.T) {
	h := domainHarness(t)
	c := h.g.cfg.Clone()
	c.IPUnavailableAction = config.IgnoreFailure
	h.g.SetConfig(h.now, c)
	r := domainReply(h, "203.0.113.10", "198.51.100.20")
	r.Domains["claude"][0].IPv6Error = "blocked by VPN"
	h.probeFull(r)
	if !h.p.frozen[100] || h.p.frozen[200] {
		t.Fatal("IPv6 error used the IPv4 failure policy")
	}
	c.IPv6UnavailableAction = config.IgnoreFailure
	h.g.SetConfig(h.now, c)
	h.probeFull(r)
	if h.p.frozen[100] {
		t.Fatal("explicit IPv6 policy was not honored")
	}
}

func TestIgnoredChildFailureCannotBypassParentDenial(t *testing.T) {
	h := domainHarness(t)
	h.p.procs[2].PPID = 100
	h.step(0)
	c := h.g.cfg.Clone()
	c.IPUnavailableAction, c.IPv6UnavailableAction = config.IgnoreFailure, config.IgnoreFailure
	h.g.SetConfig(h.now, c)
	r := domainReply(h, "192.0.2.99", "198.51.100.20")
	r.Domains["cursor"][0].IPv6Error = "timeout"
	h.probeFull(r)
	for _, pid := range []int{100, 101, 200, 201} {
		if !h.p.frozen[pid] {
			t.Fatalf("PID %d bypassed the ancestor policy", pid)
		}
	}
}

func TestMissingAndExpiredDomainProofStillRequiresIPv6Policy(t *testing.T) {
	for _, mode := range []string{"missing", "expired"} {
		t.Run(mode, func(t *testing.T) {
			h := domainHarness(t)
			c := h.g.cfg.Clone()
			c.IPUnavailableAction = config.IgnoreFailure
			h.g.SetConfig(h.now, c)
			r := domainReply(h, "203.0.113.10", "198.51.100.20")
			r.IPv6Possible = true
			if mode == "missing" {
				delete(r.Domains, "claude")
			} else {
				r.Domains["claude"][0].CheckedAt = h.now.Add(-DomainMaxAge)
			}
			h.probeFull(r)
			if !h.p.frozen[100] || h.g.Snapshot(h.now).Reason != IPv6Unconfirmed {
				t.Fatal("IP failure policy bypassed missing IPv6 domain evidence")
			}
			c.IPv6UnavailableAction = config.IgnoreFailure
			h.g.SetConfig(h.now, c)
			h.probeFull(r)
			if h.p.frozen[100] {
				t.Fatal("both explicit policies did not permit unavailable evidence")
			}
		})
	}
}

func TestIgnorePoliciesNeverBypassMonitorErrorsOrMalformedDomainResults(t *testing.T) {
	h := newHarness(t, "203.0.113.10")
	c := h.g.cfg.Clone()
	c.IPUnavailableAction, c.IPv6UnavailableAction = config.IgnoreFailure, config.IgnoreFailure
	h.g.SetConfig(h.now, c)
	h.g.d.NetworkError = func() error { return errors.New("monitor failed") }
	h.step(time.Second)
	if !h.p.frozen[100] || len(h.g.Snapshot(h.now).Errors) == 0 {
		t.Fatal("ignore bypassed the network monitor error")
	}
	for _, mode := range []string{"duplicate", "wrong-endpoint"} {
		t.Run(mode, func(t *testing.T) {
			h := domainHarness(t)
			c := h.g.cfg.Clone()
			c.IPUnavailableAction, c.IPv6UnavailableAction = config.IgnoreFailure, config.IgnoreFailure
			h.g.SetConfig(h.now, c)
			r := domainReply(h, "203.0.113.10", "198.51.100.20")
			if mode == "duplicate" {
				r.Domains["claude"] = append(r.Domains["claude"], r.Domains["claude"][0])
			} else {
				r.Domains["claude"][0].Endpoint = cursorEndpoint
			}
			h.probeFull(r)
			if !h.p.frozen[100] {
				t.Fatal("ignore accepted a malformed internal result")
			}
		})
	}
}
