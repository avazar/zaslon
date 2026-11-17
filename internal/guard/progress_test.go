package guard

import (
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
)

func TestProgressRequiresEveryApplicablePolicyBeforeResume(t *testing.T) {
	h := domainHarness(t)
	h.p.procs[2].PPID = 100 // Cursor is also subject to Claude's policy.
	h.step(0)
	completeApp := func(app, endpoint string) {
		h.g.HandleProbe(h.now, ProbeResult{ID: h.g.probeID, Part: DomainGroup, Domains: map[string][]DomainResult{
			app: {{Endpoint: endpoint, IP: "203.0.113.10", CheckedAt: h.now}},
		}})
	}
	completeApp("cursor", cursorEndpoint)
	if !h.p.frozen[200] {
		t.Fatal("released child before parent policy finished")
	}
	completeApp("claude", claudeEndpoint)
	if h.g.generalReady || !h.g.probing || h.p.frozen[100] || h.p.frozen[200] || h.p.frozen[201] {
		t.Fatal("complete domain policies should release before general diagnostics")
	}

	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	h.g.CheckNow(h.now)
	h.step(time.Millisecond)
	id := h.g.probeID
	bad := DomainResult{Endpoint: claudeEndpoint, IP6: "2001:db9::9", Country6: "RU", CheckedAt: h.now}
	h.g.HandleProbe(h.now, ProbeResult{ID: id, Part: DomainFamily, SampleIPv6: true, Sample: bad})
	if !h.p.frozen[100] || !h.p.frozen[200] || h.g.Snapshot(h.now).Reason != DomainIPNotAllowed {
		t.Fatal("a denied family did not immediately suspend the entire affected tree")
	}
	denied := domainReply(h, "203.0.113.10", "198.51.100.20")
	denied.Domains["claude"][0].IP6 = bad.IP6
	h.probeFull(denied)
	h.g.CheckNow(h.now)
	h.step(time.Millisecond)
	id = h.g.probeID
	completeApp("claude", claudeEndpoint)
	if h.p.frozen[100] || !h.p.frozen[200] {
		t.Fatal("child used old success for its own policy")
	}
	h.revision++
	completeApp("cursor", cursorEndpoint)
	if !h.p.frozen[100] || !h.p.frozen[200] || h.g.probeID == id {
		t.Fatal("stale domain group crossed network revision")
	}
}

func TestDisplaySettingsPreserveActiveCheckAndRunningApp(t *testing.T) {
	h := newHarness(t, "203.0.113.10")
	h.step(0)
	h.probe("203.0.113.10", "PL")
	h.g.CheckNow(h.now)
	h.step(time.Millisecond)
	id := h.g.probeID
	if err := h.g.Update(h.now, func(c *config.Config) {
		c.Notifications = !c.Notifications
		c.MenuBar = "country"
		c.Language = "ru"
		c.Theme = "dark"
		c.UpdateCheck = !c.UpdateCheck
	}); err != nil {
		t.Fatal(err)
	}
	if h.g.probeID != id || h.p.frozen[100] || h.saved.MenuBar != "country" || h.saved.Theme != "dark" {
		t.Fatal("display settings disrupted protection")
	}
	h.g.Update(h.now, func(c *config.Config) { c.Allow.Countries = []string{"PL"} })
	if !h.p.frozen[100] || h.g.Snapshot(h.now).Reason != SettingsChanged {
		t.Fatal("policy edit must wait for a fresh check and identify its cause")
	}
}

func TestCountryUnknownPoliciesAndConfirmedDenials(t *testing.T) {
	for _, domains := range []bool{false, true} {
		for _, ipv6 := range []bool{false, true} {
			h := domainHarness(t)
			h.g.Update(h.now, func(c *config.Config) {
				c.Allow = config.Allow{Countries: []string{"PL"}}
				c.DomainChecksEnabled["claude"] = domains
			})
			reply := func(cc string) {
				r := domainReply(h, "203.0.113.10", "198.51.100.20")
				r.Err, r.IP, r.Country, r.Votes = nil, "203.0.113.10", "PL", 2
				d := &r.Domains["claude"][0]
				d.Country = "PL"
				if ipv6 {
					r.IP6, r.Country6 = "2001:db8::1", cc
					d.IP6, d.Country6 = r.IP6, cc
				} else {
					r.Country, d.Country = cc, cc
				}
				h.probeFull(r)
			}
			reason := CountryUnknown
			if ipv6 {
				reason = IPv6CountryUnknown
			}
			reply("")
			var group *group
			for _, gr := range h.g.groups {
				for _, target := range gr.tgts {
					if target.ID == "claude" {
						group = gr
					}
				}
			}
			if !h.p.frozen[100] || group.reason != reason {
				t.Fatalf("domain=%t ipv6=%t reason=%v", domains, ipv6, group.reason)
			}
			h.g.Update(h.now, func(c *config.Config) {
				c.IPUnavailableAction = config.IgnoreFailure
				c.IPv6UnavailableAction = config.IgnoreFailure
			})
			reply("")
			if !h.p.frozen[100] || group.reason != reason {
				t.Fatal("ignoring a missing IP must not authorize a measured exit with unknown country")
			}
			// A literal IP grant is sufficient, even when location is unavailable.
			h.g.Update(h.now, func(c *config.Config) { c.Allow.IPs = []string{"203.0.113.10", "2001:db8::1"} })
			reply("")
			if h.p.frozen[100] {
				t.Fatal("an explicit address grant required a country")
			}
			h.g.Update(h.now, func(c *config.Config) { c.Allow.IPs = nil })
			reply("RU")
			reply("")
			if !h.p.frozen[100] {
				t.Fatal("missing location erased confirmed denial")
			}
			reply("PL")
			if h.p.frozen[100] {
				t.Fatal("fresh permitted location did not release")
			}
		}
	}
}

func TestCountryDisplayUsesOnlyCurrentMatchingExit(t *testing.T) {
	h := domainHarness(t)
	c := h.g.cfg.Clone()
	c.Allow = config.Allow{Countries: []string{"PL"}}
	h.g.SetConfig(h.now, c)
	measure := func(otherIP, otherCountry string) {
		r := domainReply(h, "203.0.113.10", otherIP)
		r.IP, r.Err, r.Votes = "203.0.113.10", nil, 2
		r.Domains["claude"][0].Country = "PL"
		r.Domains["cursor"][0].Country = otherCountry
		h.probeFull(r)
	}
	measure("198.51.100.3", "DE")
	s := h.g.Snapshot(h.now)
	if s.Country != "" || s.DisplayCountry() != "PL" || s.AllowedNow || h.g.AllowCurrentCountry(h.now) {
		t.Fatal("display evidence changed policy or was lost")
	}
	if h.g.Snapshot(h.now.Add(DomainMaxAge)).DisplayCountry() != "" {
		t.Fatal("expired country still displayed")
	}
	measure("203.0.113.10", "DE")
	if h.g.Snapshot(h.now).DisplayCountry() != "" {
		t.Fatal("conflicting countries displayed")
	}
	measure("203.0.113.10", "PL")
	h.revision++
	h.step(time.Millisecond)
	if h.g.Snapshot(h.now).DisplayCountry() != "" {
		t.Fatal("country survived a network change")
	}
}
