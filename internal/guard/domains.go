package guard

import (
	"slices"
	"time"

	"github.com/avazar/zaslon/internal/config"
)

const DomainInterval = 15 * time.Second

// Allow the next bounded measurement to complete without routine micro-pauses.
const DomainMaxAge = 2 * DomainInterval

type DomainResult struct {
	Endpoint    string    `json:"endpoint"`
	IP          string    `json:"ip"`
	Country     string    `json:"country"`
	IP6         string    `json:"ip6"`
	Country6    string    `json:"country6"`
	Error       string    `json:"error,omitempty"`
	IPv6Error   string    `json:"ipv6Error,omitempty"`
	Timeout     bool      `json:"timeout,omitempty"`
	IPv6Timeout bool      `json:"ipv6Timeout,omitempty"`
	CheckedAt   time.Time `json:"checkedAt"`
}

// One immediate retry per uninterrupted hold. Preserve the failed evidence
// while it runs; only HandleProbe may replace it with a current result.
func (g *Guard) retryTimedOutDomains(now time.Time) {
	if g.paused(now) {
		return
	}
	var apps []string
	for _, gr := range g.groups {
		if !g.cfg.DomainCheckEnabled(gr.key) {
			continue
		}
		a := g.assess(gr, now)
		if gr.status == OK && a.reason == NoReason && len(a.ignored) == 0 {
			gr.timeoutRetried = false
			continue
		}
		if gr.timeoutRetried || (a.reason != DomainUnconfirmed && a.reason != IPv6Unconfirmed) || !g.domainTimedOut(gr, now) {
			continue
		}
		held := false
		for _, owner := range g.groups {
			for _, p := range owner.frozen {
				if p.AppID == gr.key || slices.Contains(p.PolicyIDs, gr.key) {
					held = true
				}
			}
		}
		if !held {
			continue
		}
		gr.timeoutRetried = true
		apps = append(apps, gr.names()...)
	}
	if len(apps) == 0 {
		return
	}
	g.nextDomainCheck = now
	g.nextCheck = now
	g.emit(now, Event{Kind: EvDomainCheck, Apps: apps, Details: []string{"retry=immediate after domain timeout; processes remain suspended"}})
	g.startProbe(now) // enforcement and original failure diagnostics have finished
}

func (g *Guard) domainTimedOut(gr *group, now time.Time) bool {
	for _, d := range g.domains[gr.key] {
		if !slices.Contains(g.cfg.DomainChecks[gr.key], d.Endpoint) || d.CheckedAt.IsZero() || d.CheckedAt.Before(g.domainStarted) || d.CheckedAt.After(now) || now.Sub(d.CheckedAt) >= DomainMaxAge {
			continue
		}
		if d.Error != "" && d.Timeout && (gr.recovering || g.cfg.IPUnavailableAction != config.IgnoreFailure) {
			return true
		}
		if g.cfg.CheckIPv6 && d.IPv6Error != "" && d.IPv6Timeout && (gr.recovering || g.cfg.IPv6UnavailableAction != config.IgnoreFailure) {
			return true
		}
	}
	return false
}

func cloneDomains(in map[string][]DomainResult) map[string][]DomainResult {
	out := make(map[string][]DomainResult, len(in))
	for k, v := range in {
		out[k] = append([]DomainResult(nil), v...)
	}
	return out
}

func (g *Guard) domainsDue(now time.Time) bool {
	for _, gr := range g.groups {
		if g.cfg.DomainCheckEnabled(gr.key) && (g.nextDomainCheck.IsZero() || !now.Before(g.nextDomainCheck)) {
			return true
		}
	}
	return false
}

func (g *Guard) hasDomainTargets() bool {
	for _, gr := range g.groups {
		if g.cfg.DomainCheckEnabled(gr.key) {
			return true
		}
	}
	return false
}

func (g *Guard) domainVerdict(gr *group, now time.Time, allow config.Allow) Reason {
	return g.assessDomains(gr, now, allow).reason
}

func (g *Guard) assessDomains(gr *group, now time.Time, allow config.Allow) assessment {
	expected := g.cfg.DomainChecks[gr.key]
	if len(expected) == 0 {
		return assessment{reason: DomainUnconfirmed}
	}
	got := g.domains[gr.key]
	seen := map[string]DomainResult{}
	for _, d := range got {
		if _, ok := seen[d.Endpoint]; ok {
			return assessment{reason: DomainUnconfirmed} // malformed internal result
		}
		found := false
		for _, endpoint := range expected {
			if endpoint == d.Endpoint {
				found = true
				break
			}
		}
		if !found {
			return assessment{reason: DomainUnconfirmed}
		}
		seen[d.Endpoint] = d
	}
	var unavailable []Reason
	for _, endpoint := range expected {
		d, ok := seen[endpoint]
		if !ok || d.CheckedAt.IsZero() || d.CheckedAt.Before(g.domainStarted) || d.CheckedAt.After(now) || now.Sub(d.CheckedAt) >= DomainMaxAge {
			unavailable = append(unavailable, DomainUnconfirmed)
			if g.cfg.CheckIPv6 && g.ipv6Possible {
				unavailable = append(unavailable, IPv6Unconfirmed)
			}
			continue
		}
		if d.Error != "" || d.IP == "" {
			unavailable = append(unavailable, DomainUnconfirmed)
		} else if !allow.Matches(d.IP, d.Country) {
			return assessment{reason: DomainIPNotAllowed}
		}
		if g.cfg.CheckIPv6 {
			if d.IPv6Error != "" {
				unavailable = append(unavailable, IPv6Unconfirmed)
			}
			if d.IP6 != "" && !allow.Matches(d.IP6, d.Country6) {
				return assessment{reason: DomainIPNotAllowed}
			}
		}
		if g.cfg.DNSCheck == "block" && g.dnsCC != "" && d.Country != "" && g.dnsCC != d.Country {
			allowed := false
			for _, cc := range allow.Countries {
				if cc == g.dnsCC {
					allowed = true
				}
			}
			if !allowed {
				return assessment{reason: DNSLeak}
			}
		}
	}
	return g.assessUnavailable(unavailable)
}

func (g *Guard) expireDomains(now time.Time) {
	if g.paused(now) {
		return
	}
	for _, gr := range g.groups {
		if gr.status == OK && g.cfg.DomainCheckEnabled(gr.key) {
			if why := g.domainVerdict(gr, now, g.allowFor(gr)); why != NoReason && !(g.trusted() && !g.offline && g.ip != "") {
				gr.status, gr.reason, gr.since = Suspect, why, now
				g.emit(now, Event{Kind: EvDomainCheck, Apps: gr.names(), Details: g.domainDiagnostics(gr, now)})
			}
		}
	}
}
