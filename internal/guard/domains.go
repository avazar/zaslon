package guard

import (
	"slices"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/procs"
)

// Allow one bounded measurement to finish after the next scheduled start.
func (g *Guard) domainMaxAge() time.Duration {
	interval := g.cfg.DomainCheckInterval.D()
	return max(interval, interval+MaxProbeAge)
}

type DomainResult struct {
	Retried     [2]bool          `json:"-"` // a timed-out attempt immediately preceded this result
	RouteTime   [2]time.Duration `json:"-"`
	RouteProxy  string           `json:"-"`
	Endpoint    string           `json:"endpoint"`
	IP          string           `json:"ip"`
	Country     string           `json:"country"`
	IP6         string           `json:"ip6"`
	Country6    string           `json:"country6"`
	Error       string           `json:"error,omitempty"`
	IPv6Error   string           `json:"ipv6Error,omitempty"`
	Timeout     bool             `json:"timeout,omitempty"`
	IPv6Timeout bool             `json:"ipv6Timeout,omitempty"`
	CheckedAt   time.Time        `json:"checkedAt"`
}

type domainFamily struct {
	endpoint string
	v6       bool
}

// The shared worker requests permission after publishing the timeout.
// Only a held policy can trigger a retry, once per endpoint/family until recovery.
func (g *Guard) retryDomainFamily(now time.Time, r ProbeResult) bool {
	d := r.Sample
	key := domainFamily{d.Endpoint, r.SampleIPv6}
	if g.paused(now) || g.retried[key] || !g.currentSample(now, d) || !(d.Timeout && !key.v6 || d.IPv6Timeout && key.v6) {
		return false
	}
	var apps []string
	for _, gr := range g.groups {
		if !g.plan.Apps[gr.key] || !slices.Contains(g.cfg.DomainChecks[gr.key], d.Endpoint) {
			continue
		}
		if g.earlyDenials[gr.key].reason == NoReason {
			continue
		}
		action := g.cfg.IPUnavailableAction
		if key.v6 {
			action = g.cfg.IPv6UnavailableAction
		}
		if !gr.recovering && action == config.IgnoreFailure {
			continue
		}
		if slices.ContainsFunc(g.cfg.DomainChecks[gr.key], func(ep string) bool {
			return g.knownServiceDenial(gr.key, ep, g.allowFor(gr)) != NoReason
		}) {
			continue
		}
		why := g.verdict(gr, now)
		if why != DomainUnconfirmed && why != IPv6Unconfirmed {
			continue
		}
		if g.hasFrozenPolicy(gr.key) {
			apps = append(apps, gr.names()...)
		}
	}
	if len(apps) == 0 {
		return false
	}
	if g.retried == nil {
		g.retried = make(map[domainFamily]bool)
	}
	g.retried[key] = true
	family := "IPv4"
	if key.v6 {
		family = "IPv6"
	}
	g.emit(now, Event{Kind: EvDomainCheck, Apps: apps, CheckID: r.ID, Domain: d.Endpoint, RetryFamily: family})
	return true
}

func (g *Guard) hasFrozenPolicy(id string) bool {
	for _, owner := range g.groups {
		for _, p := range owner.frozen {
			if p.AppID == id || slices.Contains(p.PolicyIDs, id) {
				return true
			}
		}
	}
	return false
}

// Include inherited policies of surviving descendants. An app that leaves the
// process tree loses both its cached permission and its pending measurement.
func (g *Guard) updateActiveDomains(remembered map[int]procs.Proc) {
	active := make(map[string]bool)
	for _, owner := range g.groups {
		for _, p := range owner.running {
			if g.cfg.DomainCheckEnabled(p.AppID) {
				active[p.AppID] = true
			}
			for _, id := range p.PolicyIDs {
				if g.cfg.DomainCheckEnabled(id) {
					active[id] = true
				}
			}
		}
	}
	continuing := make(map[string]bool)
	for _, p := range remembered {
		continuing[p.AppID] = true
		for _, id := range p.PolicyIDs {
			continuing[id] = true
		}
	}
	for id := range g.activeDomains {
		if !active[id] || !continuing[id] {
			delete(g.domains, id)
			delete(g.plan.Apps, id)
			delete(g.readyGroups, id)
			delete(g.earlyDenials, id)
		}
	}
	for id := range active {
		if !g.activeDomains[id] || !continuing[id] {
			if g.awaitingApps == nil {
				g.awaitingApps = make(map[string]bool)
			}
			g.awaitingApps[id] = true
			g.nextDomainCheck = time.Time{}
		}
	}
	g.activeDomains = active
}

func cloneDomains(in map[string][]DomainResult) map[string][]DomainResult {
	out := make(map[string][]DomainResult, len(in))
	for k, v := range in {
		out[k] = append([]DomainResult(nil), v...)
	}
	return out
}

func (g *Guard) domainsDue(now time.Time) bool {
	return len(g.activeDomains) > 0 && !now.Before(g.nextDomainCheck)
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
		reason, missing := g.assessEndpoint(gr, endpoint, seen[endpoint], now, allow)
		if reason != NoReason {
			return assessment{reason: reason}
		}
		unavailable = append(unavailable, missing...)

	}
	return g.assessUnavailable(unavailable)
}

func (g *Guard) assessEndpoint(gr *group, endpoint string, d DomainResult, now time.Time, allow config.Allow) (Reason, []Reason) {
	var unavailable []Reason
	if why := g.knownServiceDenial(gr.key, endpoint, allow); why != NoReason {
		return why, nil
	}
	if d.CheckedAt.IsZero() || d.CheckedAt.Before(g.domainStarted) || d.CheckedAt.After(now) || now.Sub(d.CheckedAt) >= g.domainMaxAge() {
		unavailable = append(unavailable, DomainUnconfirmed)
		if g.cfg.CheckIPv6 && g.ipv6Possible {
			unavailable = append(unavailable, IPv6Unconfirmed)
		}
		return NoReason, unavailable
	}
	if d.Error != "" || d.IP == "" {
		unavailable = append(unavailable, DomainUnconfirmed)
	} else if why := addressReason(allow, d.IP, d.Country, DomainIPNotAllowed, CountryUnknown); why != NoReason {
		return why, nil
	}
	if g.cfg.CheckIPv6 {
		if d.IPv6Error != "" {
			unavailable = append(unavailable, IPv6Unconfirmed)
		}
		if why := addressReason(allow, d.IP6, d.Country6, DomainIPNotAllowed, IPv6CountryUnknown); why != NoReason {
			return why, nil
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
			return DNSLeak, nil
		}
	}
	return NoReason, unavailable
}

// Report only endpoints contributing to this hold, including failures received
// before the full group completes.
func (g *Guard) domainIssues(gr *group, now time.Time) []DomainIssue {
	if !g.activeDomains[gr.key] || gr.reason == NoReason {
		return nil
	}
	hold, early := g.earlyDenials[gr.key]
	var issues []DomainIssue
	for _, endpoint := range g.cfg.DomainChecks[gr.key] {
		var d DomainResult
		if early && endpoint == hold.sample.Endpoint && hold.reason == gr.reason {
			d = hold.sample
		} else {
			for _, sample := range g.domains[gr.key] {
				if sample.Endpoint == endpoint {
					d = sample
					break
				}
			}
			if early && d.CheckedAt.Before(g.probeStarted) {
				continue
			}
			why, missing := g.assessEndpoint(gr, endpoint, d, now, g.allowFor(gr))
			if why != gr.reason && !slices.Contains(missing, gr.reason) {
				continue
			}
		}
		issue := DomainIssue{Endpoint: endpoint, Reason: gr.reason}
		fresh := !d.CheckedAt.IsZero() && !d.CheckedAt.Before(g.domainStarted) && !d.CheckedAt.After(now) && now.Sub(d.CheckedAt) < g.domainMaxAge()
		issue.Timeout = fresh && (gr.reason == DomainUnconfirmed && d.Timeout || gr.reason == IPv6Unconfirmed && d.IPv6Timeout)
		issues = append(issues, issue)
	}
	return issues
}

func (g *Guard) expireDomains(now time.Time) {
	if g.paused(now) {
		return
	}
	for _, gr := range g.groups {
		if gr.status == OK && g.activeDomains[gr.key] {
			if why := g.verdict(gr, now); why != NoReason {
				gr.status, gr.reason, gr.since = Suspect, why, now
				g.emit(now, Event{Kind: EvDomainCheck, Apps: gr.names(), Problems: g.domainDiagnostics(gr, now)})
			}
		}
	}
}
