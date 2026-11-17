package guard

import (
	"slices"
	"time"

	"github.com/avazar/zaslon/internal/config"
)

// A failed measurement does not disprove an exit observed earlier. Keep the
// last completed observation per family and service, and evaluate it against
// the current rules. A fresh result replaces it; an explicit rule/check change
// may also make it irrelevant. This state never grants permission to run.
type exitEvidence struct {
	ip, country               string
	locatedIP, locatedCountry string // last exit whose country was actually measured
	votes                     int
	others                    []string
	conflicting               bool
}

type serviceEvidence struct{ v4, v6 exitEvidence }
type serviceSource struct{ app, endpoint string }

// A missing location can neither establish nor erase a known country denial.
func (e exitEvidence) observed(ip, country string) exitEvidence {
	next := exitEvidence{ip: ip, country: country}
	if country != "" {
		next.locatedIP, next.locatedCountry = ip, country
	} else {
		next.locatedIP, next.locatedCountry = e.locatedIP, e.locatedCountry
	}
	return next
}

func addressReason(a config.Allow, ip, country string, denied, unknown Reason) Reason {
	if ip == "" || a.Matches(ip, country) {
		return NoReason
	}
	if country == "" && len(a.Countries) != 0 {
		return unknown
	}
	return denied
}

func (e exitEvidence) reason(a config.Allow, denied, unknown Reason) Reason {
	reason := addressReason(a, e.ip, e.country, denied, unknown)
	if reason == unknown && e.locatedIP != "" && !a.Matches(e.locatedIP, e.locatedCountry) {
		return denied
	}
	return reason
}

func (g *Guard) rememberGeneral(r ProbeResult) {
	if r.Err == nil && r.IP != "" {
		g.lastIPv4 = g.lastIPv4.observed(r.IP, r.Country)
		g.lastIPv4.votes, g.lastIPv4.others = r.Votes, slices.Clone(r.Others)
	}
	if g.cfg.CheckIPv6 {
		if r.IP6 != "" || r.IPv6Conflicting {
			g.lastIPv6 = g.lastIPv6.observed(r.IP6, r.Country6)
			g.lastIPv6.conflicting = r.IPv6Conflicting
		} else if !r.IPv6Unknown && !r.IPv6Possible {
			g.lastIPv6 = exitEvidence{} // current enumeration confirms no available family
		}
	}
}

func (g *Guard) rememberDomains(now time.Time, r ProbeResult) {
	if !g.checkingDomains {
		return
	}
	for app, values := range r.Domains {
		if !g.cfg.DomainCheckEnabled(app) {
			continue
		}
		seen := map[string]bool{}
		valid := true
		for _, d := range values {
			if seen[d.Endpoint] || !slices.Contains(g.cfg.DomainChecks[app], d.Endpoint) {
				valid = false
				break
			}
			seen[d.Endpoint] = true
		}
		if !valid {
			continue // a malformed response cannot clear a previously known denial
		}
		for _, d := range values {
			if !slices.Contains(g.cfg.DomainChecks[app], d.Endpoint) ||
				d.CheckedAt.IsZero() || d.CheckedAt.Before(g.probeStarted) ||
				d.CheckedAt.After(now) || now.Sub(d.CheckedAt) >= g.domainMaxAge() {
				continue
			}
			key := serviceSource{app, d.Endpoint}
			last := g.serviceEvidence[key]
			if d.Error == "" && d.IP != "" {
				last.v4 = last.v4.observed(d.IP, d.Country)
			}
			if g.cfg.CheckIPv6 && d.IPv6Error == "" {
				// An empty successful family result means no IPv6 address for
				// this endpoint, unlike a timeout or an inconclusive lookup.
				if d.IP6 == "" {
					last.v6 = exitEvidence{}
				} else {
					last.v6 = last.v6.observed(d.IP6, d.Country6)
				}
			}
			g.serviceEvidence[key] = last
		}
	}
}

func (g *Guard) pruneEvidence() {
	if !g.cfg.CheckIPv6 {
		g.lastIPv6 = exitEvidence{}
		for key, value := range g.serviceEvidence {
			value.v6 = exitEvidence{}
			g.serviceEvidence[key] = value
		}
	}
	for key := range g.serviceEvidence {
		if !g.cfg.DomainCheckEnabled(key.app) || !slices.Contains(g.cfg.DomainChecks[key.app], key.endpoint) {
			delete(g.serviceEvidence, key)
		}
	}
}

func (g *Guard) knownGeneralDenial(a config.Allow) Reason {
	v4 := g.lastIPv4.reason(a, IPNotAllowed, CountryUnknown)
	if v4 == IPNotAllowed {
		return v4
	}
	if e := g.lastIPv4; e.ip != "" && (e.votes < g.cfg.Need() || len(e.others) != 0) {
		return Unconfirmed
	}
	if g.cfg.CheckIPv6 {
		v6 := g.lastIPv6.reason(a, IPv6Leak, IPv6CountryUnknown)
		if v6 == IPv6Leak {
			return v6
		}
		if g.lastIPv6.conflicting {
			return IPv6Conflict
		}
		if v4 == NoReason {
			return v6
		}
	}
	return v4
}

func (g *Guard) knownServiceDenial(app, endpoint string, a config.Allow) Reason {
	last := g.serviceEvidence[serviceSource{app, endpoint}]
	v4 := last.v4.reason(a, DomainIPNotAllowed, CountryUnknown)
	if !g.cfg.CheckIPv6 || v4 == DomainIPNotAllowed {
		return v4
	}
	v6 := last.v6.reason(a, DomainIPNotAllowed, IPv6CountryUnknown)
	if v6 == DomainIPNotAllowed || v4 == NoReason {
		return v6
	}
	return v4
}
