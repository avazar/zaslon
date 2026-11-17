package guard

import (
	"slices"
	"time"
)

type domainHold struct {
	reason Reason
	sample DomainResult
	ipv6   bool
}

// HandleProbe has already checked the network revision, generation and age.
// Individual families can only stop work. Only a complete group (and all
// applicable ancestor groups) can release a held process.
func (g *Guard) handleProgress(now time.Time, r ProbeResult) {
	switch r.Part {
	case GeneralMeasurement:
		if !g.plan.General || g.generalReady {
			return
		}
		g.acceptGeneral(now, r)
		g.generalReady = true
		for _, gr := range g.groups {
			if !g.cfg.DomainCheckEnabled(gr.key) {
				g.markGroupReady(gr)
				g.reevaluate(now, gr)
			} else if g.readyGroups[gr.key] || g.earlyDenials[gr.key].reason != NoReason {
				g.reevaluate(now, gr)
			}
		}
	case DomainGroup:
		for _, gr := range g.groups {
			values, ok := r.Domains[gr.key]
			if !ok || !g.plan.Apps[gr.key] || g.readyGroups[gr.key] || !g.cfg.DomainCheckEnabled(gr.key) {
				continue
			}
			expected := g.cfg.DomainChecks[gr.key]
			if len(values) == 0 || len(values) != len(expected) {
				continue
			}
			seen := map[string]bool{}
			for _, d := range values {
				if !slices.Contains(expected, d.Endpoint) || seen[d.Endpoint] || !g.currentSample(now, d) {
					return
				}
				seen[d.Endpoint] = true
			}
			if g.domains == nil {
				g.domains = map[string][]DomainResult{}
			}
			g.domains[gr.key] = slices.Clone(values)
			if g.cfg.DNSCheck == "block" {
				g.dns, g.dnsCC = r.DNS, r.DNSCountry
			}
			g.rememberDomains(now, ProbeResult{Domains: map[string][]DomainResult{gr.key: values}})
			delete(g.earlyDenials, gr.key)
			g.markGroupReady(gr)
			for _, d := range values {
				if d.Error == "" && d.IP != "" {
					delete(g.retried, domainFamily{d.Endpoint, false})
				}
				if d.IPv6Error == "" {
					delete(g.retried, domainFamily{d.Endpoint, true})
				}
			}
			g.reevaluate(now, gr)
		}
	case DomainFamily:
		if !g.applyDomainFamily(now, r) {
			return
		}
	}
	// A child may belong to an already completed group and have been waiting
	// solely for a parent. Revisit its owner after any new policy decision.
	g.enforce(now)
}

func (g *Guard) currentSample(now time.Time, d DomainResult) bool {
	return !d.CheckedAt.Before(g.probeStarted) && !d.CheckedAt.After(now) && now.Sub(d.CheckedAt) < g.domainMaxAge()
}

func (g *Guard) markGroupReady(gr *group) {
	g.readyGroups[gr.key] = true
	for _, t := range gr.tgts {
		delete(g.awaitingApps, t.ID)
	}
}

// Keep the early negative evidence across cancellation. The authoritative
// group result will replace each completed family individually.
func (g *Guard) applyDomainFamily(now time.Time, r ProbeResult) bool {
	changed := false
	d := r.Sample
	if !g.currentSample(now, d) {
		return false
	}
	for _, gr := range g.groups {
		if !g.plan.Apps[gr.key] || !g.cfg.DomainCheckEnabled(gr.key) || g.readyGroups[gr.key] || !slices.Contains(g.cfg.DomainChecks[gr.key], d.Endpoint) {
			continue
		}
		allow := g.allowFor(gr)
		ip, cc, failure, missing := d.IP, d.Country, d.Error, DomainUnconfirmed
		if r.SampleIPv6 {
			if !g.cfg.CheckIPv6 {
				continue
			}
			ip, cc, failure, missing = d.IP6, d.Country6, d.IPv6Error, IPv6Unconfirmed
			if ip == "" && failure == "" {
				continue
			}
		}
		reason := NoReason
		if failure != "" || ip == "" {
			if gr.recovering {
				reason = missing
			} else {
				reason = g.assessUnavailable([]Reason{missing}).reason
			}
		} else if !allow.Matches(ip, cc) {
			key := serviceSource{gr.key, d.Endpoint}
			previous := g.serviceEvidence[key]
			unknown := CountryUnknown
			if r.SampleIPv6 {
				previous.v6 = previous.v6.observed(ip, cc)
				unknown = IPv6CountryUnknown
			} else {
				previous.v4 = previous.v4.observed(ip, cc)
			}
			g.serviceEvidence[key] = previous
			reason = addressReason(allow, ip, cc, DomainIPNotAllowed, unknown)
		}
		if reason != NoReason {
			if known := g.knownServiceDenial(gr.key, d.Endpoint, allow); known != NoReason {
				reason = known
			}
			if g.earlyDenials[gr.key].reason != DomainIPNotAllowed {
				g.earlyDenials[gr.key] = domainHold{reason, d, r.SampleIPv6}
			}
			changed = true
			g.reevaluate(now, gr)
		}
	}
	return changed
}
