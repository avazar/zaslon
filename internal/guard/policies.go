package guard

import (
	"slices"
	"time"

	"github.com/avazar/zaslon/internal/config"
)

type assessment struct {
	reason  Reason
	ignored []Reason
}

// Known unsafe evidence always takes precedence over an ignored missing result.
func (g *Guard) assess(gr *group, now time.Time) assessment {
	a := g.assessCurrent(gr, now)
	if gr.recovering && a.reason == NoReason && len(a.ignored) > 0 {
		return assessment{reason: a.ignored[0]}
	}
	return a
}

func (g *Guard) assessCurrent(gr *group, now time.Time) assessment {
	if g.trusted() && !g.offline && g.ip != "" {
		return assessment{}
	}
	a := g.allowFor(gr)
	if g.cfg.DomainCheckEnabled(gr.key) {
		return g.assessDomains(gr, now, a)
	}
	var unavailable []Reason
	if g.offline || g.ip == "" {
		unavailable = append(unavailable, Offline)
	} else {
		if !a.Matches(g.ip, g.country) {
			return assessment{reason: IPNotAllowed}
		}
		if g.votes < g.cfg.Need() || len(g.others) > 0 {
			return assessment{reason: Unconfirmed}
		}
	}
	if g.cfg.CheckIPv6 {
		if g.ip6 != "" && !a.Matches(g.ip6, g.cc6) {
			return assessment{reason: IPv6Leak}
		}
		if g.ipv6Conflicting {
			return assessment{reason: IPv6Conflict}
		}
		if g.ipv6Unknown {
			unavailable = append(unavailable, IPv6Unconfirmed)
		}
	}
	if g.cfg.DNSCheck == "block" && g.dnsLeak(a) {
		return assessment{reason: DNSLeak}
	}
	return g.assessUnavailable(unavailable)
}

func (g *Guard) assessUnavailable(reasons []Reason) assessment {
	var ignored []Reason
	for _, reason := range reasons {
		action := g.cfg.IPUnavailableAction
		if reason == IPv6Unconfirmed {
			action = g.cfg.IPv6UnavailableAction
		}
		if action != config.IgnoreFailure {
			return assessment{reason: reason}
		}
		if !slices.Contains(ignored, reason) {
			ignored = append(ignored, reason)
		}
	}
	return assessment{ignored: ignored}
}
