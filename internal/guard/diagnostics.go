package guard

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
)

// DiagnosticText keeps an untrusted transport error on one bounded log line.
// Trace probes never attach response bodies, headers, cookies or credentials.
func DiagnosticText(s string) string {
	r := []rune(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s))
	if len(r) > 1024 {
		return string(r[:1024]) + "…"
	}
	return string(r)
}

func (g *Guard) domainDiagnostics(gr *group, now time.Time) []string {
	if !g.cfg.DomainCheckEnabled(gr.key) || len(gr.tgts) == 0 {
		return nil
	}
	var details []string
	expected := g.cfg.DomainChecks[gr.key]
	if len(expected) == 0 {
		return []string{"no domains configured for enabled service checks"}
	}
	got := make(map[string]DomainResult)
	for _, d := range g.domains[gr.key] {
		if !slices.Contains(expected, d.Endpoint) {
			details = append(details, DiagnosticText(d.Endpoint)+": unexpected measurement endpoint")
		}
		if _, exists := got[d.Endpoint]; exists {
			details = append(details, d.Endpoint+": duplicate measurement")
		}
		got[d.Endpoint] = d
	}
	for _, endpoint := range expected {
		d, ok := got[endpoint]
		var missing string
		switch {
		case !ok || d.CheckedAt.IsZero():
			missing = "no measurement returned"
		case d.CheckedAt.Before(g.domainStarted):
			missing = "measurement predates the current check"
		case d.CheckedAt.After(now):
			missing = "measurement timestamp is in the future"
		case now.Sub(d.CheckedAt) >= DomainMaxAge:
			missing = fmt.Sprintf("measurement expired (age=%s, limit=%s)", now.Sub(d.CheckedAt).Round(time.Millisecond), DomainMaxAge)
		}
		if missing != "" {
			details = append(details, endpoint+": "+missing)
			continue
		}
		if d.Error != "" {
			details = append(details, endpoint+" IPv4: "+DiagnosticText(d.Error))
		} else if d.IP == "" {
			details = append(details, endpoint+" IPv4: no address returned")
		} else if !g.allowFor(gr).Matches(d.IP, d.Country) {
			details = append(details, fmt.Sprintf("%s IPv4: exit %s (%s) is not allowed", endpoint, d.IP, d.Country))
		}
		if g.cfg.CheckIPv6 {
			if d.IPv6Error != "" {
				details = append(details, endpoint+" IPv6: "+DiagnosticText(d.IPv6Error))
			} else if d.IP6 != "" && !g.allowFor(gr).Matches(d.IP6, d.Country6) {
				details = append(details, fmt.Sprintf("%s IPv6: exit %s (%s) is not allowed", endpoint, d.IP6, d.Country6))
			}
		}
	}
	return details
}

func (g *Guard) recordDomainDiagnostics(now time.Time, id uint64) {
	for _, gr := range g.groups {
		if details := g.domainDiagnostics(gr, now); len(details) > 0 {
			details = append([]string{fmt.Sprintf("check=%d", id)}, details...)
			g.emit(now, Event{Kind: EvDomainCheck, Apps: gr.names(), Details: details})
		}
	}
}
