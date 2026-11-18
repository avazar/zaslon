package guard

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/avazar/zaslon/internal/procs"
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

// CheckProblem separates the measured endpoint from the human-readable reason
// and the unmodified diagnostic cause. It is comparable for exact deduplication.
type CheckProblem struct {
	Endpoint, Family, Code, Info string
}

func (g *Guard) domainDiagnostics(gr *group, now time.Time) []CheckProblem {
	if !g.cfg.DomainCheckEnabled(gr.key) || len(gr.tgts) == 0 {
		return nil
	}
	var problems []CheckProblem
	add := func(endpoint, family, code, info string) {
		problems = append(problems, CheckProblem{endpoint, family, code, DiagnosticText(info)})
	}
	family := func(d DomainResult, ipv6 bool) {
		f, ip, cc, problem, timeout := "IPv4", d.IP, d.Country, d.Error, d.Timeout
		if ipv6 {
			f, ip, cc, problem, timeout = "IPv6", d.IP6, d.Country6, d.IPv6Error, d.IPv6Timeout
		}
		switch {
		case timeout:
			add(d.Endpoint, f, "timeout", problem)
		case strings.HasPrefix(problem, "HTTP "):
			add(d.Endpoint, f, "http", problem)
		case problem != "":
			add(d.Endpoint, f, "error", problem)
		case ip == "":
			if !ipv6 {
				add(d.Endpoint, f, "no_address", "")
			}
		case addressReason(g.allowFor(gr), ip, cc, DomainIPNotAllowed, CountryUnknown) == CountryUnknown:
			add(d.Endpoint, f, "country", ip)
		case !g.allowFor(gr).Matches(ip, cc):
			if cc != "" {
				ip += " (" + cc + ")"
			}
			add(d.Endpoint, f, "denied", ip)
		}
	}
	if hold, ok := g.earlyDenials[gr.key]; ok {
		family(hold.sample, hold.ipv6)
		return problems
	}
	expected := g.cfg.DomainChecks[gr.key]
	if len(expected) == 0 {
		add("", "", "no_domains", "")
	}
	got := make(map[string]DomainResult)
	for _, d := range g.domains[gr.key] {
		if !slices.Contains(expected, d.Endpoint) {
			add(d.Endpoint, "", "unexpected", "")
		}
		if _, exists := got[d.Endpoint]; exists {
			add(d.Endpoint, "", "duplicate", "")
		}
		got[d.Endpoint] = d
	}
	for _, endpoint := range expected {
		d, ok := got[endpoint]
		switch {
		case !ok || d.CheckedAt.IsZero():
			add(endpoint, "", "missing", "")
		case d.CheckedAt.Before(g.domainStarted):
			add(endpoint, "", "old", "")
		case d.CheckedAt.After(now):
			add(endpoint, "", "future", "")
		case now.Sub(d.CheckedAt) >= g.domainMaxAge():
			add(endpoint, "", "expired", fmt.Sprintf("age=%s, limit=%s", now.Sub(d.CheckedAt).Round(time.Millisecond), g.domainMaxAge()))
		default:
			family(d, false)
			if g.cfg.CheckIPv6 {
				family(d, true)
			}
		}
	}
	return problems
}

func (g *Guard) recordDomainDiagnostics(now time.Time, id uint64) {
	// A shared endpoint/family is measured once. Report each distinct result
	// with just the applications it applies to, including app-specific denials.
	var order []CheckProblem
	affected := make(map[CheckProblem][]string)
	for _, gr := range g.groups {
		if !g.plan.Apps[gr.key] {
			continue
		}
		for _, problem := range g.domainDiagnostics(gr, now) {
			if _, exists := affected[problem]; !exists {
				order = append(order, problem)
			}
			for _, name := range gr.names() {
				if !slices.Contains(affected[problem], name) {
					affected[problem] = append(affected[problem], name)
				}
			}
		}
	}
	var events []Event
	for _, problem := range order {
		apps := affected[problem]
		i := slices.IndexFunc(events, func(e Event) bool { return slices.Equal(e.Apps, apps) })
		if i < 0 {
			i = len(events)
			events = append(events, Event{Kind: EvDomainCheck, Apps: apps, CheckID: id})
		}
		events[i].Problems = append(events[i].Problems, problem)
	}
	for _, e := range events {
		g.emit(now, e)
	}
}

// Fold only identical failures in consecutive completed checks. A successful
// check, a different reason or a state transition starts a new history entry.
func (g *Guard) foldRepeatedCheck(e *Event) {
	if e.Kind != EvDomainCheck || e.CheckID == 0 || len(e.Problems) == 0 {
		return
	}
	e.FirstAt, e.FirstCheck = e.At, e.CheckID
	for i := len(g.history) - 1; i >= 0; i-- {
		prev := g.history[i]
		if prev.Kind != EvDomainCheck || prev.CheckID == 0 || prev.CheckID+1 < e.CheckID {
			return
		}
		if prev.CheckID+1 == e.CheckID && slices.Equal(prev.Apps, e.Apps) && slices.Equal(prev.Problems, e.Problems) {
			e.ID, e.FirstAt, e.FirstCheck, e.Repeats = prev.ID, prev.FirstAt, prev.FirstCheck, prev.Repeats+1
			g.history = slices.Delete(g.history, i, i+1)
			return
		}
	}
}

type pauseStart struct {
	created string
	at      time.Time
}

func (g *Guard) releaseDuration(now time.Time, resumed []procs.Proc, e *Event) {
	known := 0
	for _, p := range resumed {
		stamp, ok := g.pauseStarts[p.PID]
		if !ok || stamp.created != p.Created {
			continue
		}
		delete(g.pauseStarts, p.PID)
		d := now.Sub(stamp.at)
		if d <= 0 {
			continue
		}
		if known == 0 || d < e.PauseMin {
			e.PauseMin = d
		}
		e.PauseMax = max(e.PauseMax, d)
		known++
	}
	// Adopted suspensions may predate this session. Do not invent a duration.
	if known != len(resumed) {
		e.PauseMin, e.PauseMax = 0, 0
	}
}

func (g *Guard) holdingPolicies(now time.Time, owner *group, ps []procs.Proc) []string {
	var names []string
	for _, policy := range g.groups {
		if policy == owner || g.verdict(policy, now) == NoReason {
			continue
		}
		for _, target := range policy.tgts {
			if slices.ContainsFunc(ps, func(p procs.Proc) bool { return slices.Contains(p.PolicyIDs, target.ID) }) {
				names = append(names, target.Name)
			}
		}
	}
	return names
}
