package guard

import (
	"strings"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/procs"
)

func domainEvents(events []Event) []Event {
	var out []Event
	for _, e := range events {
		if e.Kind == EvDomainCheck {
			out = append(out, e)
		}
	}
	return out
}

func TestSharedFailureFoldsUntilRecovery(t *testing.T) {
	h := domainHarness(t)
	c := h.g.cfg.Clone()
	c.DomainChecks["cursor"] = []string{claudeEndpoint}
	h.g.SetConfig(h.now, c)
	r := domainReply(h, "", "")
	for app, results := range r.Domains {
		results[0].Endpoint = claudeEndpoint
		results[0].Error = "HTTP 403"
		r.Domains[app] = results
	}
	h.probeFull(r)
	first := domainEvents(h.g.Snapshot(h.now).History)
	if len(first) != 1 || len(first[0].Apps) != 2 || len(first[0].Problems) != 1 {
		t.Fatalf("shared result was not reported once: %+v", first)
	}
	h.now = h.now.Add(time.Second)
	for _, results := range r.Domains {
		results[0].CheckedAt = h.now
	}
	h.probeFull(r)
	episodes := domainEvents(h.g.Snapshot(h.now).History)
	if len(episodes) != 1 || episodes[0].Repeats != 1 || episodes[0].ID != first[0].ID || episodes[0].FirstAt != first[0].At || episodes[0].At != h.now {
		t.Fatalf("lost repeat or start of incident: %+v", episodes)
	}
	success := domainReply(h, "203.0.113.10", "203.0.113.10")
	success.Domains["cursor"][0].Endpoint = claudeEndpoint
	h.probeFull(success)
	h.probeFull(r)
	episodes = domainEvents(h.g.Snapshot(h.now).History)
	if len(episodes) != 2 || episodes[1].Repeats != 0 || episodes[1].ID == first[0].ID {
		t.Fatalf("a new incident folded into the resolved one: %+v", episodes)
	}
}

func TestReleaseDurationUsesOnlyKnownProcessIdentities(t *testing.T) {
	now := time.Now()
	g := Guard{pauseStarts: map[int]pauseStart{1: {"first", now.Add(-time.Minute)}, 2: {"second", now.Add(-time.Second)}}}
	var e Event
	g.releaseDuration(now, []procs.Proc{{PID: 1, Created: "first"}, {PID: 2, Created: "second"}}, &e)
	if e.PauseMin != time.Second || e.PauseMax != time.Minute || len(g.pauseStarts) != 0 {
		t.Fatal(e, g.pauseStarts)
	}
	g.pauseStarts[1] = pauseStart{"first", now.Add(-time.Hour)}
	e = Event{}
	g.releaseDuration(now, []procs.Proc{{PID: 1, Created: "new"}}, &e)
	if e.PauseMax != 0 {
		t.Fatal("reused PID inherited a pause duration")
	}
}

func TestDomainDiagnosticsKeepExactFailureAfterRecovery(t *testing.T) {
	h := domainHarness(t)
	c := h.g.cfg.Clone()
	second := "https://api.claude.example/cdn-cgi/trace"
	c.DomainChecks["claude"] = append(c.DomainChecks["claude"], second)
	h.g.SetConfig(h.now, c)
	r := domainReply(h, "203.0.113.10", "198.51.100.20")
	r.Domains["claude"] = append(r.Domains["claude"], DomainResult{Endpoint: second, Error: "HTTP 403", CheckedAt: h.now})
	h.probeFull(r)
	events := domainEvents(h.events)
	if len(events) != 1 || events[0].Notify || strings.Join(events[0].Apps, ",") != "Claude" {
		t.Fatalf("wrong diagnostic events: %+v", events)
	}
	if len(events[0].Problems) != 1 || events[0].Problems[0] != (CheckProblem{second, "IPv4", "http", "HTTP 403"}) || events[0].CheckID == 0 {
		t.Fatal(events[0])
	}
	if !h.p.frozen[100] || h.p.frozen[200] {
		t.Fatal("diagnostics changed independent app gating")
	}
	// Another error with the same protection reason must not disappear just
	// because the freeze has already been announced.
	r.Domains["claude"][1].Error = "context deadline exceeded"
	h.probeFull(r)
	if got := domainEvents(h.events); len(got) != 2 || got[1].Problems[0].Info != "context deadline exceeded" {
		t.Fatalf("lost second error: %+v", got)
	}
	r.Domains["claude"][1].Error, r.Domains["claude"][1].IP = "", "203.0.113.10"
	h.probeFull(r)
	if h.p.frozen[100] {
		t.Fatal("fresh success did not resume")
	}
	if got := domainEvents(h.g.Snapshot(h.now).History); len(got) != 2 || got[0].Problems[0].Info != "HTTP 403" {
		t.Fatalf("recovery erased failure history: %+v", got)
	}
}

func TestDomainDiagnosticsAlsoRecordIgnoredFailures(t *testing.T) {
	h := domainHarness(t)
	c := h.g.cfg.Clone()
	c.IPUnavailableAction, c.IPv6UnavailableAction = config.IgnoreFailure, config.IgnoreFailure
	h.g.SetConfig(h.now, c)
	r := domainReply(h, "203.0.113.10", "198.51.100.20")
	r.Domains["claude"][0].Error = "DNS lookup failed"
	r.Domains["claude"][0].IPv6Error = "IPv6 timeout"
	h.probeFull(r)
	if h.p.frozen[100] || len(h.g.Snapshot(h.now).Warnings) == 0 {
		t.Fatal("ignore policy behavior changed")
	}
	events := domainEvents(h.events)
	if len(events) != 1 {
		t.Fatalf("diagnostics: %+v", events)
	}
	ps := events[0].Problems
	if len(ps) != 2 || ps[0].Family != "IPv4" || ps[0].Info != "DNS lookup failed" || ps[1].Family != "IPv6" || ps[1].Info != "IPv6 timeout" {
		t.Fatal(ps)
	}
}

func TestRejectedProbeDoesNotLogFailuresForCurrentNetwork(t *testing.T) {
	h := domainHarness(t)
	oldID := h.g.probeID
	h.revision++
	h.g.HandleProbe(h.now, ProbeResult{ID: oldID, Domains: map[string][]DomainResult{"claude": {{Endpoint: claudeEndpoint, Error: "old failure", CheckedAt: h.now}}}})
	if got := domainEvents(h.events); len(got) != 0 {
		t.Fatalf("obsolete failure logged as current: %+v", got)
	}
}

func TestDomainDiagnosticsExplainAbsentAndMalformedResults(t *testing.T) {
	for _, mode := range []string{"missing", "duplicate", "unexpected", "success"} {
		t.Run(mode, func(t *testing.T) {
			h := domainHarness(t)
			r := domainReply(h, "203.0.113.10", "198.51.100.20")
			var want string
			switch mode {
			case "missing":
				delete(r.Domains, "claude")
				want = "missing"
			case "duplicate":
				r.Domains["claude"] = append(r.Domains["claude"], r.Domains["claude"][0])
				want = "duplicate"
			case "unexpected":
				r.Domains["claude"] = append(r.Domains["claude"], DomainResult{Endpoint: "https://unexpected.example/cdn-cgi/trace", IP: "203.0.113.10", CheckedAt: h.now})
				want = "unexpected"
			}
			h.probeFull(r)
			events := domainEvents(h.events)
			if want == "" {
				if len(events) != 0 {
					t.Fatal("successful checks generated failure diagnostics")
				}
				return
			}
			if len(events) != 1 || len(events[0].Problems) == 0 || events[0].Problems[0].Code != want {
				t.Fatalf("missing %q: %+v", want, events)
			}
		})
	}
}

func TestExpiredDomainFreezeExplainsMissingProof(t *testing.T) {
	h := domainHarness(t)
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	h.events = nil
	h.step(DomainMaxAge)
	for _, e := range h.events {
		if e.Kind == EvDomainCheck && h.p.frozen[100] && len(e.Problems) > 0 && e.Problems[0].Endpoint == claudeEndpoint && e.Problems[0].Code == "expired" {
			return
		}
	}
	t.Fatalf("expiration was not explained: %+v", h.events)
}

func TestNetworkDiagnosticBatchAndPollingAreDistinguished(t *testing.T) {
	h := newHarness(t, "203.0.113.10")
	h.step(0)
	h.probe("203.0.113.10", "NL")
	h.g.d.NetworkDetails = func(after, through uint64) []string {
		if !h.p.frozen[100] {
			t.Fatal("diagnostic formatting ran before suspension")
		}
		if after != 0 || through != 2 {
			t.Fatalf("incorrect revision range %d..%d", after, through)
		}
		return []string{"source=NotifyRouteChange2 kind=add family=IPv6 interface=17", "source=NotifyIpInterfaceChange kind=parameter"}
	}
	h.revision = 2
	h.step(time.Millisecond)
	if !h.p.frozen[100] {
		t.Fatal("diagnostics suppressed freeze-first behavior")
	}
	var events []Event
	for _, e := range h.events {
		if e.Kind == EvNetChanged {
			events = append(events, e)
		}
	}
	if len(events) != 1 || len(events[0].Details) != 2 {
		t.Fatalf("lost burst details: %+v", events)
	}
	h.g.d.NetworkDetails = nil
	h.fp = "changed interface addresses"
	h.step(time.Millisecond)
	last := h.events[len(h.events)-1]
	if last.Kind != EvNetChanged || len(last.Details) != 3 || !strings.Contains(last.Details[0], "interface-poll") || !strings.Contains(last.Details[2], "changed interface addresses") {
		t.Fatalf("polling source missing: %+v", last)
	}
}
