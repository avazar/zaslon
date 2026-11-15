package guard

import (
	"strings"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
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
	text := strings.Join(events[0].Details, " | ")
	if !strings.Contains(text, second+" IPv4: HTTP 403") || strings.Contains(text, claudeEndpoint+" IPv4:") || !strings.Contains(text, "check=") {
		t.Fatal(text)
	}
	if !h.p.frozen[100] || h.p.frozen[200] {
		t.Fatal("diagnostics changed independent app gating")
	}
	// Another error with the same protection reason must not disappear just
	// because the freeze has already been announced.
	r.Domains["claude"][1].Error = "context deadline exceeded"
	h.probeFull(r)
	if got := domainEvents(h.events); len(got) != 2 || !strings.Contains(strings.Join(got[1].Details, " "), "context deadline exceeded") {
		t.Fatalf("lost second error: %+v", got)
	}
	r.Domains["claude"][1].Error, r.Domains["claude"][1].IP = "", "203.0.113.10"
	h.probeFull(r)
	if h.p.frozen[100] {
		t.Fatal("fresh success did not resume")
	}
	if got := domainEvents(h.g.Snapshot(h.now).History); len(got) != 2 || !strings.Contains(strings.Join(got[0].Details, " "), "HTTP 403") {
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
	text := strings.Join(events[0].Details, " ")
	if !strings.Contains(text, "IPv4: DNS lookup failed") || !strings.Contains(text, "IPv6: IPv6 timeout") {
		t.Fatal(text)
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
				want = "no measurement returned"
			case "duplicate":
				r.Domains["claude"] = append(r.Domains["claude"], r.Domains["claude"][0])
				want = "duplicate measurement"
			case "unexpected":
				r.Domains["claude"] = append(r.Domains["claude"], DomainResult{Endpoint: "https://unexpected.example/cdn-cgi/trace", IP: "203.0.113.10", CheckedAt: h.now})
				want = "unexpected measurement endpoint"
			}
			h.probeFull(r)
			events := domainEvents(h.events)
			if want == "" {
				if len(events) != 0 {
					t.Fatal("successful checks generated failure diagnostics")
				}
				return
			}
			if len(events) != 1 || !strings.Contains(strings.Join(events[0].Details, " "), want) {
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
		if e.Kind == EvDomainCheck && h.p.frozen[100] && strings.Contains(strings.Join(e.Details, " "), claudeEndpoint+": measurement expired") {
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
