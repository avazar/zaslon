package guard

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/procs"
	"github.com/avazar/zaslon/internal/recovery"
)

const claudeEndpoint = "https://claude.example/cdn-cgi/trace"
const cursorEndpoint = "https://cursor.example/cdn-cgi/trace"

func domainHarness(t *testing.T) *harness {
	h := newHarness(t, "203.0.113.10", "198.51.100.20", "2001:db8::/64")
	h.p.procs = []procs.Proc{
		{PID: 100, Created: "a", Name: "claude"}, {PID: 101, PPID: 100, Created: "ac", Name: "worker"},
		{PID: 200, Created: "b", Name: "cursor", Path: "/Applications/Cursor.app/Contents/MacOS/Cursor"}, {PID: 201, PPID: 200, Created: "bc", Name: "worker"},
	}
	c := h.g.cfg.Clone()
	c.Apps = []string{"claude", "cursor"}
	c.DomainChecks = map[string][]string{"claude": {claudeEndpoint}, "cursor": {cursorEndpoint}}
	c.DomainChecksEnabled = map[string]bool{"claude": true, "cursor": true}
	c.DNSCheck = "off"
	h.g.SetConfig(h.now, c)
	return h
}

func domainReply(h *harness, a, b string) ProbeResult {
	return ProbeResult{Err: errors.New("general checker unavailable"), Domains: map[string][]DomainResult{
		"claude": {{Endpoint: claudeEndpoint, IP: a, Country: "NL", CheckedAt: h.now}},
		"cursor": {{Endpoint: cursorEndpoint, IP: b, Country: "DE", CheckedAt: h.now}},
	}}
}

func TestDomainsIndependentlyGateAppsAndChildren(t *testing.T) {
	h := domainHarness(t)
	h.probeFull(domainReply(h, "203.0.113.10", "192.0.2.99"))
	if h.p.frozen[100] || h.p.frozen[101] || !h.p.frozen[200] || !h.p.frozen[201] {
		t.Fatalf("independent decisions: %v", h.p.frozen)
	}
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	h.want(OK)
	for _, pid := range []int{100, 101, 200, 201} {
		if h.p.frozen[pid] {
			t.Fatalf("PID %d stayed frozen", pid)
		}
	}
	h.probeFull(domainReply(h, "192.0.2.99", "198.51.100.20"))
	if !h.p.frozen[100] || !h.p.frozen[101] || h.p.frozen[200] || h.p.frozen[201] {
		t.Fatal(h.p.frozen)
	}
}

func TestDomainsFailClosedWithoutGeneralFallback(t *testing.T) {
	for _, mode := range []string{"missing", "error", "wrong-endpoint", "stale", "future", "ipv6-error", "ipv6-exit"} {
		t.Run(mode, func(t *testing.T) {
			h := domainHarness(t)
			r := domainReply(h, "203.0.113.10", "198.51.100.20")
			r.Err = nil
			r.IP = "203.0.113.10"
			r.Votes = 5
			d := r.Domains["claude"][0]
			switch mode {
			case "missing":
				delete(r.Domains, "claude")
			case "error":
				d.Error = "HTTP 403"
			case "wrong-endpoint":
				d.Endpoint = cursorEndpoint
			case "stale":
				d.CheckedAt = h.now.Add(-time.Minute)
			case "future":
				d.CheckedAt = h.now.Add(time.Minute)
			case "ipv6-error":
				d.IPv6Error = "timeout"
			case "ipv6-exit":
				d.IP6 = "2001:db9::1"
			}
			if mode != "missing" {
				r.Domains["claude"] = []DomainResult{d}
			}
			h.probeFull(r)
			if !h.p.frozen[100] || !h.p.frozen[101] || h.p.frozen[200] || h.p.frozen[201] {
				t.Fatal(h.p.frozen)
			}
		})
	}
}

func TestDomainCadenceAndCacheInvalidation(t *testing.T) {
	h := domainHarness(t)
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	var requested []bool
	h.g.d.StartProbe = func(_ *config.Config, _ uint64, domains bool) func() {
		requested = append(requested, domains)
		return func() { h.cancelled++ }
	}
	h.step(5 * time.Second)
	if requested[len(requested)-1] {
		t.Fatal("service calls repeated on a general check")
	}
	r := ProbeResult{ID: h.g.probeID, IP: "192.0.2.99", Votes: 1}
	h.g.HandleProbe(h.now, r)
	h.want(OK)
	h.step(5 * time.Second) // slow general request remains pending
	oldID := h.g.probeID
	h.step(5 * time.Second)
	if !requested[len(requested)-1] || h.g.probeID == oldID {
		t.Fatal("domain cadence waited behind the general request")
	}
	h.revision++
	h.step(0)
	old := domainReply(h, "203.0.113.10", "198.51.100.20")
	old.ID = oldID
	h.g.HandleProbe(h.now, old)
	if !h.p.frozen[100] || !h.p.frozen[200] {
		t.Fatal("old result crossed the network revision")
	}
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	h.want(OK)
	c := h.g.cfg.Clone()
	h.g.SetConfig(h.now, c)
	h.probeFull(ProbeResult{IP: "203.0.113.10", Votes: 5})
	if !h.p.frozen[100] || !h.p.frozen[200] {
		t.Fatal("settings edit reused domain evidence")
	}
}

func TestDomainExpiryAndHealthyOrphan(t *testing.T) {
	h := domainHarness(t)
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	h.p.remove(100)
	h.step(time.Second)
	h.step(DomainMaxAge)
	if !h.p.frozen[101] || !h.p.frozen[200] {
		t.Fatal("expired service proof or healthy orphan escaped protection")
	}
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	if h.p.frozen[101] {
		t.Fatal("healthy orphan was not resumed")
	}
}

func TestMatchedChildMustSatisfyParentAndOwnPolicy(t *testing.T) {
	h := domainHarness(t)
	h.p.procs[2].PPID = 100 // Cursor is also Claude's descendant.
	h.g.Shutdown()          // install the ledger before acquiring test suspensions
	ledger, err := recovery.Open(t.TempDir(), h.p)
	if err != nil {
		t.Fatal(err)
	}
	h.g.d.Procs = ledger
	h.probeFull(domainReply(h, "192.0.2.99", "198.51.100.20"))
	for _, pid := range []int{100, 101, 200, 201} {
		if !h.p.frozen[pid] {
			t.Fatalf("PID %d escaped the parent policy", pid)
		}
	}
	if len(ledger.Entries()) != 4 {
		t.Fatal("multiple owners or lost recovery records")
	}
	h.probeFull(domainReply(h, "203.0.113.10", "192.0.2.99"))
	if h.p.frozen[100] || h.p.frozen[101] || !h.p.frozen[200] || !h.p.frozen[201] {
		t.Fatal("own policy was bypassed or parent was overblocked")
	}
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	h.step(0)
	if len(ledger.Entries()) != 0 {
		t.Fatal("confirmed policies did not release the one owned suspension")
	}
}

func TestTogglingDomainChecksTransfersOneOwnedSuspension(t *testing.T) {
	h := newHarness(t, "203.0.113.10")
	h.p.procs[0].Created = "parent"
	h.p.procs = append(h.p.procs, procs.Proc{PID: 101, PPID: 100, Name: "worker", Created: "child"})
	ledger, err := recovery.Open(t.TempDir(), h.p)
	if err != nil {
		t.Fatal(err)
	}
	h.g.d.Procs = ledger
	h.step(0)
	h.probe("192.0.2.99", "RU")
	c := h.g.cfg.Clone()
	c.DomainChecks = map[string][]string{"claude": {claudeEndpoint}}
	c.DomainChecksEnabled["claude"] = true
	h.g.SetConfig(h.now, c)
	for _, pid := range []int{100, 101} {
		owners := 0
		for _, gr := range h.g.groups {
			if _, ok := gr.frozen[pid]; ok {
				owners++
			}
		}
		if owners != 1 || !h.p.frozen[pid] {
			t.Fatal("lost or duplicated suspension during regroup")
		}
	}
	h.probeFull(ProbeResult{IP: "203.0.113.10", Votes: 5})
	if len(ledger.Entries()) != 2 {
		t.Fatal("general IP released an unverified service")
	}
	h.probeFull(ProbeResult{Domains: map[string][]DomainResult{"claude": {{Endpoint: claudeEndpoint, IP: "203.0.113.10", CheckedAt: h.now}}}})
	if len(ledger.Entries()) != 0 {
		t.Fatal("verified service did not release ownership")
	}
	c.DomainChecksEnabled["claude"] = false
	if len(c.DomainChecks["claude"]) == 0 {
		t.Fatal("turning checks off lost the saved list")
	}
	h.g.SetConfig(h.now, c)
	if len(ledger.Entries()) != 2 {
		t.Fatal("disabling domain checks bypassed a fresh general check")
	}
	h.probe("203.0.113.10", "NL")
	if len(ledger.Entries()) != 0 {
		t.Fatal("general policy did not reclaim the group")
	}
}

func TestPrefilledDisabledDomainListsUseOnlyGeneralProof(t *testing.T) {
	h := newHarness(t, "203.0.113.10")
	h.step(0)
	h.probe("203.0.113.10", "NL")
	h.want(OK)
	if h.g.hasDomainTargets() || h.g.domainsDue(h.now) {
		t.Fatal("prefilled disabled lists activated checks")
	}
	c := h.g.cfg.Clone()
	c.DomainChecksEnabled["claude"] = true
	h.g.SetConfig(h.now, c)
	if !h.p.frozen[100] {
		t.Fatal("enabling did not invalidate general proof")
	}
	h.probe("203.0.113.10", "NL")
	h.want(Suspect)
	c.DomainChecksEnabled["claude"] = false
	h.g.SetConfig(h.now, c)
	h.probe("203.0.113.10", "NL")
	h.want(OK)
	if len(h.g.cfg.DomainChecks["claude"]) != 2 {
		t.Fatal("switching off deleted the list")
	}
}

func TestNewDescendantsInheritRememberedAncestorPolicies(t *testing.T) {
	for _, matched := range []bool{false, true} {
		t.Run(fmt.Sprint(matched), func(t *testing.T) {
			h := domainHarness(t)
			parent := 101 // an unmatched worker that will outlive Claude
			if matched {
				h.p.procs[2].PPID = 100
				parent = 200
			} // Cursor also has its own policy
			h.step(0) // observe the relationship while the original parent is alive
			h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
			h.p.remove(100)
			h.step(time.Second)
			h.p.procs = append(h.p.procs, procs.Proc{PID: 300, PPID: parent, Created: "new-grandchild", Name: "curl"})
			h.probeFull(domainReply(h, "192.0.2.99", "198.51.100.20"))
			if !h.p.frozen[300] {
				t.Fatal("new descendant escaped the remembered Claude policy")
			}
			h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
			if h.p.frozen[300] {
				t.Fatal("new descendant did not resume after all policies passed")
			}
		})
	}
}

func TestChangingMatchedAppRetainsOneSuspensionOwner(t *testing.T) {
	h := domainHarness(t)
	h.g.Shutdown()
	ledger, err := recovery.Open(t.TempDir(), h.p)
	if err != nil {
		t.Fatal(err)
	}
	h.g.d.Procs = ledger
	h.step(0)
	h.probeFull(domainReply(h, "192.0.2.99", "192.0.2.99"))
	// Unix exec can change the matching executable without changing PID/birth.
	h.p.procs[0].Name = "cursor"
	h.p.procs[0].Path = "/Applications/Cursor.app/Contents/MacOS/Cursor"
	h.step(time.Second)
	owners := 0
	for _, gr := range h.g.groups {
		if _, ok := gr.frozen[100]; ok {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("changed match has %d suspension owners", owners)
	}
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	h.step(0)
	if len(ledger.Entries()) != 0 {
		t.Fatal("changed match did not recover cleanly")
	}
}

func TestReusedPIDDoesNotSeedAncestorPolicies(t *testing.T) {
	h := domainHarness(t)
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	h.p.remove(100)
	h.step(time.Second)
	for i, p := range h.p.procs {
		if p.PID == 101 {
			h.p.procs[i] = procs.Proc{PID: 101, Created: "unrelated-new-birth", Name: "unrelated"}
		}
	}
	h.p.procs = append(h.p.procs, procs.Proc{PID: 300, PPID: 101, Created: "unrelated-child", Name: "curl"})
	h.probeFull(domainReply(h, "192.0.2.99", "198.51.100.20"))
	if h.p.frozen[101] || h.p.frozen[300] {
		t.Fatal("PID reuse inherited an unrelated ancestor policy")
	}
}
