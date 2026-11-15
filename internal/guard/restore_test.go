package guard

import (
	"errors"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/procs"
	"github.com/avazar/zaslon/internal/recovery"
)

type suspensionCounts struct {
	*fakeProcs
	counts           map[int]int
	freezes, resumes int
}

func (p *suspensionCounts) Freeze(pr procs.Proc) error {
	p.freezes++
	p.counts[pr.PID]++
	return p.fakeProcs.Freeze(pr)
}
func (p *suspensionCounts) Resume(pr procs.Proc) error {
	p.resumes++
	p.counts[pr.PID]--
	p.frozen[pr.PID] = p.counts[pr.PID] > 0
	return nil
}

func recordedHarness(t *testing.T) (*harness, *suspensionCounts, string) {
	h := domainHarness(t)
	h.g.Shutdown()
	p := &suspensionCounts{fakeProcs: h.p, counts: map[int]int{}}
	dir := t.TempDir()
	ledger, err := recovery.Open(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, pr := range procs.Filter(p.procs, procs.Targets(h.g.cfg), 999) {
		if err = ledger.Freeze(pr); err != nil {
			t.Fatal(err)
		}
	}
	restartRecorded(t, h, p, dir, h.g.cfg)
	return h, p, dir
}

func restartRecorded(t *testing.T, h *harness, p *suspensionCounts, dir string, cfg *config.Config) {
	t.Helper()
	ledger, err := recovery.Open(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	h.g = New(cfg, Deps{Procs: ledger, Fingerprint: func() string { return h.fp }, NetworkVersion: func() uint64 { return h.revision }, Self: 999, StartProbe: func(_ *config.Config, _ uint64, _ bool) func() { h.probes++; return func() {} }})
}

func TestRestoreProtectionNeverResumesOrAddsSuspensionBeforeProof(t *testing.T) {
	h, p, _ := recordedHarness(t)
	before := p.freezes
	n, err := h.g.RestoreProtection()
	if err != nil || n != 4 {
		t.Fatalf("adopt=%d err=%v", n, err)
	}
	h.step(0)
	if p.resumes != 0 || p.freezes != before || h.g.Snapshot(h.now).Frozen != 4 {
		t.Fatal("adoption changed OS suspension state")
	}
	// A failed first check must remain blocked even under warning-only policies.
	c := h.g.cfg.Clone()
	c.IPUnavailableAction = config.IgnoreFailure
	c.IPv6UnavailableAction = config.IgnoreFailure
	h.g.SetConfig(h.now, c)
	r := domainReply(h, "203.0.113.10", "198.51.100.20")
	r.Domains["claude"][0].Error = "HTTP 403"
	h.probeFull(r)
	if !p.frozen[100] || !p.frozen[101] || p.frozen[200] || p.frozen[201] {
		t.Fatal("first-check failure or unrelated group crossed recovery barrier")
	}
	if p.counts[100] != 1 || p.counts[101] != 1 {
		t.Fatal("adoption added a suspend count")
	}
	h.g.CheckNow(h.now)
	h.step(0)
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	if p.frozen[100] || p.frozen[101] {
		t.Fatal("fresh verified results did not release adopted tree")
	}
	// After one verified release, the user's ordinary warning-only policy applies.
	h.g.CheckNow(h.now)
	h.step(0)
	r = domainReply(h, "203.0.113.10", "198.51.100.20")
	r.Domains["claude"][0].Error = "HTTP 403"
	h.probeFull(r)
	if p.frozen[100] {
		t.Fatal("recovery permanently changed explicit ignore policy")
	}
}

func TestRestoreProtectionKeepsOrphanAncestryAcrossRepeatedCrashes(t *testing.T) {
	h, p, dir := recordedHarness(t)
	p.remove(100)
	// A child seen only after the crash belongs to an adopted orphan. It also
	// matches Cursor and therefore must satisfy both independent app policies.
	p.procs = append(p.procs, procs.Proc{PID: 102, Created: "new-child", PPID: 101, Name: "Cursor", Path: "/Applications/Cursor.app/Contents/MacOS/Cursor"})
	n, err := h.g.RestoreProtection()
	if err != nil || n != 3 {
		t.Fatalf("adopt=%d err=%v", n, err)
	}
	h.step(0)
	if p.counts[101] != 1 || p.counts[102] != 1 {
		t.Fatal("orphan doubled its count or new descendant escaped")
	}
	h.probeFull(domainReply(h, "203.0.113.10", "192.0.2.99"))
	if p.frozen[101] || !p.frozen[102] {
		t.Fatal("child bypassed its own rule")
	}
	// Lose the remaining ancestor and all guard memory. The child's persisted
	// ancestry must still prevent an otherwise allowed Cursor result releasing it.
	p.remove(101)
	restartRecorded(t, h, p, dir, h.g.cfg)
	n, err = h.g.RestoreProtection()
	if err != nil || n != 3 {
		t.Fatalf("second adopt=%d err=%v", n, err)
	}
	h.step(0)
	h.probeFull(domainReply(h, "192.0.2.99", "198.51.100.20"))
	if !p.frozen[102] {
		t.Fatal("second crash lost the absent ancestor's policy")
	}
	h.g.CheckNow(h.now)
	h.step(0)
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	if p.frozen[102] || p.counts[102] != 0 {
		t.Fatal("child was not released exactly once")
	}
}

func TestRestoreProtectionRefusesMissingPoliciesAndUnknownIdentities(t *testing.T) {
	for _, mode := range []string{"disabled", "unreadable", "reused", "no-labels"} {
		t.Run(mode, func(t *testing.T) {
			h, p, dir := recordedHarness(t)
			switch mode {
			case "disabled":
				c := h.g.cfg.Clone()
				c.Apps = []string{"cursor"}
				restartRecorded(t, h, p, dir, c)
			case "unreadable":
				p.procs[0].Created = ""
			case "reused":
				p.procs[0].Created = "another-birth"
				p.counts[100] = 0
				p.frozen[100] = false
			case "no-labels":
				// A legacy/manual suspension without a policy cannot be assigned safely.
				x := procs.Proc{PID: 700, Created: "legacy", Name: "worker"}
				p.procs = append(p.procs, x)
				ledger := h.g.d.Procs.(*recovery.Controller)
				if err := ledger.Freeze(x); err != nil {
					t.Fatal(err)
				}
			}
			before := p.freezes
			n, err := h.g.RestoreProtection()
			if mode == "reused" {
				if err != nil || n != 3 {
					t.Fatalf("prune/reuse: %d %v", n, err)
				}
			} else if err == nil || n != 0 {
				t.Fatal("unsafe partial adoption")
			}
			if p.freezes != before || p.resumes != 0 {
				t.Fatal("refused adoption touched processes")
			}
		})
	}
}

func TestRestoreProtectionBarrierSurvivesRegrouping(t *testing.T) {
	h, _, _ := recordedHarness(t)
	if _, err := h.g.RestoreProtection(); err != nil {
		t.Fatal(err)
	}
	c := h.g.cfg.Clone()
	c.DomainChecksEnabled["claude"] = false
	c.IPUnavailableAction = config.IgnoreFailure
	h.g.SetConfig(h.now, c)
	h.probeFull(ProbeResult{Err: errors.New("offline")})
	if !h.p.frozen[100] || !h.p.frozen[101] {
		t.Fatal("regrouping bypassed first-proof barrier")
	}
	h.g.CheckNow(h.now)
	h.step(0)
	h.probeFull(ProbeResult{IP: "203.0.113.10", Votes: 2})
	if h.p.frozen[100] || h.p.frozen[101] {
		t.Fatal("valid current shared rules did not release adopted app")
	}
}

func TestRestoreProtectionRejectsLateAdoption(t *testing.T) {
	h, _, _ := recordedHarness(t)
	h.step(time.Millisecond)
	if _, err := h.g.RestoreProtection(); err == nil {
		t.Fatal("adopted while guard was already running")
	}
}

type failedPolicyJournal struct {
	*recovery.Controller
	fail bool
}

func (j *failedPolicyJournal) RememberFrozen(ps []procs.Proc) error {
	if j.fail {
		return errors.New("journal write denied")
	}
	return j.Controller.RememberFrozen(ps)
}

func TestRestoreProtectionPolicyWriteFailureNeverReleasesHolds(t *testing.T) {
	h, p, _ := recordedHarness(t)
	j := &failedPolicyJournal{Controller: h.g.d.Procs.(*recovery.Controller), fail: true}
	h.g.d.Procs = j
	if n, err := h.g.RestoreProtection(); err == nil || n != 0 {
		t.Fatal("partial adoption after failed metadata write")
	}
	if p.resumes != 0 || p.freezes != 4 {
		t.Fatal("failed adoption changed OS state")
	}
	j.fail = false
	if _, err := h.g.RestoreProtection(); err != nil {
		t.Fatal(err)
	}
	h.step(0)
	j.fail = true
	h.step(time.Millisecond)
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	if p.resumes != 0 || h.g.Snapshot(h.now).Frozen != 4 || len(h.g.Snapshot(h.now).Errors) == 0 {
		t.Fatal("metadata persistence failure permitted resume")
	}
	j.fail = false
	h.step(time.Millisecond)
	if h.g.Snapshot(h.now).Frozen != 0 || len(h.g.Snapshot(h.now).Errors) != 0 {
		t.Fatal("metadata persistence recovery could not finish a verified release")
	}
}

func TestRestoreProtectionPreservesOtherOwnersSuspension(t *testing.T) {
	h, p, _ := recordedHarness(t)
	p.counts[101]++ // an independent owner had also suspended this process
	if _, err := h.g.RestoreProtection(); err != nil {
		t.Fatal(err)
	}
	h.step(0)
	h.probeFull(domainReply(h, "203.0.113.10", "198.51.100.20"))
	if p.counts[101] != 1 || !p.frozen[101] || p.freezes != 4 || p.resumes != 4 {
		t.Fatal("adoption released another owner's count or added its own twice")
	}
}

func TestRestoreProtectionTimeoutRemainsRequiredWithIgnorePolicy(t *testing.T) {
	h, p, _ := recordedHarness(t)
	h.g.cfg.IPUnavailableAction = config.IgnoreFailure
	if _, err := h.g.RestoreProtection(); err != nil {
		t.Fatal(err)
	}
	h.step(0)
	id := h.g.probeID
	h.probeFull(timedOutReply(h, false))
	if !h.g.probing || h.g.probeID != id+1 || p.resumes != 2 || !p.frozen[100] || !p.frozen[101] {
		t.Fatal("required first-proof timeout did not retain holds and request its bounded retry")
	}
}
