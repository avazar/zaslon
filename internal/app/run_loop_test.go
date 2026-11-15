package app

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
	"github.com/avazar/zaslon/internal/netwatch"
	"github.com/avazar/zaslon/internal/procs"
)

type loopFixtureProcesses struct {
	held    atomic.Bool
	freezes atomic.Int32
	resumes atomic.Int32
}

func (p *loopFixtureProcesses) List() ([]procs.Proc, error) {
	return []procs.Proc{{PID: 100, Created: "fixture", Name: "zaslon-timer-fixture.exe", Path: "/fake/zaslon-timer-fixture.exe"}}, nil
}
func (p *loopFixtureProcesses) Freeze(procs.Proc) error {
	p.held.Store(true)
	p.freezes.Add(1)
	return nil
}
func (p *loopFixtureProcesses) Resume(procs.Proc) error {
	p.held.Store(false)
	p.resumes.Add(1)
	return nil
}

type runnerLoopFixture struct {
	r          *Runner
	p          *loopFixtureProcesses
	cfg        *config.Config
	base       time.Time
	elapsed    atomic.Int64
	ticks      chan time.Time
	polls      chan time.Time
	probes     chan uint64
	steps      chan struct{}
	updates    chan guard.Snapshot
	probeCount atomic.Int32
}

func newRunnerLoopFixture(t *testing.T) *runnerLoopFixture {
	t.Helper()
	t.Setenv("ZASLON_DIR", t.TempDir())
	f := &runnerLoopFixture{p: &loopFixtureProcesses{}, cfg: config.Default(), base: time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC), ticks: make(chan time.Time), polls: make(chan time.Time), probes: make(chan uint64, 16), steps: make(chan struct{}, 32), updates: make(chan guard.Snapshot, 32)}
	f.cfg.Apps = nil
	f.cfg.CustomApps = []config.CustomApp{{Name: "fixture", Match: []string{"zaslon-timer-fixture.exe"}}}
	f.cfg.DomainChecks = map[string][]string{"fixture": {"https://fixture.example/cdn-cgi/trace"}}
	f.cfg.DomainChecksEnabled = map[string]bool{"fixture": true}
	f.cfg.Allow = config.Allow{IPs: []string{"203.0.113.10"}}
	f.cfg.DNSCheck = "off"
	f.cfg.CheckIPv6 = false
	ctx, cancel := context.WithCancel(context.Background())
	f.r = &Runner{ctx: ctx, results: make(chan guard.ProbeResult, 4), changes: &netwatch.Events{C: make(chan struct{})}}
	f.r.G = guard.New(f.cfg, guard.Deps{Procs: f.p, Fingerprint: func() string { f.steps <- struct{}{}; return "unchanged" }, StartProbe: func(_ *config.Config, id uint64, _ bool) func() {
		f.probeCount.Add(1)
		f.probes <- id
		return func() {}
	}})
	f.r.G.OnChange(func(s guard.Snapshot, _ []guard.Event) { f.updates <- s })
	done := make(chan struct{})
	go func() {
		f.r.run(f.ticks, f.polls, func() time.Time { return f.base.Add(time.Duration(f.elapsed.Load())) })
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("runner fixture did not shut down")
		}
	})
	return f
}

func loopReceive[T any](t *testing.T, c <-chan T) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("runner fixture timed out")
		var zero T
		return zero
	}
}

func (f *runnerLoopFixture) success(t *testing.T, id uint64, checked time.Duration) {
	t.Helper()
	f.r.results <- guard.ProbeResult{ID: id, IP: "203.0.113.10", Votes: 2, Domains: map[string][]guard.DomainResult{"fixture": {{Endpoint: f.cfg.DomainChecks["fixture"][0], IP: "203.0.113.10", CheckedAt: f.base.Add(checked)}}}}
	for {
		if s := loopReceive(t, f.updates); s.Status == guard.OK && !s.Checking && s.Frozen == 0 {
			return
		}
	}
}

func (f *runnerLoopFixture) drainSteps() {
	for {
		select {
		case <-f.steps:
		default:
			return
		}
	}
}

func TestDelayedTickDoesNotRefreezeFreshDomainResult(t *testing.T) {
	f := newRunnerLoopFixture(t)
	id := loopReceive(t, f.probes)
	f.elapsed.Store(int64(time.Second))
	f.success(t, id, 800*time.Millisecond)
	f.elapsed.Store(int64(1100 * time.Millisecond))
	f.drainSteps()
	// This timestamp predates the accepted result, although the loop processes
	// it afterwards. A delayed Go ticker can deliver exactly this ordering.
	f.ticks <- f.base.Add(500 * time.Millisecond)
	loopReceive(t, f.steps)
	s := f.r.G.Snapshot(f.base.Add(1100 * time.Millisecond)) // lock also waits for Step to finish
	if s.Status != guard.OK || f.p.held.Load() || f.p.freezes.Load() != 1 || f.p.resumes.Load() != 1 {
		t.Fatalf("stale tick refroze a valid result: status=%v held=%v freezes=%d resumes=%d", s.Status, f.p.held.Load(), f.p.freezes.Load(), f.p.resumes.Load())
	}
	for _, e := range s.History {
		for _, detail := range e.Details {
			if e.Kind == guard.EvDomainCheck {
				t.Fatalf("false domain diagnostic: %s", detail)
			}
		}
	}
	// The processing-time fix must not turn off genuine expiry.
	f.elapsed.Store(int64(guard.DomainMaxAge + time.Second))
	f.drainSteps()
	f.ticks <- f.base.Add(time.Second)
	loopReceive(t, f.steps)
	s = f.r.G.Snapshot(f.base.Add(guard.DomainMaxAge + time.Second))
	if !f.p.held.Load() || s.Status != guard.Suspect {
		t.Fatal("genuinely expired proof was allowed")
	}
}

func TestDelayedConfigPollDoesNotStartAnAlreadyExpiredProbe(t *testing.T) {
	f := newRunnerLoopFixture(t)
	id := loopReceive(t, f.probes)
	f.elapsed.Store(int64(time.Second))
	f.success(t, id, 800*time.Millisecond)
	if err := os.WriteFile(ConfigPath(), []byte(config.Render(f.cfg)), 0600); err != nil {
		t.Fatal(err)
	}
	f.elapsed.Store(int64(10 * time.Second))
	f.polls <- f.base.Add(-time.Minute)
	newID := loopReceive(t, f.probes)
	f.elapsed.Store(int64(11 * time.Second))
	f.drainSteps()
	f.ticks <- f.base.Add(11 * time.Second)
	loopReceive(t, f.steps)
	_ = f.r.G.Snapshot(f.base.Add(11 * time.Second))
	if f.probeCount.Load() != 2 {
		t.Fatal("old config-poll timestamp caused an immediate false stuck-probe timeout")
	}
	f.success(t, newID, 10200*time.Millisecond)
	if f.p.held.Load() {
		t.Fatal("current settings probe did not resume the fixture")
	}
}
