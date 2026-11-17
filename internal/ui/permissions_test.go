package ui

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
)

func TestExplicitAllowActionNeverSubstitutesCurrentAddresses(t *testing.T) {
	var id uint64
	g := guard.New(config.Default(), guard.Deps{
		Fingerprint: func() string { return "fixture" }, Procs: noProcs{},
		StartProbe: func(_ *config.Config, n uint64, _ guard.ProbePlan) func() { id = n; return nil },
		SaveConfig: func(*config.Config) error { return nil },
	})
	now := time.Now()
	g.Step(now)
	g.HandleProbe(now, guard.ProbeResult{ID: id, IP: "203.0.113.99", Country: "RU", Votes: 2, IP6: "2001:db9::1", Country6: "RU", NetID: "router-b"})
	s := &Server{G: g}
	// The dialog had displayed the earlier NL address; only that exact value
	// may be added even though the current network has changed meanwhile.
	if err := s.apply(action{Op: "allow_current_ip", Value: "203.0.113.10"}); err != nil {
		t.Fatal(err)
	}
	if err := s.apply(action{Op: "allow_current_country", Value: "NL"}); err != nil {
		t.Fatal(err)
	}
	cfg := g.Snapshot(time.Now()).Config
	if !slices.Equal(cfg.Allow.IPs, []string{"203.0.113.10"}) || !slices.Equal(cfg.Allow.Countries, []string{"NL"}) {
		t.Fatalf("substituted unconfirmed permissions: %+v", cfg.Allow)
	}
	for _, op := range []string{"allow_current_ip", "allow_current_country"} {
		if err := s.apply(action{Op: op}); err == nil {
			t.Fatalf("%s accepted no confirmed value", op)
		}
	}
	if err := s.apply(action{Op: "trust_network", App: "router-a", Value: "Office"}); err == nil {
		t.Fatal("trust switched to another router")
	}
	if len(g.Snapshot(time.Now()).Config.TrustedNetworks) != 0 {
		t.Fatal("stale trust confirmation mutated permissions")
	}
}

func TestPanelWriteErrorsKeepPreviouslySavedPolicy(t *testing.T) {
	failure := errors.New("read-only profile")
	g := guard.New(config.Default(), guard.Deps{
		Fingerprint: func() string { return "stable" }, Procs: noProcs{},
		StartProbe: func(*config.Config, uint64, guard.ProbePlan) func() { return nil },
		SaveConfig: func(*config.Config) error { return failure },
	})
	now := time.Now()
	g.Step(now)
	g.HandleProbe(now, guard.ProbeResult{ID: 1, IP: "203.0.113.1", Votes: 2, NetID: "fixture"})
	before := g.Snapshot(now).Config
	s := &Server{G: g}
	for _, a := range []action{
		{Op: "add_country", Value: "PL"}, {Op: "toggle_app", App: "claude"},
		{Op: "trust_network", App: "fixture", Value: "Office"},
		{Op: "settings", Settings: json.RawMessage(`{"notifications":false}`)},
	} {
		if err := s.apply(a); !errors.Is(err, failure) {
			t.Fatalf("%s lost save error: %v", a.Op, err)
		}
		if !reflect.DeepEqual(before, g.Snapshot(now).Config) {
			t.Fatalf("%s published unsaved changes", a.Op)
		}
	}
}
