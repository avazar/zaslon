package ui

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/app"
	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
)

func TestPanelFailurePoliciesValidateBeforeChangingConfig(t *testing.T) {
	s, _, g := startServer(t)
	before := config.Render(g.Snapshot(time.Now()).Config)
	for _, body := range []string{
		`{"ipv6_unavailable_action":"off","ip_unavailable_action":"ignore"}`, `{"ip_unavailable_action":true}`, `{"ip_unavailable_action":null}`,
		`{"ip_unavailable_action":"ignore","dns_check":"broken"}`, `{"ipv6_unavailable_action":"ignore","check_ipv6":"false"}`,
	} {
		if err := s.settings(time.Now(), json.RawMessage(body)); err == nil {
			t.Fatalf("accepted %s", body)
		}
		if config.Render(g.Snapshot(time.Now()).Config) != before {
			t.Fatal("invalid request changed protection settings")
		}
	}
	if err := s.settings(time.Now(), json.RawMessage(`{"ip_unavailable_action":"suspend","ipv6_unavailable_action":"ignore"}`)); err != nil {
		t.Fatal(err)
	}
	c := g.Snapshot(time.Now()).Config
	if c.IPUnavailableAction != config.SuspendOnFailure || c.IPv6UnavailableAction != config.IgnoreFailure || !c.CheckIPv6 {
		t.Fatal("policies were not saved independently of the IPv6 switch")
	}
}

func TestIgnoredFailureIsWarningInPanelTrayAndNotifications(t *testing.T) {
	t.Setenv("ZASLON_DIR", t.TempDir())
	c := config.Default()
	c.Apps = []string{"claude"}
	c.Allow.IPs = []string{"203.0.113.10"}
	c.IPv6UnavailableAction = config.IgnoreFailure
	var id uint64
	g := guard.New(c, guard.Deps{Procs: noProcs{}, Fingerprint: func() string { return "fixture" }, StartProbe: func(_ *config.Config, v uint64, _ guard.ProbePlan) func() { id = v; return nil }})
	now := time.Now()
	g.Step(now)
	g.HandleProbe(now, guard.ProbeResult{ID: id, IP: "203.0.113.10", Votes: 2, IPv6Unknown: true})
	snap := g.Snapshot(now)
	if panelStatus(snap) != "warning" || statusName(snap) != "warning" || ToneOf(snap) != Amber || snap.Allowed() {
		t.Fatal("unverified exit was presented as healthy protection")
	}
	s := &Server{G: g, Stats: app.LoadStats()}
	w := httptest.NewRecorder()
	s.state(w, httptest.NewRequest("GET", "/api/state", nil))
	var state struct {
		Status   string
		Warnings []struct {
			Reason string
			Apps   []string
		}
		Apps     []appJSON
		Settings map[string]any
	}
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.Status != "warning" || len(state.Warnings) != 1 || state.Warnings[0].Reason != "v6unknown" || state.Settings["ipv6_unavailable_action"] != "ignore" {
		t.Fatal(w.Body.String())
	}
	for _, a := range state.Apps {
		if a.ID == "claude" && (a.Status != "warning" || len(a.Warnings) != 1) {
			t.Fatal("app warning missing")
		}
	}
	old := Lang
	defer func() { Lang = old }()
	for _, lang := range []string{"ru", "en"} {
		Lang = lang
		if StatusLine(snap) != T("checks.ignored") {
			t.Fatal("status hides the ignored check")
		}
		e := guard.Event{Kind: guard.EvResumed, Apps: []string{"fixture"}, Notify: true, IgnoredChecks: true}
		_, body, ok := Notification(e)
		if !ok || body != T("ev.resumed.ignored.b") || !strings.Contains(EventLine(e), T("ev.resumed.ignored", "fixture")) {
			t.Fatal("resume notification claims a successful verification")
		}
	}
}
