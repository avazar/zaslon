package ui

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
)

func TestPanelDomainConfigurationAndValidation(t *testing.T) {
	s, _, g := startServer(t)
	if err := s.apply(action{Op: "set_domains", App: "claude", Domains: []string{"claude.ai", "api.anthropic.com"}}); err != nil {
		t.Fatal(err)
	}
	got := g.Snapshot(time.Now()).Config
	if len(got.DomainChecks["claude"]) != 2 {
		t.Fatal("domain configuration was not applied")
	}
	if got.DomainCheckEnabled("claude") {
		t.Fatal("editing a list enabled checks")
	}
	before := config.Render(got)
	for _, a := range []action{{Op: "set_domains", App: "claude", Domains: []string{"http://untrusted.example"}}, {Op: "set_domains", App: "unknown", Domains: []string{"example.com"}}} {
		if err := s.apply(a); err == nil {
			t.Fatal("accepted invalid configuration")
		}
		if config.Render(g.Snapshot(time.Now()).Config) != before {
			t.Fatal("invalid update changed protection settings")
		}
	}
	w := httptest.NewRecorder()
	s.state(w, httptest.NewRequest("GET", "/api/state", nil))
	var state struct {
		Apps []appJSON `json:"apps"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	found := false
	antigravityApps := 0
	for _, a := range state.Apps {
		if a.ID == "antigravity" || a.ID == "antigravity-ide" {
			antigravityApps++
			if !slices.Contains(a.ServiceHosts, "daily-cloudcode-pa.googleapis.com") || len(a.Domains) != 0 || a.DomainChecksEnabled {
				t.Errorf("unexpected routing domains or active IP probes for %s: %+v", a.ID, a)
			}
		}
		if a.ID == "claude" {
			found = true
			if len(a.Domains) != 2 || len(a.DefaultDomains) != 2 {
				t.Fatal("panel omitted domain settings or defaults")
			}
		}
	}
	if antigravityApps != 2 {
		t.Fatal("missing Antigravity presets")
	}
	if !found {
		t.Fatal("configured app missing from panel")
	}
	if err := s.apply(action{Op: "set_domains", App: "claude"}); err != nil {
		t.Fatal(err)
	}
	if len(g.Snapshot(time.Now()).Config.DomainChecks["claude"]) != 0 {
		t.Fatal("empty domain list did not disable checks")
	}
}

func TestDomainSwitchRetainsListAndCannotEnableEmptyChecks(t *testing.T) {
	s, _, g := startServer(t)
	on, off := true, false
	initial := g.Snapshot(time.Now()).Config.DomainChecks["claude"]
	if err := s.apply(action{Op: "set_domain_checks", App: "claude", Enabled: &on}); err != nil {
		t.Fatal(err)
	}
	before := config.Render(g.Snapshot(time.Now()).Config)
	if err := s.apply(action{Op: "set_domains", App: "claude"}); err == nil {
		t.Fatal("enabled check accepted empty list")
	}
	if config.Render(g.Snapshot(time.Now()).Config) != before {
		t.Fatal("invalid edit changed protection")
	}
	if err := s.apply(action{Op: "set_domain_checks", App: "claude", Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	c := g.Snapshot(time.Now()).Config
	if c.DomainCheckEnabled("claude") || len(c.DomainChecks["claude"]) != len(initial) {
		t.Fatal("switch did not preserve the list")
	}
	if err := s.apply(action{Op: "set_domains", App: "claude"}); err != nil {
		t.Fatal(err)
	}
	if err := s.apply(action{Op: "set_domain_checks", App: "claude", Enabled: &on}); err == nil {
		t.Fatal("enabled an empty list")
	}
	for _, a := range []action{{Op: "set_domain_checks", App: "claude"}, {Op: "set_domain_checks", App: "unknown", Enabled: &off}} {
		if err := s.apply(a); err == nil {
			t.Fatal("accepted invalid toggle")
		}
	}
	g.Update(time.Now(), func(c *config.Config) { c.Apps = nil })
	if err := s.apply(action{Op: "set_domains", App: "claude", Domains: []string{"claude.ai"}}); err != nil {
		t.Fatal("cannot prepare domains before enabling protection", err)
	}
	if err := s.apply(action{Op: "set_domain_checks", App: "claude", Enabled: &on}); err != nil {
		t.Fatal(err)
	}
	c = g.Snapshot(time.Now()).Config
	if len(c.Apps) != 0 || !c.DomainCheckEnabled("claude") {
		t.Fatal("domain toggle changed app protection selection")
	}
}

func TestPermissionSourceDoesNotChangeDomainSettings(t *testing.T) {
	s, _, g := startServer(t)
	on := true
	if err := s.apply(action{Op: "set_domain_checks", App: "claude", Enabled: &on}); err != nil {
		t.Fatal(err)
	}
	before := g.Snapshot(time.Now()).Config
	if err := s.apply(action{Op: "set_rule", App: "claude", IPs: append([]string(nil), before.Allow.IPs...), Countries: append([]string(nil), before.Allow.Countries...)}); err != nil {
		t.Fatal(err)
	}
	own := g.Snapshot(time.Now()).Config
	if !reflect.DeepEqual(own.Allow, before.Allow) || !reflect.DeepEqual(own.AppRules["claude"], before.Allow) || !own.DomainCheckEnabled("claude") || !reflect.DeepEqual(own.DomainChecks, before.DomainChecks) {
		t.Fatal("permission source changed domains or shared permissions")
	}
	if err := s.apply(action{Op: "remove_rule", App: "claude"}); err != nil {
		t.Fatal(err)
	}
	shared := g.Snapshot(time.Now()).Config
	if _, exists := shared.AppRules["claude"]; exists {
		t.Fatal("shared permissions still have an app override")
	}
	if !shared.DomainCheckEnabled("claude") || !reflect.DeepEqual(shared.DomainChecks, before.DomainChecks) {
		t.Fatal("return to shared permissions changed domain settings")
	}
}

func TestDomainReasonKeysAreDefined(t *testing.T) {
	old := Lang
	defer func() { Lang = old }()
	for _, lang := range []string{"ru", "en"} {
		Lang = lang
		for _, reason := range []guard.Reason{guard.DomainUnconfirmed, guard.DomainIPNotAllowed, guard.ProcessPolicyDenied} {
			if key := reasonKey(reason); key == "" {
				t.Fatal("missing reason key")
			}
			if text := reasonText(reason); text == "" || text == "reason."+reasonKey(reason) {
				t.Fatal("missing reason translation")
			}
		}
	}
}

func TestDomainTimeoutNamesOnlyFailedEndpoint(t *testing.T) {
	old:=Lang
	defer func(){Lang=old}()
	issue:=guard.DomainIssue{Endpoint:"https://api.anthropic.com/cdn-cgi/trace",Reason:guard.DomainUnconfirmed,Timeout:true}
	group:=guard.GroupState{Status:guard.Suspect,Reason:issue.Reason,Issues:[]guard.DomainIssue{issue}}
	for lang, want:=range map[string]string{"ru":"Тайм-аут проверки api.anthropic.com (IPv4)","en":"api.anthropic.com timed out (IPv4)"} {
		Lang=lang
		s:=guard.Snapshot{Status:guard.Suspect,Reason:issue.Reason,Groups:[]guard.GroupState{group,group}}
		if got:=StatusLine(s); got!=want {t.Fatalf("status: %q",got)}
		_,body,_:=Notification(guard.Event{Kind:guard.EvFrozen,Reason:issue.Reason,Issues:group.Issues,Notify:true})
		if body!=want {t.Fatalf("notification: %q",body)}
	}
}
