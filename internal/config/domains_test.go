package config

import (
	"strings"
	"testing"
)

func TestDomainConfigRoundTripAndIsolation(t *testing.T) {
	c, err := Parse([]byte("apps: [codex]\ndomain_checks:\n  Codex: [chatgpt.com, https://api.openai.com/cdn-cgi/trace, chatgpt.com]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.DomainChecks["codex"]) != 2 || !strings.HasPrefix(c.DomainChecks["codex"][0], "https://") {
		t.Fatal(c.DomainChecks)
	}
	copy := c.Clone()
	copy.DomainChecksEnabled["codex"] = false
	if !c.DomainCheckEnabled("codex") {
		t.Fatal("legacy state not migrated or enabled map shared")
	}
	copy.DomainChecks["codex"][0] = "changed"
	if c.DomainChecks["codex"][0] == "changed" {
		t.Fatal("shared domain slice")
	}
	got, err := Parse([]byte(Render(c)))
	if err != nil || Render(got) != Render(c) {
		t.Fatalf("round trip: %v", err)
	}
	if len(Default().DomainChecks["claude"]) != 2 || Default().DomainCheckEnabled("claude") {
		t.Fatal("defaults must prefill lists without enabling checks")
	}
}

func TestDomainListsAndEnabledStateAreIndependent(t *testing.T) {
	for _, data := range []string{"apps: []\n", "domain_checks: {}\n", "domain_checks:\n  Claude: []\n"} {
		c, err := Parse([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		if c.DomainCheckEnabled("claude") || len(c.DomainChecks["claude"]) != 2 {
			t.Fatal("legacy empty configuration enabled defaults or lost prefilled list")
		}
	}
	for _, enabled := range []string{"false", "true"} {
		c, err := Parse([]byte("domain_checks:\n  Claude: [custom.example]\ndomain_checks_enabled:\n  CLAUDE: " + enabled + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		if c.DomainCheckEnabled("claude") != (enabled == "true") || c.DomainChecks["claude"][0] != "https://custom.example/cdn-cgi/trace" {
			t.Fatal("explicit switch ignored")
		}
		got, err := Parse([]byte(Render(c)))
		if err != nil || got.DomainCheckEnabled("claude") != c.DomainCheckEnabled("claude") || len(got.DomainChecks["claude"]) != 1 {
			t.Fatalf("switch/list not persisted: %v", err)
		}
	}
	c, err := Parse([]byte("domain_checks:\n  claude: []\ndomain_checks_enabled:\n  claude: false\n"))
	if err != nil || len(c.DomainChecks["claude"]) != 0 {
		t.Fatal("explicit empty disabled list was overwritten")
	}
	for _, data := range []string{"domain_checks_enabled: null\n", "domain_checks_enabled: [claude]\n", "domain_checks: {claude: []}\ndomain_checks_enabled: {claude: true}\n", "domain_checks_enabled: {unknown: true}\n", "domain_checks_enabled: {claude: true, Claude: false}\n"} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("accepted invalid enabled configuration: %s", data)
		}
	}
}

func TestDomainEndpointRejectsAmbiguousOrUnsafeInputs(t *testing.T) {
	for _, raw := range []string{"", "http://example.com", "https://user:pass@example.com", "https://example.com/v1", "https://example.com?x=1", "https://example.com/#frag", "ftp://example.com", "https://example.com/%63dn-cgi/trace", "bad host"} {
		if _, err := DomainEndpoint(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"claude.ai", "https://api.anthropic.com/cdn-cgi/trace", "http://127.0.0.1:12345", "http://[::1]:12345"} {
		if _, err := DomainEndpoint(raw); err != nil {
			t.Errorf("%q: %v", raw, err)
		}
	}
}
