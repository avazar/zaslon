package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// DefaultDomains prefill editable lists; enabling checks is a separate choice.
func DefaultDomains(id string) []string {
	switch id {
	case "claude":
		return []string{"https://claude.ai/cdn-cgi/trace", "https://api.anthropic.com/cdn-cgi/trace"}
	case "chatgpt":
		return []string{"https://chatgpt.com/cdn-cgi/trace"}
	case "codex":
		return []string{"https://chatgpt.com/cdn-cgi/trace", "https://api.openai.com/cdn-cgi/trace"}
	case "perplexity":
		return []string{"https://www.perplexity.ai/cdn-cgi/trace"}
	}
	return nil
}

func defaultDomainLists() map[string][]string {
	lists := map[string][]string{}
	for _, id := range []string{"claude", "chatgpt", "codex", "perplexity"} {
		lists[id] = DefaultDomains(id)
	}
	return lists
}

func (c *Config) DomainCheckEnabled(id string) bool { return c.DomainChecksEnabled[id] }

// DomainEndpoint accepts a host or an HTTPS trace endpoint. Plain HTTP is only
// allowed for literal loopback addresses, for local fixtures and diagnostics.
func DomainEndpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\r\n\t ") {
		return "", fmt.Errorf("empty or invalid domain")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" {
		return "", fmt.Errorf("expected a host or HTTPS /cdn-cgi/trace URL without credentials, query or fragment")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	host := u.Hostname()
	for _, ch := range host {
		if ch > 127 || !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || strings.ContainsRune(".-:_%", ch)) {
			return "", fmt.Errorf("invalid domain")
		}
	}
	if strings.ContainsAny(host, "_%") {
		return "", fmt.Errorf("invalid domain")
	}
	if port := u.Port(); port != "" {
		if _, err := net.LookupPort("tcp", port); err != nil {
			return "", fmt.Errorf("invalid port")
		}
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(host)
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return "", fmt.Errorf("HTTPS is required; HTTP is allowed only on literal loopback addresses")
		}
	}
	if u.Path != "" && u.Path != "/" && u.Path != "/cdn-cgi/trace" {
		return "", fmt.Errorf("only /cdn-cgi/trace is supported; specify the actual service host")
	}
	u.Path = "/cdn-cgi/trace"
	return u.String(), nil
}

func (c *Config) normalizeDomains() error {
	normalized := map[string][]string{}
	for key, endpoints := range c.DomainChecks {
		id := strings.ToLower(strings.TrimSpace(key))
		if id == "" || len(endpoints) > 8 {
			return fmt.Errorf("domain_checks: nonempty app ID and at most 8 domains per app required")
		}
		if _, ok := normalized[id]; ok {
			return fmt.Errorf("domain_checks: duplicate app %q", id)
		}
		normalized[id] = nil
		seen := map[string]bool{}
		for _, raw := range endpoints {
			endpoint, err := DomainEndpoint(raw)
			if err != nil {
				return fmt.Errorf("domain_checks.%s: %w", id, err)
			}
			if !seen[endpoint] {
				normalized[id] = append(normalized[id], endpoint)
				seen[endpoint] = true
			}
		}
	}
	c.DomainChecks = normalized
	for id, endpoints := range defaultDomainLists() {
		if _, exists := c.DomainChecks[id]; !exists {
			c.DomainChecks[id] = endpoints
		}
	}
	enabled := map[string]bool{}
	for key, on := range c.DomainChecksEnabled {
		id := strings.ToLower(strings.TrimSpace(key))
		if id == "" {
			return fmt.Errorf("domain_checks_enabled: empty app ID")
		}
		if _, exists := enabled[id]; exists {
			return fmt.Errorf("domain_checks_enabled: duplicate app %q", id)
		}
		if on && len(c.DomainChecks[id]) == 0 {
			return fmt.Errorf("domain_checks_enabled.%s: at least one domain is required", id)
		}
		enabled[id] = on
	}
	c.DomainChecksEnabled = enabled
	return nil
}
