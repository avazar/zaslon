package config

import "testing"

func TestFailurePoliciesDefaultStrictAndRoundTrip(t *testing.T) {
	c, err := Parse([]byte("apps: []\n"))
	if err != nil || c.IPUnavailableAction != SuspendOnFailure || c.IPv6UnavailableAction != SuspendOnFailure {
		t.Fatalf("defaults: %+v, %v", c, err)
	}
	c.IPv6UnavailableAction = IgnoreFailure
	for _, lang := range []string{"ru", "en"} {
		old := CommentLang
		CommentLang = lang
		rendered := Render(c)
		CommentLang = old
		got, err := Parse([]byte(rendered))
		if err != nil || got.IPUnavailableAction != SuspendOnFailure || got.IPv6UnavailableAction != IgnoreFailure {
			t.Fatalf("round trip: %+v, %v", got, err)
		}
	}
	copy := c.Clone()
	copy.IPUnavailableAction = IgnoreFailure
	if c.IPUnavailableAction != SuspendOnFailure {
		t.Fatal("clone changed original policy")
	}
}

func TestFailurePoliciesRejectUnknownActions(t *testing.T) {
	for _, key := range []string{"ip_unavailable_action", "ipv6_unavailable_action"} {
		for _, value := range []string{"allow", "off", "\"\"", "true", "123"} {
			if _, err := Parse([]byte(key + ": " + value + "\n")); err == nil {
				t.Errorf("accepted %s=%s", key, value)
			}
		}
	}
}
