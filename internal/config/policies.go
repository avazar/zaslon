package config

import "fmt"

// FailureAction applies only to unavailable measurements, never to a received
// disallowed address or contradictory measurements.
type FailureAction string

const (
	SuspendOnFailure FailureAction = "suspend"
	IgnoreFailure    FailureAction = "ignore"
)

func (a FailureAction) Valid() bool { return a == SuspendOnFailure || a == IgnoreFailure }

func (c *Config) normalizePolicies() error {
	for key, action := range map[string]FailureAction{
		"ip_unavailable_action": c.IPUnavailableAction, "ipv6_unavailable_action": c.IPv6UnavailableAction,
	} {
		if !action.Valid() {
			return fmt.Errorf("%s: expected suspend or ignore, got %q", key, action)
		}
	}
	return nil
}
