//go:build zaslon_cli_e2e

package procs

import (
	"testing"

	"github.com/avazar/zaslon/internal/config"
)

// Run on a clean Windows CI runner: the real presets also match these
// fixtures in an installed guard, which would own a second suspension.
func TestWindowsCLIRecognitionAndDescendants(t *testing.T) {
	claude := `C:\User Name\npm\node_modules\@anthropic-ai\claude-code\cli.js`
	for _, tc := range []struct {
		id, key, app string
		args         []string
	}{
		{"node-v1", "v1/node", "claude", []string{claude, "--prompt", "тест"}},
		{"node-v2", "v2/node", "claude", []string{`C:/New Version/node_modules/@anthropic-ai/claude-code/cli.js`}},
		{"bun-direct", "v2/bun", "claude", []string{claude}},
		{"bun-run", "v2/bun", "claude", []string{"--bun", "run", claude}},
		{"node-codex", "v2/node", "codex", []string{`C:\Updated\node_modules\@openai\codex\bin\codex.js`}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			cfg := config.Default()
			cfg.Apps = []string{tc.app}
			cfg.CustomApps = nil
			targets := Targets(cfg)
			if len(targets) != 1 || targets[0].ID != tc.app {
				t.Fatalf("missing Windows preset %q", tc.app)
			}
			checkCLIProcessTree(t, tc.id, tc.key, tc.args, targets[0])
		})
	}
}
