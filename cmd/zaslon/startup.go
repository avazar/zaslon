package main

import (
	"fmt"
	"os"

	"github.com/avazar/zaslon/internal/app"
	"github.com/avazar/zaslon/internal/config"
)

// Defaults must not replace missing/broken rules while recorded processes are
// still held. Emergency resume intentionally does not depend on this file.
func loadStartupConfig(path string, recorded bool) (*config.Config, bool, error) {
	if !recorded {
		return config.Load(path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("recorded suspensions require an existing configuration: %w", err)
	}
	cfg, err := config.Parse(b)
	return cfg, false, err
}

func reportProtectionRecoveryError(err error, tray bool) {
	message := fmt.Sprintf("%v; journal preserved. Restore the configuration or inspect with zaslon-recover -dir %q. Emergency -resume ends protection", err, app.Dir())
	app.Logf("Recovery required: %s", message)
	if tray {
		app.Notify("Zaslon: recovery required", message)
	} else {
		fmt.Fprintln(os.Stderr, message)
	}
}
