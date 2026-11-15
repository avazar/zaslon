// Package app holds the OS glue: where files live, logging, notifications,
// autostart, opening files and links, and the loop that drives the guard.
package app

import (
	"os"
	"path/filepath"
	"runtime"
)

// Dir is where Zaslon keeps config.yaml, the log and the state file.
func Dir() string {
	if d := os.Getenv("ZASLON_DIR"); d != "" {
		return d // a separate profile for development and screenshots
	}
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.TempDir()
	}
	name := "Zaslon"
	if runtime.GOOS == "linux" {
		name = "zaslon"
	}
	return filepath.Join(base, name)
}

func ConfigPath() string { return filepath.Join(Dir(), "config.yaml") }
func LogPath() string    { return filepath.Join(Dir(), "zaslon.log") }
func StatePath() string  { return filepath.Join(Dir(), "state.json") }
func LockPath() string   { return filepath.Join(Dir(), "zaslon.lock") }

const RepoURL = "https://github.com/avazar/zaslon"
