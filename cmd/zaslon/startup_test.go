package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/avazar/zaslon/internal/config"
)

func TestRecordedSuspensionsRequireExistingValidConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if _, _, err := loadStartupConfig(p, true); err == nil {
		t.Fatal("defaulted missing recovery configuration")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("created replacement rules during recovery")
	}
	bad := []byte("invalid: [")
	if err := os.WriteFile(p, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadStartupConfig(p, true); err == nil {
		t.Fatal("defaulted corrupt recovery configuration")
	}
	if b, _ := os.ReadFile(p); string(b) != string(bad) {
		t.Fatal("rewrote invalid settings")
	}
	c := config.Default()
	c.Apps = []string{"codex"}
	if err := os.WriteFile(p, []byte(config.Render(c)), 0600); err != nil {
		t.Fatal(err)
	}
	got, created, err := loadStartupConfig(p, true)
	if err != nil || created || len(got.Apps) != 1 || got.Apps[0] != "codex" {
		t.Fatal("valid recovery settings not retained")
	}
}
