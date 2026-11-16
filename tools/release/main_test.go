package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAssembleCompleteRelease(t *testing.T) {
	dir, template := releaseFixture(t)
	if err := assemble(dir, "0.3.0", template); err != nil {
		t.Fatal(err)
	}
	script, _ := os.ReadFile(filepath.Join(dir, "install.ps1"))
	if strings.Contains(string(script), "__ZASLON_VERSION__") || !strings.Contains(string(script), "'0.3.0'") {
		t.Fatal("installer is not version pinned")
	}
	sums, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS.txt"))
	lines := strings.Split(strings.TrimSpace(string(sums)), "\n")
	if len(lines) != 6 {
		t.Fatalf("manifest contains %d entries", len(lines))
	}
	for _, line := range lines {
		fields := strings.Split(line, "  ")
		b, err := os.ReadFile(filepath.Join(dir, fields[1]))
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(b)) != fields[0] {
			t.Fatalf("invalid manifest entry %q", line)
		}
	}
}
func TestRejectIncompleteOrModifiedAssets(t *testing.T) {
	for _, scenario := range []string{"missing-package", "wrong-checksum", "foreign-asset", "invalid-version"} {
		t.Run(scenario, func(t *testing.T) {
			dir, template := releaseFixture(t)
			version := "0.3.0"
			name := archiveNames(version)[0]
			switch scenario {
			case "missing-package":
				os.Remove(filepath.Join(dir, archiveNames(version)[1]))
			case "wrong-checksum":
				os.WriteFile(filepath.Join(dir, name), []byte("changed"), 0644)
			case "foreign-asset":
				os.WriteFile(filepath.Join(dir, "profile.yaml"), []byte("private"), 0644)
			case "invalid-version":
				version = "../../outside"
			}
			if err := assemble(dir, version, template); err == nil {
				t.Fatal("invalid input accepted")
			}
			if _, err := os.Stat(filepath.Join(dir, "install.ps1")); !os.IsNotExist(err) {
				t.Fatal("installer written before input verification")
			}
		})
	}
}
func releaseFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range archiveNames("0.3.0") {
		b := []byte(name)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".sha256"), []byte(fmt.Sprintf("%x  %s\n", sha256.Sum256(b), name)), 0644); err != nil {
			t.Fatal(err)
		}
	}
	template := filepath.Join(t.TempDir(), "install.ps1")
	if err := os.WriteFile(template, []byte("param($Version='__ZASLON_VERSION__')"), 0644); err != nil {
		t.Fatal(err)
	}
	return dir, template
}
