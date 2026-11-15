package update

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBundleOf(t *testing.T) {
	if b, err := bundleOf("/Applications/Zaslon.app/Contents/MacOS/zaslon"); err != nil || b != "/Applications/Zaslon.app" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := bundleOf("/usr/local/bin/zaslon"); err == nil {
		t.Fatal("non-bundle accepted")
	}
}

// TestReplaceBundle swaps a fake installed Zaslon.app for a new one from a zip.
func TestReplaceBundle(t *testing.T) {
	root := t.TempDir()
	mk := func(dir, version string) {
		os.MkdirAll(filepath.Join(dir, "Zaslon.app", "Contents", "MacOS"), 0o755)
		os.WriteFile(filepath.Join(dir, "Zaslon.app", "Contents", "MacOS", "zaslon"), []byte(version), 0o755)
	}
	apps := filepath.Join(root, "Applications")
	mk(apps, "old")
	src := filepath.Join(root, "src")
	mk(src, "new")
	zip := filepath.Join(root, "Zaslon-macos.zip")
	if out, err := exec.Command("/usr/bin/ditto", "-c", "-k", "--keepParent", filepath.Join(src, "Zaslon.app"), zip).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	exe := filepath.Join(apps, "Zaslon.app", "Contents", "MacOS", "zaslon")
	restart, err := replace(exe, zip, root)
	if err != nil || restart == nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); string(b) != "new" {
		t.Fatalf("installed %q", b)
	}
	ents, _ := os.ReadDir(apps)
	if len(ents) != 1 {
		t.Fatalf("leftovers next to the app: %v", ents)
	}
}
