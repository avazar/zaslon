// release assembles verified CI archives and version-pinned installer scripts.
// It never creates tags or publishes a release.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var semver = regexp.MustCompile("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")

func main() {
	dir := flag.String("dir", "dist", "directory containing all five CI archives")
	version := flag.String("version", "", "release version (defaults to VERSION)")
	installer := flag.String("installer", "scripts/install.ps1", "installer template")
	flag.Parse()
	v := *version
	if v == "" {
		b, err := os.ReadFile("VERSION")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		v = strings.TrimSpace(string(b))
	}
	if err := assemble(*dir, v, *installer); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func archiveNames(version string) []string {
	return []string{
		"zaslon-" + version + "-windows-amd64.zip", "zaslon-" + version + "-windows-arm64.zip",
		"zaslon-" + version + "-linux-amd64.tar.gz", "zaslon-" + version + "-linux-arm64.tar.gz",
		"zaslon-" + version + "-macos-universal.zip",
	}
}
func regularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	return os.ReadFile(path)
}
func assemble(dir, version, installer string) error {
	if !semver.MatchString(version) {
		return errors.New("version must be x.y.z")
	}
	names := archiveNames(version)
	allowed := map[string]bool{"install.ps1": true, "install.sh": true, "SHA256SUMS.txt": true}
	for _, name := range names {
		allowed[name], allowed[name+".sha256"] = true, true
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, file := range files {
		if !file.Type().IsRegular() || !allowed[file.Name()] {
			return fmt.Errorf("unexpected release asset: %s", file.Name())
		}
	}
	sums := map[string]string{}
	for _, name := range names {
		b, err := regularFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		hash := hex.EncodeToString(sum[:])
		sidecar, err := regularFile(filepath.Join(dir, name+".sha256"))
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(sidecar)) != hash+"  "+name {
			return fmt.Errorf("archive checksum mismatch: %s", name)
		}
		sums[name] = hash
	}
	scripts := map[string][]byte{}
	for _, name := range []string{"install.ps1", "install.sh"} {
		source := installer
		if name == "install.sh" {
			source = filepath.Join(filepath.Dir(installer), name)
		}
		template, err := regularFile(source)
		if err != nil {
			return err
		}
		if !strings.Contains(string(template), "__ZASLON_VERSION__") {
			return errors.New("installer template has no version placeholder")
		}
		text := strings.ReplaceAll(string(template), "__ZASLON_VERSION__", version)
		if name == "install.sh" {
			text = strings.ReplaceAll(text, "\r\n", "\n")
		}
		script := []byte(text)
		hash := sha256.Sum256(script)
		scripts[name] = script
		sums[name] = hex.EncodeToString(hash[:])
		names = append(names, name)
	}
	sort.Strings(names)
	var manifest strings.Builder
	for _, name := range names {
		fmt.Fprintf(&manifest, "%s  %s\n", sums[name], name)
	}
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), script, 0644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, "SHA256SUMS.txt"), []byte(manifest.String()), 0644)
}
