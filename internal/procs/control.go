package procs

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type controlRole uint8

const (
	notControl controlRole = iota
	guardControl
	panelControl
)

func executablePath() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		p = resolved
	}
	return filepath.Clean(p)
}

func sameExecutable(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// Only this executable in one of its exact long-running control modes qualifies.
// A name, a substring in arguments, or an arbitrary descendant is not sufficient.
func ownRole(path, own string, argv []string) controlRole {
	if !sameExecutable(path, own) {
		return notControl
	}
	return controlMode(argv)
}

func controlMode(argv []string) controlRole {
	if len(argv) == 1 || (len(argv) == 2 && argv[1] == "headless") {
		return guardControl
	}
	if len(argv) == 2 && argv[1] == "panel" {
		return panelControl
	}
	return notControl
}
