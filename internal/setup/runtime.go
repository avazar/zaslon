package setup

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/gofrs/flock"
)

// AcquireRuntime prevents replacement/removal while a managed Unix worker runs.
// Try-locking also rejects new workers started during an installation, rather
// than letting them wait for the profile lock and run after an uninstall.
func AcquireRuntime() (io.Closer, error) {
	if runtime.GOOS == "windows" {
		return nil, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return acquireRuntime(runtime.GOOS, exe)
}
func acquireRuntime(platform, exe string) (io.Closer, error) {
	if _, err := os.Stat(exe); err != nil {
		return nil, errors.New("executable was removed; refusing to start protection")
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return nil, err
	}
	exe = resolved
	root := filepath.Dir(exe)
	if platform == "darwin" && filepath.Base(root) == "MacOS" && filepath.Base(filepath.Dir(root)) == "Contents" {
		root = filepath.Dir(filepath.Dir(filepath.Dir(root)))
	}
	target := root
	receiptPath := filepath.Join(root, "install-receipt.json")
	if b, e := os.ReadFile(receiptPath); e == nil {
		var r receipt
		if json.Unmarshal(b, &r) != nil || r.Schema != 1 || r.Product != "Zaslon" || !filepath.IsAbs(r.Target) {
			return nil, errors.New("invalid installation receipt")
		}
		target = r.Target
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	path := target + ".install.lock"
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if err := rejectLink(path); err != nil {
		return nil, err
	}
	lock := flock.New(path)
	ok, err := lock.TryRLock()
	if err != nil {
		lock.Close()
		return nil, err
	}
	if !ok {
		lock.Close()
		return nil, errors.New("installation is in progress; retry after it finishes")
	}
	return lock, nil
}
