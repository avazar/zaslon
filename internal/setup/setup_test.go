package setup

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gofrs/flock"
)

func fixtureArchive(t *testing.T, platform, mutation string) string {
	t.Helper()
	p := payload{
		"VERSION": {[]byte("1.3.0\n"), 0644}, "LICENSE": {[]byte("MIT\n"), 0644}, "README.txt": {[]byte("instructions\n"), 0644},
		executable(platform, "zaslon"): {[]byte("fixture main"), 0755}, executable(platform, "zaslon-recover"): {[]byte("fixture helper"), 0755},
	}
	if platform == "darwin" {
		p["Zaslon.app/Contents/Info.plist"] = payloadFile{[]byte("<plist/>"), 0644}
	}
	var sums strings.Builder
	for _, name := range payloadNames(p) {
		fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(p[name].data), name)
	}
	p["SHA256SUMS.txt"] = payloadFile{[]byte(sums.String()), 0644}
	switch mutation {
	case "checksum":
		v := p[executable(platform, "zaslon")]
		v.data = []byte("modified")
		p[executable(platform, "zaslon")] = v
	case "traversal":
		p["../outside"] = payloadFile{[]byte("unsafe"), 0644}
	case "missing-helper":
		delete(p, executable(platform, "zaslon-recover"))
	}
	archive := filepath.Join(t.TempDir(), "payload")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	if platform == "darwin" {
		z := zip.NewWriter(f)
		for _, name := range payloadNames(p) {
			h := &zip.FileHeader{Name: name}
			h.SetMode(p[name].mode)
			w, e := z.CreateHeader(h)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = w.Write(p[name].data); e != nil {
				t.Fatal(e)
			}
		}
		if err = z.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		g := gzip.NewWriter(f)
		w := tar.NewWriter(g)
		for _, name := range payloadNames(p) {
			b := p[name].data
			if err = w.WriteHeader(&tar.Header{Name: name, Mode: int64(p[name].mode), Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err = w.Write(b); err != nil {
				t.Fatal(err)
			}
		}
		if err = w.Close(); err != nil {
			t.Fatal(err)
		}
		if err = g.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	return archive
}
func options(t *testing.T, platform string) Options {
	t.Helper()
	root := t.TempDir()
	return Options{Archive: fixtureArchive(t, platform, ""), Target: filepath.Join(root, "program space"), Profile: filepath.Join(root, "profile"), Version: "1.3.0", NoLinks: true}
}
func canonical(t *testing.T, o Options) Options {
	t.Helper()
	var err error
	o.Target, err = filepath.EvalSymlinks(o.Target)
	if err != nil {
		t.Fatal(err)
	}
	o.Profile, err = filepath.EvalSymlinks(o.Profile)
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func TestInstallUpdateAndUninstall(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			o := options(t, platform)
			if err := run(platform, o); err != nil {
				t.Fatal(err)
			}
			o = canonical(t, o)
			config := filepath.Join(o.Profile, "config.yaml")
			journal := filepath.Join(o.Profile, "process-recovery.json")
			configBytes := []byte("apps: []\n")
			journalBytes := []byte("{\"version\":1,\"entries\":{\"123\":{\"phase\":\"frozen\"}}}")
			os.WriteFile(config, configBytes, 0600)
			os.WriteFile(journal, journalBytes, 0600)
			first, _ := readReceipt(o)
			if err := run(platform, o); err != nil {
				t.Fatal(err)
			}
			second, _ := readReceipt(o)
			if first.Transaction == second.Transaction {
				t.Fatal("no update occurred")
			}
			b, e := os.ReadFile(o.Target + ".backup-" + second.Transaction + "/profile-config-backup.yaml")
			if e != nil || string(b) != string(configBytes) {
				t.Fatal("settings backup missing")
			}
			b, _ = os.ReadFile(journal)
			if string(b) != string(journalBytes) {
				t.Fatal("recovery journal changed")
			}
			o.Uninstall = true
			if err := run(platform, o); err == nil {
				t.Fatal("unresolved suspensions accepted for uninstall")
			}
			os.WriteFile(journal, []byte("{\"version\":1,\"entries\":{}}"), 0600)
			sentinel := filepath.Join(o.Target, "user-file")
			os.WriteFile(sentinel, []byte("keep"), 0600)
			if err := run(platform, o); err != nil {
				t.Fatal(err)
			}
			if _, e := os.Stat(sentinel); e != nil {
				t.Fatal("unrelated file removed")
			}
			b, _ = os.ReadFile(config)
			if string(b) != string(configBytes) {
				t.Fatal("settings removed")
			}
			if _, e := os.Stat(filepath.Join(o.Target, filepath.FromSlash(executable(platform, "zaslon")))); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("program remains")
			}
		})
	}
}
func TestRejectActiveGuardAndBadPackages(t *testing.T) {
	o := options(t, "linux")
	os.MkdirAll(o.Profile, 0700)
	lock := flock.New(filepath.Join(o.Profile, "zaslon.lock"))
	if ok, e := lock.TryLock(); e != nil || !ok {
		t.Fatal("cannot create guard lock")
	}
	if err := run("linux", o); err == nil {
		t.Fatal("running guard not refused")
	}
	lock.Close()
	for _, platform := range []string{"linux", "darwin"} {
		for _, mutation := range []string{"checksum", "traversal", "missing-helper"} {
			t.Run(platform+"/"+mutation, func(t *testing.T) {
				o := options(t, platform)
				o.Archive = fixtureArchive(t, platform, mutation)
				if err := run(platform, o); err == nil {
					t.Fatal("unsafe archive accepted")
				}
				if _, e := os.Stat(o.Target); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("target written on failed verification")
				}
			})
		}
	}
}
func TestRollbackAndPendingRecovery(t *testing.T) {
	o := options(t, "linux")
	if err := run("linux", o); err != nil {
		t.Fatal(err)
	}
	o = canonical(t, o)
	before, _ := readReceipt(o)
	calls := 0
	o.rename = func(a, b string) error {
		calls++
		if calls == 2 {
			return errors.New("injected move failure")
		}
		return os.Rename(a, b)
	}
	if err := run("linux", o); err == nil {
		t.Fatal("rename failure ignored")
	}
	after, err := readReceipt(o)
	if err != nil || after.Transaction != before.Transaction {
		t.Fatal("old install not restored")
	}
	o.rename = nil
	id := strings.Repeat("a", 32)
	pending := transaction{Schema: 1, Target: o.Target, Profile: o.Profile, Stage: o.Target + ".stage-" + id, Backup: o.Target + ".backup-" + id, ID: id, HadInstall: true}
	if err = os.Rename(o.Target, pending.Backup); err != nil {
		t.Fatal(err)
	}
	if err = writeJSON(o.Target+".install.json", pending); err != nil {
		t.Fatal(err)
	}
	o.Archive = "does-not-exist"
	if err = run("linux", o); err == nil {
		t.Fatal("missing archive accepted")
	}
	after, err = readReceipt(o)
	if err != nil || after.Transaction != before.Transaction {
		t.Fatal("pending swap not recovered")
	}
}
func TestNativeLaunchers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native symlinks and desktop integration are tested on Unix CI")
	}
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))
	o := options(t, runtime.GOOS)
	o.NoLinks = false
	if err := run(runtime.GOOS, o); err != nil {
		t.Fatal(err)
	}
	o = canonical(t, o)
	r, err := readReceipt(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range r.Links {
		if !matchesLink(v) {
			t.Fatal("launcher not created")
		}
	}
	o.Uninstall = true
	if err = run(runtime.GOOS, o); err != nil {
		t.Fatal(err)
	}
	for _, v := range r.Links {
		if _, e := os.Lstat(v.Path); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("launcher remains")
		}
	}
}
func TestUnmanagedAndUnsafeTargets(t *testing.T) {
	o := options(t, "linux")
	os.MkdirAll(o.Target, 0700)
	os.WriteFile(filepath.Join(o.Target, "mine"), []byte("keep"), 0600)
	if err := run("linux", o); err == nil {
		t.Fatal("unmanaged directory accepted")
	}
	o.Target = o.Profile
	if err := run("linux", o); err == nil {
		t.Fatal("profile used as installation")
	}
}

func TestRuntimeLeaseBlocksReplacementAndConcurrentStartup(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			o := options(t, platform)
			if err := run(platform, o); err != nil {
				t.Fatal(err)
			}
			o = canonical(t, o)
			exe := filepath.Join(o.Target, filepath.FromSlash(executable(platform, "zaslon")))
			lease, err := acquireRuntime(platform, exe)
			if err != nil || lease == nil {
				t.Fatalf("runtime lease: %v", err)
			}
			if err = run(platform, o); err == nil {
				t.Fatal("running executable replaced")
			}
			lease.Close()
			lock := flock.New(o.Target + ".install.lock")
			if ok, e := lock.TryLock(); e != nil || !ok {
				t.Fatal("cannot lock installation")
			}
			if unexpected, e := acquireRuntime(platform, exe); e == nil {
				if unexpected != nil {
					unexpected.Close()
				}
				t.Fatal("worker started during installation")
			}
			lock.Close()
			o.Uninstall = true
			if err = run(platform, o); err != nil {
				t.Fatal(err)
			}
			if unexpected, e := acquireRuntime(platform, exe); e == nil {
				if unexpected != nil {
					unexpected.Close()
				}
				t.Fatal("removed executable started")
			}
		})
	}
}
