package setup

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/gofrs/flock"
)

type Options struct {
	Archive, Target, Profile, Version string
	Uninstall, NoLinks                bool
	rename                            func(string, string) error // filesystem fault injection in regression tests
}
type link struct {
	Path, Target, Body string
	Created            bool
}
type receipt struct {
	Schema                                         int
	Product, Target, Profile, Version, Transaction string
	Files                                          []string
	Links                                          []link
}
type transaction struct {
	Schema                             int
	Target, Profile, Stage, Backup, ID string
	HadInstall, Committed              bool
	Links                              []link
}

var versionPattern = regexp.MustCompile("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")
var siblingPattern = regexp.MustCompile("^[a-f0-9]{32}$")

func DefaultTarget(platform, home, dataHome string) string {
	if platform == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "Zaslon", "program")
	}
	if dataHome == "" {
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataHome, "zaslon", "program")
}
func Run(o Options) error { return run(runtime.GOOS, o) }
func run(platform string, o Options) error {
	if platform != "linux" && platform != "darwin" {
		return errors.New("this installer mode supports Linux and macOS only")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if o.Target == "" {
		o.Target = DefaultTarget(platform, home, os.Getenv("XDG_DATA_HOME"))
	}
	if !filepath.IsAbs(o.Target) || !filepath.IsAbs(o.Profile) {
		return errors.New("installation and profile paths must be absolute")
	}
	o.Target, o.Profile = filepath.Clean(o.Target), filepath.Clean(o.Profile)
	if inside(o.Target, home) || inside(o.Target, o.Profile) || filepath.Dir(o.Target) == o.Target {
		return errors.New("unsafe installation directory")
	}
	if err = rejectLink(o.Target); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(o.Target), 0700); err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(o.Target))
	if err != nil {
		return err
	}
	o.Target = filepath.Join(parent, filepath.Base(o.Target))
	if err = os.MkdirAll(o.Profile, 0700); err != nil {
		return err
	}
	o.Profile, err = filepath.EvalSymlinks(o.Profile)
	if err != nil {
		return err
	}
	if inside(o.Target, o.Profile) {
		return errors.New("installation contains the profile")
	}
	if o.rename == nil {
		o.rename = os.Rename
	}
	for _, name := range []string{o.Target + ".install.lock", o.Target + ".install.json", filepath.Join(o.Profile, "zaslon.lock")} {
		if err = rejectLink(name); err != nil {
			return err
		}
	}
	installLock := flock.New(o.Target + ".install.lock")
	ok, err := installLock.TryLock()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("Zaslon or another installer is using this installation; close protected apps and quit Zaslon before updating")
	}
	defer installLock.Close()
	profileLock := flock.New(filepath.Join(o.Profile, "zaslon.lock"))
	ok, err = profileLock.TryLock()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("Zaslon is running: close protected apps and quit Zaslon before updating; no process was stopped")
	}
	defer profileLock.Close()
	if err = recoverPending(o); err != nil {
		return err
	}
	old, err := readReceipt(o)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if o.Uninstall {
		if old == nil {
			return errors.New("no managed installation")
		}
		return uninstall(platform, o, *old, home)
	}
	if !versionPattern.MatchString(o.Version) {
		return errors.New("version must be x.y.z")
	}
	p, err := readPayload(o.Archive, platform, o.Version)
	if err != nil {
		return err
	}
	if old != nil && older(o.Version, old.Version) {
		return errors.New("refusing an accidental downgrade")
	}
	planned := []link{}
	if !o.NoLinks {
		planned, err = planLinks(platform, o.Target, home)
		if err != nil {
			return err
		}
	}
	if old != nil {
		for _, v := range old.Links {
			found := false
			for _, n := range planned {
				if n.Path == v.Path {
					found = true
				}
			}
			if !found {
				v.Created = false
				planned = append(planned, v)
			}
		}
	}
	idBytes := make([]byte, 16)
	if _, err = rand.Read(idBytes); err != nil {
		return err
	}
	id := hex.EncodeToString(idBytes)
	t := transaction{Schema: 1, Target: o.Target, Profile: o.Profile, Stage: o.Target + ".stage-" + id, Backup: o.Target + ".backup-" + id, ID: id, HadInstall: old != nil, Links: planned}
	if err = os.Mkdir(t.Stage, 0700); err != nil {
		return err
	}
	for _, name := range payloadNames(p) {
		file := filepath.Join(t.Stage, filepath.FromSlash(name))
		if err = os.MkdirAll(filepath.Dir(file), 0755); err != nil {
			return err
		}
		mode := os.FileMode(0644)
		if p[name].mode&0111 != 0 {
			mode = 0755
		}
		if err = os.WriteFile(file, p[name].data, mode); err != nil {
			return err
		}
	}
	r := receipt{Schema: 1, Product: "Zaslon", Target: o.Target, Profile: o.Profile, Version: o.Version, Transaction: id, Files: payloadNames(p), Links: planned}
	if err = writeJSON(filepath.Join(t.Stage, "install-receipt.json"), r); err != nil {
		return err
	}
	if err = writeJSON(o.Target+".install.json", t); err != nil {
		return err
	}
	applyErr := func() error {
		if old != nil {
			if e := o.rename(o.Target, t.Backup); e != nil {
				return e
			}
		}
		if e := o.rename(t.Stage, o.Target); e != nil {
			return e
		}
		if old != nil {
			b, e := os.ReadFile(filepath.Join(o.Profile, "config.yaml"))
			if e == nil {
				if e = os.WriteFile(filepath.Join(t.Backup, "profile-config-backup.yaml"), b, 0600); e != nil {
					return e
				}
			} else if !errors.Is(e, os.ErrNotExist) {
				return e
			}
		}
		for _, v := range planned {
			if e := createLink(v); e != nil {
				return e
			}
		}
		t.Committed = true
		return writeJSON(o.Target+".install.json", t)
	}()
	if applyErr != nil {
		if e := recoverPending(o); e != nil {
			return fmt.Errorf("install failed: %v; rollback needs inspection: %w", applyErr, e)
		}
		return applyErr
	}
	return os.Remove(o.Target + ".install.json")
}
func inside(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func rejectLink(path string) error {
	i, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if i.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlink refused: %s", path)
	}
	return nil
}
func older(a, b string) bool {
	aa, bb := strings.Split(a, "."), strings.Split(b, ".")
	if len(aa) != 3 || len(bb) != 3 {
		return true
	}
	for i := range aa {
		x, e := strconv.ParseUint(aa[i], 10, 32)
		if e != nil {
			return true
		}
		y, e := strconv.ParseUint(bb[i], 10, 32)
		if e != nil {
			return true
		}
		if x != y {
			return x < y
		}
	}
	return false
}
func readReceipt(o Options) (*receipt, error) {
	_, e := os.Lstat(o.Target)
	if e != nil {
		return nil, e
	}
	path := filepath.Join(o.Target, "install-receipt.json")
	if e = rejectLink(path); e != nil {
		return nil, e
	}
	b, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil, errors.New("directory is not managed by the Zaslon installer")
	}
	if e != nil {
		return nil, e
	}
	var r receipt
	if e = json.Unmarshal(b, &r); e != nil {
		return nil, e
	}
	if r.Schema != 1 || r.Product != "Zaslon" || r.Target != o.Target || r.Profile != o.Profile || !versionPattern.MatchString(r.Version) {
		return nil, errors.New("installation receipt does not match the target/profile")
	}
	for _, name := range r.Files {
		if !safeName(name) {
			return nil, errors.New("unsafe receipt file")
		}
	}
	for _, v := range r.Links {
		if !filepath.IsAbs(v.Path) || ((v.Target == "") == (v.Body == "")) {
			return nil, errors.New("invalid receipt link")
		}
	}
	return &r, nil
}
func writeJSON(path string, v any) error {
	if err := rejectLink(path); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := rejectLink(tmp); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func recoverPending(o Options) error {
	path := o.Target + ".install.json"
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var t transaction
	if err = json.Unmarshal(b, &t); err != nil {
		return err
	}
	validSibling := func(p, kind string) bool {
		prefix := filepath.Base(o.Target) + "." + kind + "-"
		return filepath.Dir(p) == filepath.Dir(o.Target) && strings.HasPrefix(filepath.Base(p), prefix) && siblingPattern.MatchString(strings.TrimPrefix(filepath.Base(p), prefix))
	}
	if t.Schema != 1 || t.Target != o.Target || t.Profile != o.Profile || !siblingPattern.MatchString(t.ID) || !validSibling(t.Stage, "stage") || !validSibling(t.Backup, "backup") {
		return errors.New("invalid pending transaction; preserved")
	}
	if t.Committed {
		return os.Remove(path)
	}
	if err = rejectLink(t.Backup); err != nil {
		return err
	}
	r, e := readReceipt(o)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if r != nil && r.Transaction == t.ID {
		if err = os.Rename(o.Target, o.Target+".failed-"+t.ID); err != nil {
			return err
		}
	}
	if _, e = os.Lstat(t.Backup); e == nil {
		rb, e := os.ReadFile(filepath.Join(t.Backup, "install-receipt.json"))
		if e != nil {
			return e
		}
		var previous receipt
		if e = json.Unmarshal(rb, &previous); e != nil {
			return e
		}
		if previous.Target != o.Target || previous.Profile != o.Profile || previous.Product != "Zaslon" {
			return errors.New("backup receipt mismatch")
		}
		if err = os.Rename(t.Backup, o.Target); err != nil {
			return err
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if t.HadInstall {
		if _, e = os.Stat(o.Target); e != nil {
			return errors.New("previous installation missing; transaction preserved")
		}
	}
	for _, v := range t.Links {
		if v.Created {
			if err = removeLink(v); err != nil {
				return err
			}
		}
	}
	return os.Remove(path)
}
func planLinks(platform, target, home string) ([]link, error) {
	var links []link
	if platform == "darwin" {
		links = []link{{Path: filepath.Join(home, "Applications", "Zaslon.app"), Target: filepath.Join(target, "Zaslon.app")}}
	} else {
		data := os.Getenv("XDG_DATA_HOME")
		if data == "" {
			data = filepath.Join(home, ".local", "share")
		}
		if !filepath.IsAbs(data) {
			return nil, errors.New("XDG_DATA_HOME must be absolute")
		}
		for _, name := range []string{"zaslon", "zaslon-recover"} {
			links = append(links, link{Path: filepath.Join(home, ".local", "bin", name), Target: filepath.Join(target, name)})
		}
		grave := string(rune(96))
		exe := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "$", "\\$", grave, "\\"+grave, "%", "%%").Replace(filepath.Join(target, "zaslon"))
		links = append(links, link{Path: filepath.Join(data, "applications", "zaslon.desktop"), Body: "[Desktop Entry]\nType=Application\nName=Zaslon\nExec=\"" + exe + "\"\nTerminal=false\nCategories=Utility;\n"})
	}
	for i := range links {
		if _, e := os.Lstat(links[i].Path); errors.Is(e, os.ErrNotExist) {
			links[i].Created = true
		} else if e != nil {
			return nil, e
		} else if !matchesLink(links[i]) {
			return nil, fmt.Errorf("existing launcher belongs to another installation: %s", links[i].Path)
		}
	}
	return links, nil
}
func matchesLink(v link) bool {
	if v.Target != "" {
		actual, e := os.Readlink(v.Path)
		return e == nil && actual == v.Target
	}
	i, e := os.Lstat(v.Path)
	if e != nil || !i.Mode().IsRegular() {
		return false
	}
	b, e := os.ReadFile(v.Path)
	return e == nil && string(b) == v.Body
}
func createLink(v link) error {
	if _, err := os.Lstat(v.Path); err == nil {
		if matchesLink(v) {
			return nil
		}
		return errors.New("launcher changed during install")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(v.Path), 0755); err != nil {
		return err
	}
	if v.Target != "" {
		return os.Symlink(v.Target, v.Path)
	}
	f, err := os.OpenFile(v.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	_, err = f.WriteString(v.Body)
	if e := f.Close(); err == nil {
		err = e
	}
	return err
}
func removeLink(v link) error {
	if _, e := os.Lstat(v.Path); errors.Is(e, os.ErrNotExist) {
		return nil
	} else if e != nil {
		return e
	}
	if !matchesLink(v) {
		return fmt.Errorf("launcher modified; preserved: %s", v.Path)
	}
	return os.Remove(v.Path)
}
func uninstall(platform string, o Options, r receipt, home string) error {
	b, err := os.ReadFile(filepath.Join(o.Profile, "process-recovery.json"))
	if err == nil {
		var j struct {
			Version int
			Entries map[string]json.RawMessage
		}
		if json.Unmarshal(b, &j) != nil || j.Version != 1 || j.Entries == nil || len(j.Entries) != 0 {
			return errors.New("recovery records remain; restart Zaslon or use separate emergency recovery before uninstalling")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, v := range r.Links {
		if err = removeLink(v); err != nil {
			return err
		}
	}
	exe := filepath.Join(o.Target, filepath.FromSlash(executable(platform, "zaslon")))
	var auto string
	if platform == "darwin" {
		auto = filepath.Join(home, "Library", "LaunchAgents", "io.github.avazar.zaslon.plist")
	} else {
		auto = filepath.Join(filepath.Dir(o.Profile), "autostart", "zaslon.desktop")
	}
	if err = rejectLink(auto); err != nil {
		return err
	}
	if b, e := os.ReadFile(auto); e == nil {
		expected := "Exec=" + strconv.Quote(exe)
		owned := false
		if platform == "darwin" {
			escaped := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(exe)
			owned = strings.Contains(string(b), "<array><string>"+escaped+"</string></array>") && strings.Contains(string(b), "<string>io.github.avazar.zaslon</string>")
		} else {
			for _, line := range strings.Split(string(b), "\n") {
				if line == expected {
					owned = true
				}
			}
		}
		if owned {
			if err = os.Remove(auto); err != nil {
				return err
			}
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	dirs := map[string]bool{o.Target: true}
	for _, name := range append(r.Files, "install-receipt.json") {
		if !safeName(name) {
			return errors.New("unsafe installed filename")
		}
		file := filepath.Join(o.Target, filepath.FromSlash(name))
		for part := file; part != o.Target; part = filepath.Dir(part) {
			if err = rejectLink(part); err != nil {
				return err
			}
		}
		if err = os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for d := filepath.Dir(file); inside(o.Target, d); d = filepath.Dir(d) {
			dirs[d] = true
			if d == o.Target {
				break
			}
		}
	}
	sorted := []string{}
	for d := range dirs {
		sorted = append(sorted, d)
	}
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, d := range sorted {
		entries, e := os.ReadDir(d)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if len(entries) == 0 {
			if e = os.Remove(d); e != nil {
				return e
			}
		}
	}
	return nil
}
