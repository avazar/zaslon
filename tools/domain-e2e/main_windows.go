// Windows acceptance test. Only unique copies of this fixture are targets.
// A kill-on-close Job Object contains every descendant before fixtures start.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/procs"
	"github.com/avazar/zaslon/internal/recovery"
	"golang.org/x/sys/windows"
)

var root = flag.String("root", "", "new artifact directory inside build/")
var role = flag.String("role", "outer", "outer/run/parent/child/control")
var installerPackage = flag.String("installer-package", "", "optional complete Windows ZIP for live installer handoff")

type report struct {
	Passed          bool                  `json:"passed"`
	Started         time.Time             `json:"started"`
	Finished        time.Time             `json:"finished"`
	Error           string                `json:"error,omitempty"`
	Checks          []string              `json:"checks"`
	Processes       map[string]procs.Proc `json:"processes"`
	SHA256          map[string]string     `json:"binary_sha256"`
	CleanupVerified bool                  `json:"cleanup_verified"`
}

func main() {
	flag.Parse()
	repo, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if *root == "" {
		id := make([]byte, 6)
		if _, err = rand.Read(id); err != nil {
			panic(err)
		}
		*root = filepath.Join(repo, "build", "audit", "domain-e2e-"+time.Now().Format("20060102-150405")+"-"+hex.EncodeToString(id))
	}
	*root, err = filepath.Abs(*root)
	if err != nil {
		panic(err)
	}
	rel, err := filepath.Rel(filepath.Join(repo, "build"), *root)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		panic("-root must be a fresh child of the repository build directory")
	}
	switch *role {
	case "outer":
		err = outer()
		if err == nil {
			fmt.Printf("Domain E2E passed. Artifacts: %s\n", *root)
		}
	case "run":
		err = waitFor("Job Object gate", 10*time.Second, func() bool { _, e := os.Stat(filepath.Join(*root, "start.gate")); return e == nil })
		if err == nil {
			err = run(repo)
		}
	case "parent":
		err = parent()
	case "child", "grandchild", "control":
		err = heartbeat(filepath.Join(*root, *role+".heartbeat"))
	default:
		err = errors.New("unknown fixture role")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func hidden(c *exec.Cmd) *exec.Cmd {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return c
}

func outer() error {
	if _, err := os.Stat(*root); !errors.Is(err, os.ErrNotExist) {
		return errors.New("artifact directory must not already exist")
	}
	if err := os.MkdirAll(*root, 0700); err != nil {
		return err
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := hidden(exec.Command(exe, "-role", "run", "-root", *root))
	if *installerPackage != "" {
		archive, e := filepath.Abs(*installerPackage)
		if e != nil {
			return e
		}
		cmd.Args = append(cmd.Args, "-installer-package", archive)
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err = cmd.Start(); err != nil {
		return err
	}
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, handle)
		windows.CloseHandle(handle)
	}
	if err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return err
	}
	if err = os.WriteFile(filepath.Join(*root, "start.gate"), []byte("contained"), 0600); err != nil {
		windows.TerminateJobObject(job, 1)
		cmd.Wait()
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := 90 * time.Second
	if *installerPackage != "" {
		deadline = 150 * time.Second
	}
	select {
	case err = <-done:
		return err
	case <-time.After(deadline):
		windows.TerminateJobObject(job, 1)
		<-done
		return fmt.Errorf("%s fixture deadline; only this test job was terminated", deadline)
	}
}

func parent() error {
	data, err := os.ReadFile(filepath.Join(*root, "child-path.json"))
	if err != nil {
		return err
	}
	var childPath string
	if err = json.Unmarshal(data, &childPath); err != nil {
		return err
	}
	child := hidden(exec.Command(childPath, "-role", "child", "-root", *root))
	if err = child.Start(); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(*root, "child.json"), map[string]int{"pid": child.Process.Pid}); err != nil {
		return err
	}
	return heartbeat(filepath.Join(*root, "parent.heartbeat"))
}

func heartbeat(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	spawned := false
	for {
		if *role == "child" && !spawned {
			if _, e := os.Stat(filepath.Join(*root, "spawn.request")); e == nil {
				exe, e := os.Executable()
				if e != nil {
					return e
				}
				grandchild := hidden(exec.Command(exe, "-role", "grandchild", "-root", *root))
				if e = grandchild.Start(); e != nil {
					return e
				}
				if e = writeJSON(filepath.Join(*root, "grandchild.json"), map[string]int{"pid": grandchild.Process.Pid}); e != nil {
					return e
				}
				spawned = true
			}
		}
		if _, err = fmt.Fprintln(f, time.Now().UnixNano()); err != nil {
			return err
		}
		time.Sleep(30 * time.Millisecond)
	}
}
func waitFor(label string, timeout time.Duration, f func() bool) error {
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		if f() {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("timeout: %s", label)
}
func size(path string) int64 {
	s, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return s.Size()
}
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}
func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0700)
}

// The observer must not prevent the guard's atomic journal replacement. Go's
// ordinary Windows file opens omit FILE_SHARE_DELETE and can cause a write
// failure after an OS resume, introducing an unrelated ambiguous-operation test.
func readSharedFile(path string) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	return io.ReadAll(f)
}

func run(repo string) (err error) {
	result := &report{Started: time.Now(), Processes: map[string]procs.Proc{}, SHA256: map[string]string{}}
	defer func() {
		result.Finished = time.Now()
		result.Passed = err == nil
		if err != nil {
			result.Error = err.Error()
		}
		if e := writeJSON(filepath.Join(*root, "result.json"), result); e != nil && err == nil {
			err = e
		}
	}()
	return scenario(repo, result)
}

func scenario(repo string, result *report) (err error) {
	backend := procs.New()
	bin := filepath.Join(*root, "bin")
	profile := filepath.Join(*root, "profile")
	if err = os.MkdirAll(bin, 0700); err != nil {
		return err
	}
	var commands []*exec.Cmd
	defer func() {
		// Only binaries copied into this fresh, unique directory can be terminated.
		list, e := backend.List()
		if e == nil {
			for _, p := range list {
				if strings.HasPrefix(strings.ToLower(p.Path), strings.ToLower(bin+string(os.PathSeparator))) {
					if k := backend.Kill(p); k != nil && err == nil {
						err = k
					}
				}
			}
		}
		for _, c := range commands {
			done := make(chan struct{})
			go func(c *exec.Cmd) { c.Wait(); close(done) }(c)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
		}
		list, e = backend.List()
		if e != nil && err == nil {
			err = e
		}
		clean := e == nil
		for _, p := range list {
			if strings.HasPrefix(strings.ToLower(p.Path), strings.ToLower(bin+string(os.PathSeparator))) {
				clean = false
			}
		}
		result.CleanupVerified = clean
		if !clean && err == nil {
			err = errors.New("fixture cleanup not confirmed")
		}
	}()
	paths := map[string]string{}
	installDir := filepath.Join(bin, "installed")
	install := func(noStart bool) error {
		version, e := os.ReadFile(filepath.Join(repo, "VERSION"))
		if e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		args := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", filepath.Join(repo, "scripts", "install.ps1"),
			"-Version", strings.TrimSpace(string(version)), "-PackagePath", *installerPackage, "-ChecksumPath", *installerPackage + ".sha256",
			"-InstallDirectory", installDir, "-ProfileDirectory", profile, "-NoShortcut", "-Headless"}
		if noStart {
			args = append(args, "-NoStart")
		}
		cmd := hidden(exec.CommandContext(ctx, "powershell.exe", args...))
		out, e := cmd.CombinedOutput()
		if writeErr := os.WriteFile(filepath.Join(*root, fmt.Sprintf("installer-%t.log", noStart)), out, 0600); writeErr != nil {
			return writeErr
		}
		if e != nil {
			return fmt.Errorf("installer: %w: %s", e, out)
		}
		return nil
	}
	if *installerPackage != "" {
		if err = install(true); err != nil {
			return err
		}
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	for _, name := range []string{"parent-a", "parent-b", "child", "control"} {
		paths[name] = filepath.Join(bin, name+".exe")
		if err = copyFile(self, paths[name]); err != nil {
			return err
		}
	}
	for _, name := range []string{"zaslon", "zaslon-recover"} {
		paths[name] = filepath.Join(bin, name+".exe")
		if *installerPackage != "" {
			paths[name] = filepath.Join(installDir, name+".exe")
		} else {
			if err = copyFile(filepath.Join(repo, "build", "dev", name+".exe"), paths[name]); err != nil {
				return err
			}
		}
		data, _ := os.ReadFile(paths[name])
		sum := sha256.Sum256(data)
		result.SHA256[name] = hex.EncodeToString(sum[:])
	}
	family := map[string]string{}
	for _, id := range []string{"a", "b"} {
		family[id] = filepath.Join(*root, id)
		if err = os.MkdirAll(family[id], 0700); err != nil {
			return err
		}
		if err = writeJSON(filepath.Join(family[id], "child-path.json"), paths["child"]); err != nil {
			return err
		}
	}
	start := func(name string, args ...string) (*exec.Cmd, error) {
		c := hidden(exec.Command(paths[name], args...))
		c.Env = append(os.Environ(), "ZASLON_DIR="+profile)
		log, e := os.Create(filepath.Join(*root, name+".log"))
		if e != nil {
			return nil, e
		}
		c.Stdout, c.Stderr = log, log
		e = c.Start()
		log.Close()
		if e == nil {
			commands = append(commands, c)
		}
		return c, e
	}
	a, e := start("parent-a", "-role", "parent", "-root", family["a"])
	if e != nil {
		return e
	}
	b, e := start("parent-b", "-role", "parent", "-root", family["b"])
	if e != nil {
		return e
	}
	control, e := start("control", "-role", "control", "-root", *root)
	if e != nil {
		return e
	}
	childPID := map[string]int{}
	if err = waitFor("both fixture children", 8*time.Second, func() bool {
		for _, id := range []string{"a", "b"} {
			data, e := os.ReadFile(filepath.Join(family[id], "child.json"))
			if e != nil {
				return false
			}
			var p struct {
				PID int `json:"pid"`
			}
			if json.Unmarshal(data, &p) != nil || p.PID == 0 {
				return false
			}
			childPID[id] = p.PID
		}
		return true
	}); err != nil {
		return err
	}
	list, e := backend.List()
	if e != nil {
		return e
	}
	for name, pid := range map[string]int{"a": a.Process.Pid, "ac": childPID["a"], "b": b.Process.Pid, "bc": childPID["b"], "control": control.Process.Pid} {
		for _, p := range list {
			if p.PID == pid {
				result.Processes[name] = p
			}
		}
	}
	if len(result.Processes) != 5 || result.Processes["ac"].PPID != a.Process.Pid || result.Processes["bc"].PPID != b.Process.Pid {
		return errors.New("fixture ancestry not confirmed")
	}
	var modeA, modeB atomic.Int32
	var immediateRetryCalls atomic.Int32
	retryGate := make(chan struct{})
	releaseRetry := sync.OnceFunc(func() { close(retryGate) })
	recoveryGate := make(chan struct{})
	releaseRecovery := sync.OnceFunc(func() { close(recoveryGate) })
	var recoveryRequests atomic.Int32
	modeA.Store(1)
	traceServer := func(mode *atomic.Int32, ip string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if mode.Load() == 5 {
				recoveryRequests.Add(1)
				select {
				case <-recoveryGate:
				case <-r.Context().Done():
					return
				}
			}
			if mode.CompareAndSwap(3, 4) {
				<-r.Context().Done() // first request reaches the real HTTP deadline
				return
			}
			if mode.Load() == 4 {
				immediateRetryCalls.Add(1)
				select {
				case <-retryGate:
				case <-r.Context().Done():
					return
				}
			}
			if mode.Load() == 2 {
				w.WriteHeader(403)
				return
			}
			observed := ip
			if mode.Load() == 0 {
				observed = "192.0.2.99"
			}
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "h=%s\nip=%s\nloc=NL\n", r.Host, observed)
		}))
	}
	sa, sb := traceServer(&modeA, "203.0.113.10"), traceServer(&modeB, "198.51.100.20")
	defer sa.Close()
	defer sb.Close()
	defer releaseRetry()
	defer releaseRecovery()
	cfg := config.Default()
	cfg.Apps = nil
	cfg.CustomApps = []config.CustomApp{{Name: "fixture-a", Match: []string{paths["parent-a"]}}, {Name: "fixture-b", Match: []string{paths["parent-b"]}}}
	cfg.DomainChecks = map[string][]string{"fixture-a": {sa.URL + "/cdn-cgi/trace"}, "fixture-b": {sb.URL + "/cdn-cgi/trace"}}
	cfg.DomainChecksEnabled = map[string]bool{"fixture-a": true, "fixture-b": true}
	cfg.Allow = config.Allow{IPs: []string{"203.0.113.10", "198.51.100.20"}}
	cfg.IPServices = []string{"unsupported:general-check"}
	cfg.CheckIPv6 = false
	cfg.DNSCheck = "off"
	cfg.Notifications = false
	cfg.Language = "en"
	parsed, e := config.Parse([]byte(config.Render(cfg)))
	if e != nil {
		return e
	}
	targets := procs.Filter(list, procs.Targets(parsed), os.Getpid())
	if len(targets) != 4 {
		return fmt.Errorf("unsafe target count: %d", len(targets))
	}
	for _, p := range targets {
		known := false
		for _, name := range []string{"a", "ac", "b", "bc"} {
			if procs.SameProcess(p, result.Processes[name]) {
				known = true
			}
		}
		if !known {
			return errors.New("non-fixture process matched")
		}
	}
	if err = config.Save(filepath.Join(profile, "config.yaml"), cfg); err != nil {
		return err
	}
	result.Checks = append(result.Checks, "preflight matches only two uniquely named fixtures and their descendants")
	guard, e := start("zaslon", "headless")
	if e != nil {
		return e
	}
	journal := filepath.Join(profile, "process-recovery.json")
	held := func(names ...string) bool {
		data, e := readSharedFile(journal)
		if e != nil {
			return false
		}
		var j struct {
			Version int                    `json:"version"`
			Entries map[int]recovery.Entry `json:"entries"`
		}
		if json.Unmarshal(data, &j) != nil {
			return false
		}
		if j.Version != 1 || j.Entries == nil {
			return false
		}
		if len(j.Entries) != len(names) {
			return false
		}
		for _, entry := range j.Entries {
			found := false
			for _, name := range names {
				if procs.SameProcess(entry.Process, result.Processes[name]) && entry.Phase == "frozen" {
					found = true
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	hearts := map[string]string{"a": filepath.Join(family["a"], "parent.heartbeat"), "ac": filepath.Join(family["a"], "child.heartbeat"), "b": filepath.Join(family["b"], "parent.heartbeat"), "bc": filepath.Join(family["b"], "child.heartbeat"), "control": filepath.Join(*root, "control.heartbeat")}
	checkBeats := func(running, frozen []string) error {
		before := map[string]int64{}
		for _, name := range append(append([]string{}, running...), frozen...) {
			before[name] = size(hearts[name])
		}
		time.Sleep(250 * time.Millisecond)
		for _, name := range running {
			if size(hearts[name]) <= before[name] {
				return fmt.Errorf("%s did not run", name)
			}
		}
		for _, name := range frozen {
			if before[name] == 0 || size(hearts[name]) != before[name] {
				return fmt.Errorf("%s did not stay frozen", name)
			}
		}
		return nil
	}
	if err = waitFor("only B frozen", 10*time.Second, func() bool { return held("b", "bc") }); err != nil {
		return err
	}
	if err = checkBeats([]string{"a", "ac", "control"}, []string{"b", "bc"}); err != nil {
		return err
	}
	result.Checks = append(result.Checks, "A and its child run while B and its child freeze; general IP check is unavailable")
	logPath := filepath.Join(profile, "zaslon.log")
	beforeSwitch, err := readSharedFile(logPath)
	if err != nil {
		return err
	}
	modeA.Store(0)
	modeB.Store(1)
	if err = waitFor("periodic 15-second check freezes only A", 22*time.Second, func() bool { return held("a", "ac") }); err != nil {
		return err
	}
	if err = checkBeats([]string{"b", "bc", "control"}, []string{"a", "ac"}); err != nil {
		return err
	}
	result.Checks = append(result.Checks, "the periodic 15-second check reverses decisions without a settings or network change")
	if err = waitFor("persistent suspension and release for the two process trees", 3*time.Second, func() bool {
		data, readErr := readSharedFile(logPath)
		if readErr != nil || len(data) < len(beforeSwitch) {
			return false
		}
		freezeA, resumeB := false, false
		for _, line := range strings.Split(string(data[len(beforeSwitch):]), "\n") {
			if strings.Contains(line, "Frozen (") && strings.Contains(line, "): fixture-a | ") && strings.Contains(line, "processes=2") {
				freezeA = true
			}
			if strings.Contains(line, "Resumed: fixture-b | processes=2") {
				resumeB = true
			}
		}
		return freezeA && resumeB
	}); err != nil {
		return err
	}
	result.Checks = append(result.Checks, "the ready EXE logs successful suspension and release of both real fixture processes in each tree")
	modeA.Store(1)
	modeB.Store(2)
	if err = waitFor("B held on HTTP 403", cfg.DomainCheckInterval.D()+7*time.Second, func() bool { return held("b", "bc") }); err != nil {
		return err
	}
	if err = checkBeats([]string{"a", "ac", "control"}, []string{"b", "bc"}); err != nil {
		return err
	}
	result.Checks = append(result.Checks, "HTTP 403 keeps only the affected app and descendant frozen")
	if err = waitFor("persistent domain failure diagnostics", 3*time.Second, func() bool {
		data, e := readSharedFile(filepath.Join(profile, "zaslon.log"))
		if e != nil {
			return false
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "Service check: fixture-b") && strings.Contains(line, sb.URL+"/cdn-cgi/trace IPv4: HTTP 403") {
				return true
			}
		}
		return false
	}); err != nil {
		return err
	}
	result.Checks = append(result.Checks, "the ready EXE persists the affected app, exact endpoint, IPv4 and HTTP 403 in its log")
	// Let A's next regular domain request time out. Its immediate retry is gated
	// until the observer confirms the actual processes are still suspended.
	modeA.Store(3)
	modeB.Store(1)
	if err = waitFor("A and child held after real HTTP timeout", 22*time.Second, func() bool { return held("a", "ac") }); err != nil {
		return err
	}
	if err = waitFor("immediate domain retry before the next 15-second slot", 3*time.Second, func() bool { return immediateRetryCalls.Load() > 0 }); err != nil {
		return err
	}
	if err = checkBeats([]string{"b", "bc", "control"}, []string{"a", "ac"}); err != nil {
		return err
	}
	if immediateRetryCalls.Load() != 1 {
		return errors.New("more than one immediate retry was started")
	}
	result.Checks = append(result.Checks, "a real HTTP timeout suspends only A and its child before one immediate retry; neither runs while its response is gated")
	releaseRetry()
	if err = waitFor("only successful current retry resumes A", 3*time.Second, func() bool { return held() }); err != nil {
		return err
	}
	if err = checkBeats([]string{"a", "ac", "b", "bc", "control"}, nil); err != nil {
		return err
	}
	modeA.Store(1)
	result.Checks = append(result.Checks, "successful immediate domain retry resumes the same app and child before the normal 15-second cadence")
	// Exercise the explicit failure policy on ready EXEs without any real app.
	modeB.Store(2)
	// The default cadence was tested above. Use a shorter supported interval
	// for the remaining policy and recovery checks.
	cfg.DomainCheckInterval = config.Duration(3 * time.Second)
	cfg.IPUnavailableAction = config.IgnoreFailure
	if err = config.Save(filepath.Join(profile, "config.yaml"), cfg); err != nil {
		return err
	}
	if err = waitFor("ignored service failure resumes B with a warning", 8*time.Second, func() bool {
		data, e := readSharedFile(filepath.Join(profile, "state.json"))
		var state struct {
			Status string `json:"status"`
		}
		return e == nil && json.Unmarshal(data, &state) == nil && state.Status == "warning" && held()
	}); err != nil {
		return err
	}
	if err = checkBeats([]string{"a", "ac", "b", "bc", "control"}, nil); err != nil {
		return err
	}
	result.Checks = append(result.Checks, "explicit ignore policy resumes an unavailable service and reports warning status")
	modeA.Store(0)
	if err = waitFor("known bad exit remains denied with ignore enabled", 8*time.Second, func() bool { return held("a", "ac") }); err != nil {
		return err
	}
	if err = checkBeats([]string{"b", "bc", "control"}, []string{"a", "ac"}); err != nil {
		return err
	}
	result.Checks = append(result.Checks, "ignore never permits a received disallowed service IP")
	// A later failed request must not erase the known denial, even after a
	// settings-triggered verification. Only this fixture endpoint is affected.
	modeA.Store(2)
	cfg.Allow.IPs = append(cfg.Allow.IPs, "192.0.2.123")
	if err = config.Save(filepath.Join(profile, "config.yaml"), cfg); err != nil {
		return err
	}
	if err = waitFor("A reports HTTP 403 after its known disallowed exit", 8*time.Second, func() bool {
		data, e := readSharedFile(filepath.Join(profile, "zaslon.log"))
		if e != nil {
			return false
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "Service check: fixture-a") && strings.Contains(line, sa.URL+"/cdn-cgi/trace IPv4: HTTP 403") {
				return true
			}
		}
		return false
	}); err != nil {
		return err
	}
	if !held("a", "ac") {
		return errors.New("ignored HTTP 403 erased A's known disallowed exit")
	}
	if err = checkBeats([]string{"b", "bc", "control"}, []string{"a", "ac"}); err != nil {
		return err
	}
	result.Checks = append(result.Checks, "a later ignored HTTP 403 cannot erase the prior disallowed exit or release the same app and child")
	modeA.Store(0)
	cfg.DomainChecksEnabled["fixture-a"] = false
	if err = config.Save(filepath.Join(profile, "config.yaml"), cfg); err != nil {
		return err
	}
	if err = waitFor("explicit domain switch falls back to general check", 8*time.Second, func() bool { return held() }); err != nil {
		return err
	}
	if err = checkBeats([]string{"a", "ac", "b", "bc", "control"}, nil); err != nil {
		return err
	}
	if len(cfg.DomainChecks["fixture-a"]) != 1 {
		return errors.New("domain switch lost the saved list")
	}
	beforeReenable, err := readSharedFile(logPath)
	if err != nil {
		return err
	}
	cfg.DomainChecksEnabled["fixture-a"] = true
	if err = config.Save(filepath.Join(profile, "config.yaml"), cfg); err != nil {
		return err
	}
	if err = waitFor("reenabled domain switch checks and holds the disallowed exit", 8*time.Second, func() bool {
		data, readErr := readSharedFile(logPath)
		if readErr != nil || len(data) < len(beforeReenable) {
			return false
		}
		for _, line := range strings.Split(string(data[len(beforeReenable):]), "\n") {
			if strings.Contains(line, "Service check: fixture-a") && strings.Contains(line, "exit 192.0.2.99") {
				return held("a", "ac")
			}
		}
		return false
	}); err != nil {
		return err
	}
	if err = checkBeats([]string{"b", "bc", "control"}, []string{"a", "ac"}); err != nil {
		return err
	}
	result.Checks = append(result.Checks, "domain checks switch off and on independently of the retained list")
	cfg.IPUnavailableAction = config.SuspendOnFailure
	modeA.Store(1)
	if err = config.Save(filepath.Join(profile, "config.yaml"), cfg); err != nil {
		return err
	}
	if err = waitFor("strict policy holds B again", 8*time.Second, func() bool { return held("b", "bc") }); err != nil {
		return err
	}
	if err = checkBeats([]string{"a", "ac", "control"}, []string{"b", "bc"}); err != nil {
		return err
	}
	result.Checks = append(result.Checks, "returning to suspend holds the unavailable service again")
	if err = backend.Kill(result.Processes["a"]); err != nil {
		return err
	}
	time.Sleep(650 * time.Millisecond)
	// The now-orphaned worker creates a new, previously unseen descendant.
	if err = os.WriteFile(filepath.Join(family["a"], "spawn.request"), []byte("spawn"), 0600); err != nil {
		return err
	}
	grandPID := 0
	if err = waitFor("new descendant of an orphan", 5*time.Second, func() bool {
		data, e := os.ReadFile(filepath.Join(family["a"], "grandchild.json"))
		if e != nil {
			return false
		}
		var info struct {
			PID int `json:"pid"`
		}
		if json.Unmarshal(data, &info) != nil || info.PID == 0 {
			return false
		}
		grandPID = info.PID
		return true
	}); err != nil {
		return err
	}
	list, e = backend.List()
	if e != nil {
		return e
	}
	for _, p := range list {
		if p.PID == grandPID {
			result.Processes["ag"] = p
		}
	}
	if result.Processes["ag"].Created == "" || result.Processes["ag"].PPID != result.Processes["ac"].PID {
		return errors.New("grandchild identity not confirmed")
	}
	hearts["ag"] = filepath.Join(family["a"], "grandchild.heartbeat")
	if err = waitFor("grandchild heartbeat", 3*time.Second, func() bool { return size(hearts["ag"]) > 0 }); err != nil {
		return err
	}
	modeA.Store(0)
	if err = waitFor("orphan and new descendant remain protected", 8*time.Second, func() bool { return held("ac", "ag", "b", "bc") }); err != nil {
		return err
	}
	if err = checkBeats([]string{"control"}, []string{"ac", "ag", "b", "bc"}); err != nil {
		return err
	}
	result.Checks = append(result.Checks, "an orphan and its newly spawned descendant inherit the exited ancestor's policy")
	findWorker := func(rootPID int) (procs.Proc, procs.Proc, error) {
		all, err := backend.List()
		if err != nil {
			return procs.Proc{}, procs.Proc{}, err
		}
		var supervisor, worker procs.Proc
		for _, p := range all {
			if strings.EqualFold(p.Path, paths["zaslon"]) {
				if p.PID == rootPID {
					supervisor = p
				}
				if p.PPID == rootPID {
					worker = p
				}
			}
		}
		if supervisor.Created == "" || worker.Created == "" {
			return supervisor, worker, errors.New("guard tree identity not found")
		}
		return supervisor, worker, nil
	}
	crashGuard := func(rootPID int) error {
		supervisor, worker, e := findWorker(rootPID)
		if e != nil {
			return e
		}
		result.Processes["supervisor"], result.Processes["worker"] = supervisor, worker
		if e = backend.Kill(supervisor); e != nil {
			return e
		}
		return backend.Kill(worker)
	}
	// Compare heartbeats across the entire restart, not only once it is ready.
	baseline := map[string]int64{}
	for _, name := range []string{"ac", "ag", "b", "bc"} {
		baseline[name] = size(hearts[name])
	}
	if err = crashGuard(guard.Process.Pid); err != nil {
		return err
	}
	if err = checkBeats([]string{"control"}, []string{"ac", "ag", "b", "bc"}); err != nil {
		return err
	}
	modeA.Store(2)
	modeB.Store(2)
	cfg.IPUnavailableAction = config.IgnoreFailure
	if err = config.Save(filepath.Join(profile, "config.yaml"), cfg); err != nil {
		return err
	}
	beforeRecoveryLog, err := readSharedFile(filepath.Join(profile, "zaslon.log"))
	if err != nil {
		return err
	}
	guard, e = start("zaslon", "headless")
	if e != nil {
		return e
	}
	if err = waitFor("adopted holds survive failed first proof even with ignore enabled", 8*time.Second, func() bool {
		data, e := readSharedFile(filepath.Join(profile, "zaslon.log"))
		if e != nil || len(data) < len(beforeRecoveryLog) {
			return false
		}
		tail := string(data[len(beforeRecoveryLog):])
		return strings.Contains(tail, "Protection recovery: adopted 4 confirmed suspended processes") && strings.Contains(tail, "HTTP 403") && held("ac", "ag", "b", "bc")
	}); err != nil {
		return err
	}
	for name, n := range baseline {
		if size(hearts[name]) != n {
			return fmt.Errorf("%s ran before recovery proof", name)
		}
	}
	result.Checks = append(result.Checks, "restarting the actual EXE adopts four confirmed holds, including orphans, without any heartbeat advance; failed checks stay blocked despite ignore policy")
	_, oldWorker, e := findWorker(guard.Process.Pid)
	if e != nil {
		return e
	}
	if err = backend.Kill(oldWorker); err != nil {
		return err
	}
	if err = waitFor("supervisor restarts worker and readopts without resume", 8*time.Second, func() bool {
		_, worker, e := findWorker(guard.Process.Pid)
		if e != nil || procs.SameProcess(worker, oldWorker) {
			return false
		}
		data, e := readSharedFile(filepath.Join(profile, "zaslon.log"))
		if e != nil || len(data) < len(beforeRecoveryLog) {
			return false
		}
		return strings.Count(string(data[len(beforeRecoveryLog):]), "Protection recovery: adopted 4 confirmed suspended processes") >= 2 && held("ac", "ag", "b", "bc")
	}); err != nil {
		return err
	}
	for name, n := range baseline {
		if size(hearts[name]) != n {
			return fmt.Errorf("%s ran during supervisor restart", name)
		}
	}
	result.Checks = append(result.Checks, "the supervisor's automatic worker restart preserves every existing suspension without a preliminary resume")
	activeSupervisor := guard.Process.Pid
	if *installerPackage != "" {
		beforeConfig, e := os.ReadFile(filepath.Join(profile, "config.yaml"))
		if e != nil {
			return e
		}
		receiptBefore, e := os.ReadFile(filepath.Join(installDir, "install-receipt.json"))
		if e != nil {
			return e
		}
		// Inject a startup failure in an imported copy of the installer functions.
		// There is no failure switch in the shipping installer's interface.
		rollbackScript := filepath.Join(*root, "test-installer-rollback.ps1")
		body := "param($InstallerSource,$ZipFile,$InstallTarget,$TestProfile,$TestVersion)\n" +
			"$ErrorActionPreference='Stop'\n. $InstallerSource\n" +
			"$script:originalStart=(Get-Item Function:Start-InstallRuntime).ScriptBlock\n$script:originalRead=(Get-Item Function:Read-SharedJSON).ScriptBlock\n$script:startAttempts=0\n$script:failState=$false\n" +
			"function Read-SharedJSON([string]$Path) { if($script:failState -and (Split-Path $Path -Leaf) -eq 'state.json'){throw 'Injected unavailable startup state'}; & $script:originalRead $Path }\n" +
			"function Start-InstallRuntime([bool]$Mode) { $script:startAttempts++; $script:failState=($script:startAttempts -eq 1); & $script:originalStart $Mode }\n" +
			"$failed=$false\ntry { Invoke-ZaslonInstaller @{Version=$TestVersion;PackagePath=$ZipFile;ChecksumPath=($ZipFile+'.sha256');InstallDirectory=$InstallTarget;ProfileDirectory=$TestProfile;NoShortcut=$true;Headless=$true} } catch { if($_.Exception.Message -notmatch 'did not confirm startup'){throw}; $failed=$true }\n" +
			"if(-not $failed -or $script:startAttempts -ne 2){throw 'Rollback did not restart the previous instance'}\n"
		if e = os.WriteFile(rollbackScript, []byte(body), 0600); e != nil {
			return e
		}
		version, e := os.ReadFile(filepath.Join(repo, "VERSION"))
		if e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		rollback := hidden(exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", rollbackScript,
			"-InstallerSource", filepath.Join(repo, "scripts", "install.ps1"), "-ZipFile", *installerPackage,
			"-InstallTarget", installDir, "-TestProfile", profile, "-TestVersion", strings.TrimSpace(string(version))))
		rollbackOutput, rollbackErr := rollback.CombinedOutput()
		cancel()
		if e = os.WriteFile(filepath.Join(*root, "installer-rollback.log"), rollbackOutput, 0600); e != nil {
			return e
		}
		if rollbackErr != nil {
			return fmt.Errorf("live installer rollback: %w: %s", rollbackErr, rollbackOutput)
		}
		receiptAfter, e := os.ReadFile(filepath.Join(installDir, "install-receipt.json"))
		if e != nil || !bytes.Equal(receiptBefore, receiptAfter) {
			return errors.New("live rollback did not restore the original receipt/files")
		}
		for name, n := range baseline {
			if size(hearts[name]) != n {
				return fmt.Errorf("%s ran during installer rollback", name)
			}
		}
		if !held("ac", "ag", "b", "bc") {
			return errors.New("live installer rollback lost suspension ownership")
		}
		result.Checks = append(result.Checks, "failed installer startup restores and restarts the old version while every protected fixture remains suspended")
		if err = install(false); err != nil {
			return err
		}
		afterConfig, e := os.ReadFile(filepath.Join(profile, "config.yaml"))
		if e != nil || !bytes.Equal(beforeConfig, afterConfig) {
			return errors.New("installer changed settings")
		}
		for name, n := range baseline {
			if size(hearts[name]) != n {
				return fmt.Errorf("%s ran during installer handoff", name)
			}
		}
		if !held("ac", "ag", "b", "bc") {
			return errors.New("installer changed confirmed suspension ownership")
		}
		all, e := backend.List()
		if e != nil {
			return e
		}
		candidates := map[int]procs.Proc{}
		for _, p := range all {
			if strings.EqualFold(p.Path, paths["zaslon"]) {
				candidates[p.PID] = p
			}
		}
		if len(candidates) != 2 {
			return errors.New("installer did not restart supervisor and worker")
		}
		for _, p := range candidates {
			if _, child := candidates[p.PPID]; !child {
				activeSupervisor = p.PID
			}
		}
		if activeSupervisor == guard.Process.Pid {
			return errors.New("installer kept the old supervisor")
		}
		if err = checkBeats([]string{"control"}, []string{"ac", "ag", "b", "bc"}); err != nil {
			return err
		}
		result.Checks = append(result.Checks, "PowerShell installer replaces the active supervisor/worker and helper, preserves settings and all four paused fixtures without a heartbeat advance")
	}
	modeA.Store(5)
	modeB.Store(5)
	if err = waitFor("fresh recovery checks reach gated servers", 6*time.Second, func() bool { return recoveryRequests.Load() >= 2 }); err != nil {
		return err
	}
	if err = checkBeats([]string{"control"}, []string{"ac", "ag", "b", "bc"}); err != nil {
		return err
	}
	for name, n := range baseline {
		if size(hearts[name]) != n {
			return fmt.Errorf("%s ran while recovery checks were pending", name)
		}
	}
	releaseRecovery()
	if err = waitFor("only current successful proof releases adopted processes", 4*time.Second, func() bool { return held() }); err != nil {
		return err
	}
	if err = checkBeats([]string{"ac", "ag", "b", "bc", "control"}, nil); err != nil {
		return err
	}
	result.Checks = append(result.Checks, "fresh gated success releases adopted processes exactly once after two restarts, with no doubled suspension counts")
	modeA.Store(0)
	modeB.Store(2)
	cfg.IPUnavailableAction = config.SuspendOnFailure
	if err = config.Save(filepath.Join(profile, "config.yaml"), cfg); err != nil {
		return err
	}
	if err = waitFor("refreeze fixtures for independent emergency resume", 8*time.Second, func() bool { return held("ac", "ag", "b", "bc") }); err != nil {
		return err
	}
	if err = crashGuard(activeSupervisor); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	restore := hidden(exec.CommandContext(ctx, paths["zaslon-recover"], "-dir", profile, "-resume"))
	var log bytes.Buffer
	restore.Stdout, restore.Stderr = &log, &log
	if e = restore.Run(); e != nil {
		return fmt.Errorf("recovery: %w: %s", e, log.String())
	}
	if err = os.WriteFile(filepath.Join(*root, "restore.log"), log.Bytes(), 0600); err != nil {
		return err
	}
	if err = checkBeats([]string{"ac", "ag", "b", "bc", "control"}, nil); err != nil {
		return err
	}
	if !held() {
		return errors.New("recovery left journal entries")
	}
	result.Checks = append(result.Checks, "crashing supervisor/worker preserves suspension; independent recovery resumes the same fixture processes")
	return nil
}
