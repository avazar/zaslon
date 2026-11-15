package procs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/avazar/zaslon/internal/config"
	"golang.org/x/sys/windows"
)

// Copies of the test executable pretend to be node/bun. No runtime, package,
// real CLI, network request or user profile is needed. A job contains each tree
// before its gate opens, so a test crash also cleans up suspended descendants.
func init() {
	if os.Getenv("ZASLON_CLI_FIXTURE") != "1" {
		return
	}
	dir, id, role := os.Getenv("ZASLON_CLI_DIR"), os.Getenv("ZASLON_CLI_ID"), os.Getenv("ZASLON_CLI_ROLE")
	deadline := time.Now().Add(25 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, id+".gate")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			os.Exit(41)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if role == "parent" {
		exe, _ := os.Executable()
		child := hiddenCLIFixture(exec.Command(exe))
		child.Env = append(os.Environ(), "ZASLON_CLI_ROLE=child")
		if err := child.Start(); err != nil {
			os.Exit(42)
		}
		if os.WriteFile(filepath.Join(dir, id+".child.pid"), []byte(strconv.Itoa(child.Process.Pid)), 0600) != nil {
			os.Exit(43)
		}
	}
	for time.Now().Before(deadline) {
		f, err := os.OpenFile(filepath.Join(dir, id+"."+role+".ticks"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			os.Exit(44)
		}
		_, err = fmt.Fprintln(f, "tick")
		f.Close()
		if err != nil {
			os.Exit(45)
		}
		time.Sleep(15 * time.Millisecond)
	}
	os.Exit(0)
}

func hiddenCLIFixture(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd
}

func waitCLIFixture(t *testing.T, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("fixture timeout: " + what)
}

func startCLIFixture(t *testing.T, exe, dir, id, role string, args ...string) *exec.Cmd {
	t.Helper()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.CloseHandle(job)
		t.Fatal(err)
	}
	cmd := hiddenCLIFixture(exec.Command(exe, args...))
	cmd.Env = append(os.Environ(), "ZASLON_CLI_FIXTURE=1", "ZASLON_CLI_DIR="+dir, "ZASLON_CLI_ID="+id, "ZASLON_CLI_ROLE="+role)
	if err = cmd.Start(); err != nil {
		windows.CloseHandle(job)
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		defer windows.CloseHandle(job)
		if err := windows.TerminateJobObject(job, 1); err != nil {
			t.Errorf("terminating fixture job: %v", err)
		}
		// Also cover failure to assign the gated root to its job.
		cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("fixture root survived cleanup")
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			info := struct {
				Assigned, Count uint32
				PIDs            [8]uintptr
			}{}
			err := windows.QueryInformationJobObject(job, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil)
			if err != nil {
				t.Errorf("checking fixture cleanup: %v", err)
				break
			}
			if info.Count == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Error("fixture job still contains processes")
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
	})
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, h)
		windows.CloseHandle(h)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, id+".gate"), []byte("contained"), 0600); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestWindowsCLIRecognitionAndDescendants(t *testing.T) {
	dir := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, key := range []string{"v1/node", "v2/node", "v2/bun"} {
		p := filepath.Join(dir, "Тест обновления", filepath.FromSlash(key)+".exe")
		if err = os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(p, data, 0700); err != nil {
			t.Fatal(err)
		}
		paths[key] = p
	}
	claude := `C:\User Name\npm\node_modules\@anthropic-ai\claude-code\cli.js`
	for _, tc := range []struct {
		id, key, app string
		args         []string
	}{
		{"node-v1", "v1/node", "claude", []string{claude, "--prompt", "тест"}},
		{"node-v2", "v2/node", "claude", []string{`C:/New Version/node_modules/@anthropic-ai/claude-code/cli.js`}},
		{"bun-direct", "v2/bun", "claude", []string{claude}},
		{"bun-run", "v2/bun", "claude", []string{"--bun", "run", claude}},
		{"node-codex", "v2/node", "codex", []string{`C:\Updated\node_modules\@openai\codex\bin\codex.js`}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			marker := "--zaslon-test=" + tc.id
			root := startCLIFixture(t, paths[tc.key], dir, tc.id, "parent", append(tc.args, marker)...)
			control := startCLIFixture(t, paths[tc.key], dir, tc.id+"-control", "control", "server.js", "--prompt", claude)
			parentTick, childTick, controlTick := filepath.Join(dir, tc.id+".parent.ticks"), filepath.Join(dir, tc.id+".child.ticks"), filepath.Join(dir, tc.id+"-control.control.ticks")
			size := func(f string) int64 {
				st, e := os.Stat(f)
				if e != nil {
					return 0
				}
				return st.Size()
			}
			var childPID int
			waitCLIFixture(t, "heartbeat and child", func() bool {
				b, _ := os.ReadFile(filepath.Join(dir, tc.id+".child.pid"))
				childPID, _ = strconv.Atoi(string(b))
				return childPID > 0 && size(parentTick) > 0 && size(childTick) > 0 && size(controlTick) > 0
			})
			c := New().(*osController)
			// A stale cache entry simulates PID reuse; it must not supply old args.
			c.cache[root.Process.Pid] = cached{created: -1, path: "wrong.exe", args: "old arguments", script: "wrong.js", argsRead: true}
			all, err := c.List()
			if err != nil {
				t.Fatal(err)
			}
			owned := map[int]Proc{}
			for _, p := range all {
				if p.PID == root.Process.Pid || p.PID == childPID || p.PID == control.Process.Pid {
					if p.Created == "" || !strings.EqualFold(p.Path, paths[tc.key]) {
						t.Fatal("fixture identity/path mismatch")
					}
					owned[p.PID] = p
				}
			}
			if len(owned) != 3 || owned[childPID].PPID != root.Process.Pid {
				t.Fatal("fixture tree not confirmed")
			}
			parent := owned[root.Process.Pid]
			if parent.Args == "" || parent.ScriptPath == "" || parent.Args == "old arguments" {
				t.Fatal("entry script was not collected")
			}
			cfg := config.Default()
			cfg.Apps = []string{tc.app}
			cfg.CustomApps = nil
			// Only positively identified test processes enter the filter or suspender.
			var candidates []Proc
			for _, p := range owned {
				candidates = append(candidates, p)
			}
			matched := Filter(candidates, Targets(cfg), os.Getpid())
			if len(matched) != 2 {
				t.Fatalf("matched %d fixture processes, want parent and child", len(matched))
			}
			custom := Filter(candidates, []Target{{ID: "fixture", Name: "Fixture", Rule: ParseMatch([]string{"args:" + marker})}}, os.Getpid())
			if len(custom) != 2 || custom[0].PID == control.Process.Pid || custom[1].PID == control.Process.Pid {
				t.Fatal("custom args: rule failed to isolate fixture tree")
			}
			for _, p := range matched {
				if (p.PID != root.Process.Pid && p.PID != childPID) || p.AppID != tc.app {
					t.Fatal("matched control or wrong app")
				}
				if err = c.Freeze(p); err != nil {
					t.Fatal(err)
				}
			}
			time.Sleep(80 * time.Millisecond)
			pBefore, cBefore, controlBefore := size(parentTick), size(childTick), size(controlTick)
			time.Sleep(160 * time.Millisecond)
			if size(parentTick) != pBefore || size(childTick) != cBefore || size(controlTick) <= controlBefore {
				t.Fatal("suspension did not isolate CLI tree from unrelated runtime")
			}
			for _, p := range matched {
				if err = c.Resume(p); err != nil {
					t.Fatal(err)
				}
			}
			waitCLIFixture(t, "resumed CLI tree", func() bool { return size(parentTick) > pBefore && size(childTick) > cBefore })
			all, err = c.List()
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range all {
				if p.PID == parent.PID && (p.Created != parent.Created || p.Args != parent.Args || p.ScriptPath != parent.ScriptPath) {
					t.Fatal("cached identity/arguments changed")
				}
			}
			// Failed/empty startup reads remain retryable for the same identity.
			ce := c.cache[parent.PID]
			ce.args, ce.script, ce.argsRead = "", "", false
			c.cache[parent.PID] = ce
			if _, err = c.List(); err != nil {
				t.Fatal(err)
			}
			if ce = c.cache[parent.PID]; !ce.argsRead || ce.args != parent.Args || ce.script != parent.ScriptPath {
				t.Fatal("command line was not retried after unavailable metadata")
			}
			t.Log("CLI and descendant recognised, suspended and resumed; unrelated runtime kept running")
		})
	}
}
