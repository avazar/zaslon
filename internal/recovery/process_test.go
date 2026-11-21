package recovery

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/procs"
)

// Only test-created children are ever suspended; no app names/config are used.
func TestMain(m *testing.M) {
	switch os.Getenv("ZASLON_RECOVERY_TEST_ROLE") {
	case "heartbeat":
		for {
			f, err := os.OpenFile(os.Getenv("ZASLON_RECOVERY_TEST_FILE"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				os.Exit(30)
			}
			fmt.Fprintln(f, "tick")
			f.Close()
			time.Sleep(20 * time.Millisecond)
		}
	case "crash":
		backend := procs.New()
		c, err := Open(os.Getenv("ZASLON_RECOVERY_TEST_DIR"), backend)
		if err != nil {
			os.Exit(31)
		}
		pid, _ := strconv.Atoi(os.Getenv("ZASLON_RECOVERY_TEST_PID"))
		all, err := backend.List()
		if err != nil {
			os.Exit(32)
		}
		for _, p := range all {
			if p.PID == pid && p.Created == os.Getenv("ZASLON_RECOVERY_TEST_CREATED") {
				if err := c.Freeze(p); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(33)
				}
				os.Exit(23) // deliberately bypass all cleanup
			}
		}
		os.Exit(34)
	}
	os.Exit(m.Run())
}

func TestRealCrashAndRecovery(t *testing.T) {
	dir := t.TempDir()
	heartbeat := filepath.Join(dir, "heartbeat")
	child := exec.Command(os.Args[0], "-test.run=^$")
	child.Env = append(os.Environ(), "ZASLON_RECOVERY_TEST_ROLE=heartbeat", "ZASLON_RECOVERY_TEST_FILE="+heartbeat)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	size := func() int64 {
		st, err := os.Stat(heartbeat)
		if err != nil {
			return 0
		}
		return st.Size()
	}
	waitGrowth := func(before int64) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if size() > before {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("test child did not run")
	}
	waitGrowth(0)
	all, err := procs.New().List()
	if err != nil {
		t.Fatal(err)
	}
	created := ""
	for _, p := range all {
		if p.PID == child.Process.Pid && p.PPID == os.Getpid() {
			created = p.Created
		}
	}
	if created == "" {
		t.Fatal("could not identify our own test child")
	}
	worker := exec.Command(os.Args[0], "-test.run=^$")
	worker.Env = append(os.Environ(), "ZASLON_RECOVERY_TEST_ROLE=crash", "ZASLON_RECOVERY_TEST_DIR="+dir, "ZASLON_RECOVERY_TEST_PID="+strconv.Itoa(child.Process.Pid), "ZASLON_RECOVERY_TEST_CREATED="+created)
	out, err := worker.CombinedOutput()
	if err == nil || worker.ProcessState.ExitCode() != 23 {
		t.Fatalf("crash worker: %v %s", err, out)
	}
	before := size()
	time.Sleep(200 * time.Millisecond)
	if size() != before {
		t.Fatal("child continued running after guard crash")
	}
	c, err := Open(dir, procs.New())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Entries()) != 1 {
		t.Fatal("crash lost process ownership")
	}
	if err := c.Recover(false); err != nil {
		t.Fatal(err)
	}
	waitGrowth(before)
	if err := c.Recover(false); err != nil {
		t.Fatal(err)
	}
	if len(c.Entries()) != 0 {
		t.Fatal("journal not cleared")
	}
	if runtime.GOOS == "windows" {
		backend := procs.New()
		all, err := backend.List()
		if err != nil {
			t.Fatal(err)
		}
		var p procs.Proc
		for _, candidate := range all {
			if candidate.PID == child.Process.Pid {
				p = candidate
			}
		}
		if p.Created == "" {
			t.Fatal("missing test child identity")
		}
		if err := backend.Freeze(p); err != nil {
			t.Fatal(err)
		} // suspension owned by another controller
		if err := c.Freeze(p); err != nil {
			t.Fatal(err)
		}
		if err := c.Freeze(p); err != nil {
			t.Fatal(err)
		} // must not increment again
		if err := c.Resume(p); err != nil {
			t.Fatal(err)
		}
		wrong := p
		wrong.Created = "a-different-process"
		if err := backend.Resume(wrong); err != nil {
			t.Fatal(err)
		}
		if err := backend.Kill(wrong); err != nil {
			t.Fatal(err)
		}
		wrong = p
		wrong.Sequence++
		if err := backend.Close(wrong); err != nil {
			t.Fatal(err)
		}
		if err := c.Freeze(wrong); !errors.Is(err, procs.ErrProcessGone) || len(c.Entries()) != 0 {
			t.Fatalf("stale freeze recorded ownership: err=%v, entries=%v", err, c.Entries())
		}
		before = size()
		time.Sleep(200 * time.Millisecond)
		if size() != before {
			t.Fatal("released a suspension owned by someone else")
		}
		if err := backend.Resume(p); err != nil {
			t.Fatal(err)
		}
		waitGrowth(before) // also proves the mismatched identity was not terminated
		if err := child.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		_ = child.Wait()
		if err := c.Freeze(p); !errors.Is(err, procs.ErrProcessGone) || len(c.Entries()) != 0 {
			t.Fatalf("exited child recorded ownership: err=%v, entries=%v", err, c.Entries())
		}
		reopened, err := Open(dir, procs.New())
		if err != nil || len(reopened.Entries()) != 0 {
			t.Fatalf("stale freeze left a recovery record on disk: %v", err)
		}
	}
}
