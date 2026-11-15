package recovery

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avazar/zaslon/internal/procs"
)

type fakeOS struct {
	all                     []procs.Proc
	count                   map[int]int
	freezes, resumes, kills int
	failResume              int
	resumeErr               error
	listErr                 error
}

func (f *fakeOS) List() ([]procs.Proc, error) { return f.all, f.listErr }
func (f *fakeOS) Freeze(p procs.Proc) error   { f.freezes++; f.count[p.PID]++; return nil }
func (f *fakeOS) Resume(p procs.Proc) error {
	f.resumes++
	if f.resumeErr != nil {
		return f.resumeErr
	}
	if p.PID == f.failResume {
		return errors.New("resume failed")
	}
	f.count[p.PID]--
	return nil
}

func TestPreconditionFailureCanBeRetriedWithoutLosingOwnership(t *testing.T) {
	c, f, _ := fixture(t)
	if err := c.Freeze(testProc); err != nil {
		t.Fatal(err)
	}
	f.resumeErr = errors.Join(procs.ErrNotApplied, errors.New("access denied opening process"))
	if c.Recover(false) == nil || c.Entries()[0].Phase != "frozen" {
		t.Fatal("lost known suspension on precondition failure")
	}
	f.resumeErr = nil
	if err := c.Recover(false); err != nil {
		t.Fatal(err)
	}
	if f.count[testProc.PID] != 0 || len(c.Entries()) != 0 {
		t.Fatal("retry failed")
	}
}
func (f *fakeOS) Kill(p procs.Proc) error  { f.kills++; return nil }
func (f *fakeOS) Close(p procs.Proc) error { panic("graceful close would run the app") }

var testProc = procs.Proc{PID: 123, Created: "birth-1", Name: "test.exe"}

func fixture(t *testing.T) (*Controller, *fakeOS, string) {
	t.Helper()
	dir := t.TempDir()
	f := &fakeOS{all: []procs.Proc{testProc}, count: map[int]int{}}
	c, err := Open(dir, f)
	if err != nil {
		t.Fatal(err)
	}
	return c, f, dir
}

func TestOnlyOneOwnedSuspendIsReleased(t *testing.T) {
	c, f, _ := fixture(t)
	f.count[testProc.PID] = 2 // pre-existing suspensions are not ours
	for range 3 {
		if err := c.Freeze(testProc); err != nil {
			t.Fatal(err)
		}
	}
	if f.freezes != 1 || f.count[testProc.PID] != 3 {
		t.Fatal("duplicate freeze")
	}
	for range 3 {
		if err := c.Resume(testProc); err != nil {
			t.Fatal(err)
		}
	}
	if f.resumes != 1 || f.count[testProc.PID] != 2 {
		t.Fatal("resumed someone else's suspension")
	}
}

func TestJournalDoesNotPersistCommandLineMetadata(t *testing.T) {
	c, f, dir := fixture(t)
	p := testProc
	p.Args = "node private-cli.js --token=command-line-secret"
	p.ScriptPath = "C:/private-script-directory/entry.js"
	if err := c.Freeze(p); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "command-line-secret") || strings.Contains(string(data), "private-script-directory") {
		t.Fatal("journal persisted command line metadata")
	}
	restarted, err := Open(dir, f)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.Recover(false); err != nil || f.count[p.PID] != 0 {
		t.Fatal("recovery depended on command line metadata")
	}
}

func TestRecoveryAfterRestartIsIndependentOfConfig(t *testing.T) {
	c, f, dir := fixture(t)
	if err := c.Freeze(testProc); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("invalid: ["), 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(dir, f)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Recover(false); err != nil {
		t.Fatal(err)
	}
	if len(restarted.Entries()) != 0 || f.count[testProc.PID] != 0 {
		t.Fatal("recovery incomplete")
	}
	if err := restarted.Recover(false); err != nil {
		t.Fatal(err)
	}
	if f.resumes != 1 {
		t.Fatal("recovery was not idempotent")
	}
}

func TestWriteFailureBeforeFreezeNeverTouchesProcess(t *testing.T) {
	c, f, _ := fixture(t)
	c.write = func(string, []byte) error { return errors.New("disk full") }
	if c.Freeze(testProc) == nil {
		t.Fatal("write failure hidden")
	}
	if f.freezes != 0 || len(c.Entries()) != 0 {
		t.Fatal("changed process without recovery intent")
	}
}

func TestCrashWindowAfterFreezeIsNotBlindlyResumed(t *testing.T) {
	c, f, dir := fixture(t)
	writes := 0
	c.write = func(path string, b []byte) error {
		writes++
		if writes == 2 {
			return errors.New("crash before result commit")
		}
		return writeAtomic(path, b)
	}
	if c.Freeze(testProc) == nil {
		t.Fatal("commit failure hidden")
	}
	restarted, err := Open(dir, f)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Recover(false) == nil || f.resumes != 0 {
		t.Fatal("guessed uncertain suspension")
	}
	if len(restarted.Entries()) != 1 {
		t.Fatal("lost unresolved intent")
	}
	if err := restarted.Recover(true); err != nil {
		t.Fatal(err)
	}
	if f.kills != 1 || len(restarted.Entries()) != 0 {
		t.Fatal("explicit termination failed")
	}
}

func TestCrashWindowAfterResumeCannotDoubleResume(t *testing.T) {
	c, f, dir := fixture(t)
	if err := c.Freeze(testProc); err != nil {
		t.Fatal(err)
	}
	writes := 0
	c.write = func(path string, b []byte) error {
		writes++
		if writes == 2 {
			return errors.New("crash after OS resume")
		}
		return writeAtomic(path, b)
	}
	if c.Resume(testProc) == nil {
		t.Fatal("commit failure hidden")
	}
	if c.Resume(testProc) == nil || f.resumes != 1 {
		t.Fatal("same controller repeated uncertain resume")
	}
	restarted, err := Open(dir, f)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Recover(false) == nil || f.resumes != 1 {
		t.Fatal("restart repeated uncertain resume")
	}
}

func TestOneFailedResumeDoesNotPreventTheOthers(t *testing.T) {
	c, f, _ := fixture(t)
	p2 := testProc
	p2.PID++
	f.all = append(f.all, p2)
	for _, p := range f.all {
		if err := c.Freeze(p); err != nil {
			t.Fatal(err)
		}
	}
	f.failResume = testProc.PID
	if c.Recover(false) == nil {
		t.Fatal("failure hidden")
	}
	if f.resumes != 2 || len(c.Entries()) != 1 || f.count[p2.PID] != 0 {
		t.Fatal("independent recovery failed")
	}
}

func TestReusedPIDAndMissingProcessArePrunedWithoutActions(t *testing.T) {
	for _, gone := range []bool{false, true} {
		t.Run(map[bool]string{true: "gone", false: "reused"}[gone], func(t *testing.T) {
			c, f, _ := fixture(t)
			if err := c.Freeze(testProc); err != nil {
				t.Fatal(err)
			}
			if gone {
				f.all = nil
			} else {
				f.all[0].Created = "different-birth"
			}
			if err := c.Recover(false); err != nil {
				t.Fatal(err)
			}
			if len(c.Entries()) != 0 || f.resumes != 0 || f.kills != 0 {
				t.Fatal("acted on a replaced process")
			}
		})
	}
}

func TestPrunePreservesUnreadableIdentityAndSnapshotFailure(t *testing.T) {
	c, f, _ := fixture(t)
	if err := c.Freeze(testProc); err != nil {
		t.Fatal(err)
	}
	f.all[0].Created = ""
	if err := c.Prune(); err != nil {
		t.Fatal(err)
	}
	if len(c.Entries()) != 1 {
		t.Fatal("discarded unreadable identity")
	}
	f.listErr = errors.New("snapshot failed")
	if c.Prune() == nil || len(c.Entries()) != 1 {
		t.Fatal("snapshot failure erased recovery")
	}
}

func TestCorruptJournalIsPreserved(t *testing.T) {
	_, f, dir := fixture(t)
	path := filepath.Join(dir, FileName)
	for _, bad := range []string{"{", `{"version":99,"entries":{}}`, `{"version":1,"entries":{"123":{"process":{"PID":123},"phase":"frozen"}}}`} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(dir, f); err == nil {
			t.Fatal("accepted invalid journal")
		}
		got, _ := os.ReadFile(path)
		if string(got) != bad {
			t.Fatal("overwrote invalid journal")
		}
	}
}
