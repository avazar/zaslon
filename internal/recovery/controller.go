// Package recovery records process operations before they reach the OS.
// A caller must hold the profile's zaslon.lock for this controller's lifetime.
package recovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"

	"github.com/avazar/zaslon/internal/procs"
)

const FileName = "process-recovery.json"

type Entry struct {
	Process procs.Proc          `json:"process"`
	Group   *procs.FreezerGroup `json:"freezer,omitempty"`
	Phase   string              `json:"phase"` // freezing/resuming are ambiguous after a crash
}

type journal struct {
	Version int           `json:"version"`
	Entries map[int]Entry `json:"entries"`
}

type Controller struct {
	mu      sync.Mutex
	os      procs.Controller
	path    string
	entries map[int]Entry
	write   func(string, []byte) error
}

func Open(dir string, backend procs.Controller) (*Controller, error) {
	c := &Controller{os: backend, path: filepath.Join(dir, FileName), entries: map[int]Entry{}, write: writeAtomic}
	b, err := os.ReadFile(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	var j journal
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("recovery journal: %w", err)
	}
	if j.Version != 1 || j.Entries == nil {
		return nil, errors.New("unsupported recovery journal; preserved for inspection")
	}
	for pid, e := range j.Entries {
		if pid <= 0 || e.Process.PID != pid || e.Process.Created == "" || (e.Phase != "freezing" && e.Phase != "frozen" && e.Phase != "resuming") {
			return nil, errors.New("invalid recovery entry; journal preserved")
		}
	}
	c.entries = j.Entries
	return c, nil
}

func (c *Controller) Entries() []Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Entry
	for _, e := range c.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Process.PID < out[j].Process.PID })
	return out
}

func (c *Controller) save() error {
	b, err := json.MarshalIndent(journal{Version: 1, Entries: c.entries}, "", "  ")
	if err != nil {
		return err
	}
	return c.write(c.path, b)
}

// ConfirmedSuspensions changes no OS state. Unknown outcomes and inaccessible
// identities must be inspected separately; the caller holds the profile lock.
func (c *Controller) ConfirmedSuspensions() ([]procs.Proc, error) {
	all, err := c.List()
	if err != nil {
		return nil, err
	}
	alive := map[int]procs.Proc{}
	for _, p := range all {
		alive[p.PID] = p
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []procs.Proc
	for pid, e := range c.entries {
		if e.Phase != "frozen" {
			return nil, fmt.Errorf("PID %d: ambiguous %s; protection recovery refused", pid, e.Phase)
		}
		if p, ok := alive[pid]; !ok || p.Created == "" || !procs.SameProcess(p, e.Process) {
			return nil, fmt.Errorf("PID %d: process identity unavailable; protection recovery refused", pid)
		}
		p := e.Process
		p.PolicyIDs = append([]string(nil), p.PolicyIDs...)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}

// RememberFrozen durably updates ancestry without adding suspend counts.
// On write failure retain the previous metadata and every recorded OS phase.
func (c *Controller) RememberFrozen(ps []procs.Proc) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := map[int]Entry{}
	for _, p := range ps {
		e, ok := c.entries[p.PID]
		if !ok || !procs.SameProcess(p, e.Process) || e.Phase != "frozen" {
			continue
		}
		if p.App == e.Process.App && p.AppID == e.Process.AppID && slices.Equal(p.PolicyIDs, e.Process.PolicyIDs) {
			continue
		}
		if _, saved := old[p.PID]; !saved {
			old[p.PID] = e
		}
		e.Process.App, e.Process.AppID = p.App, p.AppID
		e.Process.PolicyIDs = append([]string(nil), p.PolicyIDs...)
		c.entries[p.PID] = e
	}
	if len(old) == 0 {
		return nil
	}
	if err := c.save(); err != nil {
		for pid, e := range old {
			c.entries[pid] = e
		}
		return err
	}
	return nil
}

func (c *Controller) List() ([]procs.Proc, error) {
	all, err := c.os.List()
	if err != nil {
		return nil, err
	}
	if err := c.pruneSnapshot(all); err != nil {
		return nil, err
	}
	return all, nil
}

func (c *Controller) Owns(p procs.Proc) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[p.PID]
	return ok && procs.SameProcess(e.Process, p)
}

func (c *Controller) Freeze(p procs.Proc) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p.Args = "" // command lines may contain credentials; recovery needs only identity
	p.ScriptPath = ""
	if p.PID <= 0 || p.Created == "" {
		return errors.New("cannot freeze without process birth identity")
	}
	if e, ok := c.entries[p.PID]; ok {
		if !procs.SameProcess(p, e.Process) {
			return errors.New("PID reused; recovery required before another freeze")
		}
		if e.Phase == "frozen" {
			return c.save()
		} // never add another suspend count
		return fmt.Errorf("PID %d: unfinished %s operation; recovery required", p.PID, e.Phase)
	}
	c.entries[p.PID] = Entry{Process: p, Phase: "freezing"}
	if err := c.save(); err != nil {
		delete(c.entries, p.PID)
		return err
	}
	var group *procs.FreezerGroup
	var err error
	if backend, ok := c.os.(procs.GroupController); ok {
		group, err = backend.FreezeTracked(p, func(intent *procs.FreezerGroup) error {
			c.entries[p.PID] = Entry{Process: p, Phase: "freezing", Group: intent}
			return c.save()
		})
	} else {
		err = c.os.Freeze(p)
	}
	if err != nil {
		if errors.Is(err, procs.ErrNotApplied) {
			delete(c.entries, p.PID)
			if saveErr := c.save(); saveErr != nil {
				c.entries[p.PID] = Entry{Process: p, Phase: "freezing"}
				return errors.Join(err, saveErr)
			}
		}
		return err
	}
	c.entries[p.PID] = Entry{Process: p, Phase: "frozen", Group: group}
	return c.save()
}

func (c *Controller) Resume(p procs.Proc) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[p.PID]
	if !ok || !procs.SameProcess(p, e.Process) {
		return nil
	} // never resume another owner's process
	if e.Phase != "frozen" {
		return fmt.Errorf("PID %d: ambiguous %s; refusing a blind resume", p.PID, e.Phase)
	}
	intent := e
	intent.Phase = "resuming"
	c.entries[p.PID] = intent
	if err := c.save(); err != nil {
		c.entries[p.PID] = e
		return err
	}
	var err error
	if e.Group != nil {
		backend, ok := c.os.(procs.GroupController)
		if !ok {
			err = errors.Join(procs.ErrNotApplied, errors.New("Linux cgroup recovery unavailable"))
		} else {
			err = backend.ReleaseGroup(e.Process, e.Group)
		}
	} else {
		err = c.os.Resume(e.Process)
	}
	if err != nil {
		if errors.Is(err, procs.ErrNotApplied) {
			c.entries[p.PID] = e
			return errors.Join(err, c.save())
		}
		return err
	}
	delete(c.entries, p.PID)
	// If this write fails, keep the uncertain on-disk intent; do not resume twice.
	if err := c.save(); err != nil {
		c.entries[p.PID] = intent
		return err
	}
	return nil
}

// Kill never resumes the process. Repeating termination of the same identity is safe.
func (c *Controller) Kill(p procs.Proc) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.os.Kill(p); err != nil {
		return err
	}
	e, ok := c.entries[p.PID]
	if !ok || !procs.SameProcess(p, e.Process) {
		return nil
	}
	if e.Group != nil {
		// SIGKILL is asynchronous. Prune after the target has actually exited.
		return nil
	}
	delete(c.entries, p.PID)
	if err := c.save(); err != nil {
		c.entries[p.PID] = e
		return err
	}
	return nil
}

func (c *Controller) Close(p procs.Proc) error { return c.Kill(p) }

// Prune removes only identities confirmed absent from a complete OS snapshot.
// An inaccessible identity is retained, so access failures cannot erase recovery data.
func (c *Controller) Prune() error {
	all, err := c.os.List()
	if err != nil {
		return err
	}
	return c.pruneSnapshot(all)
}

func (c *Controller) pruneSnapshot(all []procs.Proc) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	alive := map[int]procs.Proc{}
	for _, p := range all {
		alive[p.PID] = p
	}
	old := map[int]Entry{}
	for pid, e := range c.entries {
		p, exists := alive[pid]
		if !exists || (p.Created != "" && !procs.SameProcess(p, e.Process)) {
			if e.Group != nil {
				backend, ok := c.os.(procs.GroupController)
				if !ok {
					return errors.New("Linux cgroup recovery unavailable")
				}
				if err := backend.ForgetGroup(e.Process, e.Group); err != nil {
					return err
				}
			}
			old[pid] = e
		}
	}
	if len(old) == 0 {
		return nil
	}
	for pid := range old {
		delete(c.entries, pid)
	}
	if err := c.save(); err != nil {
		for pid, e := range old {
			c.entries[pid] = e
		}
		return err
	}
	return nil
}

// Recover attempts every entry independently. terminate is an explicit, destructive
// escape hatch for uncertain operations; it never guesses a Windows suspend count.
func (c *Controller) Recover(terminate bool) error {
	if err := c.Prune(); err != nil {
		return err
	}
	var errs []error
	for _, e := range c.Entries() {
		var err error
		if terminate {
			err = c.Kill(e.Process)
		} else {
			err = c.Resume(e.Process)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("PID %d (%s): %w", e.Process.PID, e.Process.Name, err))
		}
	}
	return errors.Join(errs...)
}

func writeAtomic(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".process-recovery-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return replaceFile(tmp, path)
}
