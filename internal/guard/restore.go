package guard

import (
	"errors"
	"fmt"
	"slices"

	"github.com/avazar/zaslon/internal/procs"
)

type suspensionJournal interface {
	ConfirmedSuspensions() ([]procs.Proc, error)
	RememberFrozen([]procs.Proc) error
	Owns(procs.Proc) bool
}

// RestoreProtection is startup-only, before Step, actions or any probe. It plans
// the whole adoption before installing ownership; no Freeze/Resume is performed.
func (g *Guard) RestoreProtection() (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.probing || g.known || !g.lastStep.IsZero() {
		return 0, errors.New("protection recovery is only allowed before starting the guard")
	}
	journal, ok := g.d.Procs.(suspensionJournal)
	if !ok {
		return 0, errors.New("protection recovery requires a suspension journal")
	}
	for _, gr := range g.groups {
		if len(gr.frozen) > 0 {
			return 0, errors.New("protection recovery already installed")
		}
	}
	recorded, err := journal.ConfirmedSuspensions()
	if err != nil {
		return 0, err
	}
	if len(recorded) == 0 {
		return 0, nil
	}
	all, err := g.d.Procs.List()
	if err != nil {
		return 0, err
	}
	all = append([]procs.Proc(nil), all...)
	active := map[string]bool{}
	var targets []procs.Target
	for _, gr := range g.groups {
		for _, t := range gr.tgts {
			active[t.ID] = true
			targets = append(targets, t)
		}
	}
	byPID := map[int]int{}
	for i, p := range all {
		byPID[p.PID] = i
		all[i].App, all[i].AppID, all[i].PolicyIDs = "", "", nil
	}
	live := map[int]procs.Proc{}
	var controls []procs.Proc
	for _, p := range recorded {
		i, exists := byPID[p.PID]
		if !exists || (all[i].Created != "" && !procs.SameProcess(all[i], p)) {
			continue
		}
		if p.PID <= 1 || p.PID == g.d.Self || all[i].Created == "" || !journal.Owns(p) {
			return 0, fmt.Errorf("PID %d: cannot confirm recorded ownership", p.PID)
		}
		if all[i].Control {
			// Own control processes are not protected traffic. Plan their
			// release, but perform no OS operation during adoption.
			controls = append(controls, p)
			continue
		}
		ids := append(append([]string(nil), p.PolicyIDs...), p.AppID)
		hasPolicy := false
		for _, id := range ids {
			if id == "" {
				continue
			}
			hasPolicy = true
			if !active[id] {
				return 0, fmt.Errorf("PID %d: recorded app %q is not enabled; restore its selection or use explicit emergency recovery", p.PID, id)
			}
		}
		if !hasPolicy {
			return 0, fmt.Errorf("PID %d: recorded application policy is missing", p.PID)
		}
		all[i].App, all[i].AppID, all[i].PolicyIDs = p.App, p.AppID, append([]string(nil), p.PolicyIDs...)
		live[p.PID] = p
	}
	matched := procs.Filter(all, targets, g.d.Self)
	plan := map[*group][]procs.Proc{}
	var adopted []procs.Proc
	for _, p := range matched {
		if old, ok := live[p.PID]; ok && procs.SameProcess(old, p) {
			owner := g.ownerOf(p)
			if owner == nil {
				return 0, fmt.Errorf("PID %d: no protection owner", p.PID)
			}
			plan[owner] = append(plan[owner], p)
			adopted = append(adopted, p)
		}
	}
	if len(adopted) != len(live) {
		return 0, errors.New("not every recorded process has a protection owner")
	}
	if err = journal.RememberFrozen(adopted); err != nil {
		return 0, err
	}
	for owner, ps := range plan {
		for _, p := range ps {
			owner.frozen[p.PID] = p
			owner.running = append(owner.running, p)
			g.markRecovering(p)
		}
	}
	for _, p := range controls {
		g.releasing[p.PID] = p
	}
	return len(adopted), nil
}

func (g *Guard) recoveryPending(p procs.Proc) bool {
	for _, gr := range g.groups {
		if gr.recovering {
			for _, t := range gr.tgts {
				if p.AppID == t.ID || slices.Contains(p.PolicyIDs, t.ID) {
					return true
				}
			}
		}
	}
	return false
}

func (g *Guard) markRecovering(p procs.Proc) {
	for _, gr := range g.groups {
		for _, t := range gr.tgts {
			if p.AppID == t.ID || slices.Contains(p.PolicyIDs, t.ID) {
				gr.recovering = true
			}
		}
	}
}

func (g *Guard) rememberFrozenPolicies() {
	journal, ok := g.d.Procs.(interface{ RememberFrozen([]procs.Proc) error })
	if !ok {
		return
	}
	var ps []procs.Proc
	for _, gr := range g.groups {
		for _, p := range gr.frozen {
			ps = append(ps, p)
		}
	}
	err := journal.RememberFrozen(ps)
	g.policyJournalFailed = err != nil
	g.operation("journal-policies", procs.Proc{}, err)
}
