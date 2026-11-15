package netwatch

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Events records relevant changes at the callback, before a queued probe result can be
// consumed. The channel may coalesce bursts; the revision must never lose them.
type Events struct {
	C             <-chan struct{}
	wake          chan struct{}
	version       atomic.Uint64
	mu            sync.Mutex
	err           error
	changes       [changeHistory]Change
	ignored       uint64
	lastIgnored   Change
	FilterStatus  string // immutable after Watch returns
	refreshFilter func() string
}

const changeHistory = 64

// Change contains only copied notification data; OS-owned row pointers must
// never escape the callback. Recording it does not query or modify the network.
type Change struct {
	Version   uint64
	At        time.Time
	Source    string
	Kind      string
	Family    string
	Interface uint32
	Address   string
	Prefix    string
	NextHop   string
	Error     string
}

func (c Change) String() string {
	s := fmt.Sprintf("#%d %s source=%s kind=%s", c.Version, c.At.Format(time.RFC3339Nano), c.Source, c.Kind)
	if c.Family != "" {
		s += " family=" + c.Family
	}
	if c.Interface != 0 {
		s += fmt.Sprintf(" interface=%d", c.Interface)
	}
	if c.Address != "" {
		s += " address=" + c.Address
	}
	if c.Prefix != "" {
		s += " prefix=" + c.Prefix
	}
	if c.NextHop != "" {
		s += " next_hop=" + c.NextHop
	}
	if c.Error != "" {
		s += " error=" + c.Error
	}
	return s
}

// The revision must advance before formatting diagnostics or waiting for their
// buffer. Otherwise a busy logger could let an old successful probe slip past
// an already delivered OS callback. describe is called synchronously.
func (e *Events) record(describe func() Change) {
	version, at := e.version.Add(1), time.Now()
	select {
	case e.wake <- struct{}{}:
	default:
	}
	c := describe()
	c.Version, c.At = version, at
	e.mu.Lock()
	slot := &e.changes[(version-1)%changeHistory]
	// Descriptions may complete out of order on different callback threads.
	if slot.Version < version {
		*slot = c
	}
	e.mu.Unlock()
}

// Details returns exactly the revisions observed by the guard, including an
// explicit gap if a burst exceeded the bounded buffer. It never drains newer
// records that may already belong to the next invalidation.
func (e *Events) Details(after, through uint64) []string {
	e.mu.Lock()
	changes := e.changes
	e.mu.Unlock()
	if through <= after {
		return nil
	}
	var out []string
	first, gap := after+1, uint64(0)
	missing := func(start, end uint64) {
		out = append(out, fmt.Sprintf("notifications #%d..#%d: details unavailable (pending or expired from buffer)", start, end))
	}
	if through-first >= changeHistory {
		missing(first, through-changeHistory)
		first = through - changeHistory + 1
	}
	for version := first; version <= through; version++ {
		c := changes[(version-1)%changeHistory]
		if c.Version != version {
			if gap == 0 {
				gap = version
			}
			continue
		}
		if gap != 0 {
			missing(gap, version-1)
			gap = 0
		}
		out = append(out, c.String())
	}
	if gap != 0 {
		missing(gap, through)
	}
	return out
}

func (e *Events) Version() uint64 { return e.version.Load() }

// Filtered notifications do not advance the protection revision or wake the
// guard. Keep a count and one example for bounded, aggregated diagnostics.
func (e *Events) ignore(describe func() Change) {
	c := describe()
	c.At = time.Now()
	e.mu.Lock()
	e.ignored++
	c.Version = e.ignored
	e.lastIgnored = c
	e.mu.Unlock()
}

func (e *Events) Ignored() (uint64, string) {
	e.mu.Lock()
	count, c := e.ignored, e.lastIgnored
	e.mu.Unlock()
	if count == 0 {
		return 0, ""
	}
	return count, c.String()
}

// RefreshFilter may read OS metadata, so call it only outside the guard and
// callbacks. It is requested when an initially unidentified interface appears.
func (e *Events) RefreshFilter() string {
	if e.refreshFilter == nil {
		return ""
	}
	return e.refreshFilter()
}

func (e *Events) Error() error { e.mu.Lock(); defer e.mu.Unlock(); return e.err }

// Changes delivers a tick whenever the OS reports a relevant network change (an address,
// interface or route came or went). Bursts are coalesced into one tick. The runner
// also polls interface addresses and periodically checks the public IP.
func Changes(ctx context.Context) <-chan struct{} {
	return Watch(ctx).C
}

func Watch(ctx context.Context) *Events {
	ch := make(chan struct{}, 1)
	e := &Events{C: ch, wake: ch}
	fail := func(err error) {
		if ctx.Err() != nil {
			return
		}
		e.mu.Lock()
		e.err = err
		e.mu.Unlock()
		e.record(func() Change { return Change{Source: "network-monitor", Kind: "error", Error: err.Error()} })
	}
	e.FilterStatus, e.refreshFilter = watch(ctx, e.record, e.ignore, fail)
	return e
}
