// Package guard is Zaslon's core: it decides when the protected apps may run.
//
//	Starting ──first check──▶ OK ◀───────── allowed IP ──────────┐
//	                           │                                 │
//	         network changed / IP not allowed / offline          │
//	                           ▼                                 │
//	                        Suspect (apps frozen without a deadline)
//
// A current-network check must finish before apps resume. Unavailable results
// suspend apps unless the user explicitly ignores them with a warning.
// Process termination is reserved for the explicit recovery tool.
//
// Apps with their own rules (app_rules) form separate groups, each with its own
// state: Claude can be frozen while Cursor, allowed in more countries, runs on.
//
// Guard does no I/O of its own beyond Deps and is driven by Step and HandleProbe,
// so tests can run it on a fake clock.
package guard

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/procs"
)

type Status int

const (
	Starting Status = iota // the first IP check hasn't finished
	OK                     // apps may run
	Suspect                // apps frozen, waiting for an allowed IP
	Blocked                // legacy state; treated as suspended, never terminated
)

// worse orders statuses for the overall state shown in the menu.
func worse(a, b Status) bool {
	rank := map[Status]int{OK: 0, Starting: 1, Suspect: 2, Blocked: 3}
	return rank[a] > rank[b]
}

type Reason int

const (
	NoReason            Reason = iota
	NetChanged                 // routine re-check after a network change
	IPNotAllowed               // the public IPv4 is not on the allow-list
	Offline                    // no internet
	IPv6Leak                   // IPv4 is fine, but there is a public IPv6 that isn't allowed
	Unconfirmed                // services disagree about the IP, or too few answered
	DNSLeak                    // DNS lookups go out somewhere else than the VPN (dns_check: block)
	IPv6Unconfirmed            // IPv6 may be available, but its exit could not be verified
	DomainUnconfirmed          // a mandatory service measurement is missing, stale or failed
	DomainIPNotAllowed         // a service host sees an exit not allowed for its app
	ProcessPolicyDenied        // another matching app or ancestor policy holds a child
	IPv6Conflict               // IPv6 services returned conflicting addresses
	AppCheckPending            // a newly enabled app is waiting for a current check
	SettingsChanged
	CountryUnknown
	IPv6CountryUnknown
)

const (
	// FastCheck is the re-check interval while something is wrong.
	FastCheck = 2 * time.Second
	// MaxProbeAge bounds completed results as well as checks that never report
	// back. The production request budget is 12 seconds.
	MaxProbeAge = 15 * time.Second
	probeStuck  = MaxProbeAge
	historyLen  = 50
)

// Forever pauses until Zaslon restarts.
const Forever = time.Duration(1<<63 - 1)

type ProbePart int

const (
	CompleteProbe ProbePart = iota
	DomainFamily
	DomainGroup
	GeneralMeasurement
)

type ProbePlan struct {
	General bool
	Apps    map[string]bool // running service policies due for a measurement
}

type ProbeResult struct {
	Retry           chan bool // buffered reply to a family timeout, after enforcement
	Part            ProbePart
	Sample          DomainResult
	SampleIPv6      bool
	ID              uint64 // identifies one check; superseded/duplicate results are ignored
	IP, Country     string
	Votes           int      // how many IP services agreed on IP
	Others          []string // other addresses some services reported
	IP6, Country6   string   // public IPv6, empty if there is none
	IPv6Unknown     bool
	IPv6Possible    bool // current network requires IPv6 evidence for missing/stale domain results
	IPv6Conflicting bool
	DNS, DNSCountry string // public address of the DNS resolver in use
	NetID           string // identifies the local network (the router's MAC)
	Err             error
	Domains         map[string][]DomainResult // nil when service measurements were not requested
}

type Deps struct {
	Fingerprint    func() string
	NetworkVersion func() uint64                        // increases at the OS callback, before event-loop delivery
	NetworkDetails func(after, through uint64) []string // copied diagnostics for the observed revisions
	NetworkError   func() error
	// StartProbe begins an IP check in the background; its result must come back through HandleProbe.
	StartProbe func(c *config.Config, id uint64, plan ProbePlan) (cancel func())
	Procs      procs.Suspender
	SaveConfig func(*config.Config) error
	Self       int
}

// group is a set of apps sharing one allow-list, with its own state.
type group struct {
	key     string // "" for the shared rules, else the app_rules key
	tgts    []procs.Target
	status  Status
	reason  Reason
	since   time.Time
	frozen  map[int]procs.Proc
	running []procs.Proc

	recovering bool // adopted holds require confirmed evidence before ignored failures may apply
}

func newGroup(key string, st Status) *group {
	return &group{key: key, status: st, frozen: map[int]procs.Proc{}}
}

func (gr *group) names() []string {
	var n []string
	for _, t := range gr.tgts {
		n = append(n, t.Name)
	}
	return n
}

type Guard struct {
	mu     sync.Mutex
	d      Deps
	cfg    *config.Config
	groups []*group

	ip, country         string
	ip6, cc6            string
	ipv6Unknown         bool
	ipv6Possible        bool
	ipv6Conflicting     bool
	votes               int
	others              []string
	dns, dnsCC          string
	netID               string
	offline             bool
	known               bool // at least one check finished
	lastFP              string
	seenNetwork         bool
	lastVersion         uint64
	verified            bool
	probeID             uint64
	cancelProbe         func()
	nextCheck           time.Time
	probing             bool
	probeStarted        time.Time
	awaitingApps        map[string]bool
	pausedUntil         time.Time
	releasing           map[int]procs.Proc // removed rules whose processes could not be resumed yet
	failures            map[operationKey]string
	lastStep            time.Time
	policyJournalFailed bool
	domains             map[string][]DomainResult
	nextDomainCheck     time.Time
	domainStarted       time.Time
	activeDomains       map[string]bool
	plan                ProbePlan
	retried             map[domainFamily]bool
	checkingDomains     bool
	readyGroups         map[string]bool // complete policies in the in-flight generation
	earlyDenials        map[string]domainHold
	generalReady        bool
	measuredAt          time.Time
	dnsWarned           string
	lastIPv4, lastIPv6  exitEvidence
	serviceEvidence     map[serviceSource]serviceEvidence

	counters    Counters
	history     []Event
	eventID     uint64
	pauseStarts map[int]pauseStart
	listener    func(Snapshot, []Event)
	pending     []Event
	lastKey     string
}

type operationKey struct {
	op      string
	pid     int
	created string
}

// Counters are totals since Zaslon started, for the statistics.
type Counters struct {
	Freezes, Saves, Blocks, Killed int
	FrozenSeconds                  float64
}

func New(cfg *config.Config, d Deps) *Guard {
	g := &Guard{d: d, releasing: map[int]procs.Proc{}, failures: map[operationKey]string{}, serviceEvidence: map[serviceSource]serviceEvidence{}}
	g.setConfig(cfg)
	return g
}

// OnChange is called after every change with the new state and the events since the last call.
func (g *Guard) OnChange(f func(Snapshot, []Event)) {
	g.mu.Lock()
	g.listener = f
	g.mu.Unlock()
}

// setConfig applies a config and regroups the apps, keeping each group's state.
// It returns apps it un-froze because they are no longer protected.
func (g *Guard) setConfig(c *config.Config) []procs.Proc {
	g.cfg = c.Clone()
	g.pruneEvidence()
	all := procs.Targets(g.cfg)
	byKey := map[string][]procs.Target{}
	order := []string{""}
	for _, t := range all {
		key := ""
		if _, ok := g.cfg.AppRules[t.ID]; ok || g.cfg.DomainCheckEnabled(t.ID) {
			key = t.ID
		}
		if _, seen := byKey[key]; !seen && key != "" {
			order = append(order, key)
		}
		byKey[key] = append(byKey[key], t)
	}
	old := map[string]*group{}
	type heldProcess struct {
		process    procs.Proc
		recovering bool
	}
	var held []heldProcess
	for _, gr := range g.groups {
		old[gr.key] = gr
		for _, p := range gr.frozen {
			held = append(held, heldProcess{p, g.recoveryPending(p)})
		}
		gr.frozen = map[int]procs.Proc{}
	}
	for _, p := range g.releasing {
		held = append(held, heldProcess{p, g.recoveryPending(p)})
	}
	clear(g.releasing)
	// A new group starts where the shared group is: reevaluateAll fixes it right
	// after, except while offline, and then the shared group's state is the right one.
	base := old[""]
	var groups []*group
	for _, key := range order {
		gr, ok := old[key]
		if !ok {
			gr = newGroup(key, Starting)
			if base != nil {
				gr.status, gr.reason, gr.since = base.status, base.reason, base.since
			}
		}
		gr.tgts = byKey[key]
		groups = append(groups, gr)
	}
	g.groups = groups
	// Redistribute every suspension, including those in surviving groups and
	// pending releases. Exactly one group may own it; the old group must never
	// resume a process now subject to a different group's rules.
	var resumed []procs.Proc
	for _, h := range held {
		p := h.process
		if h.recovering {
			g.markRecovering(p)
		}
		if to := g.ownerOf(p); to != nil {
			to.frozen[p.PID] = p
			continue
		}
		err := g.d.Procs.Resume(p)
		g.operation("resume", p, err)
		if err != nil {
			g.releasing[p.PID] = p
		} else {
			g.operation("freeze", p, nil)
			resumed = append(resumed, p)
		}
	}
	return resumed
}

func (g *Guard) paused(now time.Time) bool { return now.Before(g.pausedUntil) }

func (g *Guard) allowFor(gr *group) config.Allow {
	if a, ok := g.cfg.AppRules[gr.key]; ok {
		return a
	}
	return g.cfg.Allow
}

func (g *Guard) trusted() bool {
	_, ok := g.cfg.Trusted(g.netID)
	return ok
}

// dnsLeak: the resolver is in another country than the VPN exit, and that country isn't allowed either.
func (g *Guard) dnsLeak(a config.Allow) bool {
	return g.dnsCC != "" && g.country != "" && g.dnsCC != g.country && !slices.Contains(a.Countries, g.dnsCC)
}

func (g *Guard) emit(now time.Time, e Event) {
	e.At = now
	switch e.Kind {
	case EvFrozen:
		g.counters.Freezes++
	case EvResumed:
		if e.Reason != NoReason {
			g.counters.Saves++
		}
	case EvBlocked:
		g.counters.Blocks++
	case EvKilledNew:
		g.counters.Killed++
	}
	g.eventID++
	e.ID = g.eventID
	g.foldRepeatedCheck(&e)
	g.history = append(g.history, e)
	if len(g.history) > historyLen {
		g.history = g.history[len(g.history)-historyLen:]
	}
	g.pending = append(g.pending, e)
	if g.listener == nil && len(g.pending) > historyLen {
		g.pending = g.pending[len(g.pending)-historyLen:]
	}
}

// publish must be called with g.mu held; it runs the listener without the lock.
func (g *Guard) publish(now time.Time) {
	s := g.snapshot(now)
	key := s.key()
	if key == g.lastKey && len(g.pending) == 0 {
		return
	}
	g.lastKey = key
	if f := g.listener; f != nil {
		evs := g.pending
		g.pending = nil
		g.mu.Unlock()
		f(s, evs)
		g.mu.Lock()
	}
}

// Step runs every ~500 ms and on OS network events: notices network changes,
// schedules checks, enforces the state.
func (g *Guard) Step(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.lastStep.IsZero() {
		if dt := now.Sub(g.lastStep).Seconds(); dt > 0 && dt < 5 && g.anyAlarm() {
			g.counters.FrozenSeconds += dt
		}
	}
	g.lastStep = now

	g.observeNetwork(now)

	if !g.pausedUntil.IsZero() && !g.paused(now) {
		g.pausedUntil = time.Time{}
		g.emit(now, Event{Kind: EvUnpaused})
		g.invalidate(now)
	}

	if g.probing && now.Sub(g.probeStarted) > probeStuck {
		g.invalidate(now)
	}
	// Service checks have their own cadence and must not wait behind a slow
	// periodic diagnostic. Cancel only that request; current-network evidence stays.
	if g.probing && !g.checkingDomains && g.domainsDue(now) {
		if g.cancelProbe != nil {
			g.cancelProbe()
			g.cancelProbe = nil
		}
		g.probing = false
		g.nextCheck = now
	}
	g.expireDomains(now)
	g.enforce(now)
	g.startProbe(now) // processes are suspended before any new check is started
	g.publish(now)
}

// observeNetwork includes the event revision: a route change must count even if
// every adapter address is unchanged. Also used before accepting a probe result.
func (g *Guard) observeNetwork(now time.Time) {
	fp := g.d.Fingerprint()
	// Enumeration can take time. Include callbacks received during it before
	// deciding whether a completed probe still belongs to the current network.
	version := uint64(0)
	if g.d.NetworkVersion != nil {
		version = g.d.NetworkVersion()
	}
	changed := g.seenNetwork && (fp != g.lastFP || version != g.lastVersion)
	previousFP, previousVersion := g.lastFP, g.lastVersion
	g.seenNetwork, g.lastFP, g.lastVersion = true, fp, version
	if changed {
		// Diagnostic formatting must not postpone the first suspension.
		g.invalidate(now)
		var details []string
		if version != previousVersion {
			if g.d.NetworkDetails != nil {
				details = g.d.NetworkDetails(previousVersion, version)
			}
			if len(details) == 0 {
				details = append(details, fmt.Sprintf("OS notifications #%d..#%d (details unavailable)", previousVersion+1, version))
			}
		}
		if fp != previousFP {
			details = append(details, "source=interface-poll fingerprint changed")
			details = append(details, fmt.Sprintf("previous interfaces=%q", DiagnosticText(previousFP)), fmt.Sprintf("current interfaces=%q", DiagnosticText(fp)))
		}
		g.emit(now, Event{Kind: EvNetChanged, Details: details})
	}
	if g.d.NetworkError != nil {
		err := g.d.NetworkError()
		g.operation("network-monitor", procs.Proc{}, err)
		if err != nil && (g.verified || g.probing) {
			g.invalidate(now)
		}
	}
}

func (g *Guard) cancelCurrentProbe() {
	if g.cancelProbe != nil {
		g.cancelProbe()
		g.cancelProbe = nil
	}
	g.probing = false
	g.readyGroups, g.earlyDenials, g.generalReady = nil, nil, false
}

func (g *Guard) invalidate(now time.Time) { g.invalidateFor(now, NetChanged) }

func (g *Guard) invalidateFor(now time.Time, why Reason) {
	g.cancelCurrentProbe()
	g.verified = false
	g.domains = nil
	g.domainStarted = time.Time{}
	g.retried = make(map[domainFamily]bool)
	g.nextDomainCheck = time.Time{}
	g.nextCheck = now
	if !g.paused(now) {
		// Change every group's state before enforcement, avoiding intermediate resumes.
		for _, gr := range g.groups {
			gr.status, gr.reason, gr.since = Suspect, why, now
		}
		g.enforce(now)
	}
}

func (g *Guard) startProbe(now time.Time) {
	if g.probing || (now.Before(g.nextCheck) && !g.domainsDue(now)) {
		return
	}
	g.observeNetwork(now) // also initializes the baseline when a settings action starts the first check
	if g.d.NetworkError != nil && g.d.NetworkError() != nil {
		return
	}
	g.probeID++
	g.probing, g.probeStarted = true, now
	g.checkingDomains = g.domainsDue(now)
	g.readyGroups, g.earlyDenials, g.generalReady = make(map[string]bool), make(map[string]domainHold), false
	if g.checkingDomains {
		g.nextDomainCheck = now.Add(g.cfg.DomainCheckInterval.D())
	}
	g.plan = ProbePlan{General: !now.Before(g.nextCheck)}
	if g.checkingDomains {
		g.plan.Apps = maps.Clone(g.activeDomains)
	}
	plan := g.plan
	plan.Apps = maps.Clone(plan.Apps) // the worker owns its copy while apps can exit
	g.cancelProbe = g.d.StartProbe(g.cfg.Clone(), g.probeID, plan)
}

// HandleProbe takes the result of an IP check started by StartProbe.
func (g *Guard) HandleProbe(now time.Time, r ProbeResult) {
	g.mu.Lock()
	defer g.mu.Unlock()
	defer g.publish(now)
	retry := false
	if r.Retry != nil {
		defer func() { r.Retry <- retry }()
	}
	g.observeNetwork(now)
	if !g.probing || r.ID != g.probeID {
		g.startProbe(now)
		return
	}
	if !freshProbe(g.probeStarted, now) {
		g.invalidate(now)
		g.emit(now, Event{Kind: EvNetChanged, Details: []string{"source=probe kind=expired-result; fresh verification required"}})
		g.startProbe(now)
		return
	}
	if r.Part != CompleteProbe {
		if g.checkingDomains {
			g.handleProgress(now, r)
			if r.Retry != nil && r.Part == DomainFamily {
				retry = g.retryDomainFamily(now, r)
			}
		}
		return
	}
	if g.cancelProbe != nil {
		g.cancelProbe()
		g.cancelProbe = nil
	}
	g.probing = false
	g.known = true
	g.verified = true // each group evaluates the completed check's own source
	for _, gr := range g.groups {
		if g.plan.Apps[gr.key] || (g.plan.General && !g.cfg.DomainCheckEnabled(gr.key)) {
			g.markGroupReady(gr)
		}
	}
	for app := range r.Domains {
		if !g.plan.Apps[app] {
			delete(r.Domains, app)
		}
	}
	g.rememberDomains(now, r)
	if g.plan.General && !g.generalReady {
		g.acceptGeneral(now, r)
	}
	g.readyGroups, g.earlyDenials, g.generalReady = nil, nil, false
	if g.checkingDomains {
		if !g.plan.General && g.cfg.DNSCheck == "block" {
			g.dns, g.dnsCC = r.DNS, r.DNSCountry
		}
		g.domains = cloneDomains(r.Domains)
		g.domainStarted = g.probeStarted
		// The completed result is enforced before recording its diagnostics.
		defer g.recordDomainDiagnostics(now, r.ID)
	}

	g.reevaluateAll(now)
}

func (g *Guard) acceptGeneral(now time.Time, r ProbeResult) {
	g.measuredAt = g.probeStarted
	g.rememberGeneral(r)
	if r.NetID != g.netID {
		g.netID = r.NetID
		if n, ok := g.cfg.Trusted(r.NetID); ok {
			g.emit(now, Event{Kind: EvTrusted, Network: n.Name})
		}
	}

	// IPv6 evidence remains relevant when the IPv4 checker is unavailable.
	g.ip6, g.cc6 = r.IP6, r.Country6
	g.ipv6Unknown, g.ipv6Conflicting = r.IPv6Unknown, r.IPv6Conflicting
	g.ipv6Possible = r.IPv6Possible || r.IPv6Unknown || r.IPv6Conflicting || r.IP6 != ""
	if r.Err != nil {
		if !g.offline && !g.hasDomainTargets() {
			g.emit(now, Event{Kind: EvOffline})
		}
		g.offline, g.ip, g.country, g.votes, g.others = true, "", "", 0, nil
		g.dns, g.dnsCC = r.DNS, r.DNSCountry
		return
	}

	if g.offline && !g.hasDomainTargets() {
		g.emit(now, Event{Kind: EvOnline, IP: r.IP, Country: r.Country})
	} else if g.ip != "" && r.IP != g.ip {
		g.emit(now, Event{Kind: EvIPChanged, IP: r.IP, Country: r.Country})
	}
	g.offline, g.ip, g.country = false, r.IP, r.Country
	g.ip6, g.cc6, g.votes, g.others = r.IP6, r.Country6, r.Votes, r.Others
	g.ipv6Unknown = r.IPv6Unknown
	g.dns, g.dnsCC = r.DNS, r.DNSCountry

	if g.cfg.DNSCheck == "warn" && !g.trusted() && g.dnsLeak(g.cfg.Allow) {
		if k := g.netID + "|" + g.dnsCC; k != g.dnsWarned {
			g.dnsWarned = k
			g.emit(now, Event{Kind: EvDNSLeak, IP: g.dns, Country: g.dnsCC, Notify: true})
		}
	}
}

// verdict says why apps are held. NoReason permits running; ignored checks are
// reported separately and do not establish a verified allowed exit.
func (g *Guard) verdict(gr *group, now time.Time) Reason {
	return g.assess(gr, now).reason
}

func (g *Guard) reevaluateAll(now time.Time) {
	if !g.verified {
		return
	}
	allOK := true
	for _, gr := range g.groups {
		g.reevaluate(now, gr)
		if !g.cfg.DomainCheckEnabled(gr.key) && (gr.status != OK || len(g.assess(gr, now).ignored) > 0) && len(gr.tgts) > 0 {
			allOK = false
		}
	}
	if !g.plan.General {
		return
	}
	if allOK {
		g.nextCheck = now.Add(g.cfg.CheckInterval.D())
	} else {
		g.nextCheck = now.Add(FastCheck)
	}
}

func (g *Guard) reevaluate(now time.Time, gr *group) {
	if g.paused(now) || (g.cfg.DomainCheckEnabled(gr.key) && !g.activeDomains[gr.key]) {
		gr.status, gr.reason = OK, NoReason
		return
	}
	why := g.verdict(gr, now)
	if why == NoReason {
		g.toOK(now, gr)
		return
	}
	switch gr.status {
	case OK, Starting:
		g.toSuspect(now, gr, why)
	case Suspect:
		if gr.reason != why {
			gr.reason = why
			g.announceHoldReason(now, gr)
		}
	case Blocked:
		gr.reason = why
	}
}

func (g *Guard) event(now time.Time, gr *group, kind EventKind, apps []string, notify bool) Event {
	e := Event{Kind: kind, Reason: gr.reason, IP: g.ip, Country: g.country, IP6: g.ip6, Country6: g.cc6,
		Others: g.others, DNS: g.dns, DNSCountry: g.dnsCC, Apps: apps, Notify: notify}
	e.IgnoredChecks = len(g.assess(gr, now).ignored) > 0
	if (kind == EvFrozen || kind == EvHoldReason) && gr.reason != NoReason && gr.reason != NetChanged && gr.reason != SettingsChanged && gr.status != OK {
		e.Problems = g.domainDiagnostics(gr, now)
	}
	if kind == EvFrozen || kind == EvHoldReason {
		e.Issues = g.domainIssues(gr, now)
		if len(e.Issues) > 0 {
			e.Domain = e.Issues[0].Endpoint
		}
	} else if measurements := g.domains[gr.key]; len(measurements) > 0 {
		d := measurements[0]
		e.Domain = d.Endpoint
		e.IP, e.Country, e.IP6, e.Country6 = d.IP, d.Country, d.IP6, d.Country6
	}
	return e
}

func (g *Guard) toOK(now time.Time, gr *group) {
	gr.recovering = false // verdict accepted a current result without ignored checks
	g.resumePermitted(gr, now)
	if gr.status == Blocked {
		g.emit(now, g.event(now, gr, EvUnblocked, gr.names(), true))
	}
	gr.status, gr.reason = OK, NoReason
}

func (g *Guard) toSuspect(now time.Time, gr *group, r Reason) {
	alreadyHeld := gr.status == Starting && len(gr.frozen) > 0
	gr.status, gr.reason, gr.since = Suspect, r, now
	if !g.cfg.DomainCheckEnabled(gr.key) {
		g.nextCheck = now
	}
	g.enforce(now) // freeze right now, not on the next tick
	if alreadyHeld {
		g.announceHoldReason(now, gr)
	}
}

func (g *Guard) announceHoldReason(now time.Time, gr *group) {
	if len(gr.frozen) > 0 {
		g.emit(now, g.event(now, gr, EvHoldReason, procs.AppNames(mapValues(gr.frozen)), true))
	}
}

func (g *Guard) recordRelease(now time.Time, resumed []procs.Proc, cause string) {
	if len(resumed) == 0 {
		return
	}
	e := Event{Kind: EvResumed, Apps: procs.AppNames(resumed), ReleaseCause: cause,
		Details: []string{fmt.Sprintf("processes=%d; cause=%s", len(resumed), cause)}}
	g.releaseDuration(now, resumed, &e)
	g.emit(now, e)
}

func (g *Guard) resume(gr *group) []procs.Proc {
	return g.resumeMatching(gr, func(procs.Proc) bool { return true })
}

func (g *Guard) resumePermitted(gr *group, now time.Time) {
	resumed := g.resumeMatching(gr, func(p procs.Proc) bool { return g.processPermitted(p, now, g.probing && g.checkingDomains) })
	if len(resumed) == 0 {
		return
	}
	e := g.event(now, gr, EvResumed, procs.AppNames(resumed), gr.reason != NetChanged && gr.reason != SettingsChanged && gr.status != Starting)
	if gr.status == OK {
		e.Reason = ProcessPolicyDenied
		// Only this process's full set of policies permitted release. The
		// group's own endpoint does not describe the earlier denial.
		e.Notify = false
	}
	e.Details = []string{fmt.Sprintf("processes=%d", len(resumed))}
	g.releaseDuration(now, resumed, &e)
	g.emit(now, e)
}

func (g *Guard) resumeMatching(gr *group, permitted func(procs.Proc) bool) []procs.Proc {
	var resumed []procs.Proc
	for pid, p := range gr.frozen {
		if !permitted(p) {
			continue
		}
		err := g.d.Procs.Resume(p)
		g.operation("resume", p, err)
		if err == nil {
			delete(gr.frozen, pid)
			g.operation("freeze", p, nil)
			resumed = append(resumed, p)
		}
	}
	return resumed
}

func (g *Guard) operation(op string, p procs.Proc, err error) {
	key := operationKey{op: op, pid: p.PID, created: p.Created}
	if err == nil {
		delete(g.failures, key)
		return
	}
	msg := fmt.Sprintf("%s PID %d (%s): %v", op, p.PID, p.Name, err)
	if g.failures[key] != msg {
		g.failures[key] = msg
		e := Event{Kind: EvProcessError, Operation: op, Error: msg, Notify: true}
		if p.PID != 0 {
			name := p.App
			if name == "" {
				name = p.Name
			}
			e.Apps = []string{name}
		}
		g.emit(g.lastStep, e)
	}
}

func (g *Guard) retryReleases() []procs.Proc {
	var resumed []procs.Proc
	for pid, p := range g.releasing {
		err := g.d.Procs.Resume(p)
		g.operation("resume", p, err)
		if err == nil {
			delete(g.releasing, pid)
			g.operation("freeze", p, nil)
			resumed = append(resumed, p)
		}
	}
	return resumed
}

func (g *Guard) resumeAll() []procs.Proc {
	resumed := g.retryReleases()
	for _, gr := range g.groups {
		resumed = append(resumed, g.resume(gr)...)
	}
	return resumed
}

// anyAlarm: apps are frozen because something is wrong (not the short freeze at start).
func (g *Guard) anyAlarm() bool {
	for _, gr := range g.groups {
		if gr.status == Suspect && gr.reason != NetChanged && gr.reason != SettingsChanged && len(gr.frozen) > 0 {
			return true
		}
	}
	return false
}

func (g *Guard) ownerOf(p procs.Proc) *group {
	for _, gr := range g.groups {
		for _, t := range gr.tgts {
			if p.AppID != "" && t.ID == p.AppID {
				return gr
			}
		}
		if len(procs.Filter([]procs.Proc{p}, gr.tgts, g.d.Self)) > 0 {
			return gr
		}
	}
	for _, id := range p.PolicyIDs {
		for _, gr := range g.groups {
			for _, t := range gr.tgts {
				if t.ID == id {
					return gr
				}
			}
		}
	}
	return nil
}

// releaseUntargeted resumes frozen processes that no group claims any more.
func (g *Guard) releaseUntargeted() []procs.Proc {
	var resumed []procs.Proc
	for _, gr := range g.groups {
		for pid, p := range gr.frozen {
			if g.ownerOf(p) == nil {
				err := g.d.Procs.Resume(p)
				g.operation("resume", p, err)
				if err == nil {
					delete(gr.frozen, pid)
					g.operation("freeze", p, nil)
					resumed = append(resumed, p)
				}
			}
		}
	}
	return resumed
}

// A directly matched child must also satisfy its ancestors' policies. Policy
// checks use the complete current result, never another group's old status.
func (g *Guard) processAllowed(p procs.Proc, now time.Time) bool {
	return g.processPermitted(p, now, false)
}

func (g *Guard) processPermitted(p procs.Proc, now time.Time, fresh bool) bool {
	if g.paused(now) {
		return true
	}
	if fresh && !g.generalReady && g.verified && g.trusted() {
		return false
	}
	if g.awaitingAppCheck(p) {
		return false
	}
	if g.policyJournalFailed {
		return false
	}
	matched := false
	ids := append([]string{p.AppID}, p.PolicyIDs...)
	for _, id := range ids {
		for _, gr := range g.groups {
			for _, target := range gr.tgts {
				if target.ID != id {
					continue
				}
				matched = true
				if (fresh || !g.verified) && !g.readyGroups[gr.key] {
					return false
				}
				if g.verdict(gr, now) != NoReason {
					return false
				}
			}
		}
	}
	return matched
}

func (g *Guard) awaitingAppCheck(p procs.Proc) bool {
	if g.awaitingApps[p.AppID] {
		return true
	}
	for _, id := range p.PolicyIDs {
		if g.awaitingApps[id] {
			return true
		}
	}
	return false
}

func (g *Guard) enforce(now time.Time) {
	g.recordRelease(now, g.retryReleases(), "protection removed")
	all, err := g.d.Procs.List()
	g.operation("list", procs.Proc{}, err)
	if err != nil {
		return
	}
	var tgts []procs.Target
	groupOf := map[string]*group{}
	for _, gr := range g.groups {
		tgts = append(tgts, gr.tgts...)
		for _, t := range gr.tgts {
			groupOf[t.ID] = gr
		}
	}
	// Retain live descendants after an allowed parent exits, and retain policy
	// ancestry for frozen children. PID reuse never inherits the old identity.
	aliveNow := map[int]procs.Proc{}
	for _, p := range all {
		aliveNow[p.PID] = p
	}
	for pid, stamp := range g.pauseStarts {
		if p, ok := aliveNow[pid]; !ok || (p.Created != "" && p.Created != stamp.created) {
			delete(g.pauseStarts, pid)
		}
	}
	// Release only a positively identified own control process if an older
	// version had suspended it. The identity check remains in the controller.
	var controlReleased []procs.Proc
	for _, gr := range g.groups {
		for pid, held := range gr.frozen {
			if current, ok := aliveNow[pid]; ok && current.Control && procs.SameProcess(current, held) {
				err := g.d.Procs.Resume(held)
				g.operation("resume", held, err)
				if err == nil {
					delete(gr.frozen, pid)
					g.operation("freeze", held, nil)
					controlReleased = append(controlReleased, held)
				}
			}
		}
	}
	g.recordRelease(now, controlReleased, "control process excluded")
	remembered := map[int]procs.Proc{}
	for _, gr := range g.groups {
		for _, p := range append(append([]procs.Proc{}, gr.running...), mapValues(gr.frozen)...) {
			if current, ok := aliveNow[p.PID]; ok && procs.SameProcess(current, p) && g.ownerOf(p) != nil {
				remembered[p.PID] = p
			}
		}
	}
	seeded := append([]procs.Proc(nil), all...)
	for i, p := range seeded {
		seeded[i].App, seeded[i].AppID, seeded[i].PolicyIDs = "", "", nil
		if old, ok := remembered[p.PID]; ok {
			seeded[i].App, seeded[i].AppID = old.App, old.AppID
			seeded[i].PolicyIDs = append([]string(nil), old.PolicyIDs...)
		}
	}
	// Propagate remembered policies as part of the same tree walk, not after it.
	list := procs.Filter(seeded, tgts, g.d.Self)
	for _, p := range list {
		to := groupOf[p.AppID]
		if to == nil {
			to = g.ownerOf(p)
		}
		if to == nil {
			continue
		}
		held := false
		for _, gr := range g.groups {
			if old, ok := gr.frozen[p.PID]; ok && procs.SameProcess(old, p) {
				delete(gr.frozen, p.PID)
				held = true
			}
		}
		// An exec/new match may change the primary app without changing identity.
		// Transfer ownership without another OS suspend or an intermediate resume.
		if held {
			to.frozen[p.PID] = p
		}
	}
	for _, gr := range g.groups {
		gr.running = nil
	}
	for _, p := range list {
		if gr := groupOf[p.AppID]; gr != nil {
			gr.running = append(gr.running, p)
		} else if gr := g.ownerOf(p); gr != nil {
			for _, target := range gr.tgts {
				if slices.Contains(p.PolicyIDs, target.ID) {
					p.AppID, p.App = target.ID, target.Name
					break
				}
			}
			gr.running = append(gr.running, p)
		}
	}

	// A suspended descendant remains ours even if its parent exits. Only an OS
	// snapshot confirming that identity disappeared can drop it from the ledger.
	alive := map[int]procs.Proc{}
	for _, p := range all {
		alive[p.PID] = p
	}
	// Failed freezes have no entry in gr.frozen. Prune errors independently,
	// using only a complete snapshot and a known identity change or absence.
	for key := range g.failures {
		if key.pid <= 0 {
			continue // list/network-monitor errors are not process-specific
		}
		current, exists := alive[key.pid]
		if !exists || (current.Created != "" && current.Created != key.created) {
			delete(g.failures, key)
		}
	}
	g.rememberFrozenPolicies()
	for _, gr := range g.groups {
		for pid, p := range gr.frozen {
			current, exists := alive[pid]
			if !exists || (current.Created != "" && !procs.SameProcess(current, p)) {
				delete(gr.frozen, pid)
				for _, op := range []string{"freeze", "resume", "kill"} {
					g.operation(op, p, nil)
				}
				continue
			}
			found := false
			for _, running := range gr.running {
				if procs.SameProcess(running, p) {
					found = true
					break
				}
			}
			if !found {
				gr.running = append(gr.running, p)
			}
		}
	}
	g.updateActiveDomains(remembered)
	for _, gr := range g.groups {
		g.enforceGroup(now, gr)
	}
}

func (g *Guard) enforceGroup(now time.Time, gr *group) {
	if g.paused(now) {
		g.recordRelease(now, g.resume(gr), "protection paused")
		return
	}
	if gr.status == OK {
		g.resumePermitted(gr, now)
	}
	var frozen []procs.Proc
	alive := map[int]bool{}
	for _, p := range gr.running {
		alive[p.PID] = true
		if gr.status != OK || !g.processAllowed(p, now) {
			if _, ok := gr.frozen[p.PID]; !ok {
				err := g.d.Procs.Freeze(p)
				g.operation("freeze", p, err)
				if err == nil {
					gr.frozen[p.PID] = p
					frozen = append(frozen, p)
					if g.pauseStarts == nil {
						g.pauseStarts = make(map[int]pauseStart)
					}
					g.pauseStarts[p.PID] = pauseStart{p.Created, now}
				} else if owner, ok := g.d.Procs.(interface{ Owns(procs.Proc) bool }); ok && owner.Owns(p) {
					// The OS may have suspended it before a journal/result failure.
					gr.frozen[p.PID] = p
				}
			}
		}
	}
	for pid := range gr.frozen {
		if !alive[pid] {
			delete(gr.frozen, pid)
		}
	}
	if len(frozen) > 0 {
		e := g.event(now, gr, EvFrozen, procs.AppNames(frozen), gr.reason != NetChanged && gr.reason != SettingsChanged && gr.status != Starting)
		if gr.status == OK {
			e.Reason = ProcessPolicyDenied
			e.HeldBy = g.holdingPolicies(now, gr, frozen)
			if slices.ContainsFunc(frozen, g.awaitingAppCheck) {
				e.Reason, e.Notify = AppCheckPending, false
			}
		}
		e.Details = append(e.Details, fmt.Sprintf("processes=%d", len(frozen)))
		g.emit(now, e)
	}
}

// Persist before installing a change or announcing a grant. A failed write
// leaves both the current policy and its in-flight checks intact.
func (g *Guard) persist(c *config.Config) error {
	if g.d.SaveConfig != nil {
		if err := g.d.SaveConfig(c); err != nil {
			return fmt.Errorf("config.yaml: %w", err)
		}
	}
	return nil
}

func (g *Guard) apply(now time.Time, c *config.Config) {
	// Strip only fields which cannot affect protection. Newly added policy
	// fields participate in the comparison by default.
	previous := *g.cfg
	previous.Language, previous.MenuBar, previous.Theme = c.Language, c.MenuBar, c.Theme
	previous.Notifications, previous.UpdateCheck = c.Notifications, c.UpdateCheck
	if g.seenNetwork && reflect.DeepEqual(&previous, c) {
		g.cfg = c.Clone()
		return
	}
	g.invalidateFor(now, SettingsChanged)
	clear(g.awaitingApps)
	g.reconfigure(now, c)
	g.startProbe(now)
}

func (g *Guard) reconfigure(now time.Time, c *config.Config) {
	resumed := g.setConfig(c)
	resumed = append(resumed, g.releaseUntargeted()...)
	g.recordRelease(now, resumed, "protection removed")
	g.expireDomains(now)
	g.enforce(now)
}

// SetConfig applies an edited config.yaml.
func (g *Guard) SetConfig(now time.Time, c *config.Config) {
	g.mu.Lock()
	defer g.mu.Unlock()
	defer g.publish(now)
	g.apply(now, c.Clone())
}

// ReloadConfig serializes an external read with menu and panel saves. A nil
// config means the file has not changed since the last successful read/write.
func (g *Guard) ReloadConfig(now time.Time, read func() (*config.Config, error)) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, err := read()
	if c == nil || err != nil {
		return false, err
	}
	defer g.publish(now)
	g.apply(now, c.Clone())
	return true, nil
}

// Update changes the config from the menu or the panel and saves it.
func (g *Guard) Update(now time.Time, fn func(*config.Config)) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	defer g.publish(now)
	c := g.cfg.Clone()
	fn(c)
	if err := g.persist(c); err != nil {
		return err
	}
	g.apply(now, c)
	return nil
}

func (g *Guard) AllowCurrentIP(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	defer g.publish(now)
	if g.ip == "" {
		return false
	}
	c := g.cfg.Clone()
	added := c.Allow.AddIP(g.ip)
	if !added {
		return false
	}
	if err := g.persist(c); err != nil {
		return false
	}
	g.emit(now, Event{Kind: EvAllowedIP, IP: g.ip, Country: g.country})
	g.apply(now, c)
	return true
}

func (g *Guard) AllowCurrentCountry(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	defer g.publish(now)
	if g.country == "" {
		return false
	}
	c := g.cfg.Clone()
	added := c.Allow.AddCountry(g.country)
	if !added {
		return false
	}
	if err := g.persist(c); err != nil {
		return false
	}
	g.emit(now, Event{Kind: EvAllowedCountry, IP: g.ip, Country: g.country})
	g.apply(now, c)
	return true
}

// TrustCurrentNetwork marks the local network Zaslon is on as trusted.
func (g *Guard) TrustCurrentNetwork(now time.Time, name string) bool {
	return g.TrustNetwork(now, "", name)
}

// TrustNetwork binds a panel confirmation to the router identity displayed to
// the user. A network change while the dialog is open cannot trust another LAN.
func (g *Guard) TrustNetwork(now time.Time, expected, name string) bool {
	ok, _ := g.SaveTrustedNetwork(now, expected, name)
	return ok
}

func (g *Guard) SaveTrustedNetwork(now time.Time, expected, name string) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	defer g.publish(now)
	if g.netID == "" || g.trusted() || (expected != "" && expected != g.netID) {
		return false, nil
	}
	if name = strings.TrimSpace(name); name == "" {
		name = g.netID
	}
	c := g.cfg.Clone()
	c.TrustedNetworks = append(c.TrustedNetworks, config.TrustedNetwork{Name: name, ID: g.netID})
	if err := g.persist(c); err != nil {
		return false, err
	}
	g.emit(now, Event{Kind: EvTrusted, Network: name})
	g.apply(now, c)
	return true, nil
}

// ToggleApp turns a built-in preset on or off.
func (g *Guard) ToggleApp(now time.Time, id string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.setAppEnabled(now, id, !slices.Contains(g.cfg.Apps, id))
}

// SetAppEnabled applies the choice shown in a menu even if another UI has
// already applied it while the menu was open.
func (g *Guard) SetAppEnabled(now time.Time, id string, enabled bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.setAppEnabled(now, id, enabled)
}

func (g *Guard) setAppEnabled(now time.Time, id string, enabled bool) error {
	if _, ok := procs.PresetByID(id); !ok {
		return fmt.Errorf("unknown application %q", id)
	}
	defer g.publish(now)
	g.observeNetwork(now)
	if slices.Contains(g.cfg.Apps, id) == enabled {
		return nil
	}
	c := g.cfg.Clone()
	i := slices.Index(c.Apps, id)
	if i >= 0 {
		c.Apps = slices.Delete(c.Apps, i, i+1)
	} else {
		c.Apps = append(c.Apps, id)
	}
	if err := g.persist(c); err != nil {
		return err
	}
	if i >= 0 {
		delete(g.awaitingApps, id)
	} else {
		if g.awaitingApps == nil {
			g.awaitingApps = make(map[string]bool)
		}
		g.awaitingApps[id] = true
		delete(g.domains, id)
		g.cancelCurrentProbe()
		g.nextCheck, g.nextDomainCheck = now, time.Time{}
	}
	g.reconfigure(now, c)
	g.startProbe(now)
	return nil
}

// Pause stops protecting for d (Forever = until restart).
func (g *Guard) Pause(now time.Time, d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	defer g.publish(now)
	if d == Forever {
		g.pausedUntil = now.AddDate(100, 0, 0)
	} else {
		g.pausedUntil = now.Add(d)
	}
	var resumed []procs.Proc
	for _, gr := range g.groups {
		gr.status, gr.reason = OK, NoReason
		resumed = append(resumed, g.resume(gr)...)
		if len(gr.frozen) == 0 {
			gr.recovering = false
		}
	}
	g.recordRelease(now, resumed, "protection paused")
	g.emit(now, Event{Kind: EvPaused, Dur: d})
}

func (g *Guard) Unpause(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	defer g.publish(now)
	if g.pausedUntil.IsZero() {
		return
	}
	g.pausedUntil = time.Time{}
	g.emit(now, Event{Kind: EvUnpaused})
	g.invalidate(now)
	g.startProbe(now)
}

// CheckNow re-checks the IP on the next step.
func (g *Guard) CheckNow(now time.Time) {
	g.mu.Lock()
	g.nextCheck = now
	g.nextDomainCheck = time.Time{}
	g.mu.Unlock()
}

// Recheck invalidates proof after an event-loop interruption, even when the
// interface fingerprint and network callback revision have not changed.
func (g *Guard) Recheck(now time.Time, detail string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.invalidate(now)
	g.emit(now, Event{Kind: EvNetChanged, Details: []string{detail}})
	g.publish(now)
}

func freshProbe(start, now time.Time) bool {
	if start.IsZero() {
		return false
	}
	// Some monotonic clocks stop during sleep. Wall time also catches that
	// interruption; a large clock correction must not validate old evidence.
	elapsed := now.Sub(start)
	wall := now.Round(0).Sub(start.Round(0))
	return elapsed >= 0 && elapsed < MaxProbeAge && wall >= 0 && wall < MaxProbeAge
}

// Shutdown un-freezes everything; called on exit.
func (g *Guard) Shutdown() {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	defer g.publish(now)
	if g.cancelProbe != nil {
		g.cancelProbe()
		g.cancelProbe = nil
	}
	g.probing = false
	g.recordRelease(now, g.resumeAll(), "Zaslon exiting")
}

func (g *Guard) Snapshot(now time.Time) Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.snapshot(now)
}

func mapValues(m map[int]procs.Proc) []procs.Proc {
	out := make([]procs.Proc, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	return out
}
