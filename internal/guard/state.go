package guard

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/procs"
)

type EventKind int

const (
	EvAutoAllowed EventKind = iota // first run: current IP became the allowed one
	EvNetChanged                   // local network changed
	EvIPChanged                    // public IP changed
	EvOffline                      // internet is gone
	EvOnline                       // internet is back
	EvFrozen                       // apps frozen (Reason says why)
	EvResumed                      // owned suspensions were released successfully
	EvBlocked                      // legacy event; no longer emitted by the guard
	EvKilledNew                    // legacy event; no longer emitted by the guard
	EvUnblocked                    // allowed IP is back after a block
	EvPaused
	EvUnpaused
	EvAllowedIP
	EvAllowedCountry
	EvDNSLeak // DNS resolver is elsewhere than the VPN (dns_check: warn)
	EvTrusted // on a trusted network (or it was just added)
	EvProcessError
	EvDomainCheck // failed service measurements, including failures explicitly ignored by policy
	EvHoldReason  // existing suspensions remain necessary for a different reason
)

type Event struct {
	At              time.Time
	Kind            EventKind
	Reason          Reason
	IP, Country     string
	Issues          []DomainIssue
	Domain          string
	IP6, Country6   string
	IPv6Unknown     bool
	Others          []string
	DNS, DNSCountry string
	Network         string
	Apps            []string
	Dur             time.Duration
	Notify          bool // worth a system notification, not just a line in the history
	IgnoredChecks   bool // resumed under an explicit unavailable-result policy
	Error           string
	Details         []string // immutable diagnostic context retained in history and the log
}

// GroupState is one set of apps sharing rules, for the panel.
type DomainIssue struct {
	Endpoint string
	Reason   Reason
	Timeout  bool
}

type GroupState struct {
	Issues   []DomainIssue
	Key      string // "" for the shared rules
	Apps     []string
	Status   Status
	Reason   Reason
	Running  []string
	Frozen   int
	Domains  []DomainResult
	Warnings []Reason
}

type CheckWarning struct {
	Reason Reason
	Apps   []string
}

type Snapshot struct {
	DomainCountry   string    // Display only: a recent service measurement of the same IPv4.
	MeasuredAt      time.Time // start of the last accepted general measurement
	Status          Status    // the worst of the groups
	Reason          Reason
	IP, Country     string
	IP6, Country6   string
	IPv6Unknown     bool
	IPv6Conflicting bool
	Others          []string // addresses other IP services reported
	DNS, DNSCountry string
	DNSLeak         bool
	NetID           string
	Network         string // name of the trusted network we're on, if any
	Offline         bool
	Checking        bool
	AllowedNow      bool         // the shared rules allow the current network
	PausedUntil     time.Time    // zero if not paused
	Running         []procs.Proc // protected apps' processes right now
	Frozen          int
	FrozenApps      map[string]int
	Groups          []GroupState
	Counters        Counters
	Config          *config.Config
	History         []Event
	Errors          []string       // process control failed; never present this as healthy protection
	Warnings        []CheckWarning // unavailable results explicitly ignored by user policy
}

func (g *Guard) snapshot(now time.Time) Snapshot {
	s := Snapshot{
		Status: OK, MeasuredAt: g.measuredAt,
		IP: g.ip, Country: g.country, IP6: g.ip6, Country6: g.cc6, Others: append([]string(nil), g.others...),
		DNS: g.dns, DNSCountry: g.dnsCC, NetID: g.netID,
		Offline: g.offline, Checking: g.probing,
		IPv6Unknown:     g.ipv6Unknown,
		IPv6Conflicting: g.ipv6Conflicting,
		Counters:        g.counters,
		Config:          g.cfg.Clone(),
		History:         append([]Event(nil), g.history...),
	}
	for _, err := range g.failures {
		s.Errors = append(s.Errors, err)
	}
	sort.Strings(s.Errors)
	if n, ok := g.cfg.Trusted(g.netID); ok {
		s.Network = n.Name
	}
	s.DNSLeak = g.cfg.DNSCheck != "off" && s.Network == "" && g.dnsLeak(g.cfg.Allow)
	if g.paused(now) {
		s.PausedUntil = g.pausedUntil
	}
	first := true
	for _, gr := range g.groups {
		gs := GroupState{Key: gr.key, Apps: gr.names(), Status: gr.status, Reason: gr.reason, Frozen: len(gr.frozen)}
		idle := g.cfg.DomainCheckEnabled(gr.key) && !g.activeDomains[gr.key]
		if idle {
			gs.Status, gs.Reason = OK, NoReason
		}
		gs.Issues = g.domainIssues(gr, now)
		gs.Domains = append([]DomainResult(nil), g.domains[gr.key]...)
		if !idle && (g.verified || g.readyGroups[gr.key]) && !g.paused(now) && len(gr.tgts) > 0 {
			gs.Warnings = append([]Reason(nil), g.assess(gr, now).ignored...)
			for _, reason := range gs.Warnings {
				s.Warnings = append(s.Warnings, CheckWarning{Reason: reason, Apps: gr.names()})
			}
		}
		if gr.status == OK && len(gr.frozen) > 0 {
			gs.Status, gs.Reason = Suspect, ProcessPolicyDenied
		}
		for _, p := range gr.frozen {
			if s.FrozenApps == nil {
				s.FrozenApps = make(map[string]int)
			}
			s.FrozenApps[p.AppID]++
			if gs.Reason == ProcessPolicyDenied && g.awaitingAppCheck(p) {
				gs.Reason = AppCheckPending
			}
		}
		gs.Running = procs.AppNames(gr.running)
		s.Running = append(s.Running, gr.running...)
		s.Frozen += len(gr.frozen)
		if gr.key == "" {
			s.AllowedNow = (g.verified || g.generalReady) && g.ip != "" && !g.offline && g.verdict(gr, now) == NoReason
		}
		if !idle && len(gr.tgts) > 0 && (first || worse(gs.Status, s.Status)) {
			s.Status, s.Reason = gs.Status, gs.Reason
			first = false
		}
		s.Groups = append(s.Groups, gs)
	}
	if s.Country == "" && s.IP != "" && !s.Offline && (g.verified || g.generalReady) && len(s.Others) == 0 && g.votes >= g.cfg.Need() {
		s.DomainCountry = g.matchingDomainCountry(now)
	}
	return s
}

// DisplayCountry is presentation data. Grants and policy checks use Country.
func (s Snapshot) DisplayCountry() string {
	if s.Country != "" {
		return s.Country
	}
	return s.DomainCountry
}

func (g *Guard) matchingDomainCountry(now time.Time) string {
	var country string
	for _, gr := range g.groups {
		if !g.cfg.DomainCheckEnabled(gr.key) {
			continue
		}
		for _, d := range g.domains[gr.key] {
			if d.IP != g.ip || d.Country == "" || d.Error != "" || d.CheckedAt.Before(g.domainStarted) ||
				d.CheckedAt.After(now) || now.Sub(d.CheckedAt) >= g.domainMaxAge() || !slices.Contains(g.cfg.DomainChecks[gr.key], d.Endpoint) {
				continue
			}
			if country != "" && d.Country != country {
				return ""
			}
			country = d.Country
		}
	}
	return country
}

// Paused reports whether protection is paused.
func (s Snapshot) Paused() bool { return !s.PausedUntil.IsZero() }

// Allowed reports whether the shared rules allow the current network.
func (s Snapshot) Allowed() bool { return s.AllowedNow && len(s.Errors) == 0 && len(s.Warnings) == 0 }

// key changes whenever something visible in the menu changes.
func (s Snapshot) key() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%v|%v|%s|%s|%t|%t|", s.DomainCountry, s.Errors, s.MeasuredAt, s.Config.Language, s.Config.Theme, s.Config.Notifications, s.Config.UpdateCheck)
	fmt.Fprintf(&b, "%d|%d|%s|%s|%s|%s|%v|%s|%s|%s|%t|%d|%v|%d|%t|", s.Status, s.Reason, s.IP, s.Country, s.IP6, s.Country6,
		s.Others, s.DNS, s.DNSCountry, s.Network, s.Offline, s.Frozen, s.PausedUntil.Unix(), len(s.Running), s.Checking)
	for _, gr := range s.Groups {
		fmt.Fprintf(&b, "%d%d%v;", gr.Status, gr.Reason, gr.Running)
		fmt.Fprintf(&b, "%v%v;", gr.Domains, gr.Issues)
	}
	fmt.Fprintf(&b, "|%v|%v|%v|%v|%v|%s", s.Config.Allow, s.Config.Apps, len(s.Config.CustomApps), s.Config.AppRules, s.Config.TrustedNetworks, s.Config.MenuBar)
	fmt.Fprintf(&b, "|%v", s.Config.DomainChecks)
	fmt.Fprintf(&b, "|%v", s.Config.DomainChecksEnabled)
	fmt.Fprintf(&b, "|%v|%t|%s|%s", s.Warnings, s.IPv6Conflicting, s.Config.IPUnavailableAction, s.Config.IPv6UnavailableAction)
	return b.String()
}
