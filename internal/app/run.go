package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
	"github.com/avazar/zaslon/internal/netwatch"
	"github.com/avazar/zaslon/internal/procs"
)

const (
	tick        = 500 * time.Millisecond
	cfgPoll     = 2 * time.Second
	httpTimeout = 4 * time.Second
)

// Runner owns the guard and feeds it time, IP checks and config edits.
type Runner struct {
	G             *guard.Guard
	results       chan guard.ProbeResult
	geo           *netwatch.Geo
	ctx           context.Context
	changes       *netwatch.Events
	modMu         sync.Mutex // save runs on the menu's goroutine too
	cfgMod        time.Time
	OnConfigError func(error)
	traceIP       func(context.Context, string, time.Duration, bool) (netwatch.TraceResult, error)
	ipv6Possible  func() (bool, error)
	dnsResolver   func(context.Context) string
}

func NewRunner(ctx context.Context, cfg *config.Config, processes procs.Controller) *Runner {
	r := &Runner{results: make(chan guard.ProbeResult, 4), geo: netwatch.NewGeo(), ctx: ctx, changes: netwatch.Watch(ctx)}
	if r.changes.FilterStatus != "" {
		Logf("%s", r.changes.FilterStatus)
	}
	if st, err := os.Stat(ConfigPath()); err == nil {
		r.cfgMod = st.ModTime()
	}
	r.G = guard.New(cfg, guard.Deps{
		Fingerprint:    netwatch.Fingerprint,
		NetworkVersion: r.changes.Version,
		NetworkDetails: r.changes.Details,
		NetworkError:   r.changes.Error,
		StartProbe:     r.probe,
		Procs:          processes,
		SaveConfig:     r.save,
		Self:           os.Getpid(),
	})
	return r
}

func (r *Runner) probe(c *config.Config, id uint64, plan guard.ProbePlan) func() {
	ctx, cancel := context.WithTimeout(r.ctx, 12*time.Second)
	go func() {
		defer cancel()
		res := guard.ProbeResult{ID: id, RouteProxy: netwatch.ProxyIdentity(netwatch.SystemProxy())}
		possible, possibleErr := false, error(nil)
		if c.CheckIPv6 {
			if r.ipv6Possible != nil {
				possible, possibleErr = r.ipv6Possible()
			} else {
				possible, possibleErr = netwatch.IPv6Possible()
			}
		}
		trace := r.traceIP
		res.IPv6Possible = possible || possibleErr != nil
		if trace == nil {
			trace = netwatch.TraceIP
		}
		active := map[string][]string{}
		type measurement struct {
			endpoint string
			result   guard.DomainResult
			done     chan struct{}
		}
		var measurements []measurement
		indices := map[string]int{}
		if len(plan.Apps) > 0 {
			for _, t := range procs.Targets(c) {
				if !plan.Apps[t.ID] || !c.DomainCheckEnabled(t.ID) {
					continue
				}
				for _, endpoint := range c.DomainChecks[t.ID] {
					active[t.ID] = append(active[t.ID], endpoint)
					if _, seen := indices[endpoint]; !seen {
						indices[endpoint] = len(measurements)
						measurements = append(measurements, measurement{endpoint: endpoint, done: make(chan struct{})})
					}
				}
			}
		}
		send := func(part guard.ProbeResult) {
			if ctx.Err() != nil {
				return
			}
			part.ID = id
			select {
			case r.results <- part:
			case <-ctx.Done():
			}
		}
		var domainWG sync.WaitGroup
		dnsReady := make(chan struct{})
		for i := range measurements {
			m := &measurements[i]
			go func() {
				defer close(m.done)
				measure := func(v6 bool) guard.DomainResult {
					for attempt := 0; ; attempt++ {
						d := guard.DomainResult{Endpoint: m.endpoint, CheckedAt: time.Now(), RouteProxy: res.RouteProxy}
						value, err := trace(ctx, m.endpoint, httpTimeout, v6)
						if v6 {
							d.Retried[1] = attempt > 0
							d.RouteTime[1] = time.Since(d.CheckedAt)
							if err == nil {
								d.IP6, d.Country6 = value.IP, value.Country
							} else if !errors.Is(err, netwatch.ErrNoIPv6) {
								d.IPv6Error, d.IPv6Timeout = err.Error(), isProbeTimeout(err)
							}
						} else {
							d.Retried[0] = attempt > 0
							d.RouteTime[0] = time.Since(d.CheckedAt)
							if err != nil {
								d.Error, d.Timeout = err.Error(), isProbeTimeout(err)
							} else {
								d.IP, d.Country = value.IP, value.Country
							}
						}
						part := guard.ProbeResult{Part: guard.DomainFamily, Sample: d, SampleIPv6: v6}
						if attempt == 0 && (d.Timeout || d.IPv6Timeout) {
							part.Retry = make(chan bool, 1)
						}
						send(part)
						if part.Retry != nil {
							select {
							case retry := <-part.Retry:
								if retry {
									continue
								}
							case <-ctx.Done():
							}
						}
						return d
					}
				}
				var v6Result chan guard.DomainResult
				if res.IPv6Possible {
					v6Result = make(chan guard.DomainResult, 1)
					go func() { v6Result <- measure(true) }()
				}
				d := measure(false)
				if v6Result != nil {
					v := <-v6Result
					d.RouteTime[1] = v.RouteTime[1]
					d.Retried[1] = v.Retried[1]
					if v.CheckedAt.Before(d.CheckedAt) {
						d.CheckedAt = v.CheckedAt
					}
					d.IP6, d.Country6, d.IPv6Error, d.IPv6Timeout = v.IP6, v.Country6, v.IPv6Error, v.IPv6Timeout
				}
				m.result = d
			}()
		}
		for app, endpoints := range active {
			domainWG.Go(func() {
				values := make([]guard.DomainResult, 0, len(endpoints))
				for _, endpoint := range endpoints {
					m := &measurements[indices[endpoint]]
					<-m.done
					values = append(values, m.result)
				}
				part := guard.ProbeResult{Part: guard.DomainGroup, Domains: map[string][]guard.DomainResult{app: values}, IPv6Possible: res.IPv6Possible}
				if c.DNSCheck == "block" {
					<-dnsReady
					part.DNS, part.DNSCountry = res.DNS, res.DNSCountry
				}
				send(part)
			})
		}
		var wg sync.WaitGroup
		if plan.General {
			wg.Go(func() {
				start := time.Now()
				v4, err := netwatch.PublicIP(ctx, c.IPServices, httpTimeout, false)
				res.RouteTime[0] = time.Since(start)
				res.IP, res.Votes, res.Others, res.Err = v4.IP, v4.Votes, v4.Others, err
				if err == nil {
					res.Country = r.geo.Country(ctx, v4.IP, httpTimeout)
				}
			})
			if c.CheckIPv6 {
				wg.Go(func() {
					start := time.Now()
					v6, err := netwatch.PublicIP(ctx, c.IPv6Services, httpTimeout, true)
					res.RouteTime[1] = time.Since(start)
					if err == nil {
						res.IP6 = v6.IP
						res.IPv6Conflicting = len(v6.Others) != 0
						res.Country6 = r.geo.Country(ctx, v6.IP, httpTimeout)
					} else {
						res.IPv6Unknown = res.IPv6Possible
					}
				})
			}
			wg.Go(func() { res.NetID = netwatch.NetworkID() })
		}
		wg.Go(func() {
			defer close(dnsReady)
			if c.DNSCheck == "block" || (plan.General && c.DNSCheck == "warn") {
				dnsCtx, stop := context.WithTimeout(ctx, httpTimeout)
				resolve := r.dnsResolver
				if resolve == nil {
					resolve = netwatch.DNSResolver
				}
				res.DNS = resolve(dnsCtx)
				stop()
				if res.DNS != "" {
					res.DNSCountry = r.geo.Country(ctx, res.DNS, httpTimeout)
				}
			}
		})
		wg.Wait()
		if len(plan.Apps) > 0 {
			if plan.General {
				general := res
				general.Part = guard.GeneralMeasurement
				send(general)
			}
			domainWG.Wait()
			res.Domains = make(map[string][]guard.DomainResult, len(active))
			for app, endpoints := range active {
				for _, endpoint := range endpoints {
					res.Domains[app] = append(res.Domains[app], measurements[indices[endpoint]].result)
				}
			}
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return
		}
		select {
		case r.results <- res:
		case <-r.ctx.Done():
		}
	}()
	return cancel
}

func isProbeTimeout(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	var transport net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &transport) && transport.Timeout())
}

func (r *Runner) save(c *config.Config) error {
	r.modMu.Lock()
	defer r.modMu.Unlock()
	err := config.Save(ConfigPath(), c)
	if err != nil {
		return err
	}
	if st, e := os.Stat(ConfigPath()); e == nil {
		r.cfgMod = st.ModTime() // our own write is not an "edit" to reload
	}
	return nil
}

func (r *Runner) readEditedConfig() (*config.Config, error) {
	r.modMu.Lock()
	defer r.modMu.Unlock()
	st, err := os.Stat(ConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if st.ModTime().Equal(r.cfgMod) {
		return nil, nil
	}
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		return nil, err
	}
	r.cfgMod = st.ModTime()
	return config.Parse(data)
}

func (r *Runner) reloadIfEdited(now time.Time) {
	changed, err := r.G.ReloadConfig(now, r.readEditedConfig)
	if err != nil {
		Logf("config.yaml: %v", err)
		if r.OnConfigError != nil {
			r.OnConfigError(err)
		}
	} else if changed {
		Logf("config.yaml перечитан")
	}
}

// Run blocks until ctx is cancelled, then un-freezes everything.
func (r *Runner) Run() {
	t := time.NewTicker(tick)
	defer t.Stop()
	cp := time.NewTicker(cfgPoll)
	defer cp.Stop()
	r.run(t.C, cp.C, time.Now)
}

// Timer values describe when delivery was scheduled, which can precede a
// successful probe already handled by this loop. Evaluate state at processing
// time, retaining strict checks for genuinely future or expired measurements.
func (r *Runner) run(ticks, configPolls <-chan time.Time, now func() time.Time) {
	defer r.G.Shutdown()
	lastActivity := now()
	r.G.Step(lastActivity)
	processedAt := func() time.Time {
		current := now()
		// Check every delivered event, not just ticks: a queued probe may be
		// selected before the first post-sleep timer. Wall time covers Unix
		// monotonic clocks that pause while the machine sleeps.
		gap := current.Sub(lastActivity)
		wall := current.Round(0).Sub(lastActivity.Round(0))
		if gap > 3*time.Second || wall > 3*time.Second || wall < -3*time.Second {
			r.G.Recheck(current, "source=event-loop kind=interruption; fresh verification required")
		}
		lastActivity = current
		return current
	}
	var ignored uint64
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.changes.C:
			r.G.Step(processedAt()) // never discard a relevant event due to a throttle
		case <-ticks:
			r.G.Step(processedAt())
		case res := <-r.results:
			r.G.HandleProbe(processedAt(), res)
		case <-configPolls:
			r.reloadIfEdited(processedAt())
			if note := r.changes.RefreshFilter(); note != "" {
				Logf("%s", note)
			}
			if count, detail := r.changes.Ignored(); count != ignored {
				Logf("Network notifications filtered: count=%d total=%d reason=local-only-Teredo-IPv6 | last: %s", count-ignored, count, detail)
				ignored = count
			}
		}
	}
}

// State is what `zaslon status` reads from state.json.
type State struct {
	DomainCountry string    `json:"domain_country,omitempty"`
	MeasuredAt    time.Time `json:"measured_at,omitempty"`
	IP6           string    `json:"ipv6,omitempty"`
	Country6      string    `json:"country6,omitempty"`
	Updated       time.Time `json:"updated"`
	Status        string    `json:"status"`
	Line          string    `json:"line"`
	IP            string    `json:"ip"`
	Country       string    `json:"country"`
	Allowed       bool      `json:"allowed"`
	Apps          []string  `json:"running_apps"`
	Frozen        int       `json:"frozen"`
	PID           int       `json:"pid"`
	Paused        bool      `json:"paused"`
	ConfigLoc     string    `json:"config"`
}

func WriteState(s State) {
	s.Updated = time.Now()
	s.PID = os.Getpid()
	s.ConfigLoc = ConfigPath()
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := StatePath() + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, StatePath())
	}
}

func ReadState() (State, error) {
	var s State
	b, err := os.ReadFile(StatePath())
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}
