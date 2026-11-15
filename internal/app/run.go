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

func (r *Runner) probe(c *config.Config, id uint64, domains bool) func() {
	ctx, cancel := context.WithTimeout(r.ctx, 12*time.Second)
	go func() {
		defer cancel()
		res := guard.ProbeResult{ID: id}
		var v6 netwatch.IPResult
		var err6 error = netwatch.ErrOffline
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
		}
		var measurements []measurement
		indices := map[string]int{}
		if domains {
			for _, t := range procs.Targets(c) {
				if !c.DomainCheckEnabled(t.ID) {
					continue
				}
				for _, endpoint := range c.DomainChecks[t.ID] {
					active[t.ID] = append(active[t.ID], endpoint)
					if _, seen := indices[endpoint]; !seen {
						indices[endpoint] = len(measurements)
						measurements = append(measurements, measurement{endpoint: endpoint})
					}
				}
			}
		}
		var wg sync.WaitGroup
		for i := range measurements {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				endpoint := measurements[i].endpoint
				d := guard.DomainResult{Endpoint: endpoint, CheckedAt: time.Now()}
				var parts sync.WaitGroup
				parts.Add(1)
				go func() {
					defer parts.Done()
					result, err := trace(ctx, endpoint, httpTimeout, false)
					if err != nil {
						d.Error = err.Error()
						d.Timeout = isProbeTimeout(err)
					} else {
						d.IP, d.Country = result.IP, result.Country
					}
				}()
				if c.CheckIPv6 && (possible || possibleErr != nil) {
					parts.Add(1)
					go func() {
						defer parts.Done()
						result, err := trace(ctx, endpoint, httpTimeout, true)
						if err != nil && !errors.Is(err, netwatch.ErrNoIPv6) {
							d.IPv6Error = err.Error()
							d.IPv6Timeout = isProbeTimeout(err)
						} else if err == nil {
							d.IP6, d.Country6 = result.IP, result.Country
						}
					}()
				}
				parts.Wait()
				measurements[i].result = d
			}(i)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			var v4 netwatch.IPResult
			v4, res.Err = netwatch.PublicIP(ctx, c.IPServices, httpTimeout, false)
			res.IP, res.Votes, res.Others = v4.IP, v4.Votes, v4.Others
		}()
		if c.CheckIPv6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// One answer is enough here: the point is to see whether IPv6 goes around the VPN.
				v6, err6 = netwatch.PublicIP(ctx, c.IPv6Services, httpTimeout, true)
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			res.NetID = netwatch.NetworkID()
			if c.DNSCheck != "off" {
				dnsCtx, dnsCancel := context.WithTimeout(ctx, httpTimeout)
				res.DNS = netwatch.DNSResolver(dnsCtx)
				dnsCancel()
			}
		}()
		wg.Wait()
		// Geolocation must not serialize several four-second failures ahead of
		// already completed service checks. Trace responses supply their own loc.
		var geoWG sync.WaitGroup
		if res.Err == nil {
			geoWG.Add(1)
			go func() { defer geoWG.Done(); res.Country = r.geo.Country(ctx, res.IP, httpTimeout) }()
		}
		if res.DNS != "" {
			geoWG.Add(1)
			go func() { defer geoWG.Done(); res.DNSCountry = r.geo.Country(ctx, res.DNS, httpTimeout) }()
		}
		if err6 == nil {
			res.IP6 = v6.IP
			// A conflicting IPv6 exit must not be hidden by the winning address.
			res.IPv6Conflicting = len(v6.Others) != 0
			geoWG.Add(1)
			go func() { defer geoWG.Done(); res.Country6 = r.geo.Country(ctx, v6.IP, httpTimeout) }()
		} else if c.CheckIPv6 {
			res.IPv6Unknown = possible || possibleErr != nil
		}
		geoWG.Wait()
		if domains {
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
	if st, e := os.Stat(ConfigPath()); e == nil {
		r.cfgMod = st.ModTime() // our own write is not an "edit" to reload
	}
	return err
}

func (r *Runner) reloadIfEdited(now time.Time) {
	r.modMu.Lock()
	st, err := os.Stat(ConfigPath())
	if err != nil || st.ModTime().Equal(r.cfgMod) {
		r.modMu.Unlock()
		return
	}
	r.cfgMod = st.ModTime()
	r.modMu.Unlock()
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		return
	}
	c, err := config.Parse(data)
	if err != nil {
		Logf("config.yaml: %v", err)
		if r.OnConfigError != nil {
			r.OnConfigError(err)
		}
		return
	}
	Logf("config.yaml перечитан")
	r.G.SetConfig(now, c)
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
	r.G.Step(now())
	var ignored uint64
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.changes.C:
			r.G.Step(now()) // never discard a relevant event due to a throttle
		case <-ticks:
			r.G.Step(now())
		case res := <-r.results:
			r.G.HandleProbe(now(), res)
		case <-configPolls:
			r.reloadIfEdited(now())
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
	Updated   time.Time `json:"updated"`
	Status    string    `json:"status"`
	Line      string    `json:"line"`
	IP        string    `json:"ip"`
	Country   string    `json:"country"`
	Allowed   bool      `json:"allowed"`
	Apps      []string  `json:"running_apps"`
	Frozen    int       `json:"frozen"`
	PID       int       `json:"pid"`
	Paused    bool      `json:"paused"`
	ConfigLoc string    `json:"config"`
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
