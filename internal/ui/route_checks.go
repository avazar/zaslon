package ui

import (
	"context"
	"errors"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/avazar/zaslon/internal/app"
	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
	"github.com/avazar/zaslon/internal/netwatch"
	"github.com/avazar/zaslon/internal/procs"
)

type routeFamily struct {
	IP      string `json:"ip,omitempty"`
	Country string `json:"country,omitempty"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
	MS      *int64 `json:"ms,omitempty"`
	Average *int64 `json:"average,omitempty"`
}

type routeSample struct {
	at      time.Time
	proxy   string
	family  [2]routeFamily
	retried [2]bool
}

type routeApp struct {
	Name    string    `json:"name"`
	Status  string    `json:"status,omitempty"`
	Verdict [2]string `json:"verdict"`
	rule    config.Allow
}

type routeRow struct {
	Endpoint string         `json:"endpoint"`
	Apps     []routeApp     `json:"apps"`
	Family   [2]routeFamily `json:"family"`
	At       *time.Time     `json:"at,omitempty"`
	Stale    bool           `json:"stale,omitempty"`
}

type routeStore struct {
	mu     sync.Mutex
	since  time.Time
	series map[string][]routeSample
	job    *routeJob
}

type routeJob struct {
	done chan struct{}
	err  error
}

func activeRouteApps(s guard.Snapshot) map[string]bool {
	active := make(map[string]bool)
	for _, p := range s.Running {
		active[p.AppID] = true
		for _, id := range p.PolicyIDs {
			active[id] = true
		}
	}
	return active
}

func configuredRows(s guard.Snapshot) []routeRow {
	rows := []routeRow{{Apps: []routeApp{{rule: s.Config.Allow}}}}
	indices := map[string]int{}
	active := activeRouteApps(s)
	for _, target := range procs.Targets(s.Config) {
		a := routeApp{Name: target.Name, rule: s.Config.Allow}
		if rule, ok := s.Config.AppRules[target.ID]; ok {
			a.rule = rule
		}
		if !s.Config.DomainCheckEnabled(target.ID) {
			a.Status = "disabled"
		} else if !active[target.ID] {
			a.Status = "idle"
		}
		for _, ep := range s.Config.DomainChecks[target.ID] {
			i, ok := indices[ep]
			if !ok {
				i = len(rows)
				indices[ep] = i
				rows = append(rows, routeRow{Endpoint: ep})
			}
			rows[i].Apps = append(rows[i].Apps, a)
		}
	}
	return rows
}

func sampleFamily(ip, cc, detail string, timeout bool, duration time.Duration) routeFamily {
	f := routeFamily{IP: ip, Country: cc, Detail: detail, Status: "unavailable"}
	switch {
	case timeout:
		f.Status = "timeout"
	case detail != "":
		f.Status = "error"
	case ip != "":
		f.Status = "measured"
		if duration > 0 {
			ms := duration.Round(time.Millisecond).Milliseconds()
			f.MS = &ms
		}
	}
	return f
}

func generalSample(at time.Time, r guard.ProbeResult, need int) routeSample {
	four := sampleFamily(r.IP, r.Country, "", false, r.RouteTime[0])
	six := sampleFamily(r.IP6, r.Country6, "", false, r.RouteTime[1])
	if len(r.Others) > 0 {
		four.Status = "conflict"
	} else if r.IP != "" && r.Votes < need {
		four.Status = "quorum"
	}
	if r.IPv6Conflicting {
		six.Status = "conflict"
	} else if r.IPv6Unknown {
		six.Status = "unknown"
	}
	return routeSample{at: at, proxy: r.RouteProxy, family: [2]routeFamily{four, six}}
}

func domainSample(d guard.DomainResult) routeSample {
	return routeSample{at: d.CheckedAt, proxy: d.RouteProxy, retried: d.Retried, family: [2]routeFamily{
		sampleFamily(d.IP, d.Country, d.Error, d.Timeout, d.RouteTime[0]),
		sampleFamily(d.IP6, d.Country6, d.IPv6Error, d.IPv6Timeout, d.RouteTime[1]),
	}}
}

// Samples can arrive out of order from the independent manual and guard workers.
func (store *routeStore) add(endpoint string, m routeSample) {
	if m.at.IsZero() || m.at.Before(store.since) {
		return
	}
	series := store.series[endpoint]
	i, found := slices.BinarySearchFunc(series, m.at, func(s routeSample, t time.Time) int { return s.at.Compare(t) })
	if found || (len(series) == 5 && i == 0) {
		return
	}
	series = slices.Insert(series, i, m)
	if len(series) > 5 {
		series = series[1:]
	}
	store.series[endpoint] = series
}

func (s *Server) ObserveRoutes(snap guard.Snapshot) {
	store := &s.routes
	store.mu.Lock()
	defer store.mu.Unlock()
	if snap.RoutesSince.Before(store.since) {
		return
	}
	if store.series == nil || !store.since.Equal(snap.RoutesSince) {
		store.series = map[string][]routeSample{}
		store.since = snap.RoutesSince
	}
	store.add("", generalSample(snap.MeasuredAt, guard.ProbeResult{IP: snap.IP, Country: snap.Country, IP6: snap.IP6, Country6: snap.Country6,
		Votes: snap.Votes, Others: snap.Others, IPv6Unknown: snap.IPv6Unknown, IPv6Conflicting: snap.IPv6Conflicting, RouteTime: snap.RouteTime, RouteProxy: snap.RouteProxy}, snap.Config.Need()))
	active := activeRouteApps(snap)
	live := map[string]bool{"": true}
	for _, group := range snap.Groups {
		if !active[group.Key] || !snap.Config.DomainCheckEnabled(group.Key) {
			continue
		}
		for _, ep := range snap.Config.DomainChecks[group.Key] {
			live[ep] = true
		}
		for _, d := range group.Domains {
			if live[d.Endpoint] {
				store.add(d.Endpoint, domainSample(d))
			}
		}
	}
	for ep := range store.series {
		if !live[ep] {
			delete(store.series, ep)
		}
	}
}

func routeVerdict(a routeApp, f routeFamily) string {
	if a.Status != "" {
		return a.Status
	}
	if f.Status != "measured" {
		return f.Status
	}
	if a.rule.Matches(f.IP, f.Country) {
		return "allowed"
	}
	if f.Country == "" && len(a.rule.Countries) > 0 {
		return "countryUnknown"
	}
	return "denied"
}

func (s *Server) routeView(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	snap := s.G.Snapshot(now)
	s.ObserveRoutes(snap)
	proxy := netwatch.ProxyIdentity(netwatch.SystemProxy())
	rows := configuredRows(snap)
	store := &s.routes
	store.mu.Lock()
	for i := range rows {
		row := &rows[i]
		series := store.series[row.Endpoint]
		for f := range row.Family {
			row.Family[f].Status = "pending"
		}
		if len(series) > 0 && series[len(series)-1].proxy == proxy {
			last := series[len(series)-1]
			row.At = &last.at
			interval := snap.Config.DomainCheckInterval.D()
			if i == 0 {
				interval = snap.Config.CheckInterval.D()
			}
			row.Stale = now.Sub(last.at) >= interval+guard.MaxProbeAge
			row.Family = last.family
			for f := range row.Family {
				var total, count int64
				attempts := 0
				for j := len(series) - 1; j >= 0 && attempts < 5 && series[j].proxy == proxy; j-- {
					attempts++
					if ms := series[j].family[f].MS; ms != nil {
						total += *ms
						count++
					}
					if series[j].retried[f] {
						attempts++
					}
				}
				if count > 0 {
					avg := (total + count/2) / count
					row.Family[f].Average = &avg
				}
			}
		}
		if !snap.Config.CheckIPv6 {
			row.Family[1] = routeFamily{Status: "disabled"}
		}
		for j, a := range row.Apps {
			for f, v := range row.Family {
				row.Apps[j].Verdict[f] = routeVerdict(a, v)
			}
		}
	}
	busy := store.job != nil
	store.mu.Unlock()
	writeJSON(w, map[string]any{"rows": rows, "proxy": proxy != "", "network": routeNetwork(snap, proxy), "busy": busy})
}

func routeNetwork(snap guard.Snapshot, proxy string) string {
	return snap.RoutesSince.UTC().Format(time.RFC3339Nano) + "|" + snap.NetID + "|" + proxy
}

func (s *Server) runRoutes(w http.ResponseWriter, r *http.Request) {
	store := &s.routes
	store.mu.Lock()
	job := store.job
	if job != nil {
		store.mu.Unlock()
		select {
		case <-r.Context().Done():
			return
		case <-job.done:
		}
	} else {
		job = &routeJob{done: make(chan struct{})}
		store.job = job
		store.mu.Unlock()
		job.err = s.measureRoutes(r.Context())
		store.mu.Lock()
		store.job = nil
		close(job.done)
		store.mu.Unlock()
	}
	if job.err != nil {
		http.Error(w, job.err.Error(), http.StatusConflict)
		return
	}
	s.routeView(w, r)
}

func (s *Server) measureRoutes(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 16*time.Second)
	defer cancel()
	start := time.Now()
	snap := s.G.Snapshot(start)
	scope := routeNetwork(snap, netwatch.ProxyIdentity(netwatch.SystemProxy()))
	result, err := app.MeasureRoutes(ctx, snap.Config, activeRouteApps(snap))
	if err != nil {
		return err
	}
	current := s.G.Snapshot(time.Now())
	if scope != routeNetwork(current, netwatch.ProxyIdentity(netwatch.SystemProxy())) || scope != routeNetwork(snap, result.RouteProxy) {
		return errors.New("networkChanged")
	}
	s.ObserveRoutes(current)
	store := &s.routes
	store.mu.Lock()
	defer store.mu.Unlock()
	store.add("", generalSample(start, result, snap.Config.Need()))
	active := activeRouteApps(current)
	for id, domains := range result.Domains {
		if !active[id] || !current.Config.DomainCheckEnabled(id) {
			continue
		}
		for _, d := range domains {
			if slices.Contains(current.Config.DomainChecks[id], d.Endpoint) {
				store.add(d.Endpoint, domainSample(d))
			}
		}
	}
	return nil
}

func (s *Server) compareRoutes(w http.ResponseWriter, r *http.Request) {
	proxy := netwatch.SystemProxy()
	if proxy == nil {
		http.Error(w, "noProxy", http.StatusConflict)
		return
	}
	scope := routeNetwork(s.G.Snapshot(time.Now()), netwatch.ProxyIdentity(proxy))
	if r.URL.Query().Get("network") != scope {
		http.Error(w, "networkChanged", http.StatusConflict)
		return
	}
	a, b, e1, e2 := netwatch.CompareIPv4(r.Context(), proxy, 5*time.Second)
	if scope != routeNetwork(s.G.Snapshot(time.Now()), netwatch.ProxyIdentity(netwatch.SystemProxy())) {
		http.Error(w, "networkChanged", http.StatusConflict)
		return
	}
	family := func(v netwatch.TraceResult, e error) routeFamily {
		var timeout net.Error
		if e != nil {
			return sampleFamily("", "", e.Error(), errors.As(e, &timeout) && timeout.Timeout(), 0)
		}
		return sampleFamily(v.IP, v.Country, "", false, 0)
	}
	writeJSON(w, map[string]any{"proxy": family(a, e1), "direct": family(b, e2), "network": scope})
}
