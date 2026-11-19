package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
	"github.com/avazar/zaslon/internal/netwatch"
)

func TestManualRouteCheckMeasuresOnlyRunningSharedEndpoint(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "h=%s\nip=203.0.113.10\nloc=NL\n", r.Host)
	}))
	defer server.Close()
	cfg := config.Default()
	cfg.Apps = []string{"chatgpt", "codex", "claude"}
	cfg.DomainChecksEnabled = map[string]bool{"chatgpt": true, "codex": true, "claude": true}
	ep := server.URL + "/cdn-cgi/trace"
	cfg.DomainChecks = map[string][]string{"chatgpt": {ep}, "codex": {ep}, "claude": {ep}}
	cfg.CheckIPv6 = false
	cfg.IPServices = []string{"unsupported:fixture"}
	res, err := MeasureRoutes(t.Context(), cfg, map[string]bool{"chatgpt": true, "codex": true})
	if err != nil || hits.Load() != 1 || len(res.Domains) != 2 {
		t.Fatalf("hits=%d: %+v, %v", hits.Load(), res, err)
	}
	for _, id := range []string{"chatgpt", "codex"} {
		d := res.Domains[id][0]
		if d.IP != "203.0.113.10" || d.Country != "NL" || d.RouteTime[0] <= 0 || d.RouteTime[1] != 0 {
			t.Fatal(d)
		}
	}
	if cfg.DNSCheck != "warn" {
		t.Fatal("diagnostics changed live config")
	}
}

func TestProbeTimeoutClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{context.DeadlineExceeded, true},
		{&url.Error{Op: "Get", URL: "https://fixture.example", Err: context.DeadlineExceeded}, true},
		{&net.DNSError{Err: "fixture timeout", IsTimeout: true}, true},
		{fmt.Errorf("wrapped: %w", context.Canceled), false},
		{errors.New("HTTP 403"), false},
		{errors.New("a string containing timeout"), false},
	} {
		if isProbeTimeout(tc.err) != tc.want {
			t.Fatalf("timeout classification of %v", tc.err)
		}
	}
}

func TestProbeChecksOnlyActiveDomainsAndDeduplicatesRequests(t *testing.T) {
	c := config.Default()
	c.Apps = nil
	c.CustomApps = []config.CustomApp{{Name: "a", Match: []string{"a.exe"}}, {Name: "b", Match: []string{"b.exe"}}}
	endpoint := "https://shared.example/cdn-cgi/trace"
	c.DomainChecks = map[string][]string{"a": {endpoint}, "b": {endpoint}, "disabled": {"https://unused.example/cdn-cgi/trace"}}
	c.DomainChecksEnabled = map[string]bool{"a": true, "b": true, "disabled": true}
	c.IPServices = []string{"unsupported:ip"}
	c.IPv6Services = []string{"unsupported:ip6"}
	c.DNSCheck = "off"
	var calls atomic.Int32
	r := &Runner{ctx: context.Background(), geo: netwatch.NewGeo(), results: make(chan guard.ProbeResult, 2), ipv6Possible: func() (bool, error) { return true, nil }}
	r.traceIP = func(_ context.Context, got string, _ time.Duration, v6 bool) (netwatch.TraceResult, error) {
		calls.Add(1)
		if got != endpoint {
			t.Errorf("inactive endpoint %q", got)
		}
		if v6 {
			return netwatch.TraceResult{}, netwatch.ErrNoIPv6
		}
		return netwatch.TraceResult{IP: "203.0.113.10", Country: "NL"}, nil
	}
	cancel := r.probe(c, 42, guard.ProbePlan{General: true, Apps: map[string]bool{"a": true, "b": true, "claude": true, "cursor": true}})
	defer cancel()
	res := completedProbe(t, r)
	if res.ID != 42 || res.Err == nil || len(res.Domains) != 2 || calls.Load() != 2 {
		t.Fatalf("wrong result: %+v, calls=%d", res, calls.Load())
	}
	for _, id := range []string{"a", "b"} {
		d := res.Domains[id]
		if len(d) != 1 || d[0].IP != "203.0.113.10" || d[0].IPv6Error != "" || d[0].CheckedAt.IsZero() {
			t.Fatalf("%s: %+v", id, d)
		}
	}
	calls.Store(0)
	c.DomainChecksEnabled["a"], c.DomainChecksEnabled["b"] = false, false
	cancelOff := r.probe(c, 44, guard.ProbePlan{General: true, Apps: map[string]bool{"a": true, "b": true, "claude": true, "cursor": true}})
	defer cancelOff()
	res = completedProbe(t, r)
	if len(res.Domains) != 0 || calls.Load() != 0 || len(c.DomainChecks["a"]) != 1 {
		t.Fatal("disabled saved lists were queried or discarded")
	}
	cancel2 := r.probe(c, 43, guard.ProbePlan{General: true})
	defer cancel2()
	res = completedProbe(t, r)
	if res.Domains != nil || calls.Load() != 0 {
		t.Fatal("periodic general check queried service domains")
	}
}

func TestProbeKeepsIPv6FailureAndDiscardsCancellation(t *testing.T) {
	c := config.Default()
	c.Apps = []string{"claude"}
	c.IPServices = []string{"unsupported:ip"}
	c.IPv6Services = []string{"unsupported:ip6"}
	c.DNSCheck = "off"
	c.DomainChecks = map[string][]string{"claude": {"https://claude.example/cdn-cgi/trace"}}
	c.DomainChecksEnabled["claude"] = true
	r := &Runner{ctx: context.Background(), geo: netwatch.NewGeo(), results: make(chan guard.ProbeResult, 1), ipv6Possible: func() (bool, error) { return true, nil }}
	r.traceIP = func(_ context.Context, _ string, _ time.Duration, v6 bool) (netwatch.TraceResult, error) {
		if v6 {
			return netwatch.TraceResult{}, &net.DNSError{Err: "IPv6 timeout", IsTimeout: true}
		}
		return netwatch.TraceResult{IP: "203.0.113.10"}, nil
	}
	cancel := r.probe(c, 1, guard.ProbePlan{General: true, Apps: map[string]bool{"a": true, "b": true, "claude": true, "cursor": true}})
	defer cancel()
	res := completedProbe(t, r)
	if res.Domains["claude"][0].IPv6Error == "" || !res.Domains["claude"][0].IPv6Timeout {
		t.Fatal("IPv6 error disappeared")
	}
	ctx, stop := context.WithCancel(context.Background())
	r.ctx = ctx
	r.traceIP = func(ctx context.Context, _ string, _ time.Duration, _ bool) (netwatch.TraceResult, error) {
		<-ctx.Done()
		return netwatch.TraceResult{}, ctx.Err()
	}
	cancelled := r.probe(c, 2, guard.ProbePlan{General: true, Apps: map[string]bool{"a": true, "b": true, "claude": true, "cursor": true}})
	stop()
	defer cancelled()
	select {
	case res := <-r.results:
		t.Fatalf("cancelled probe published %+v", res)
	case <-time.After(100 * time.Millisecond):
	}
}

func completedProbe(t *testing.T, r *Runner) guard.ProbeResult {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case res := <-r.results:
			if res.Retry != nil {
				res.Retry <- false
			}
			if res.Part == guard.CompleteProbe {
				return res
			}
		case <-deadline:
			t.Fatal("probe did not finish")
		}
	}
}

func TestDomainDeliveryIsIndependentOfOtherAppsAndWarningDNS(t *testing.T) {
	for _, mode := range []string{"warn", "block"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			slowDNS, slowApp := make(chan struct{}), make(chan struct{})
			cfg := config.Default()
			cfg.Apps = []string{"claude", "cursor"}
			cfg.DomainChecks = map[string][]string{"claude": {"fast"}, "cursor": {"slow"}}
			cfg.DomainChecksEnabled = map[string]bool{"claude": true, "cursor": true}
			cfg.IPServices = []string{"unsupported:ip"}
			cfg.CheckIPv6 = false
			cfg.DNSCheck = mode
			r := &Runner{ctx: ctx, geo: netwatch.NewGeo(), results: make(chan guard.ProbeResult, 16)}
			r.dnsResolver = func(ctx context.Context) string {
				select {
				case <-slowDNS:
				case <-ctx.Done():
				}
				return ""
			}
			r.traceIP = func(ctx context.Context, name string, _ time.Duration, _ bool) (netwatch.TraceResult, error) {
				if name == "slow" {
					select {
					case <-slowApp:
					case <-ctx.Done():
						return netwatch.TraceResult{}, ctx.Err()
					}
				}
				return netwatch.TraceResult{IP: "203.0.113.10", Country: "PL"}, nil
			}
			stop := r.probe(cfg, 7, guard.ProbePlan{General: true, Apps: map[string]bool{"a": true, "b": true, "claude": true, "cursor": true}})
			defer stop()
			if first := loopReceive(t, r.results); first.Part != guard.DomainFamily || first.Sample.Endpoint != "fast" {
				t.Fatalf("ready family delayed: %+v", first)
			}
			if mode == "block" {
				select {
				case part := <-r.results:
					t.Fatalf("policy was released before blocking DNS: %+v", part)
				case <-time.After(50 * time.Millisecond):
				}
				close(slowDNS)
			}
			for {
				part := loopReceive(t, r.results)
				if part.Part == guard.DomainGroup {
					if len(part.Domains["claude"]) != 1 {
						t.Fatal(part)
					}
					break
				}
			}
			if mode == "warn" {
				close(slowDNS)
			}
			close(slowApp)
			if len(completedProbe(t, r).Domains) != 2 {
				t.Fatal("final summary lost an application")
			}
		})
	}
}

func TestTimeoutRetriesOnlyFailedSharedFamily(t *testing.T) {
	c := config.Default()
	c.DNSCheck = "warn"
	c.Apps = []string{"claude", "cursor"}
	c.DomainChecksEnabled = map[string]bool{"claude": true, "cursor": true}
	c.DomainChecks = map[string][]string{"claude": {"shared", "healthy"}, "cursor": {"shared"}}
	r := &Runner{ctx: context.Background(), results: make(chan guard.ProbeResult, 10), ipv6Possible: func() (bool, error) { return true, nil }}
	r.dnsResolver = func(context.Context) string { t.Error("unexpected diagnostic DNS"); return "" }
	var shared, healthy, ipv6 atomic.Int32
	r.traceIP = func(ctx context.Context, endpoint string, _ time.Duration, v6 bool) (netwatch.TraceResult, error) {
		if v6 {
			ipv6.Add(1)
			return netwatch.TraceResult{}, netwatch.ErrNoIPv6
		}
		if endpoint == "healthy" {
			healthy.Add(1)
		} else if shared.Add(1) == 1 {
			return netwatch.TraceResult{}, context.DeadlineExceeded
		}
		return netwatch.TraceResult{IP: "203.0.113.10", Country: "PL"}, nil
	}
	stop := r.probe(c, 1, guard.ProbePlan{Apps: map[string]bool{"claude": true, "cursor": true}})
	defer stop()
	for {
		part := loopReceive(t, r.results)
		if part.Retry != nil {
			part.Retry <- true
		}
		if part.Part == guard.GeneralMeasurement {
			t.Fatal("unexpected general check")
		}
		if part.Part == guard.CompleteProbe {
			if part.Err != nil || part.IP != "" || len(part.Domains) != 2 || shared.Load() != 2 || healthy.Load() != 1 || ipv6.Load() != 2 {
				t.Fatalf("incorrect retry scope: %+v, calls=%d/%d/%d", part, shared.Load(), healthy.Load(), ipv6.Load())
			}
			break
		}
	}
}
