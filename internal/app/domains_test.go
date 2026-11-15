package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
	"github.com/avazar/zaslon/internal/netwatch"
)

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
	cancel := r.probe(c, 42, true)
	defer cancel()
	select {
	case res := <-r.results:
		if res.ID != 42 || res.Err == nil || len(res.Domains) != 2 || calls.Load() != 2 {
			t.Fatalf("wrong result: %+v, calls=%d", res, calls.Load())
		}
		for _, id := range []string{"a", "b"} {
			d := res.Domains[id]
			if len(d) != 1 || d[0].IP != "203.0.113.10" || d[0].IPv6Error != "" || d[0].CheckedAt.IsZero() {
				t.Fatalf("%s: %+v", id, d)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not finish")
	}
	calls.Store(0)
	c.DomainChecksEnabled["a"], c.DomainChecksEnabled["b"] = false, false
	cancelOff := r.probe(c, 44, true)
	defer cancelOff()
	select {
	case res := <-r.results:
		if len(res.Domains) != 0 || calls.Load() != 0 || len(c.DomainChecks["a"]) != 1 {
			t.Fatal("disabled saved lists were queried or discarded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("disabled-list probe did not finish")
	}
	cancel2 := r.probe(c, 43, false)
	defer cancel2()
	select {
	case res := <-r.results:
		if res.Domains != nil || calls.Load() != 0 {
			t.Fatal("periodic general check queried service domains")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not finish")
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
	cancel := r.probe(c, 1, true)
	defer cancel()
	select {
	case res := <-r.results:
		if res.Domains["claude"][0].IPv6Error == "" || !res.Domains["claude"][0].IPv6Timeout {
			t.Fatal("IPv6 error disappeared")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not finish")
	}
	ctx, stop := context.WithCancel(context.Background())
	r.ctx = ctx
	r.traceIP = func(ctx context.Context, _ string, _ time.Duration, _ bool) (netwatch.TraceResult, error) {
		<-ctx.Done()
		return netwatch.TraceResult{}, ctx.Err()
	}
	cancelled := r.probe(c, 2, true)
	stop()
	defer cancelled()
	select {
	case res := <-r.results:
		t.Fatalf("cancelled probe published %+v", res)
	case <-time.After(100 * time.Millisecond):
	}
}
