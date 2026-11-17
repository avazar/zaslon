package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/app"
	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/netwatch"
)

func allowTestServer(t *testing.T, v6 bool, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	if v6 {
		s.Listener.Close()
		ln, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		s.Listener = ln
	}
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func TestAllowCurrentAddsOnlyIPv4WithAnUnresponsiveService(t *testing.T) {
	if netwatch.SystemProxy() != nil {
		t.Skip("local CLI fixture requires no system proxy")
	}
	t.Setenv("ZASLON_DIR", t.TempDir())
	fast4 := allowTestServer(t, false, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "203.0.113.10") })
	var queried6 atomic.Int32
	fast6 := allowTestServer(t, true, func(w http.ResponseWriter, _ *http.Request) { queried6.Add(1); fmt.Fprint(w, "2001:db8::10") })
	hang := func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
	slow4, slow6 := allowTestServer(t, false, hang), allowTestServer(t, true, hang)
	c := config.Default()
	c.MinAgree = 1
	c.IPServices = []string{fast4.URL, slow4.URL}
	c.IPv6Services = []string{fast6.URL, slow6.URL}
	if err := allow(c, nil); err != nil {
		t.Fatal(err)
	}
	saved, _, err := config.Load(app.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Allow.Matches("203.0.113.10", "") {
		t.Fatalf("successful IPv4 response missing from %v", saved.Allow.IPs)
	}
	if queried6.Load() != 0 || saved.Allow.Matches("2001:db8::10", "") {
		t.Fatal("allow current implicitly queried or allowed IPv6")
	}
}

func TestAllowExplicitIPv6DoesNotExpandItsScope(t *testing.T) {
	t.Setenv("ZASLON_DIR", t.TempDir())
	c := config.Default()
	if err := allow(c, []string{"2001:db8::10"}); err != nil {
		t.Fatal(err)
	}
	saved, _, err := config.Load(app.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Allow.Matches("2001:db8::10", "") || saved.Allow.Matches("2001:db8::11", "") {
		t.Fatalf("IPv6 grant scope changed: %v", saved.Allow.IPs)
	}
	if err := allow(saved, []string{"2001:db8:1::/64"}); err != nil {
		t.Fatal(err)
	}
	if !saved.Allow.Matches("2001:db8:1::11", "") {
		t.Fatal("explicit IPv6 prefix was not allowed")
	}
}

func TestAllowDoesNotQueryDisabledIPv6(t *testing.T) {
	if netwatch.SystemProxy() != nil {
		t.Skip("local CLI fixture requires no system proxy")
	}
	t.Setenv("ZASLON_DIR", t.TempDir())
	var queried atomic.Int32
	fast4 := allowTestServer(t, false, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "203.0.113.10") })
	fast6 := allowTestServer(t, true, func(w http.ResponseWriter, _ *http.Request) { queried.Add(1); fmt.Fprint(w, "2001:db8::10") })
	c := config.Default()
	c.CheckIPv6 = false
	c.IPServices = []string{fast4.URL}
	c.IPv6Services = []string{fast6.URL}
	if err := allow(c, nil); err != nil {
		t.Fatal(err)
	}
	if queried.Load() != 0 {
		t.Fatal("disabled IPv6 was queried")
	}
}

func TestImplicitAllowRequiresQuorumWithoutConflict(t *testing.T) {
	if netwatch.SystemProxy() != nil {
		t.Skip("local CLI fixture requires no system proxy")
	}
	for _, conflict := range []bool{false, true} {
		t.Setenv("ZASLON_DIR", t.TempDir())
		a := allowTestServer(t, false, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "203.0.113.1") })
		b := allowTestServer(t, false, func(w http.ResponseWriter, _ *http.Request) {
			if conflict {
				fmt.Fprint(w, "203.0.113.2")
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		})
		c := config.Default()
		c.IPServices = []string{a.URL, b.URL}
		c.MinAgree = 2
		if conflict {
			c.MinAgree = 1
		}
		if err := allow(c, nil); err == nil {
			t.Fatal("unconfirmed IPv4 persisted")
		}
		if _, err := os.Stat(app.ConfigPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected saved profile: %v", err)
		}
	}
}

func TestStatusUsesLiveMeasurementOrConfiguredStandaloneCheck(t *testing.T) {
	if netwatch.SystemProxy() != nil {
		t.Skip("local CLI fixture requires no system proxy")
	}
	t.Setenv("ZASLON_DIR", t.TempDir())
	var v4, v6 atomic.Int32
	server := func(counter *atomic.Int32, v6 bool) *httptest.Server {
		return allowTestServer(t, v6, func(w http.ResponseWriter, _ *http.Request) {
			counter.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
		})
	}
	cfg := config.Default()
	cfg.IPServices = []string{server(&v4, false).URL}
	cfg.IPv6Services = []string{server(&v6, true).URL}
	cfg.CheckIPv6 = false
	var output bytes.Buffer
	measured := time.Now().Add(-time.Minute)
	app.WriteState(app.State{MeasuredAt: measured, Line: "fixture", IP: "203.0.113.17", Country: "PL"})
	if err := status(cfg, &output); err != nil {
		t.Fatal(err)
	}
	if v4.Load() != 0 || v6.Load() != 0 || !strings.Contains(output.String(), measured.Format(time.RFC3339)) || !strings.Contains(output.String(), "203.0.113.17") {
		t.Fatal(output.String())
	}
	if err := os.Remove(app.StatePath()); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := status(cfg, &output); err != nil {
		t.Fatal(err)
	}
	if v4.Load() != 1 || v6.Load() != 0 || !strings.Contains(output.String(), "Standalone") {
		t.Fatal(output.String())
	}
}
