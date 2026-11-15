package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

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

func TestAllowKeepsIPv6WhenEachFamilyHasAnUnresponsiveService(t *testing.T) {
	if netwatch.SystemProxy() != nil {
		t.Skip("local CLI fixture requires no system proxy")
	}
	t.Setenv("ZASLON_DIR", t.TempDir())
	fast4 := allowTestServer(t, false, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "203.0.113.10") })
	fast6 := allowTestServer(t, true, func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "2001:db8::10") })
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
	for _, ip := range []string{"203.0.113.10", "2001:db8::10"} {
		if !saved.Allow.Matches(ip, "") {
			t.Fatalf("successful %s response missing from %v", ip, saved.Allow.IPs)
		}
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
