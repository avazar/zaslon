package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
	"github.com/avazar/zaslon/internal/procs"
)

func TestSharedDiagnosticRouteUsesEachAppsPolicy(t *testing.T) {
	cfg := config.Default()
	cfg.Apps = []string{"chatgpt", "codex"}
	const ep = "https://chatgpt.com/cdn-cgi/trace"
	cfg.DomainChecks = map[string][]string{"chatgpt": {ep}, "codex": {ep}}
	cfg.DomainChecksEnabled = map[string]bool{"chatgpt": true, "codex": true}
	cfg.Allow.IPs = []string{"203.0.113.0/24"}
	cfg.AppRules = map[string]config.Allow{"codex": {Countries: []string{"DE"}}}
	snap := guard.Snapshot{Config: cfg, Running: []procs.Proc{{AppID: "chatgpt", PolicyIDs: []string{"codex"}}}}
	rows := configuredRows(snap)
	if len(rows) != 2 || len(rows[1].Apps) != 2 {
		t.Fatal(rows)
	}
	f := sampleFamily("203.0.113.7", "NL", "", false, time.Millisecond)
	if routeVerdict(rows[1].Apps[0], f) != "allowed" || routeVerdict(rows[1].Apps[1], f) != "denied" {
		t.Fatal(rows[1])
	}
	f.Country = ""
	if routeVerdict(rows[1].Apps[1], f) != "countryUnknown" {
		t.Fatal("missing country marked denied")
	}
	snap.Running = nil
	if configuredRows(snap)[1].Apps[0].Status != "idle" {
		t.Fatal("closed application marked active")
	}
}

func TestRouteSeriesKeepsFiveDistinctChecksAndInvalidates(t *testing.T) {
	s := Server{}
	now := time.Now()
	snap := guard.Snapshot{Config: config.Default(), IP: "203.0.113.10", Votes: 2}
	for _, i := range []int{1, 2, 4, 3, 6, 5, 5, 1} {
		snap.MeasuredAt = now.Add(time.Duration(i) * time.Second)
		snap.RouteTime[0] = time.Duration(i) * time.Millisecond
		s.ObserveRoutes(snap)
	}
	series := s.routes.series[""]
	if len(series) != 5 || *series[0].family[0].MS != 2 || *series[4].family[0].MS != 6 {
		t.Fatal(series)
	}
	snap.RoutesSince = now.Add(time.Minute)
	s.ObserveRoutes(snap)
	if len(s.routes.series[""]) != 0 {
		t.Fatal("previous network survived invalidation")
	}
}

type lookupTransport func(*http.Request) (*http.Response, error)

func (f lookupTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestIPQueryFieldsCacheAndAddressBinding(t *testing.T) {
	t.Setenv("ZASLON_DIR", t.TempDir())
	ip := netip.MustParseAddr("2001:db8::12")
	returned := ip.String()
	client := &http.Client{Transport: lookupTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://api.ipquery.io/"+ip.String() {
			t.Fatal(r.URL)
		}
		body := fmt.Sprintf(`{"ip":%q,"isp":{"isp":"Example","asn":"AS64496"},"risk":{"is_proxy":false,"is_vpn":true}}`, returned)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	v, err := fetchIPReport(context.Background(), client, ip)
	if err != nil || v.ISP.Name != "Example" || v.Risk.VPN == nil || !*v.Risk.VPN || v.Risk.Proxy == nil || *v.Risk.Proxy || v.Risk.Tor != nil {
		t.Fatalf("%+v %v", v, err)
	}
	s := Server{}
	url := "/api/routes/ip?ip=" + ip.String()
	read := func() (*ipReport, bool) {
		t.Helper()
		w := httptest.NewRecorder()
		s.cachedIP(w, httptest.NewRequest("GET", url, nil))
		var data struct {
			Report *ipReport
			Stale  bool
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &data) != nil {
			t.Fatal(w.Body.String())
		}
		return data.Report, data.Stale
	}
	if cached, _ := read(); cached != nil {
		t.Fatal("lookup performed without a click")
	}
	v.Fetched = time.Now().Add(-8 * 24 * time.Hour)
	if err = s.saveIPReport(v); err != nil {
		t.Fatal(err)
	}
	if cached, stale := read(); cached == nil || !stale {
		t.Fatal("expired report should remain visible")
	}
	returned = "203.0.113.13"
	if _, err = fetchIPReport(context.Background(), client, ip); err == nil {
		t.Fatal("accepted answer for a different IP")
	}
}
