package netwatch

import (
	"testing"
	"time"
	"unsafe"

	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
	"github.com/avazar/zaslon/internal/procs"
	"golang.org/x/sys/windows"
)

type notificationFixtureProcesses struct{ held bool }

func (p *notificationFixtureProcesses) List() ([]procs.Proc, error) {
	return []procs.Proc{{PID: 100, Created: "fixture", Name: "zaslon-network-fixture.exe", Path: "/fake/zaslon-network-fixture.exe"}}, nil
}
func (p *notificationFixtureProcesses) Freeze(procs.Proc) error { p.held = true; return nil }
func (p *notificationFixtureProcesses) Resume(procs.Proc) error { p.held = false; return nil }

func TestNativeCallbackFilteringPreservesFreezeBeforeCurrentProbe(t *testing.T) {
	e := &Events{}
	f := readyTeredoFilter()
	p := &notificationFixtureProcesses{}
	cfg := config.Default()
	cfg.Apps = nil
	cfg.CustomApps = []config.CustomApp{{Name: "fixture", Match: []string{"zaslon-network-fixture.exe"}}}
	cfg.Allow = config.Allow{IPs: []string{"203.0.113.10"}}
	cfg.CheckIPv6 = false
	cfg.DNSCheck = "off"
	var id uint64
	var requireFrozen bool
	g := guard.New(cfg, guard.Deps{Fingerprint: func() string { return "same addresses" }, NetworkVersion: e.Version, NetworkDetails: e.Details, Procs: p, StartProbe: func(_ *config.Config, current uint64, _ bool) func() {
		if requireFrozen && !p.held {
			t.Fatal("probe started before suspension")
		}
		id = current
		return func() {}
	}})
	defer g.Shutdown()
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	g.Step(now)
	g.HandleProbe(now.Add(time.Second), guard.ProbeResult{ID: id, IP: "203.0.113.10", Votes: 2})
	if p.held {
		t.Fatal("initial allowed result did not resume")
	}
	iface := interfaceChangeRow{Family: windows.AF_INET6, Luid: fixtureLUID, Index: 17}
	nativeFilteredCallback(e, f, "NotifyIpInterfaceChange", unsafe.Pointer(&iface), windows.MibParameterNotification)
	g.Step(now.Add(1100 * time.Millisecond))
	if p.held {
		t.Fatal("local-only Teredo event interrupted a permitted fixture")
	}
	g.CheckNow(now.Add(2 * time.Second))
	g.Step(now.Add(2 * time.Second))
	oldID := id
	requireFrozen = true
	route := routeChangeRow{Luid: fixtureLUID, Index: 17, Destination: changeSockaddr{Family: windows.AF_INET6}, NextHop: changeSockaddr{Family: windows.AF_INET6}}
	nativeFilteredCallback(e, f, "NotifyRouteChange2", unsafe.Pointer(&route), windows.MibAddInstance)
	// A result queued before this callback cannot win, even though no event-loop
	// tick has been delivered and all adapter addresses are unchanged.
	g.HandleProbe(now.Add(2100*time.Millisecond), guard.ProbeResult{ID: oldID, IP: "203.0.113.10", Votes: 2})
	if !p.held || id == oldID {
		t.Fatal("old successful result escaped a public route change")
	}
	g.HandleProbe(now.Add(2200*time.Millisecond), guard.ProbeResult{ID: id, IP: "203.0.113.10", Votes: 2})
	if p.held {
		t.Fatal("fresh allowed result failed to resume")
	}
}
