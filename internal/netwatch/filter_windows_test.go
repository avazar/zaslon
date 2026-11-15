package netwatch

import (
	"errors"
	"net/netip"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const fixtureLUID = uint64(0x100000017)

func readyTeredoFilter() *windowsEventFilter {
	f := &windowsEventFilter{}
	f.initialize(map[uint64]uint32{fixtureLUID: 17}, nil)
	return f
}

func nativeFilteredCallback(e *Events, f *windowsEventFilter, source string, row unsafe.Pointer, kind uint32) {
	token := watchID.Add(1)
	watchCallbacks.Store(token, windowsSubscription{source: source, notify: e.record, ignored: e.ignore, filter: f})
	defer watchCallbacks.Delete(token)
	syscall.SyscallN(changeCallback, token, uintptr(row), uintptr(kind))
	runtime.KeepAlive(row)
}

func TestTeredoLocalNotificationsDoNotInvalidateOrWakeGuard(t *testing.T) {
	wake := make(chan struct{}, 1)
	e := &Events{C: wake, wake: wake}
	f := readyTeredoFilter()
	iface := interfaceChangeRow{Family: windows.AF_INET6, Luid: fixtureLUID, Index: 17}
	address := changeSockaddr{Family: windows.AF_INET6}
	ip := netip.MustParseAddr("fe80::ffff:ffff:fffe").As16()
	copy(address.Data[6:22], ip[:])
	addr := addressChangeRow{Address: address, Luid: fixtureLUID, Index: 17}
	route := routeChangeRow{Luid: fixtureLUID, Index: 17, Destination: address, PrefixLength: 128, NextHop: changeSockaddr{Family: windows.AF_INET6}}
	for range 3 {
		for _, kind := range []uint32{windows.MibAddInstance, windows.MibParameterNotification, windows.MibDeleteInstance} {
			nativeFilteredCallback(e, f, "NotifyIpInterfaceChange", unsafe.Pointer(&iface), kind)
			nativeFilteredCallback(e, f, "NotifyUnicastIpAddressChange", unsafe.Pointer(&addr), kind)
			nativeFilteredCallback(e, f, "NotifyRouteChange2", unsafe.Pointer(&route), kind)
		}
	}
	if e.Version() != 0 {
		t.Fatal("local-only Teredo noise invalidated the current check")
	}
	select {
	case <-e.C:
		t.Fatal("filtered noise woke the runner")
	default:
	}
	if n, last := e.Ignored(); n != 27 || !strings.Contains(last, "source=NotifyRouteChange2") {
		t.Fatalf("filtered diagnostic count=%d last=%s", n, last)
	}
	// Once a public route appears, the first callback must invalidate immediately;
	// interface events must stay relevant even after this route is removed.
	route.Destination = changeSockaddr{Family: windows.AF_INET6}
	route.PrefixLength = 0
	nativeFilteredCallback(e, f, "NotifyRouteChange2", unsafe.Pointer(&route), windows.MibAddInstance)
	if e.Version() != 1 {
		t.Fatal("Teredo public route was filtered")
	}
	select {
	case <-e.C:
	default:
		t.Fatal("public route did not wake guard")
	}
	nativeFilteredCallback(e, f, "NotifyIpInterfaceChange", unsafe.Pointer(&iface), windows.MibDeleteInstance)
	if e.Version() != 2 {
		t.Fatal("previously external Teredo interface was ignored")
	}
}

func TestOnlyProvenLocalTeredoEventsAreFiltered(t *testing.T) {
	base := windowsChangeHint{source: "NotifyIpInterfaceChange", family: windows.AF_INET6, luid: fixtureLUID, index: 17}
	for _, test := range []struct {
		name   string
		change func(*windowsChangeHint)
	}{
		{"IPv4", func(h *windowsChangeHint) { h.family = windows.AF_INET }},
		{"unknown-family", func(h *windowsChangeHint) { h.family = 0 }},
		{"unknown-source", func(h *windowsChangeHint) { h.source = "unknown" }},
		{"unknown-kind", func(h *windowsChangeHint) { h.kind = 99 }},
		{"missing-identity", func(h *windowsChangeHint) { h.luid = 0 }},
		{"reused-index", func(h *windowsChangeHint) { h.luid = fixtureLUID + 1 }},
		{"changed-index", func(h *windowsChangeHint) { h.index = 18 }},
		{"public-address", func(h *windowsChangeHint) {
			h.source = "NotifyUnicastIpAddressChange"
			h.address = netip.MustParseAddr("2001:db8::1")
		}},
		{"ULA-address", func(h *windowsChangeHint) {
			h.source = "NotifyUnicastIpAddressChange"
			h.address = netip.MustParseAddr("fd00::1")
		}},
		{"malformed-address", func(h *windowsChangeHint) { h.source = "NotifyUnicastIpAddressChange" }},
		{"default-route", func(h *windowsChangeHint) {
			h.source = "NotifyRouteChange2"
			h.prefix = netip.MustParsePrefix("::/0")
			h.nextHop = netip.IPv6Unspecified()
		}},
		{"VPN-split-route", func(h *windowsChangeHint) {
			h.source = "NotifyRouteChange2"
			h.prefix = netip.MustParsePrefix("::/1")
			h.nextHop = netip.IPv6Unspecified()
		}},
		{"public-host-route", func(h *windowsChangeHint) {
			h.source = "NotifyRouteChange2"
			h.prefix = netip.MustParsePrefix("2001:db8::1/128")
			h.nextHop = netip.IPv6Unspecified()
		}},
		{"broad-local-prefix", func(h *windowsChangeHint) {
			h.source = "NotifyRouteChange2"
			h.prefix = netip.MustParsePrefix("fe80::/8")
			h.nextHop = netip.IPv6Unspecified()
		}},
		{"routed-local-prefix", func(h *windowsChangeHint) {
			h.source = "NotifyRouteChange2"
			h.prefix = netip.MustParsePrefix("fe80::/64")
			h.nextHop = netip.MustParseAddr("fe80::1")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := readyTeredoFilter()
			h := base
			test.change(&h)
			if f.ignore(h) {
				t.Fatal("relevant or unknown notification was filtered")
			}
			if h.luid == fixtureLUID && f.ignore(base) {
				t.Fatal("interface became filterable again after external/unknown activity")
			}
		})
	}
	for _, prefix := range []string{"fe80::/10", "fe80::/64", "fe80::1/128", "ff00::/8", "ff02::1/128"} {
		h := base
		h.source = "NotifyRouteChange2"
		h.prefix = netip.MustParsePrefix(prefix)
		h.nextHop = netip.IPv6Unspecified()
		if !readyTeredoFilter().ignore(h) {
			t.Errorf("expected local route to be filtered: %s", prefix)
		}
	}
}

func TestFilterInitializationKeepsUnknownAndRacingInterfacesRelevant(t *testing.T) {
	h := windowsChangeHint{source: "NotifyIpInterfaceChange", family: windows.AF_INET6, luid: fixtureLUID, index: 17}
	f := &windowsEventFilter{}
	if f.ignore(h) {
		t.Fatal("uninitialized filter suppressed a callback")
	}
	f.initialize(map[uint64]uint32{fixtureLUID: 17}, nil)
	if f.ignore(h) {
		t.Fatal("interface changed during snapshot was treated as local-only")
	}
	f = &windowsEventFilter{}
	f.initialize(map[uint64]uint32{fixtureLUID: 17}, errors.New("snapshot access denied"))
	if f.ignore(h) {
		t.Fatal("snapshot failure allowed filtering")
	}
	f = readyTeredoFilter()
	if f.ignore(windowsChangeHint{}) || f.ignore(h) {
		t.Fatal("unidentifiable notification did not disable exclusions")
	}
	// Unknown VPN and physical interfaces remain relevant, even for local addresses.
	h.luid++
	if readyTeredoFilter().ignore(h) {
		t.Fatal("unknown interface filtered")
	}
}

func TestInitialSnapshotExcludesExternallyCapableTeredo(t *testing.T) {
	ifs := []windows.MibIfRow2{
		{InterfaceLuid: 1, InterfaceIndex: 17, Type: ifTypeTunnel, TunnelType: tunnelTypeTeredo},
		{InterfaceLuid: 2, InterfaceIndex: 18, Type: ifTypeTunnel, TunnelType: tunnelTypeTeredo},
		{InterfaceLuid: 3, InterfaceIndex: 19, Type: ifTypeTunnel, TunnelType: tunnelTypeTeredo},
		{InterfaceLuid: 4, InterfaceIndex: 20, Type: ifTypeTunnel, TunnelType: 1}, // ordinary VPN
		{InterfaceLuid: 5, InterfaceIndex: 21, Type: 6},                           // Ethernet
	}
	addresses := []windows.MibUnicastIpAddressRow{{InterfaceLuid: 2, Address: windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: netip.MustParseAddr("2001:db8::1").As16()}}}
	routes := []windows.MibIpForwardRow2{{InterfaceLuid: 3, DestinationPrefix: windows.IpAddressPrefix{Prefix: windows.RawSockaddrInet{Family: windows.AF_INET6}, PrefixLength: 0}, NextHop: windows.RawSockaddrInet{Family: windows.AF_INET6}}}
	got := candidateTeredoInterfaces(ifs, addresses, routes)
	if len(got) != 1 || got[1] != 17 {
		t.Fatalf("unsafe candidates: %v", got)
	}
}

func TestReadOnlyWindowsFilterSnapshot(t *testing.T) {
	candidates, err := localTeredoInterfaces()
	if err != nil {
		t.Logf("filter conservatively disabled on this host: %v", err)
		return
	}
	t.Logf("read-only snapshot contains %d local-only Teredo candidate(s)", len(candidates))
}

func TestTeredoCanBeLearnedAfterInactiveStartupWithoutRelearningExternalActivity(t *testing.T) {
	h := windowsChangeHint{source: "NotifyIpInterfaceChange", family: windows.AF_INET6, luid: fixtureLUID, index: 17}
	f := &windowsEventFilter{}
	f.initialize(nil, nil) // Windows has not assigned an IPv6 interface/type yet.
	if f.ignore(h) || !f.beginRefresh() {
		t.Fatal("first unidentified event must stay relevant and request metadata")
	}
	f.initialize(map[uint64]uint32{fixtureLUID: 17}, nil)
	if !f.ignore(h) {
		t.Fatal("quiet, verified Teredo interface was not learned")
	}
	// Inactive snapshots no longer report the type; retain the proved identity.
	f.needsRefresh.Store(true)
	if !f.beginRefresh() {
		t.Fatal("refresh not requested")
	}
	f.initialize(nil, nil)
	if !f.ignore(h) {
		t.Fatal("inactive snapshot forgot the verified tunnel identity")
	}
	public := h
	public.source = "NotifyRouteChange2"
	public.prefix = netip.MustParsePrefix("::/0")
	public.nextHop = netip.IPv6Unspecified()
	if f.ignore(public) {
		t.Fatal("public route filtered")
	}
	f.needsRefresh.Store(true)
	_ = f.beginRefresh()
	f.initialize(map[uint64]uint32{fixtureLUID: 17}, nil)
	if f.ignore(h) {
		t.Fatal("public activity was forgotten by a later snapshot")
	}
}

func TestRefreshRacesCannotAddUncertainInterface(t *testing.T) {
	h := windowsChangeHint{source: "NotifyIpInterfaceChange", family: windows.AF_INET6, luid: fixtureLUID, index: 17}
	f := &windowsEventFilter{}
	f.initialize(nil, nil)
	_ = f.ignore(h)
	if !f.beginRefresh() {
		t.Fatal("refresh not requested")
	}
	if f.ignore(h) {
		t.Fatal("unverified callback was ignored during metadata refresh")
	}
	f.initialize(map[uint64]uint32{fixtureLUID: 17}, nil)
	if f.count() != 0 || !f.needsRefresh.Load() {
		t.Fatal("racing candidate added without a quiet snapshot")
	}
	if !f.beginRefresh() {
		t.Fatal("conservative retry not requested")
	}
	f.initialize(map[uint64]uint32{fixtureLUID: 17}, nil)
	if !f.ignore(h) {
		t.Fatal("quiet retry did not establish metadata")
	}
	f.needsRefresh.Store(true)
	_ = f.beginRefresh()
	f.initialize(nil, errors.New("read failed"))
	if f.ignore(h) {
		t.Fatal("snapshot failure kept an exclusion enabled")
	}
}
