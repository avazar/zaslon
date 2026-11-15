package netwatch

import (
	"context"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Registers read-only OS notifications, then simulates callback delivery.
// Does not alter any adapter, address, route, DNS or firewall setting.
func TestWindowsSubscriptionsAndCoalescedEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := Watch(ctx)
	if err := e.Error(); err != nil {
		t.Fatal(err)
	}
	token := watchID.Load()
	callback, ok := watchCallbacks.Load(token)
	if !ok {
		t.Fatal("subscription was not registered")
	}
	before := e.Version()
	for range 100 {
		cb := callback.(windowsSubscription)
		cb.notify(func() Change { return windowsChange(cb.source, nil, 0) })
	}
	if e.Version() < before+100 {
		t.Fatal("coalesced channel lost revisions")
	}
	select {
	case <-e.C:
	default:
		t.Fatal("callback did not wake runner")
	}
	if details := e.Details(before, e.Version()); len(details) < 2 {
		t.Fatal("coalesced diagnostics were lost")
	}
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := watchCallbacks.Load(token); !ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("notification callbacks survived cancellation")
}

func TestWindowsNotificationRowsAreCopied(t *testing.T) {
	v4 := changeSockaddr{Family: windows.AF_INET}
	copy(v4.Data[2:6], []byte{192, 0, 2, 0})
	route := routeChangeRow{Index: 17, Destination: v4, PrefixLength: 24, NextHop: v4}
	c := windowsChange("NotifyRouteChange2", unsafe.Pointer(&route), 1)
	route.Index = 99
	if c.Interface != 17 || c.Family != "IPv4" || c.Kind != "add" || c.Prefix != "192.0.2.0/24" || c.NextHop != "192.0.2.0" {
		t.Fatalf("route details: %+v", c)
	}
	v6 := changeSockaddr{Family: windows.AF_INET6}
	copy(v6.Data[6:22], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	addr := addressChangeRow{Address: v6, Index: 8}
	c = windowsChange("NotifyUnicastIpAddressChange", unsafe.Pointer(&addr), 2)
	if c.Address != "2001:db8::1" || c.Family != "IPv6" || c.Interface != 8 || c.Kind != "delete" {
		t.Fatalf("address: %+v", c)
	}
	iface := interfaceChangeRow{Family: windows.AF_INET6, Index: 11}
	c = windowsChange("NotifyIpInterfaceChange", unsafe.Pointer(&iface), 0)
	if c.Interface != 11 || c.Family != "IPv6" || c.Kind != "parameter" {
		t.Fatalf("interface: %+v", c)
	}
	if c := windowsChange("NotifyIpInterfaceChange", nil, 3); c.Interface != 0 || c.Kind != "initial" {
		t.Fatalf("initial: %+v", c)
	}
	// SDK field offsets, including 8-byte NET_LUID alignment on Windows/386.
	if unsafe.Offsetof(route.Destination) != 12 || unsafe.Offsetof(route.NextHop) != 44 || unsafe.Offsetof(addr.Index) != 40 || unsafe.Offsetof(iface.Index) != 16 {
		t.Fatal("Windows MIB row ABI mismatch")
	}
}

func TestNativeWindowsCallbackPreservesSourceAndRow(t *testing.T) {
	// Invoke the registered callback through its Windows ABI. This is a synthetic
	// notification in the test process; it changes no system networking state.
	e := &Events{}
	token := watchID.Add(1)
	watchCallbacks.Store(token, windowsSubscription{source: "NotifyIpInterfaceChange", notify: e.record})
	defer watchCallbacks.Delete(token)
	row := interfaceChangeRow{Family: windows.AF_INET6, Index: 23}
	syscall.SyscallN(changeCallback, token, uintptr(unsafe.Pointer(&row)), 0)
	runtime.KeepAlive(&row)
	if got := e.Details(0, e.Version()); len(got) != 1 || !strings.Contains(got[0], "source=NotifyIpInterfaceChange kind=parameter family=IPv6 interface=23") {
		t.Fatalf("callback ABI lost source or row fields: %v", got)
	}
}
