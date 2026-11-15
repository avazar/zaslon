package netwatch

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi   = windows.NewLazySystemDLL("iphlpapi.dll")
	changeAPIs = []*windows.LazyProc{
		iphlpapi.NewProc("NotifyRouteChange2"),
		iphlpapi.NewProc("NotifyUnicastIpAddressChange"),
		iphlpapi.NewProc("NotifyIpInterfaceChange"),
	}
	cancelChange   = iphlpapi.NewProc("CancelMibChangeNotify2")
	watchID        atomic.Uintptr
	watchCallbacks sync.Map
	// One callback for the process lifetime: NewCallback allocations cannot be freed.
	changeCallback = windows.NewCallback(func(token uintptr, row unsafe.Pointer, kind uint32) uintptr {
		if callback, ok := watchCallbacks.Load(token); ok {
			cb := callback.(windowsSubscription)
			if cb.filter != nil && cb.filter.ignore(windowsHint(cb.source, row, kind)) {
				if cb.ignored != nil {
					cb.ignored(func() Change { return windowsChange(cb.source, row, kind) })
				}
				return 0
			}
			cb.notify(func() Change { return windowsChange(cb.source, row, kind) })
		}
		return 0
	})
)

type windowsSubscription struct {
	source  string
	notify  func(func() Change)
	ignored func(func() Change)
	filter  *windowsEventFilter
}

// Prefixes of the SDK's MIB_*_ROW structures. Explicit padding preserves the
// Windows ABI on 32- and 64-bit builds. Only fields provided in notifications
// are read, before returning control to Windows.
type changeSockaddr struct {
	Family uint16
	Data   [26]byte
}
type routeChangeRow struct {
	Luid         uint64
	Index        uint32
	Destination  changeSockaddr
	PrefixLength uint8
	_            [3]byte
	NextHop      changeSockaddr
}
type addressChangeRow struct {
	Address changeSockaddr
	_       [4]byte
	Luid    uint64
	Index   uint32
}
type interfaceChangeRow struct {
	Family uint16
	_      [6]byte
	Luid   uint64
	Index  uint32
}

func changeAddress(s changeSockaddr) string {
	if ip := changeIP(s); ip.IsValid() {
		return ip.String()
	}
	return ""
}

func changeIP(s changeSockaddr) netip.Addr {
	switch s.Family {
	case windows.AF_INET:
		return netip.AddrFrom4([4]byte(s.Data[2:6]))
	case windows.AF_INET6:
		return netip.AddrFrom16([16]byte(s.Data[6:22]))
	}
	return netip.Addr{}
}

func windowsChange(source string, row unsafe.Pointer, kind uint32) Change {
	c := Change{Source: source, Kind: fmt.Sprintf("notification-%d", kind)}
	switch kind {
	case 0:
		c.Kind = "parameter"
	case 1:
		c.Kind = "add"
	case 2:
		c.Kind = "delete"
	case 3:
		c.Kind = "initial"
	}
	if row == nil {
		return c
	}
	var family uint16
	switch source {
	case "NotifyRouteChange2":
		r := *(*routeChangeRow)(row)
		c.Interface, family = r.Index, r.Destination.Family
		if addr := changeAddress(r.Destination); addr != "" {
			c.Prefix = fmt.Sprintf("%s/%d", addr, r.PrefixLength)
		}
		c.NextHop = changeAddress(r.NextHop)
	case "NotifyUnicastIpAddressChange":
		r := *(*addressChangeRow)(row)
		c.Interface, family, c.Address = r.Index, r.Address.Family, changeAddress(r.Address)
	case "NotifyIpInterfaceChange":
		r := *(*interfaceChangeRow)(row)
		c.Interface, family = r.Index, r.Family
	}
	switch family {
	case windows.AF_INET:
		c.Family = "IPv4"
	case windows.AF_INET6:
		c.Family = "IPv6"
	}
	return c
}

// AF_UNSPEC subscribes to IPv4 and IPv6. No adapters, addresses or routes are
// modified. Cancellation runs outside the callback to avoid an API deadlock.
func watch(ctx context.Context, notify, ignored func(func() Change), fail func(error)) (string, func() string) {
	if err := cancelChange.Find(); err != nil {
		fail(err)
		return "Network notification filter disabled: notification API unavailable", nil
	}
	filter := &windowsEventFilter{touched: map[uint64]bool{}}
	var handles []windows.Handle
	var tokens []uintptr
	for _, api := range changeAPIs {
		if err := api.Find(); err != nil {
			fail(fmt.Errorf("%s: %w", api.Name, err))
			continue
		}
		token := watchID.Add(1)
		watchCallbacks.Store(token, windowsSubscription{source: api.Name, notify: notify, ignored: ignored, filter: filter})
		var handle windows.Handle
		status, _, _ := api.Call(windows.AF_UNSPEC, changeCallback, token, 0, uintptr(unsafe.Pointer(&handle)))
		if status == 0 {
			handles = append(handles, handle)
			tokens = append(tokens, token)
		} else {
			watchCallbacks.Delete(token)
			fail(fmt.Errorf("%s: %w", api.Name, syscall.Errno(status)))
		}
	}
	if len(handles) == 0 {
		return "Network notification filter disabled: no subscriptions", nil
	}
	// Subscribe first: any interface touched during the read-only snapshot is
	// conservatively excluded from filtering. No OS query runs in a callback.
	candidates, err := localTeredoInterfaces()
	filter.initialize(candidates, err)
	go func() {
		<-ctx.Done()
		for _, handle := range handles {
			cancelChange.Call(uintptr(handle))
		}
		for _, token := range tokens {
			watchCallbacks.Delete(token)
		}
	}()
	status := func(err error) string {
		if err != nil {
			return fmt.Sprintf("Network notification filter disabled (all events remain relevant): %v", err)
		}
		return fmt.Sprintf("Network notification filter: local-only Teredo IPv6; candidates=%d", filter.count())
	}
	refresh := func() string {
		if ctx.Err() != nil || !filter.beginRefresh() {
			return ""
		}
		candidates, err := localTeredoInterfaces()
		filter.initialize(candidates, err)
		return status(err)
	}
	return status(err), refresh
}
