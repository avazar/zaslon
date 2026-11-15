package netwatch

import (
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

const tunnelTypeTeredo = 14 // TUNNEL_TYPE_TEREDO, Windows SDK

type windowsChangeHint struct {
	source  string
	kind    uint32
	family  uint16
	luid    uint64
	index   uint32
	address netip.Addr
	prefix  netip.Prefix
	nextHop netip.Addr
}

// Read only the notification key fields. No formatting, interface enumeration,
// name lookup or OS calls may delay marking a relevant callback's revision.
func windowsHint(source string, row unsafe.Pointer, kind uint32) windowsChangeHint {
	h := windowsChangeHint{source: source, kind: kind}
	if row == nil {
		return h
	}
	switch source {
	case "NotifyRouteChange2":
		r := (*routeChangeRow)(row)
		h.family, h.luid, h.index = r.Destination.Family, r.Luid, r.Index
		h.prefix = netip.PrefixFrom(changeIP(r.Destination), int(r.PrefixLength))
		h.nextHop = changeIP(r.NextHop)
	case "NotifyUnicastIpAddressChange":
		r := (*addressChangeRow)(row)
		h.family, h.luid, h.index = r.Address.Family, r.Luid, r.Index
		h.address = changeIP(r.Address)
	case "NotifyIpInterfaceChange":
		r := (*interfaceChangeRow)(row)
		h.family, h.luid, h.index = r.Family, r.Luid, r.Index
	}
	return h
}

type windowsEventFilter struct {
	mu           sync.Mutex
	ready        bool
	touched      map[uint64]bool
	local        map[uint64]uint32 // LUID -> index; never identify a tunnel by its name or index alone
	blocked      map[uint64]bool   // external/unknown activity must never be relearned as local-only
	disabled     bool
	refreshing   bool
	needsRefresh atomic.Bool
}

func (f *windowsEventFilter) initialize(candidates map[uint64]uint32, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		if f.local == nil {
			f.local = make(map[uint64]uint32)
		}
		for luid, index := range candidates {
			if !f.disabled && !f.blocked[luid] && !f.touched[luid] && !f.touched[0] {
				f.local[luid] = index
			} else if !f.disabled && !f.blocked[luid] {
				f.needsRefresh.Store(true)
			}
		}
	} else {
		clear(f.local)
	}
	f.ready = true
	f.refreshing = false
	f.touched = nil
}

func (f *windowsEventFilter) beginRefresh() bool {
	if !f.needsRefresh.Swap(false) {
		return false
	}
	f.mu.Lock()
	f.refreshing = true
	f.touched = map[uint64]bool{}
	f.mu.Unlock()
	return true
}

func (f *windowsEventFilter) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.local) }

func (f *windowsEventFilter) ignore(h windowsChangeHint) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.ready || f.refreshing {
		if f.touched == nil {
			f.touched = map[uint64]bool{}
		}
		f.touched[h.luid] = true
	}
	if h.luid == 0 {
		// An unidentifiable notification may have changed any candidate.
		clear(f.local)
		f.disabled = true
		return false
	}
	if f.disabled {
		return false
	}
	index, known := f.local[h.luid]
	localOnly := false
	if h.family == windows.AF_INET6 && h.kind <= windows.MibDeleteInstance {
		switch h.source {
		case "NotifyIpInterfaceChange":
			localOnly = true
		case "NotifyUnicastIpAddressChange":
			localOnly = h.address.IsLinkLocalUnicast()
		case "NotifyRouteChange2":
			localOnly = localIPv6Route(h.prefix, h.nextHop)
		}
	}
	if localOnly && (!known || h.index == index) {
		if known && f.ready {
			return true
		}
		if f.ready && !f.blocked[h.luid] && h.source == "NotifyIpInterfaceChange" {
			f.needsRefresh.Store(true)
		}
		return false
	}
	// Once external/unknown activity is seen, all later interface and local
	// notifications remain relevant for this watcher lifetime, even after delete.
	delete(f.local, h.luid)
	if f.blocked == nil {
		f.blocked = map[uint64]bool{}
	}
	f.blocked[h.luid] = true
	return false
}

func localIPv6Route(prefix netip.Prefix, nextHop netip.Addr) bool {
	if !prefix.IsValid() || !prefix.Addr().Is6() || !nextHop.IsValid() || !nextHop.Is6() || !nextHop.IsUnspecified() {
		return false
	}
	ip := prefix.Masked().Addr()
	return (prefix.Bits() >= 10 && ip.IsLinkLocalUnicast()) || (prefix.Bits() >= 8 && ip.IsMulticast())
}

// All three tables are snapshots read after notification registration. Any
// lookup failure keeps the old conservative behavior for every notification.
func localTeredoInterfaces() (map[uint64]uint32, error) {
	interfaces, err := teredoInterfaceTypes()
	if err != nil {
		return nil, err
	}
	var addresses *windows.MibUnicastIpAddressTable
	if err := windows.GetUnicastIpAddressTable(windows.AF_INET6, &addresses); err != nil {
		return nil, fmt.Errorf("address snapshot: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(addresses))
	var routes *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET6, &routes); err != nil {
		return nil, fmt.Errorf("route snapshot: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(routes))
	return candidateTeredoInterfaces(interfaces, unsafe.Slice(&addresses.Table[0], addresses.NumEntries), routes.Rows()), nil
}

// The IP stack's adapter table supplies TunnelType even on hosts whose NDIS
// interface table reports zero for Teredo. Do not infer it from a display name.
func teredoInterfaceTypes() ([]windows.MibIfRow2, error) {
	size := uint32(15000)
	for range 4 {
		buf := make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET6, windows.GAA_FLAG_INCLUDE_ALL_INTERFACES, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("adapter type snapshot: %w", err)
		}
		var out []windows.MibIfRow2
		for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
			if uintptr(a.Length) < unsafe.Offsetof(a.TunnelType)+unsafe.Sizeof(a.TunnelType) {
				return nil, fmt.Errorf("adapter type snapshot: incomplete structure")
			}
			out = append(out, windows.MibIfRow2{InterfaceLuid: a.Luid, InterfaceIndex: a.Ipv6IfIndex, Type: a.IfType, TunnelType: a.TunnelType})
		}
		runtime.KeepAlive(buf)
		return out, nil
	}
	return nil, fmt.Errorf("adapter type snapshot kept changing")
}

func candidateTeredoInterfaces(interfaces []windows.MibIfRow2, addresses []windows.MibUnicastIpAddressRow, routes []windows.MibIpForwardRow2) map[uint64]uint32 {
	local := map[uint64]uint32{}
	for _, r := range interfaces {
		if r.Type == ifTypeTunnel && r.TunnelType == tunnelTypeTeredo && r.InterfaceLuid != 0 && r.InterfaceIndex != 0 {
			local[r.InterfaceLuid] = r.InterfaceIndex
		}
	}
	for _, r := range addresses {
		if r.Address.Family != windows.AF_INET6 || !netip.AddrFrom16(r.Address.Addr).IsLinkLocalUnicast() {
			delete(local, r.InterfaceLuid)
		}
	}
	for _, r := range routes {
		dest := *(*changeSockaddr)(unsafe.Pointer(&r.DestinationPrefix.Prefix))
		next := *(*changeSockaddr)(unsafe.Pointer(&r.NextHop))
		if !localIPv6Route(netip.PrefixFrom(changeIP(dest), int(r.DestinationPrefix.PrefixLength)), changeIP(next)) {
			delete(local, r.InterfaceLuid)
		}
	}
	return local
}
