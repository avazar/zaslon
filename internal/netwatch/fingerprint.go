// Package netwatch notices network changes and finds out the public IP and its country.
package netwatch

import (
	"net"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Filter noisy virtual adapter addresses from the polling fallback. OS route,
// address and interface notifications still invalidate the cached check.
var skipIface = map[string]*regexp.Regexp{
	"darwin":  regexp.MustCompile(`^(lo|bridge|awdl|llw|anpi|ap|gif|stf|vmenet|vmnet)`),
	"windows": regexp.MustCompile(`(?i)loopback|vethernet|vmware|virtualbox|hyper-v|docker|wsl|bluetooth|npcap|vbox`),
	"linux":   regexp.MustCompile(`^(lo|docker|br-|veth|virbr|vmnet|vboxnet|lxc|lxd|cni|flannel|podman)`),
}

type ifaceAddr struct{ name, ip string }

// IPv6Possible is deliberately conservative: a non-link-local address on any
// active interface means that a failed external IPv6 check is inconclusive.
func IPv6Possible() (bool, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return false, err
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		as, err := ifc.Addrs()
		if err != nil {
			return false, err
		}
		for _, a := range as {
			if ipn, ok := a.(*net.IPNet); ok && possibleIPv6(ipn.IP) {
				return true, nil
			}
		}
	}
	return false, nil
}

func possibleIPv6(ip net.IP) bool {
	return ip != nil && ip.To4() == nil && ip.IsGlobalUnicast()
}

// Fingerprint describes active interfaces with their IPv4 and IPv6 addresses.
// Turning a VPN on or off, or switching Wi-Fi, changes it.
func Fingerprint() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return "error"
	}
	var addrs []ifaceAddr
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		as, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range as {
			if ipn, ok := a.(*net.IPNet); ok {
				addrs = append(addrs, ifaceAddr{ifc.Name, ipn.IP.String()})
			}
		}
	}
	return fingerprintOf(addrs, runtime.GOOS)
}

func fingerprintOf(addrs []ifaceAddr, goos string) string {
	skip := skipIface[goos]
	var parts []string
	for _, a := range addrs {
		ip := net.ParseIP(a.ip)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		if skip != nil && skip.MatchString(a.name) {
			continue
		}
		parts = append(parts, a.name+"="+ip.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
