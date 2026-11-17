package procs

import (
	"net/netip"
	"slices"
	"strconv"
)

func darwinProbePath(path string) bool {
	return path == "/usr/sbin/scutil" || path == "/usr/sbin/netstat" || path == "/usr/sbin/arp"
}

// These exact read-only commands are synchronous collectors used by Zaslon.
// Suspending one while waiting for its output would prevent fresh verification.
// An arbitrary command, descendant, or helper launched by a user app is not exempt.
func darwinProbeHelper(parent, child Proc, path string, argv []string) bool {
	if !parent.Control || parent.control != guardControl || child.PPID != parent.PID {
		return false
	}
	parentBirth, e1 := strconv.ParseInt(parent.Created, 10, 64)
	childBirth, e2 := strconv.ParseInt(child.Created, 10, 64)
	if e1 != nil || e2 != nil || parentBirth <= 0 || childBirth < parentBirth {
		return false
	}
	switch path {
	case "/usr/sbin/scutil":
		return slices.Equal(argv, []string{path, "--proxy"})
	case "/usr/sbin/netstat":
		return slices.Equal(argv, []string{path, "-rn", "-f", "inet"})
	case "/usr/sbin/arp":
		if len(argv) != 3 || argv[0] != path || argv[1] != "-n" {
			return false
		}
		ip, err := netip.ParseAddr(argv[2])
		return err == nil && ip.Is4()
	}
	return false
}
