package procs

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnControlRequiresExactExecutableAndMode(t *testing.T) {
	own := filepath.Join(t.TempDir(), "zaslon.exe")
	for _, tc := range []struct {
		path string
		argv []string
		want controlRole
	}{
		{own, []string{own}, guardControl},
		{own, []string{own, "headless"}, guardControl},
		{own, []string{own, "panel"}, panelControl},
		{own, []string{own, "--eval", "panel"}, notControl},
		{own, []string{own, "panel", "ordinary-app"}, notControl},
		{own, []string{own, "fixture"}, notControl},
		{own, nil, notControl},
		{filepath.Join(t.TempDir(), "zaslon.exe"), []string{own, "panel"}, notControl},
	} {
		if got := ownRole(tc.path, own, tc.argv); got != tc.want {
			t.Fatalf("%q %v: role=%v want=%v", tc.path, tc.argv, got, tc.want)
		}
	}
}

func TestControlMarkerCannotBeSuppliedByRecoveryJSON(t *testing.T) {
	p := Proc{PID: 42, Created: "fixture", Control: true, control: panelControl}
	raw, err := json.Marshal(p)
	if err != nil || strings.Contains(string(raw), "Control") {
		t.Fatalf("control proof persisted: %s %v", raw, err)
	}
	var decoded Proc
	if err := json.Unmarshal([]byte(`{"PID":42,"Control":true,"control":2}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Control || decoded.control != notControl {
		t.Fatal("JSON forged an own-control exemption")
	}
}

func TestDarwinCollectorExceptionRequiresExactCommandAndParent(t *testing.T) {
	parent := Proc{PID: 42, Created: "100", Control: true, control: guardControl}
	child := Proc{PID: 43, PPID: 42, Created: "101"}
	for _, tc := range []struct {
		path string
		argv []string
		want bool
	}{
		{"/usr/sbin/scutil", []string{"/usr/sbin/scutil", "--proxy"}, true},
		{"/usr/sbin/netstat", []string{"/usr/sbin/netstat", "-rn", "-f", "inet"}, true},
		{"/usr/sbin/arp", []string{"/usr/sbin/arp", "-n", "192.0.2.1"}, true},
		{"/usr/sbin/scutil", []string{"/usr/sbin/scutil", "--set", "HostName", "test"}, false},
		{"/tmp/scutil", []string{"/usr/sbin/scutil", "--proxy"}, false},
		{"/usr/sbin/arp", []string{"/usr/sbin/arp", "-n", "router.example"}, false},
		{"/usr/sbin/arp", []string{"/usr/sbin/arp", "-n", "2001:db8::1"}, false},
		{"/usr/sbin/scutil", []string{"/usr/sbin/scutil", "--proxy", "extra"}, false},
		{"/bin/sh", []string{"sh", "-c", "/usr/sbin/scutil --proxy"}, false},
	} {
		if got := darwinProbeHelper(parent, child, tc.path, tc.argv); got != tc.want {
			t.Fatalf("%s %v: control=%v want=%v", tc.path, tc.argv, got, tc.want)
		}
	}
	for _, change := range []func(*Proc, *Proc){
		func(p, _ *Proc) { p.Control = false },
		func(p, _ *Proc) { p.control = panelControl },
		func(_, c *Proc) { c.PPID = 99 },
		func(_, c *Proc) { c.Created = "99" },
		func(_, c *Proc) { c.Created = "" },
	} {
		p, c := parent, child
		change(&p, &c)
		if darwinProbeHelper(p, c, "/usr/sbin/scutil", []string{"/usr/sbin/scutil", "--proxy"}) {
			t.Fatal("unverified collector parent/birth obtained an exemption")
		}
	}
}
