package netwatch

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestPowerNotificationsInvalidateAndUnregisterWithoutSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := Watch(ctx)
	if err := e.Error(); err != nil {
		t.Fatal(err)
	}
	token := powerID.Load()
	callback, ok := powerCallbacks.Load(token)
	if !ok {
		t.Fatal("power callback not registered")
	}
	before := e.Version()
	for _, kind := range []uint32{4, 18, 7} {
		callback.(func(uint32))(kind)
	}
	if e.Version() < before+3 {
		t.Fatal("power notifications did not invalidate network evidence")
	}
	details := strings.Join(e.Details(before, e.Version()), "\n")
	for _, want := range []string{"source=power", "suspend", "resume-automatic"} {
		if !strings.Contains(details, want) {
			t.Fatalf("missing %q in %s", want, details)
		}
	}
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := powerCallbacks.Load(token); !ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("power callback not unregistered")
}
