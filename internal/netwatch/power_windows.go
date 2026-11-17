package netwatch

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	powerLibrary    = windows.NewLazySystemDLL("powrprof.dll")
	registerPower   = powerLibrary.NewProc("PowerRegisterSuspendResumeNotification")
	unregisterPower = powerLibrary.NewProc("PowerUnregisterSuspendResumeNotification")
	powerID         atomic.Uintptr
	powerCallbacks  sync.Map
	powerCallback   = windows.NewCallback(func(token uintptr, kind uint32, _ unsafe.Pointer) uintptr {
		if value, ok := powerCallbacks.Load(token); ok {
			value.(func(uint32))(kind)
		}
		return 0
	})
)

type powerParameters struct{ Callback, Context uintptr }

func powerChange(kind uint32) Change {
	c := Change{Source: "power", Kind: fmt.Sprintf("event-%d", kind)}
	switch kind {
	case 4: // PBT_APMSUSPEND
		c.Kind = "suspend"
	case 6: // PBT_APMRESUMECRITICAL
		c.Kind = "resume-critical"
	case 7: // PBT_APMRESUMESUSPEND
		c.Kind = "resume"
	case 18: // PBT_APMRESUMEAUTOMATIC
		c.Kind = "resume-automatic"
	}
	return c
}

// Register only; this API neither requests sleep nor changes power/network
// settings. The callback invalidates evidence through the usual revision path.
func watchPower(ctx context.Context, notify func(func() Change), fail func(error)) {
	if err := registerPower.Find(); err != nil {
		fail(fmt.Errorf("power notifications: %w", err))
		return
	}
	if err := unregisterPower.Find(); err != nil {
		fail(fmt.Errorf("power notifications: %w", err))
		return
	}
	token := powerID.Add(1)
	parameters := &powerParameters{Callback: powerCallback, Context: token}
	var pin runtime.Pinner
	pin.Pin(parameters)
	powerCallbacks.Store(token, func(kind uint32) {
		runtime.KeepAlive(parameters)
		runtime.KeepAlive(&pin)
		if ctx.Err() == nil {
			notify(func() Change { return powerChange(kind) })
		}
	})
	var handle windows.Handle
	status, _, _ := registerPower.Call(2, uintptr(unsafe.Pointer(parameters)), uintptr(unsafe.Pointer(&handle))) // DEVICE_NOTIFY_CALLBACK
	if status != 0 {
		powerCallbacks.Delete(token)
		pin.Unpin()
		fail(fmt.Errorf("power notifications: %w", syscall.Errno(status)))
		return
	}
	go func() {
		<-ctx.Done()
		status, _, _ := unregisterPower.Call(uintptr(handle))
		if status != 0 {
			// Keep the registration's pinned storage alive if Windows could not
			// release it. The context check makes further callbacks inert.
			fail(fmt.Errorf("power notification cancellation: %w", syscall.Errno(status)))
			return
		}
		powerCallbacks.Delete(token)
		pin.Unpin()
		runtime.KeepAlive(parameters)
	}()
}
