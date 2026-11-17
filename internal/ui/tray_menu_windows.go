package ui

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/avazar/zaslon/internal/app"
)

// fyne/systray opens the context menu with TrackPopupMenu.
// Render on the tray window's own thread before Windows lays out the popup.
func onTrayMenuOpening(open func()) func() {
	const whCallWndProc = 4
	const wmEnterMenuLoop = 0x0211
	type cwpStruct struct {
		lParam, wParam uintptr
		message        uint32
		hwnd           uintptr
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	next := user32.NewProc("CallNextHookEx")
	callback := windows.NewCallback(func(code int32, param uintptr, msg *cwpStruct) uintptr {
		if code == 0 && msg.message == wmEnterMenuLoop && msg.wParam != 0 {
			open()
		}
		result, _, _ := next.Call(0, uintptr(code), param, uintptr(unsafe.Pointer(msg)))
		return result
	})
	runtime.LockOSThread()
	hook, _, err := user32.NewProc("SetWindowsHookExW").Call(whCallWndProc, callback, 0, uintptr(windows.GetCurrentThreadId()))
	if hook == 0 {
		runtime.UnlockOSThread()
		app.Logf("Tray menu open notification unavailable: %v", err)
		return nil
	}
	return func() {
		user32.NewProc("UnhookWindowsHookEx").Call(hook)
		runtime.UnlockOSThread()
	}
}
