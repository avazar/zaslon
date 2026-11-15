package window

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const panelAppID = "Zaslon.Panel"

var (
	shell32                = windows.NewLazySystemDLL("shell32.dll")
	ole32                  = windows.NewLazySystemDLL("ole32.dll")
	propertyStoreForWindow = shell32.NewProc("SHGetPropertyStoreForWindow")
	coInitialize           = ole32.NewProc("CoInitializeEx")
	coUninitialize         = ole32.NewProc("CoUninitialize")
	clearVariant           = ole32.NewProc("PropVariantClear")
	messageTimeout         = user32.NewProc("SendMessageTimeoutW")
	destroyIcon            = user32.NewProc("DestroyIcon")
	propertyStoreIID       = windows.GUID{Data1: 0x886d8eeb, Data2: 0x8cf2, Data3: 0x4446, Data4: [8]byte{0x8d, 0x02, 0xcd, 0xba, 0x1d, 0xbd, 0xcf, 0x99}}
	appModelFormat         = windows.GUID{Data1: 0x9f4c2855, Data2: 0x9f79, Data3: 0x4b39, Data4: [8]byte{0xa8, 0xd0, 0xe1, 0xd4, 0x2d, 0xe1, 0xd5, 0xf3}}
	appIDKey               = propertyKey{appModelFormat, 5}
	iconResourceKey        = propertyKey{appModelFormat, 3}
)

type propertyKey struct {
	format windows.GUID
	id     uint32
}

// PROPVARIANT is 24 bytes on 64-bit Windows and 16 bytes on 32-bit Windows.
type propVariant struct {
	kind     uint16
	reserved [3]uint16
	value    unsafe.Pointer
	padding  uintptr
}

type propertyStore struct {
	vtable *struct {
		queryInterface, addRef, release, getCount, getAt, getValue, setValue, commit uintptr
	}
}

func hresultError(operation string, hr uintptr) error {
	if int32(hr) < 0 {
		return fmt.Errorf("%s: HRESULT 0x%08x", operation, uint32(hr))
	}
	return nil
}

func withWindowStore(hwnd uintptr, use func(*propertyStore) error) error {
	// COM initialization, interface calls and release must stay on one OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hr, _, _ := coInitialize.Call(0, 2) // COINIT_APARTMENTTHREADED
	if uint32(hr) != 0x80010106 {       // RPC_E_CHANGED_MODE: this thread already has COM
		if err := hresultError("initialize panel properties", hr); err != nil {
			return err
		}
		defer coUninitialize.Call()
	}
	var store *propertyStore
	hr, _, _ = propertyStoreForWindow.Call(hwnd, uintptr(unsafe.Pointer(&propertyStoreIID)), uintptr(unsafe.Pointer(&store)))
	if err := hresultError("get panel properties", hr); err != nil {
		return err
	}
	if store == nil {
		return fmt.Errorf("panel property store is unavailable")
	}
	defer syscall.SyscallN(store.vtable.release, uintptr(unsafe.Pointer(store)))
	return use(store)
}

func (s *propertyStore) text(key propertyKey) (string, error) {
	var value propVariant
	hr, _, _ := syscall.SyscallN(s.vtable.getValue, uintptr(unsafe.Pointer(s)), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value)))
	defer clearVariant.Call(uintptr(unsafe.Pointer(&value)))
	if err := hresultError("read panel property", hr); err != nil {
		return "", err
	}
	if value.kind == 0 {
		return "", nil
	} // VT_EMPTY
	if value.kind != 31 {
		return "", fmt.Errorf("unexpected panel property type %d", value.kind)
	}
	return windows.UTF16PtrToString((*uint16)(value.value)), nil
}

func (s *propertyStore) setText(key propertyKey, text *string) error {
	var value propVariant // VT_EMPTY removes the property before closing
	var encoded *uint16
	if text != nil {
		var err error
		encoded, err = windows.UTF16PtrFromString(*text)
		if err != nil {
			return err
		}
		value.kind, value.value = 31, unsafe.Pointer(encoded) // VT_LPWSTR
	}
	hr, _, _ := syscall.SyscallN(s.vtable.setValue, uintptr(unsafe.Pointer(s)), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value)))
	runtime.KeepAlive(encoded)
	// The window store applies SetValue immediately; Commit is unnecessary.
	return hresultError("set panel property", hr)
}

func windowMessage(hwnd, message, wp, lp uintptr) (uintptr, error) {
	var result uintptr
	ok, _, err := messageTimeout.Call(hwnd, message, wp, lp, 0x23, 200, uintptr(unsafe.Pointer(&result))) // BLOCK | ABORTIFHUNG | ERRORONEXIT
	if ok == 0 {
		if err == syscall.Errno(0) {
			err = windows.ERROR_TIMEOUT
		}
		return 0, fmt.Errorf("panel window message: %w", err)
	}
	return result, nil
}

type panelIdentity struct {
	job                windows.Handle
	hwnd, small, large uintptr
	iconResource       string
}

func newPanelIdentity(job windows.Handle, hwnd uintptr, profile string, icon []byte) (*panelIdentity, error) {
	if !jobOwnsWindow(job, hwnd) {
		return nil, fmt.Errorf("refusing to brand a window outside the panel job")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	p := &panelIdentity{job: job, hwnd: hwnd, iconResource: exe + ",0"}
	path := filepath.Join(profile, "panel.ico")
	if err := os.WriteFile(path, icon, 0600); err != nil {
		return p, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return p, err
	}
	var dpi uintptr = 96
	getDPI := user32.NewProc("GetDpiForWindow")
	if getDPI.Find() == nil {
		if d, _, _ := getDPI.Call(hwnd); d != 0 {
			dpi = d
		}
	}
	metric := func(index uintptr) uintptr {
		get := user32.NewProc("GetSystemMetricsForDpi")
		if get.Find() == nil {
			n, _, _ := get.Call(index, dpi)
			return n
		}
		n, _, _ := user32.NewProc("GetSystemMetrics").Call(index)
		return n
	}
	load := func(width, height uintptr) (uintptr, error) {
		h, _, e := user32.NewProc("LoadImageW").Call(0, uintptr(unsafe.Pointer(name)), 1, width, height, 0x10) // IMAGE_ICON, LR_LOADFROMFILE; caller owns HICON
		if h == 0 {
			return 0, fmt.Errorf("load Zaslon panel icon: %w", e)
		}
		return h, nil
	}
	p.small, err = load(metric(49), metric(50)) // SM_CXSMICON, SM_CYSMICON
	if err != nil {
		return p, err
	}
	p.large, err = load(metric(11), metric(12)) // SM_CXICON, SM_CYICON
	if err != nil {
		return p, err
	}
	return p, p.ensure()
}

func (p *panelIdentity) ensure() error {
	if !jobOwnsWindow(p.job, p.hwnd) {
		return fmt.Errorf("panel window no longer belongs to its job")
	}
	for _, item := range []struct{ kind, icon uintptr }{{0, p.small}, {1, p.large}} {
		current, err := windowMessage(p.hwnd, 0x007f, item.kind, 0) // WM_GETICON
		if err != nil {
			return err
		}
		if current != item.icon {
			if _, err := windowMessage(p.hwnd, 0x0080, item.kind, item.icon); err != nil {
				return err
			}
		} // WM_SETICON
	}
	// Apply the ID last: it asks the taskbar to refresh the window's group.
	return withWindowStore(p.hwnd, func(s *propertyStore) error {
		for _, item := range []struct {
			key  propertyKey
			text string
		}{{iconResourceKey, p.iconResource}, {appIDKey, panelAppID}} {
			current, err := s.text(item.key)
			if err != nil {
				return err
			}
			if current != item.text {
				if err := s.setText(item.key, &item.text); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (p *panelIdentity) clearProperties() {
	if !jobOwnsWindow(p.job, p.hwnd) {
		return
	}
	_ = withWindowStore(p.hwnd, func(s *propertyStore) error {
		for _, item := range []struct {
			key  propertyKey
			text string
		}{{appIDKey, panelAppID}, {iconResourceKey, p.iconResource}} {
			if current, err := s.text(item.key); err == nil && current == item.text {
				_ = s.setText(item.key, nil)
			}
		}
		return nil
	})
}

// The browser job is stopped first, so no surviving window refers to these icons.
func (p *panelIdentity) destroyIcons() {
	if p.small != 0 {
		destroyIcon.Call(p.small)
	}
	if p.large != 0 {
		destroyIcon.Call(p.large)
	}
}
