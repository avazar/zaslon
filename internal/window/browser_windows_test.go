package window

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/avazar/zaslon/internal/ui"
	"golang.org/x/sys/windows"
)

// The test executable also acts as a disposable browser. No protected apps,
// personal browser profile or network configuration are involved.
func TestMain(m *testing.M) {
	switch os.Getenv("ZASLON_PANEL_TEST_CHILD") {
	case "window":
		os.Exit(fixtureWindow())
	case "idle":
		for {
			time.Sleep(time.Second)
		}
	case "owner":
		_ = os.Setenv("ZASLON_PANEL_TEST_CHILD", "window")
		exe, _ := os.Executable()
		err := openBrowserPanel(context.Background(), nil, exe, "http://127.0.0.1/fixture", os.Getenv("ZASLON_PANEL_TEST_BASE"), ui.PanelIconICO(), func(_ windows.Handle, hwnd uintptr) {
			_ = os.WriteFile(os.Getenv("ZASLON_PANEL_TEST_READY"), []byte(fmt.Sprint(hwnd)), 0600)
		})
		if err != nil {
			os.Exit(4)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fixtureWindow() int {
	runtime.LockOSThread()
	register := user32.NewProc("RegisterClassW")
	create := user32.NewProc("CreateWindowExW")
	def := user32.NewProc("DefWindowProcW")
	destroy := user32.NewProc("DestroyWindow")
	quit := user32.NewProc("PostQuitMessage")
	get := user32.NewProc("GetMessageW")
	dispatch := user32.NewProc("DispatchMessageW")
	var mainWindow uintptr
	callback := windows.NewCallback(func(hwnd, msg, wp, lp uintptr) uintptr {
		switch msg {
		case 0x0010: // WM_CLOSE
			destroy.Call(hwnd)
			return 0
		case 0x0002: // WM_DESTROY
			if hwnd == mainWindow {
				quit.Call(0)
			}
			return 0
		}
		r, _, _ := def.Call(hwnd, msg, wp, lp)
		return r
	})
	name, _ := windows.UTF16PtrFromString("ZaslonDisposablePanelTest")
	class := struct {
		style                              uint32
		proc                               uintptr
		classExtra, windowExtra            int32
		instance, icon, cursor, background uintptr
		menu, name                         *uint16
	}{proc: callback, name: name}
	if r, _, _ := register.Call(uintptr(unsafe.Pointer(&class))); r == 0 {
		return 2
	}
	hwnd, _, _ := create.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)), 0x10cf0000, 30, 30, 400, 250, 0, 0, 0, 0)
	if hwnd == 0 {
		return 3
	}
	mainWindow = hwnd
	if os.Getenv("ZASLON_PANEL_TEST_AUXILIARY") == "1" {
		// A visible, owned tool popup must not become the tracked panel window.
		_, _, _ = create.Call(0x08000080, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)), 0x90000000, 35, 35, 80, 30, hwnd, 0, 0, 0)
	}
	var message struct {
		hwnd    uintptr
		message uint32
		wp, lp  uintptr
		time    uint32
		x, y    int32
		private uint32
	}
	for {
		r, _, _ := get.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		dispatch.Call(uintptr(unsafe.Pointer(&message)))
	}
	return 0
}

func eventually(t *testing.T, description string, check func() bool) {
	eventuallyWithin(t, 5*time.Second, description, check)
}

func eventuallyWithin(t *testing.T, timeout time.Duration, description string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal(description)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func panelPropertyText(hwnd uintptr, key propertyKey) (text string, err error) {
	err = withWindowStore(hwnd, func(s *propertyStore) error {
		text, err = s.text(key)
		return err
	})
	return
}

func testBrowserLifecycle(t *testing.T, browser, url string, manualClose bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	focus := make(chan struct{}, 1)
	type ownedWindow struct {
		job  windows.Handle
		hwnd uintptr
	}
	ready := make(chan ownedWindow, 1)
	done := make(chan error, 1)
	exited := make(chan struct{})
	base := t.TempDir()
	t.Cleanup(func() { cancel(); <-exited })
	go func() {
		defer close(exited)
		done <- openBrowserPanel(ctx, focus, browser, url, base, ui.PanelIconICO(), func(job windows.Handle, hwnd uintptr) {
			ready <- ownedWindow{job, hwnd}
		})
	}()
	var owned ownedWindow
	select {
	case owned = <-ready:
	case err := <-done:
		t.Fatalf("panel closed before creating window: %v", err)
	case <-ctx.Done():
		t.Fatal("panel did not create its window")
	}
	var pid uint32
	getWindowPID.Call(owned.hwnd, uintptr(unsafe.Pointer(&pid)))
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if all := jobWindows(owned.job); len(all) != 1 {
		t.Fatalf("visible private windows: %d", len(all))
	}
	if id, err := panelPropertyText(owned.hwnd, appIDKey); err != nil || id != "Zaslon.Panel" {
		t.Fatalf("native panel AppUserModelID=%q err=%v", id, err)
	}
	iconResource, err := panelPropertyText(owned.hwnd, iconResourceKey)
	if err != nil || iconResource == "" {
		t.Fatalf("native group icon: %q %v", iconResource, err)
	}
	small, err := windowMessage(owned.hwnd, 0x007f, 0, 0)
	if err != nil || small == 0 {
		t.Fatalf("small window icon: %d %v", small, err)
	}
	large, err := windowMessage(owned.hwnd, 0x007f, 1, 0)
	if err != nil || large == 0 {
		t.Fatalf("large window icon: %d %v", large, err)
	}
	if exe, _ := os.Executable(); browser != exe {
		getTitle := user32.NewProc("GetWindowTextW")
		eventually(t, "browser renderer did not load the fixture", func() bool {
			buf := make([]uint16, 256)
			getTitle.Call(owned.hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
			return strings.Contains(windows.UTF16ToString(buf), "Zaslon isolated panel test")
		})
	}
	// Simulate a late browser/favicon update after the native window appears.
	if err := withWindowStore(owned.hwnd, func(s *propertyStore) error {
		other := "Edge.TestFixture"
		if err := s.setText(appIDKey, &other); err != nil {
			return err
		}
		return s.setText(iconResourceKey, &other)
	}); err != nil {
		t.Fatal(err)
	}
	_, _ = windowMessage(owned.hwnd, 0x0080, 0, 0)
	_, _ = windowMessage(owned.hwnd, 0x0080, 1, 0)
	eventually(t, "browser overwrote the panel identity or icons", func() bool {
		id, e1 := panelPropertyText(owned.hwnd, appIDKey)
		resource, e2 := panelPropertyText(owned.hwnd, iconResourceKey)
		s, e3 := windowMessage(owned.hwnd, 0x007f, 0, 0)
		b, e4 := windowMessage(owned.hwnd, 0x007f, 1, 0)
		return e1 == nil && e2 == nil && e3 == nil && e4 == nil && id == "Zaslon.Panel" && resource == iconResource && s == small && b == large
	})
	foreignJob, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(foreignJob)
	if branding, err := newPanelIdentity(foreignJob, owned.hwnd, base, ui.PanelIconICO()); err == nil || branding != nil {
		t.Fatal("accepted a window outside the designated job")
	}
	showWindow.Call(owned.hwnd, 6) // SW_MINIMIZE
	eventually(t, "window did not minimize", func() bool { r, _, _ := isIconic.Call(owned.hwnd); return r != 0 })
	focus <- struct{}{}
	eventually(t, "duplicate open did not restore minimized window", func() bool { r, _, _ := isIconic.Call(owned.hwnd); return r == 0 })
	if manualClose {
		postMessage.Call(owned.hwnd, 0x0010, 0, 0)
	} else {
		cancel()
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("panel did not close")
	}
	if r, _, _ := isWindow.Call(owned.hwnd); r != 0 {
		t.Fatal("panel window survived shutdown")
	}
	if r, err := windows.WaitForSingleObject(h, 0); err != nil || r != windows.WAIT_OBJECT_0 {
		t.Fatalf("private browser survived shutdown: result=%d err=%v", r, err)
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 0 {
		t.Fatalf("private profile remained: %v %v", entries, err)
	}
}

func TestPrivatePanelLifecycle(t *testing.T) {
	t.Setenv("ZASLON_PANEL_TEST_CHILD", "window")
	exe, _ := os.Executable()
	for _, manual := range []bool{false, true} {
		t.Run(fmt.Sprintf("manual-close=%v", manual), func(t *testing.T) {
			testBrowserLifecycle(t, exe, "http://127.0.0.1/fixture", manual)
		})
	}
}

func TestPrivatePanelIgnoresAuxiliaryWindows(t *testing.T) {
	t.Setenv("ZASLON_PANEL_TEST_CHILD", "window")
	t.Setenv("ZASLON_PANEL_TEST_AUXILIARY", "1")
	exe, _ := os.Executable()
	testBrowserLifecycle(t, exe, "http://127.0.0.1/fixture", false)
}

func TestPrivatePanelLeavesUnrelatedProcess(t *testing.T) {
	t.Setenv("ZASLON_PANEL_TEST_CHILD", "idle")
	exe, _ := os.Executable()
	other := exec.Command(exe)
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Process.Kill(); _ = other.Wait() }()
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(other.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	t.Setenv("ZASLON_PANEL_TEST_CHILD", "window")
	testBrowserLifecycle(t, exe, "http://127.0.0.1/fixture", false)
	if r, err := windows.WaitForSingleObject(h, 0); err != nil || r != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("unrelated process affected: result=%d err=%v", r, err)
	}
}

func TestPrivatePanelCancelledDuringStartup(t *testing.T) {
	t.Setenv("ZASLON_PANEL_TEST_CHILD", "idle")
	exe, _ := os.Executable()
	base := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- openBrowserPanel(ctx, nil, exe, "http://127.0.0.1/fixture", base, ui.PanelIconICO(), nil)
	}()
	eventually(t, "private profile was not created", func() bool { files, _ := os.ReadDir(base); return len(files) != 0 })
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startup cancellation did not stop browser")
	}
	files, _ := os.ReadDir(base)
	if len(files) != 0 {
		t.Fatal("cancelled startup left a profile")
	}
}

func TestPrivatePanelOwnerCrash(t *testing.T) {
	base := t.TempDir()
	ready := base + "/ready.txt"
	t.Setenv("ZASLON_PANEL_TEST_CHILD", "owner")
	t.Setenv("ZASLON_PANEL_TEST_BASE", base+"/profiles")
	t.Setenv("ZASLON_PANEL_TEST_READY", ready)
	exe, _ := os.Executable()
	owner := exec.Command(exe)
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Process.Kill(); _ = owner.Wait() }()
	var hwnd uintptr
	eventually(t, "owner did not create its private window", func() bool {
		b, err := os.ReadFile(ready)
		if err != nil {
			return false
		}
		_, err = fmt.Sscan(string(b), &hwnd)
		return err == nil && hwnd != 0
	})
	var pid uint32
	getWindowPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	if err := owner.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if r, err := windows.WaitForSingleObject(h, 5000); err != nil || r != windows.WAIT_OBJECT_0 {
		t.Fatalf("browser survived owner crash: %d %v", r, err)
	}
	if r, _, _ := isWindow.Call(hwnd); r != 0 {
		t.Fatal("window survived owner crash")
	}
}

// Opt-in smoke test of real Edge, using only a fresh disposable profile and
// a loopback fixture. Normal CI exercises the same lifecycle with the fixture.
func TestRealEdgePrivatePanel(t *testing.T) {
	if os.Getenv("ZASLON_TEST_EDGE") != "1" {
		t.Skip("set ZASLON_TEST_EDGE=1 for isolated Edge smoke test")
	}
	edge := findEdge()
	if edge == "" {
		t.Fatal("Edge not installed")
	}
	loaded := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case loaded <- struct{}{}:
		default:
		}
		fmt.Fprint(w, "<!doctype html><title>Zaslon isolated panel test</title><p>Disposable test panel</p>")
	}))
	defer ts.Close()
	testBrowserLifecycle(t, edge, ts.URL, false)
	select {
	case <-loaded:
	default:
		t.Fatal("Edge did not load the local test page")
	}
}
