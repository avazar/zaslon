package window

import (
	"context"
	"crypto/sha256"
	"fmt"
	"image"
	"image/color"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/avazar/zaslon/internal/app"
	"github.com/avazar/zaslon/internal/config"
	"github.com/avazar/zaslon/internal/guard"
	"github.com/avazar/zaslon/internal/ui"
	"golang.org/x/sys/windows"
)

// HICON handles can change when Edge refreshes the same favicon. Compare the
// actual pixels, including fallback class icons, rather than handle numbers.
func windowIconPixels(hwnd, kind uintptr) (string, error) {
	icon, err := windowMessage(hwnd, 0x007f, kind, 0)
	if err != nil {
		return "", err
	}
	if icon == 0 {
		index := int32(-14) // GCLP_HICON
		if kind == 0 {
			index = -34
		} // GCLP_HICONSM
		get := user32.NewProc("GetClassLongPtrW")
		if unsafe.Sizeof(uintptr(0)) == 4 {
			get = user32.NewProc("GetClassLongW")
		}
		icon, _, _ = get.Call(hwnd, uintptr(index))
	}
	if icon == 0 {
		return "no-icon", nil
	}
	return iconPixels(icon)
}

func iconPixels(icon uintptr) (string, error) {
	var info struct {
		icon        int32
		x, y        uint32
		mask, color windows.Handle
	}
	if ok, _, err := user32.NewProc("GetIconInfo").Call(icon, uintptr(unsafe.Pointer(&info))); ok == 0 {
		return "", err
	}
	gdi := windows.NewLazySystemDLL("gdi32.dll")
	defer gdi.NewProc("DeleteObject").Call(uintptr(info.mask))
	defer gdi.NewProc("DeleteObject").Call(uintptr(info.color))
	var bitmap struct {
		kind, width, height, rowBytes int32
		planes, bits                  uint16
		data                          unsafe.Pointer
	}
	if n, _, err := gdi.NewProc("GetObjectW").Call(uintptr(info.color), unsafe.Sizeof(bitmap), uintptr(unsafe.Pointer(&bitmap))); n == 0 {
		return "", err
	}
	if bitmap.width <= 0 || bitmap.height <= 0 || bitmap.width > 1024 || bitmap.height > 1024 {
		return "", fmt.Errorf("unexpected icon dimensions")
	}
	dc, _, err := gdi.NewProc("CreateCompatibleDC").Call(0)
	if dc == 0 {
		return "", err
	}
	defer gdi.NewProc("DeleteDC").Call(dc)
	pixels := make([]byte, int(bitmap.width)*int(bitmap.height)*4)
	header := struct {
		size                   uint32
		width, height          int32
		planes, bits           uint16
		compression, imageSize uint32
		xppm, yppm             int32
		used, important        uint32
	}{size: 40, width: bitmap.width, height: -bitmap.height, planes: 1, bits: 32, imageSize: uint32(len(pixels))}
	if n, _, err := gdi.NewProc("GetDIBits").Call(dc, uintptr(info.color), 0, uintptr(bitmap.height), uintptr(unsafe.Pointer(&pixels[0])), uintptr(unsafe.Pointer(&header)), 0); n != uintptr(bitmap.height) {
		return "", err
	}
	return fmt.Sprintf("%dx%d:%x", bitmap.width, bitmap.height, sha256.Sum256(pixels)), nil
}

func approvedIconPixels(t *testing.T, hwnd uintptr, directory string) (small, large string) {
	t.Helper()
	path := filepath.Join(directory, "approved.ico")
	if err := os.WriteFile(path, ui.PanelIconICO(), 0600); err != nil {
		t.Fatal(err)
	}
	name, _ := windows.UTF16PtrFromString(path)
	dpi, _, _ := user32.NewProc("GetDpiForWindow").Call(hwnd)
	metric := user32.NewProc("GetSystemMetricsForDpi")
	load := func(cx, cy uintptr) string {
		x, _, _ := metric.Call(cx, dpi)
		y, _, _ := metric.Call(cy, dpi)
		icon, _, err := user32.NewProc("LoadImageW").Call(0, uintptr(unsafe.Pointer(name)), 1, x, y, 0x10)
		if icon == 0 {
			t.Fatal(err)
		}
		defer destroyIcon.Call(icon)
		pixels, err := iconPixels(icon)
		if err != nil {
			t.Fatal(err)
		}
		return pixels
	}
	return load(49, 50), load(11, 12)
}

func identityTestJob(t *testing.T) windows.Handle {
	t.Helper()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.CloseHandle(job)
		t.Fatal(err)
	}
	t.Cleanup(func() { windows.CloseHandle(job) })
	return job
}

func TestReadyPanelIdentityEXE(t *testing.T) {
	exe := os.Getenv("ZASLON_TEST_PANEL_EXE")
	if exe == "" {
		t.Skip("set ZASLON_TEST_PANEL_EXE to the ready Windows EXE")
	}
	edge := findEdge()
	if edge == "" {
		t.Fatal("Edge not installed")
	}
	profile := t.TempDir()
	t.Setenv("ZASLON_DIR", profile)
	t.Setenv("LOCALAPPDATA", filepath.Join(profile, "cache"))
	t.Setenv("ZASLON_CHILD", "1")
	if err := os.WriteFile(filepath.Join(profile, "config.yaml"), []byte("apps: []\nnotifications: false\nupdate_check: false\ncheck_ipv6: false\ndns_check: off\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := config.Default()
	cfg.Apps = nil
	// No runner/Step, probes or process backend: this serves only the real UI.
	server := &ui.Server{G: guard.New(cfg, guard.Deps{}), Stats: app.LoadStats(), Version: "identity-test"}
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); server.WaitClosed() })

	// An unmodified, separately owned Edge app represents the browser host's
	// default grouping. It must retain its own identity and icons throughout.
	controlImage := image.NewNRGBA(image.Rect(0, 0, 32, 32))
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			controlImage.SetNRGBA(x, y, color.NRGBA{R: 220, G: 45, B: 45, A: 255})
		}
	}
	controlICO := ui.ICO(controlImage)
	faviconRequested := make(chan struct{}, 1)
	controlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/control.ico" {
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write(controlICO)
			select {
			case faviconRequested <- struct{}{}:
			default:
			}
			return
		}
		fmt.Fprint(w, "<!doctype html><title>Edge control fixture</title><link rel=\"icon\" href=\"/control.ico\"><p>Unmodified control window</p>")
	}))
	defer controlServer.Close()
	controlJob := identityTestJob(t)
	control, err := startPanelBrowser(controlJob, edge, []string{"--app=" + controlServer.URL, "--user-data-dir=" + filepath.Join(profile, "control-browser"), "--no-first-run", "--no-default-browser-check", "--disable-background-mode"})
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(control)
	var controlWindow uintptr
	var controlTitles []string
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Last observed control window titles: %q", controlTitles)
		}
	})
	// A cold Edge on a hosted runner can take longer to navigate and may
	// include its product name in the caption. Wait for the fixture page.
	eventuallyWithin(t, 15*time.Second, "control Edge page did not appear", func() bool {
		controlTitles = nil
		for _, candidate := range jobWindows(controlJob) {
			buf := make([]uint16, 256)
			user32.NewProc("GetWindowTextW").Call(candidate, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
			title := windows.UTF16ToString(buf)
			controlTitles = append(controlTitles, title)
			if strings.Contains(title, "Edge control fixture") {
				controlWindow = candidate
				return true
			}
		}
		return false
	})
	select {
	case <-faviconRequested:
	case <-time.After(5 * time.Second):
		t.Fatal("control favicon did not load")
	}
	controlID, err := panelPropertyText(controlWindow, appIDKey)
	if err != nil || controlID == "Zaslon.Panel" {
		t.Fatalf("control identity=%q err=%v", controlID, err)
	}
	controlIconResource, err := panelPropertyText(controlWindow, iconResourceKey)
	if err != nil {
		t.Fatal(err)
	}

	job := identityTestJob(t)
	panel, err := startPanelBrowser(job, exe, []string{"panel"})
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(panel)
	var hwnd uintptr
	eventuallyWithin(t, 15*time.Second, "ready EXE did not assign its native identity", func() bool {
		all := jobWindows(job)
		if len(all) != 1 {
			return false
		}
		hwnd = all[0]
		id, err := panelPropertyText(hwnd, appIDKey)
		small, e1 := windowMessage(hwnd, 0x007f, 0, 0)
		large, e2 := windowMessage(hwnd, 0x007f, 1, 0)
		return err == nil && id == "Zaslon.Panel" && e1 == nil && e2 == nil && small != 0 && large != 0
	})
	iconResource, err := panelPropertyText(hwnd, iconResourceKey)
	if err != nil || iconResource != exe+",0" {
		t.Fatalf("taskbar group icon=%q err=%v", iconResource, err)
	}
	small, e1 := windowMessage(hwnd, 0x007f, 0, 0)
	large, e2 := windowMessage(hwnd, 0x007f, 1, 0)
	if e1 != nil || e2 != nil || small == 0 || large == 0 {
		t.Fatalf("native icons missing: %d %d %v %v", small, large, e1, e2)
	}
	expectedSmall, expectedLarge := approvedIconPixels(t, hwnd, profile)
	if jobOwnsWindow(job, controlWindow) {
		t.Fatal("control window belongs to the panel test job")
	}
	// Capture the control after its initial page/favicon loading has settled.
	controlSmall, err := windowIconPixels(controlWindow, 0)
	if err != nil {
		t.Fatal(err)
	}
	controlLarge, err := windowIconPixels(controlWindow, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := startPanelBrowser(job, exe, []string{"panel"})
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(second)
	if r, err := windows.WaitForSingleObject(second, 5000); err != nil || r != windows.WAIT_OBJECT_0 {
		t.Fatalf("duplicate opener did not exit: %d %v", r, err)
	}
	var exit uint32
	if err := windows.GetExitCodeProcess(second, &exit); err != nil || exit != 0 {
		t.Fatalf("duplicate opener failed: %d %v", exit, err)
	}
	if all := jobWindows(job); len(all) != 1 || all[0] != hwnd {
		var details []string
		for _, window := range all {
			buf := make([]uint16, 256)
			user32.NewProc("GetWindowTextW").Call(window, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
			details = append(details, fmt.Sprintf("%d:%s", window, windows.UTF16ToString(buf)))
		}
		var firstExit uint32
		_ = windows.GetExitCodeProcess(panel, &firstExit)
		t.Fatalf("panel windows changed: initial=%d current=%v first-exit=%d", hwnd, details, firstExit)
	}
	// Wait through the real page/favicon load and subsequent identity refreshes.
	time.Sleep(2200 * time.Millisecond)
	if id, err := panelPropertyText(hwnd, appIDKey); err != nil || id != "Zaslon.Panel" {
		t.Fatalf("identity changed after page load: %q %v", id, err)
	}
	eventually(t, "native icons do not match approved Zaslon artwork after page load", func() bool {
		small, e1 := windowIconPixels(hwnd, 0)
		large, e2 := windowIconPixels(hwnd, 1)
		return e1 == nil && e2 == nil && small == expectedSmall && large == expectedLarge
	})
	if id, _ := panelPropertyText(controlWindow, appIDKey); id != controlID {
		t.Fatal("control browser identity changed")
	}
	if resource, _ := panelPropertyText(controlWindow, iconResourceKey); resource != controlIconResource {
		t.Fatal("control browser group icon changed")
	}
	if s, err := windowIconPixels(controlWindow, 0); err != nil || s != controlSmall {
		t.Fatal("control browser small icon changed")
	}
	if b, err := windowIconPixels(controlWindow, 1); err != nil || b != controlLarge {
		t.Fatal("control browser large icon changed")
	}
	t.Logf("ready EXE: AppUserModelID=Zaslon.Panel; group icon=%s; small/large icons present; control AppUserModelID=%q unchanged", iconResource, controlID)
	cancel()
	server.WaitClosed()
	if r, err := windows.WaitForSingleObject(panel, 7000); err != nil || r != windows.WAIT_OBJECT_0 {
		t.Fatalf("panel survived server exit: %d %v", r, err)
	}
	if len(jobWindows(job)) != 0 {
		t.Fatal("panel window survived server exit")
	}
	if all := jobWindows(controlJob); len(all) != 1 || all[0] != controlWindow {
		var exit uint32
		_ = windows.GetExitCodeProcess(control, &exit)
		t.Fatalf("control window changed after panel exit: original=%d now=%v control-process-exit=%d", controlWindow, all, exit)
	}
}
