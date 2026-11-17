package window

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/avazar/zaslon/internal/procs"
	"golang.org/x/sys/windows"
)

var (
	user32         = windows.NewLazySystemDLL("user32.dll")
	enumWindows    = user32.NewProc("EnumWindows")
	isVisible      = user32.NewProc("IsWindowVisible")
	isWindow       = user32.NewProc("IsWindow")
	getWindowPID   = user32.NewProc("GetWindowThreadProcessId")
	getOwner       = user32.NewProc("GetWindow")
	getWindowStyle = func() *windows.LazyProc {
		if unsafe.Sizeof(uintptr(0)) == 4 {
			return user32.NewProc("GetWindowLongW")
		}
		return user32.NewProc("GetWindowLongPtrW")
	}()
	isIconic     = user32.NewProc("IsIconic")
	showWindow   = user32.NewProc("ShowWindowAsync")
	foreground   = user32.NewProc("SetForegroundWindow")
	postMessage  = user32.NewProc("PostMessageW")
	inJob        = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")
	enumMu       sync.Mutex
	enumJob      windows.Handle
	enumResult   []uintptr
	enumCallback = windows.NewCallback(func(hwnd, _ uintptr) uintptr {
		if isPanelWindow(hwnd) && jobOwnsWindow(enumJob, hwnd) {
			enumResult = append(enumResult, hwnd)
		}
		return 1
	})
)

// Edge also creates tooltips, menus and owned popups. They are not the panel's
// taskbar window and may disappear while the real panel is still open.
func isPanelWindow(hwnd uintptr) bool {
	if visible, _, _ := isVisible.Call(hwnd); visible == 0 {
		return false
	}
	index := int32(-20) // GWL_EXSTYLE
	style, _, _ := getWindowStyle.Call(hwnd, uintptr(index))
	if style&(0x80|0x08000000) != 0 {
		return false
	} // TOOLWINDOW | NOACTIVATE
	owner, _, _ := getOwner.Call(hwnd, 4)   // GW_OWNER
	return owner == 0 || style&0x40000 != 0 // WS_EX_APPWINDOW
}

func jobOwnsWindow(job windows.Handle, hwnd uintptr) bool {
	var pid uint32
	getWindowPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var member int32
	ok, _, _ := inJob.Call(uintptr(h), uintptr(job), uintptr(unsafe.Pointer(&member)))
	return ok != 0 && member != 0
}

func jobWindows(job windows.Handle) []uintptr {
	enumMu.Lock()
	defer enumMu.Unlock()
	enumJob, enumResult = job, nil
	enumWindows.Call(enumCallback, 0)
	result := enumResult
	enumResult = nil
	enumJob = 0
	return result
}

func focusWindow(job windows.Handle, hwnd uintptr) {
	if !jobOwnsWindow(job, hwnd) {
		return
	}
	if iconic, _, _ := isIconic.Call(hwnd); iconic != 0 {
		showWindow.Call(hwnd, 9)
	} // SW_RESTORE only if minimized
	foreground.Call(hwnd)
}

// The browser starts suspended, joins our private job, then begins running.
// Descendants cannot escape into the user's ordinary Edge process tree.
func startPanelBrowser(job windows.Handle, exe string, args []string) (windows.Handle, error) {
	app, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	line, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{exe}, args...)))
	if err != nil {
		return 0, err
	}
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation
	if err = windows.CreateProcess(app, line, nil, nil, false, windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT, nil, nil, &startup, &pi); err != nil {
		return 0, err
	}
	defer windows.CloseHandle(pi.Thread)
	if err = windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Process)
		return 0, err
	}
	if _, err = windows.ResumeThread(pi.Thread); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		windows.CloseHandle(pi.Process)
		return 0, err
	}
	return pi.Process, nil
}

func removePrivateProfile(base, profile string) {
	root, err := filepath.Abs(base)
	if err != nil {
		return
	}
	target, err := filepath.Abs(profile)
	if err != nil {
		return
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return
	}
	for i := 0; i < 5; i++ {
		if os.RemoveAll(target) == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func openBrowserPanel(ctx context.Context, focus <-chan struct{}, browser, url, base string, icon []byte, ready func(windows.Handle, uintptr)) error {
	if ctx.Err() != nil {
		return nil
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		return err
	}
	profile, err := os.MkdirTemp(base, "window-")
	if err != nil {
		return err
	}
	defer removePrivateProfile(base, profile)
	// Disable account sign-in before Edge opens this disposable profile.
	defaultDir := filepath.Join(profile, "Default")
	if err := os.Mkdir(defaultDir, 0700); err != nil {
		return err
	}
	const prefs = `{"signin":{"allowed":false,"allowed_on_next_startup":false},"translate":{"enabled":false}}`
	if err := os.WriteFile(filepath.Join(defaultDir, "Preferences"), []byte(prefs), 0600); err != nil {
		return err
	}
	job, err := procs.NewPanelJob()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return err
	}
	process, err := startPanelBrowser(job, browser, []string{
		"--app=" + url, fmt.Sprintf("--window-size=%d,%d", Width, Height), "--user-data-dir=" + profile,
		"--disable-sync", "--no-first-run", "--no-default-browser-check",
		"--disable-background-mode", "--disable-features=Translate,msImplicitSignin",
	})
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	var identity *panelIdentity
	defer func() {
		if identity != nil {
			identity.clearProperties()
		}
		for _, hwnd := range jobWindows(job) {
			if jobOwnsWindow(job, hwnd) {
				postMessage.Call(hwnd, 0x0010, 0, 0)
			}
		} // WM_CLOSE
		_, _ = windows.WaitForSingleObject(process, 400)
		_ = windows.TerminateJobObject(job, 0) // also remove private background descendants
		_, _ = windows.WaitForSingleObject(process, 2000)
		if identity != nil {
			identity.destroyIcons()
		}
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.Now().Add(15 * time.Second)
	var hwnd uintptr
	wantFocus := false
	for hwnd == 0 {
		select {
		case <-ctx.Done():
			return nil
		case <-focus:
			wantFocus = true
		case <-ticker.C:
			if all := jobWindows(job); len(all) > 0 {
				hwnd = all[0]
				break
			}
			if time.Now().After(deadline) {
				return errors.New("panel browser did not create its window")
			}
		}
	}
	identity, err = newPanelIdentity(job, hwnd, profile, icon)
	if err != nil {
		return err
	}
	identityTick := time.NewTicker(time.Second)
	defer identityTick.Stop()
	if ready != nil {
		ready(job, hwnd)
	}
	if wantFocus {
		focusWindow(job, hwnd)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-focus:
			focusWindow(job, hwnd)
		case <-identityTick.C:
			// Edge can refresh its favicon/identity after navigation. Retry a
			// transient visual update failure without closing a working panel.
			_ = identity.ensure()
		case <-ticker.C:
			if exists, _, _ := isWindow.Call(hwnd); exists == 0 || !jobOwnsWindow(job, hwnd) {
				return nil
			}
		}
	}
}
