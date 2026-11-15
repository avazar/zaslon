package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Runs the ready GUI EXE against a disposable, authenticated local server.
// There is no guard, process matching or internet probe in this fixture.
func TestReadyPanelEXE(t *testing.T) {
	exe := os.Getenv("ZASLON_TEST_PANEL_EXE")
	if exe == "" {
		t.Skip("set ZASLON_TEST_PANEL_EXE to the ready Windows EXE")
	}
	for _, crash := range []bool{false, true} {
		t.Run(fmt.Sprintf("server-disconnect=%v", crash), func(t *testing.T) {
			profile := t.TempDir()
			t.Setenv("ZASLON_DIR", profile)
			t.Setenv("LOCALAPPDATA", filepath.Join(profile, "cache"))
			t.Setenv("ZASLON_CHILD", "1")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &Server{token: "ready-panel-test-secret"}
			title := "Zaslon-test-" + filepath.Base(profile)
			mux := http.NewServeMux()
			mux.HandleFunc("/api/panel-session", func(w http.ResponseWriter, r *http.Request) { s.panelSession(ctx, w, r) })
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "<!doctype html><title>%s</title><p>Isolated panel EXE test</p>", title)
			})
			ts := httptest.NewServer(s.guardRequest(mux))
			defer ts.Close()
			u, _ := url.Parse(ts.URL)
			s.addr = u.Host
			info, _ := json.Marshal(PanelInfo{URL: ts.URL + "/", Token: s.token})
			if err := os.WriteFile(filepath.Join(profile, "panel.json"), info, 0600); err != nil {
				t.Fatal(err)
			}
			first := exec.Command(exe, "panel")
			if err := first.Start(); err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() { finished <- first.Wait() }()
			defer func() { _ = first.Process.Kill() }()
			user32 := windows.NewLazySystemDLL("user32.dll")
			getTitle := user32.NewProc("GetWindowTextW")
			var matches []uintptr
			callback := windows.NewCallback(func(hwnd, _ uintptr) uintptr {
				buf := make([]uint16, 256)
				getTitle.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
				if strings.Contains(windows.UTF16ToString(buf), title) {
					matches = append(matches, hwnd)
				}
				return 1
			})
			find := func() []uintptr {
				matches = nil
				user32.NewProc("EnumWindows").Call(callback, 0)
				return matches
			}
			deadline := time.Now().Add(15 * time.Second)
			for len(find()) == 0 && time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
			}
			if len(matches) != 1 {
				t.Fatalf("first open: windows=%d", len(matches))
			}
			hwnd := matches[0]
			user32.NewProc("ShowWindowAsync").Call(hwnd, 6)
			time.Sleep(150 * time.Millisecond)
			secondCtx, secondCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer secondCancel()
			if err := exec.CommandContext(secondCtx, exe, "panel").Run(); err != nil {
				t.Fatal(err)
			}
			deadline = time.Now().Add(3 * time.Second)
			for {
				minimized, _, _ := user32.NewProc("IsIconic").Call(hwnd)
				if minimized == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("second open did not restore existing window")
				}
				time.Sleep(25 * time.Millisecond)
			}
			if len(find()) != 1 || matches[0] != hwnd {
				t.Fatal("duplicate panel window")
			}
			if crash {
				ts.CloseClientConnections()
			} else {
				cancel()
			}
			select {
			case err := <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(7 * time.Second):
				t.Fatal("panel EXE survived server shutdown")
			}
			if len(find()) != 0 {
				t.Fatal("window survived server shutdown")
			}
		})
	}
}
