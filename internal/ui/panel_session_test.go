package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func panelTestServer(t *testing.T) (*httptest.Server, PanelInfo, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{token: "panel-test-secret"}
	ts := httptest.NewServer(s.guardRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.panelSession(ctx, w, r)
	})))
	u, _ := url.Parse(ts.URL)
	s.addr = u.Host
	t.Cleanup(ts.Close)
	t.Cleanup(cancel)
	return ts, PanelInfo{URL: ts.URL + "/", Token: s.token}, cancel
}

func awaitPanelEvent(t *testing.T, event <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for " + name)
	}
}

func TestNativePanelSingletonAndFocus(t *testing.T) {
	_, info, _ := panelTestServer(t)
	first, existing, err := AttachNativePanel(context.Background(), info)
	if err != nil || existing {
		t.Fatalf("first open: existing=%v err=%v", existing, err)
	}
	defer first.Close()
	second, existing, err := AttachNativePanel(context.Background(), info)
	if err != nil || !existing || second != nil {
		t.Fatalf("second open: session=%v existing=%v err=%v", second, existing, err)
	}
	awaitPanelEvent(t, first.Focus, "existing window activation")
	select {
	case <-first.Context.Done():
		t.Fatal("duplicate open closed the existing panel")
	default:
	}
	first.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		next, existing, err := AttachNativePanel(context.Background(), info)
		if err != nil {
			t.Fatal(err)
		}
		if !existing {
			next.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closed panel retained the singleton lease")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNativePanelConcurrentOpen(t *testing.T) {
	_, info, _ := panelTestServer(t)
	const count = 12
	type result struct {
		p        *NativePanelSession
		existing bool
		err      error
	}
	results := make(chan result, count)
	var wg sync.WaitGroup
	for range count {
		wg.Go(func() {
			p, existing, err := AttachNativePanel(context.Background(), info)
			results <- result{p, existing, err}
		})
	}
	wg.Wait()
	close(results)
	opened := 0
	for r := range results {
		if r.err != nil {
			t.Errorf("open: %v", r.err)
		}
		if r.p != nil {
			opened++
			defer r.p.Close()
		} else if !r.existing {
			t.Error("neither an active panel nor an existing panel")
		}
	}
	if opened != 1 {
		t.Fatalf("opened %d panels, want 1", opened)
	}
}

func TestNativePanelFollowsServerLifetime(t *testing.T) {
	for _, crash := range []bool{false, true} {
		t.Run(map[bool]string{false: "exit", true: "crash"}[crash], func(t *testing.T) {
			ts, info, cancel := panelTestServer(t)
			p, _, err := AttachNativePanel(context.Background(), info)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if crash {
				ts.CloseClientConnections()
			} else {
				cancel()
			}
			awaitPanelEvent(t, p.Context.Done(), "panel cancellation")
		})
	}
}

func TestNativePanelAuthAndLocalAddress(t *testing.T) {
	_, info, _ := panelTestServer(t)
	for _, bad := range []PanelInfo{
		{URL: info.URL, Token: "wrong"},
		{URL: info.URL},
		{URL: "http://example.com:1234/", Token: info.Token},
		{URL: "http://127.0.0.1.evil:1234/", Token: info.Token},
		{URL: "https://127.0.0.1:1234/", Token: info.Token},
	} {
		p, existing, err := AttachNativePanel(context.Background(), bad)
		if p != nil || existing || err == nil {
			t.Fatalf("accepted invalid session: %+v", bad)
		}
	}
	// A failed/unauthenticated attempt must not reserve the window.
	p, existing, err := AttachNativePanel(context.Background(), info)
	if err != nil || existing {
		t.Fatalf("valid open after rejected attempt: %v %v", existing, err)
	}
	p.Close()
}
