package ui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type panelLease struct{ focus chan struct{} }

// One native panel per server instance. A second opener asks the existing
// helper to focus its window instead of creating another browser process.
func (s *Server) panelSession(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	s.panelMu.Lock()
	if s.panel != nil {
		select {
		case s.panel.focus <- struct{}{}:
		default:
		}
		s.panelMu.Unlock()
		w.WriteHeader(http.StatusConflict)
		return
	}
	lease := &panelLease{focus: make(chan struct{}, 1)}
	s.panel = lease
	s.panelMu.Unlock()
	defer func() {
		s.panelMu.Lock()
		if s.panel == lease {
			s.panel = nil
		}
		s.panelMu.Unlock()
	}()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	send := func(message string) bool {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := fmt.Fprintln(w, message); err != nil {
			return false
		}
		return http.NewResponseController(w).Flush() == nil
	}
	if !send("ready") {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.Context().Done():
			return
		case <-lease.focus:
			if !send("focus") {
				return
			}
		}
	}
}

// NativePanelSession lives only as long as the authenticated connection to the
// exact server instance. EOF also covers an abrupt worker crash or restart.
type NativePanelSession struct {
	Context context.Context
	Focus   <-chan struct{}
	cancel  context.CancelFunc
	body    interface{ Close() error }
	once    sync.Once
}

func (p *NativePanelSession) Close() { p.once.Do(func() { p.cancel(); _ = p.body.Close() }) }

func AttachNativePanel(parent context.Context, info PanelInfo) (*NativePanelSession, bool, error) {
	base, err := url.Parse(info.URL)
	if err != nil || base.Scheme != "http" || base.Hostname() != "127.0.0.1" || base.Port() == "" || base.User != nil || info.Token == "" {
		return nil, false, errors.New("invalid local panel address")
	}
	ctx, cancel := context.WithCancel(parent)
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, ResponseHeaderTimeout: 3 * time.Second, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.ResolveReference(&url.URL{Path: "/api/panel-session"}).String(), nil)
	if err != nil {
		cancel()
		return nil, false, err
	}
	req.AddCookie(&http.Cookie{Name: cookieName, Value: info.Token})
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		return nil, false, errors.New("Zaslon panel server is not available")
	}
	if resp.StatusCode == http.StatusConflict {
		_ = resp.Body.Close()
		cancel()
		return nil, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		cancel()
		return nil, false, fmt.Errorf("panel session: HTTP %d", resp.StatusCode)
	}
	reader := bufio.NewScanner(resp.Body)
	reader.Buffer(make([]byte, 64), 256)
	if !reader.Scan() || strings.TrimSpace(reader.Text()) != "ready" {
		_ = resp.Body.Close()
		cancel()
		return nil, false, errors.New("panel session did not start")
	}
	focus := make(chan struct{}, 1)
	p := &NativePanelSession{Context: ctx, Focus: focus, cancel: cancel, body: resp.Body}
	go func() {
		defer p.Close()
		for reader.Scan() {
			if reader.Text() == "focus" {
				select {
				case focus <- struct{}{}:
				default:
				}
			}
		}
	}()
	return p, false, nil
}
