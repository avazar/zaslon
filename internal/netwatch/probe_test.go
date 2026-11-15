package netwatch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ipTestServer binds IPv6 explicitly when needed; it never uses the host proxy.
func ipTestServer(t *testing.T, v6 bool, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	if v6 {
		_ = s.Listener.Close()
		ln, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		s.Listener = ln
	}
	s.Start()
	t.Cleanup(s.Close)
	return s
}

func TestPublicIPKeepsLateConflictingResponse(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%t", v6), func(t *testing.T) {
			allowed, other := "203.0.113.10", "198.51.100.20"
			if v6 {
				allowed, other = "2001:db8::10", "2001:db8::20"
			}
			fast := make(chan struct{}, 2)
			respond := func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintln(w, allowed)
				w.(http.Flusher).Flush()
				fast <- struct{}{}
			}
			one := ipTestServer(t, v6, respond)
			two := ipTestServer(t, v6, respond)
			release := make(chan struct{})
			var once sync.Once
			finish := func() { once.Do(func() { close(release) }) }
			slow := ipTestServer(t, v6, func(w http.ResponseWriter, r *http.Request) {
				select {
				case <-release:
					fmt.Fprintln(w, other)
				case <-r.Context().Done():
				}
			})
			// Release the handler before httptest.Close even if an assertion fails.
			t.Cleanup(finish)
			type outcome struct {
				r   IPResult
				err error
			}
			done := make(chan outcome, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			go func() {
				r, err := publicIP(ctx, []string{one.URL, two.URL, slow.URL}, 3*time.Second, v6, nil)
				done <- outcome{r, err}
			}()
			for range 2 {
				select {
				case <-fast:
				case <-ctx.Done():
					t.Fatal("fast services did not respond")
				}
			}
			select {
			case got := <-done:
				t.Fatalf("accepted early quorum before the pending service: %+v, %v", got.r, got.err)
			case <-time.After(100 * time.Millisecond):
			}
			finish()
			select {
			case got := <-done:
				if got.err != nil || got.r.IP != allowed || got.r.Votes != 2 ||
					len(got.r.Others) != 1 || got.r.Others[0] != other || got.r.Confirmed(2) {
					t.Fatalf("late conflict lost: %+v, %v", got.r, got.err)
				}
			case <-ctx.Done():
				t.Fatal("check did not finish after all responses")
			}
		})
	}
}

func TestPublicIPTimeoutRetainsCompletedVotes(t *testing.T) {
	for _, votes := range []int{1, 2} {
		t.Run(fmt.Sprintf("votes=%d", votes), func(t *testing.T) {
			slow := ipTestServer(t, false, func(_ http.ResponseWriter, r *http.Request) {
				<-r.Context().Done()
			})
			services := []string{slow.URL}
			for range votes {
				fast := ipTestServer(t, false, func(w http.ResponseWriter, _ *http.Request) {
					fmt.Fprintln(w, "203.0.113.10")
				})
				services = append(services, fast.URL)
			}
			start := time.Now()
			r, err := publicIP(context.Background(), services, 500*time.Millisecond, false, nil)
			if err != nil || r.IP != "203.0.113.10" || r.Votes != votes || r.Confirmed(2) != (votes == 2) {
				t.Fatalf("completed votes were lost or quorum changed: %+v, %v", r, err)
			}
			if time.Since(start) > 3*time.Second {
				t.Fatal("unresponsive service exceeded the bounded check")
			}
		})
	}
}

func TestPublicIPCancellationDiscardsPartialSuccess(t *testing.T) {
	fast := make(chan struct{}, 1)
	one := ipTestServer(t, false, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "203.0.113.10")
		w.(http.Flusher).Flush()
		fast <- struct{}{}
	})
	pending := ipTestServer(t, false, func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		select {
		case <-fast:
			cancel()
		case <-ctx.Done():
		}
	}()
	r, err := publicIP(ctx, []string{one.URL, pending.URL}, 2*time.Second, false, nil)
	if !errors.Is(err, context.Canceled) || r.IP != "" || r.Votes != 0 {
		t.Fatalf("cancelled check returned partial success: %+v, %v", r, err)
	}
}
