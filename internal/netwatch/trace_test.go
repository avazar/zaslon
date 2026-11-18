package netwatch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTraceUsesFreshUnauthenticatedConnections(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprint(v6), func(t *testing.T) {
			ip := "203.0.113.10"
			if v6 {
				ip = "2001:db8::10"
			}
			connections := make(chan string, 2)
			s := ipTestServer(t, v6, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/cdn-cgi/trace" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || !r.Close {
					t.Error("unexpected request or reused connection")
				}
				connections <- r.RemoteAddr
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintf(w, "h=%s\nip=%s\nloc=NL\n", r.Host, ip)
			})
			for range 2 {
				got, err := traceIP(context.Background(), s.URL, time.Second, v6, nil, nil)
				if err != nil || got.IP != ip || got.Country != "NL" {
					t.Fatalf("%+v %v", got, err)
				}
			}
			if len(connections) != 2 {
				t.Fatal("missing requests")
			}
			if one, two := <-connections, <-connections; one == two {
				t.Fatal("connection was reused")
			}
		})
	}
}

func TestTraceRejectsFailuresWithoutFollowingRedirects(t *testing.T) {
	var followed atomic.Int32
	target := ipTestServer(t, false, func(w http.ResponseWriter, r *http.Request) { followed.Add(1) })
	for _, mode := range []string{"redirect", "forbidden", "html", "oversized", "wrong-host", "duplicate", "private", "wrong-family", "invalid-country", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			s := ipTestServer(t, false, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				switch mode {
				case "redirect":
					http.Redirect(w, r, target.URL, http.StatusFound)
					return
				case "forbidden":
					w.WriteHeader(403)
					return
				case "html":
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprint(w, "<html>challenge</html>")
					return
				case "oversized":
					fmt.Fprint(w, strings.Repeat("a", 4097))
					return
				case "timeout":
					<-r.Context().Done()
					return
				}
				host, ip, cc := r.Host, "203.0.113.10", "NL"
				switch mode {
				case "wrong-host":
					host = "other.example"
				case "private":
					ip = "192.168.1.10"
				case "wrong-family":
					ip = "2001:db8::10"
				case "invalid-country":
					cc = "NLD"
				}
				fmt.Fprintf(w, "h=%s\nip=%s\nloc=%s\n", host, ip, cc)
				if mode == "duplicate" {
					fmt.Fprintln(w, "ip=198.51.100.20")
				}
			})
			if got, err := traceIP(context.Background(), s.URL, 150*time.Millisecond, false, nil, nil); err == nil || got.IP != "" {
				t.Fatalf("accepted %s: %+v %v", mode, got, err)
			} else if mode == "timeout" && (!errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), s.URL)) {
				t.Fatalf("expected a typed timeout without a redundant endpoint: %v", err)
			}
		})
	}
	if followed.Load() != 0 {
		t.Fatal("redirect target received a request")
	}
}

func TestTraceDistinguishesAbsentIPv6FromDNSFailure(t *testing.T) {
	for _, absent := range []bool{true, false} {
		lookup := func(context.Context, string, string) ([]net.IP, error) {
			if absent {
				return nil, &net.DNSError{IsNotFound: true, Name: "example.test", Err: "no AAAA"}
			}
			return nil, context.DeadlineExceeded
		}
		_, err := traceIP(context.Background(), "https://example.test", time.Second, true, nil, lookup)
		if errors.Is(err, ErrNoIPv6) != absent {
			t.Fatalf("absent=%v: %v", absent, err)
		}
	}
}
