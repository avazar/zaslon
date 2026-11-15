package netwatch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/avazar/zaslon/internal/config"
)

var ErrNoIPv6 = errors.New("the service has no IPv6 address in the system DNS")

type TraceResult struct{ IP, Country string }

// TraceIP measures a new connection to the configured service host. This is not
// an observation of another process's socket, proxy, credentials or API session.
func TraceIP(ctx context.Context, endpoint string, timeout time.Duration, v6 bool) (TraceResult, error) {
	return traceIP(ctx, endpoint, timeout, v6, SystemProxy(), net.DefaultResolver.LookupIP)
}

func traceIP(parent context.Context, endpoint string, timeout time.Duration, v6 bool, proxy *url.URL,
	lookup func(context.Context, string, string) ([]net.IP, error)) (TraceResult, error) {
	canonical, err := config.DomainEndpoint(endpoint)
	if err != nil {
		return TraceResult{}, err
	}
	u, _ := url.Parse(canonical)
	if u.Scheme == "http" {
		proxy = nil
	} // validated literal loopback fixture; never send it to an external proxy
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if v6 && proxy == nil {
		if ip := net.ParseIP(u.Hostname()); ip != nil {
			if ip.To4() != nil {
				return TraceResult{}, ErrNoIPv6
			}
		} else {
			ips, e := lookup(ctx, "ip6", u.Hostname())
			var dns *net.DNSError
			if e != nil {
				if ctx.Err() == nil && errors.As(e, &dns) && dns.IsNotFound {
					return TraceResult{}, ErrNoIPv6
				}
				return TraceResult{}, e
			}
			if len(ips) == 0 {
				return TraceResult{}, ErrNoIPv6
			}
		}
	}
	network := "tcp4"
	if v6 {
		network = "tcp6"
	}
	c := client(proxy, timeout, network)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, canonical, nil)
	if err != nil {
		return TraceResult{}, err
	}
	req.Header.Set("User-Agent", "Zaslon/trace")
	req.Header.Set("Cache-Control", "no-cache, no-store")
	resp, err := c.Do(req)
	if err != nil {
		return TraceResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return TraceResult{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	typ, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || typ != "text/plain" {
		return TraceResult{}, errors.New("trace response is not text/plain")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil {
		return TraceResult{}, err
	}
	if len(body) > 4096 {
		return TraceResult{}, errors.New("trace response exceeds 4096 bytes")
	}
	result, err := parseTrace(string(body), u.Host, v6)
	if ctx.Err() != nil {
		return TraceResult{}, ctx.Err()
	}
	return result, err
}

func parseTrace(body, host string, v6 bool) (TraceResult, error) {
	fields := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return TraceResult{}, errors.New("invalid trace line")
		}
		if _, exists := fields[k]; exists {
			return TraceResult{}, errors.New("duplicate trace field")
		}
		fields[k] = v
	}
	expected, _ := url.Parse("//" + host)
	if !strings.EqualFold(fields["h"], host) && !strings.EqualFold(fields["h"], expected.Hostname()) {
		return TraceResult{}, errors.New("trace host does not match the requested service")
	}
	ip, err := netip.ParseAddr(fields["ip"])
	if err != nil || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Is4() == v6 {
		return TraceResult{}, errors.New("trace did not return a public IP of the requested family")
	}
	cc := fields["loc"]
	if cc != "" && (len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z') {
		return TraceResult{}, errors.New("invalid trace country")
	}
	return TraceResult{IP: ip.String(), Country: cc}, nil
}
