package netwatch

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"time"
)

// ProxyIdentity lets diagnostics discard observations across proxy changes
// without retaining or displaying proxy credentials.
func ProxyIdentity(proxy *url.URL) string {
	if proxy != nil {
		return fmt.Sprintf("%x", sha256.Sum256([]byte(proxy.String())))
	}
	return ""
}

// CompareIPv4 measures the same endpoint through each explicitly chosen transport.
func CompareIPv4(ctx context.Context, proxy *url.URL, timeout time.Duration) (proxied, direct TraceResult, proxyErr, directErr error) {
	measure := func(p *url.URL) (TraceResult, error) {
		return traceIP(ctx, "https://www.cloudflare.com/cdn-cgi/trace", timeout, false, p, net.DefaultResolver.LookupIP)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		proxied, proxyErr = measure(proxy)
	}()
	direct, directErr = measure(nil)
	<-done
	return
}
