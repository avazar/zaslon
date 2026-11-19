package ui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/avazar/zaslon/internal/app"
	"github.com/avazar/zaslon/internal/netwatch"
)

type ipReport struct {
	IP  string `json:"ip"`
	ISP struct {
		Name string `json:"isp"`
		ASN  string `json:"asn"`
	} `json:"isp"`
	Location struct {
		Country string `json:"country_code"`
	} `json:"location"`
	Risk struct {
		Mobile     *bool `json:"is_mobile"`
		Datacenter *bool `json:"is_datacenter"`
		VPN        *bool `json:"is_vpn"`
		Proxy      *bool `json:"is_proxy"`
		Tor        *bool `json:"is_tor"`
	} `json:"risk"`
	Fetched time.Time `json:"fetched"`
}

const ipCacheTTL = 7 * 24 * time.Hour

var errInvalidIPCache = errors.New("invalid IPQuery cache")

func readIPCache() (map[string]*ipReport, error) {
	entries := map[string]*ipReport{}
	b, err := os.ReadFile(filepath.Join(app.Dir(), "ipquery.json"))
	if os.IsNotExist(err) {
		return entries, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &entries); err != nil || entries == nil {
		return nil, errInvalidIPCache
	}
	return entries, nil
}

func (s *Server) saveIPReport(report *ipReport) error {
	s.ipCacheMu.Lock()
	defer s.ipCacheMu.Unlock()
	entries, err := readIPCache()
	if errors.Is(err, errInvalidIPCache) {
		entries, err = make(map[string]*ipReport), nil
	}
	if err != nil {
		return err
	}
	if previous := entries[report.IP]; previous != nil && previous.Fetched.After(report.Fetched) {
		return nil
	}
	entries[report.IP] = report
	if len(entries) > 128 {
		oldest := report.IP
		for ip, v := range entries {
			if v == nil || v.Fetched.Before(entries[oldest].Fetched) {
				oldest = ip
				if v == nil {
					break
				}
			}
		}
		delete(entries, oldest)
	}
	file, err := os.CreateTemp(app.Dir(), ".ipquery-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	err = json.NewEncoder(file).Encode(entries)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(file.Name(), filepath.Join(app.Dir(), "ipquery.json"))
}

func queryAddr(w http.ResponseWriter, r *http.Request) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(r.URL.Query().Get("ip"))
	if err != nil || ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		http.Error(w, "invalidIP", http.StatusBadRequest)
		return netip.Addr{}, false
	}
	return ip, true
}

func (s *Server) cachedIP(w http.ResponseWriter, r *http.Request) {
	ip, ok := queryAddr(w, r)
	if !ok {
		return
	}
	s.ipCacheMu.Lock()
	cache, err := readIPCache()
	s.ipCacheMu.Unlock()
	if err != nil {
		http.Error(w, "cacheError", http.StatusInternalServerError)
		return
	}
	v := cache[ip.String()]
	writeJSON(w, map[string]any{"report": v, "stale": v != nil && time.Since(v.Fetched) >= ipCacheTTL})
}

func fetchIPReport(ctx context.Context, client *http.Client, ip netip.Addr) (*ipReport, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipquery.io/"+ip.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IPQuery HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32769))
	if err != nil {
		return nil, err
	}
	var result ipReport
	if len(data) > 32768 || json.Unmarshal(data, &result) != nil {
		return nil, fmt.Errorf("invalidReport")
	}
	got, err := netip.ParseAddr(result.IP)
	if err != nil || got != ip {
		return nil, fmt.Errorf("invalidReport")
	}
	result.IP = ip.String()
	result.Fetched = time.Now()
	return &result, nil
}

func (s *Server) lookupIP(w http.ResponseWriter, r *http.Request) {
	ip, ok := queryAddr(w, r)
	if !ok {
		return
	}
	client := netwatch.HTTPClient(7 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	report, err := fetchIPReport(r.Context(), client, ip)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	err = s.saveIPReport(report)
	writeJSON(w, map[string]any{"report": report, "stale": false, "cacheError": err != nil})
}
