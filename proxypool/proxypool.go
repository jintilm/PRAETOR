// Package proxypool parses, normalizes and checks egress proxies.
//
// It deliberately has no database or HTTP-server dependency: source collection
// is an orchestration concern, while the rules for what counts as a usable proxy
// stay small and testable here.
package proxypool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const (
	DefaultProbeURL       = "https://api.ipify.org?format=json"
	DefaultTimeout        = 8 * time.Second
	DefaultConcurrency    = 20
	DefaultMaxEntries     = 2000
	DefaultFailureLimit   = 3
	DefaultCollectMinutes = 360
	DefaultCheckMinutes   = 30
	maxProbeBody          = 64 * 1024
)

var (
	urlPattern  = regexp.MustCompile(`(?i)\b(?:https?|socks5)://[^\s<>"',;]+`)
	hostPattern = regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?|\d{1,3}(?:\.\d{1,3}){3}):\d{2,5}`)
	ipPattern   = regexp.MustCompile(`(?i)(?:"ip"\s*:\s*"|^ip=)([0-9a-f:.]+)`)
	htmlRow     = regexp.MustCompile(`(?is)<tr[^>]*>(.*?)</tr>`)
	htmlTag     = regexp.MustCompile(`(?s)<[^>]+>`)
	ipv4Pattern = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}$`)
)

// Candidate is one parsed proxy before it is written to the database.
type Candidate struct {
	URL      string `json:"url"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Region   string `json:"region"`
	Source   string `json:"source"`
}

// CheckResult is the deterministic outcome of one proxy probe.
type CheckResult struct {
	URL       string        `json:"url"`
	OK        bool          `json:"ok"`
	Latency   time.Duration `json:"-"`
	LatencyMS int64         `json:"latency_ms"`
	ExitIP    string        `json:"exit_ip"`
	Error     string        `json:"error"`
	CheckedAt time.Time     `json:"checked_at"`
}

// Config controls collection and checks. Source URLs themselves live in the
// database so operators can add domestic/regional lists without a rebuild.
type Config struct {
	Enabled          bool   `json:"enabled"`
	RouteMode        string `json:"route_mode"`    // pool | system | direct
	FallbackMode     string `json:"fallback_mode"` // system | direct
	AutoCollect      bool   `json:"auto_collect"`
	AutoCheck        bool   `json:"auto_check"`
	SourcesViaSystem bool   `json:"sources_via_system"`
	CollectMinutes   int    `json:"collect_interval_minutes"`
	CheckMinutes     int    `json:"check_interval_minutes"`
	ProbeURL         string `json:"probe_url"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	Concurrency      int    `json:"concurrency"`
	MaxEntries       int    `json:"max_entries"`
	FailureThreshold int    `json:"failure_threshold"`
}

// DefaultConfig keeps routing ready for a healthy pool while falling back to the
// existing system/global proxy until one is verified.
func DefaultConfig() Config {
	return Config{
		Enabled: true, RouteMode: "pool", FallbackMode: "system",
		AutoCollect: true, AutoCheck: true, SourcesViaSystem: true,
		CollectMinutes: DefaultCollectMinutes, CheckMinutes: DefaultCheckMinutes,
		ProbeURL: DefaultProbeURL, TimeoutSeconds: int(DefaultTimeout / time.Second),
		Concurrency: DefaultConcurrency, MaxEntries: DefaultMaxEntries,
		FailureThreshold: DefaultFailureLimit,
	}
}

// ParseConfig decodes persisted JSON over the defaults. Unknown fields are
// ignored so older/newer UI builds can share the same settings row.
func ParseConfig(raw string) Config {
	cfg := DefaultConfig()
	if strings.TrimSpace(raw) == "" {
		return cfg
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return DefaultConfig()
	}
	return cfg.Normalize()
}

// Normalize fills omitted/invalid values with conservative defaults. Validate
// is the authority for operator input; Normalize is for persisted settings so a
// partially written or legacy row cannot disable the whole egress path.
func (c Config) Normalize() Config {
	d := DefaultConfig()
	c.RouteMode = strings.ToLower(strings.TrimSpace(c.RouteMode))
	if c.RouteMode == "" {
		c.RouteMode = d.RouteMode
	}
	c.FallbackMode = strings.ToLower(strings.TrimSpace(c.FallbackMode))
	if c.FallbackMode == "" {
		c.FallbackMode = d.FallbackMode
	}
	c.ProbeURL = strings.TrimSpace(c.ProbeURL)
	if c.ProbeURL == "" {
		c.ProbeURL = d.ProbeURL
	}
	if c.CollectMinutes <= 0 {
		c.CollectMinutes = d.CollectMinutes
	}
	if c.CheckMinutes <= 0 {
		c.CheckMinutes = d.CheckMinutes
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = d.TimeoutSeconds
	}
	if c.Concurrency <= 0 {
		c.Concurrency = d.Concurrency
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = d.MaxEntries
	}
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = d.FailureThreshold
	}
	return c
}

// Validate rejects values that would make collection/checking unsafe or
// unbounded. Intervals are intentionally capped below so a typo cannot cause a
// request storm against public sources.
func (c Config) Validate() error {
	if c.RouteMode != "pool" && c.RouteMode != "system" && c.RouteMode != "direct" {
		return errors.New("route_mode 必须是 pool、system 或 direct")
	}
	if c.FallbackMode != "system" && c.FallbackMode != "direct" {
		return errors.New("fallback_mode 必须是 system 或 direct")
	}
	if c.CollectMinutes < 5 || c.CollectMinutes > 7*24*60 {
		return errors.New("采集间隔需在 5 到 10080 分钟之间")
	}
	if c.CheckMinutes < 5 || c.CheckMinutes > 7*24*60 {
		return errors.New("检查间隔需在 5 到 10080 分钟之间")
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 60 {
		return errors.New("代理探测超时需在 1 到 60 秒之间")
	}
	if c.Concurrency < 1 || c.Concurrency > 100 {
		return errors.New("检查并发需在 1 到 100 之间")
	}
	if c.MaxEntries < 1 || c.MaxEntries > 20000 {
		return errors.New("最大条目数需在 1 到 20000 之间")
	}
	if c.FailureThreshold < 1 || c.FailureThreshold > 20 {
		return errors.New("失败隔离阈值需在 1 到 20 之间")
	}
	u, err := url.Parse(strings.TrimSpace(c.ProbeURL))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("探测 URL 必须是有效的 http/https 地址")
	}
	return nil
}

// Normalize validates a proxy URL and returns its canonical form.
func Normalize(raw, defaultScheme string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("代理地址为空")
	}
	if !strings.Contains(raw, "://") {
		if strings.TrimSpace(defaultScheme) == "" {
			defaultScheme = "http"
		}
		raw = strings.ToLower(strings.TrimSpace(defaultScheme)) + "://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("解析代理地址 %q: %w", raw, err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme == "socks5h" {
		u.Scheme = "socks5"
	}
	switch u.Scheme {
	case "http", "https", "socks5":
	default:
		return nil, fmt.Errorf("不支持的代理协议 %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("代理 %q 缺少主机地址", raw)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("代理 %q 缺少有效端口", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("代理 %q 不能包含路径", raw)
	}
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "", "", "", ""
	return u, nil
}

// Parse extracts proxies from plain text, CSV, JSON and HTML dumps.
func Parse(text, defaultScheme, source, region string) []Candidate {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	if strings.TrimSpace(defaultScheme) == "" {
		defaultScheme = "http"
	}
	seen := map[string]bool{}
	out := make([]Candidate, 0)
	add := func(raw string) {
		raw = strings.Trim(raw, " \t\r\n\"'`,;()[]{}<>")
		if raw == "" {
			return
		}
		u, err := Normalize(raw, defaultScheme)
		if err != nil || seen[u.String()] {
			return
		}
		seen[u.String()] = true
		port, _ := strconv.Atoi(u.Port())
		out = append(out, Candidate{URL: u.String(), Protocol: u.Scheme, Host: u.Hostname(), Port: port, Region: strings.TrimSpace(region), Source: strings.TrimSpace(source)})
	}

	var decoded any
	if json.Unmarshal([]byte(text), &decoded) == nil {
		walkStrings(decoded, add, func(raw, scheme string) {
			if scheme != "" && !strings.Contains(raw, "://") {
				raw = scheme + "://" + raw
			}
			add(raw)
		})
	}
	for _, m := range urlPattern.FindAllString(text, -1) {
		add(m)
	}
	// Bare host:port matching must not re-parse the host:port inside a URL that
	// already carried an explicit scheme (otherwise socks5://x:1080 also becomes
	// an http proxy).
	bareText := urlPattern.ReplaceAllString(text, " ")
	for _, m := range hostPattern.FindAllString(bareText, -1) {
		add(m)
	}
	for _, row := range htmlRow.FindAllStringSubmatch(text, -1) {
		plain := strings.Fields(htmlTag.ReplaceAllString(row[1], " "))
		for i := 0; i+1 < len(plain); i++ {
			if ipv4Pattern.MatchString(plain[i]) {
				if port, err := strconv.Atoi(plain[i+1]); err == nil && port >= 1 && port <= 65535 {
					add(plain[i] + ":" + plain[i+1])
				}
			}
		}
	}
	return out
}

func walkStrings(v any, add func(string), addStructured func(string, string)) {
	switch x := v.(type) {
	case string:
		add(x)
		for _, m := range hostPattern.FindAllString(x, -1) {
			add(m)
		}
	case []any:
		for _, item := range x {
			walkStrings(item, add, addStructured)
		}
	case map[string]any:
		// Some public lists expose ip_address/port/protocols as separate JSON
		// fields instead of a host:port string, so walkStrings also understands
		// that shape and maps SOCKS5/HTTP capability to a supported proxy URL.
		if host, port, scheme, ok := structuredJSONProxy(x); ok {
			addStructured(net.JoinHostPort(host, strconv.Itoa(port)), scheme)
			return
		}
		for _, item := range x {
			walkStrings(item, add, addStructured)
		}
	}
}

func structuredJSONProxy(m map[string]any) (host string, port int, scheme string, ok bool) {
	for _, key := range []string{"ip_address", "ip", "host", "address"} {
		if value, found := m[key].(string); found && strings.TrimSpace(value) != "" {
			host = strings.TrimSpace(value)
			break
		}
	}
	if host == "" || strings.ContainsAny(host, "/@") || (strings.Contains(host, ":") && net.ParseIP(host) == nil) {
		return "", 0, "", false
	}
	switch value := m["port"].(type) {
	case float64:
		port = int(value)
		if value != float64(port) {
			return "", 0, "", false
		}
	case string:
		port, _ = strconv.Atoi(strings.TrimSpace(value))
	}
	if port < 1 || port > 65535 {
		return "", 0, "", false
	}

	protocols := jsonProtocols(m)
	if len(protocols) == 0 {
		return host, port, "", true
	}
	for _, protocol := range protocols {
		if protocol == "socks5" || protocol == "socks5h" {
			return host, port, "socks5", true
		}
	}
	for _, protocol := range protocols {
		if protocol == "http" || protocol == "https" {
			return host, port, "http", true
		}
	}
	return "", 0, "", false
}

func jsonProtocols(m map[string]any) []string {
	var raw any
	if value, ok := m["protocols"]; ok {
		raw = value
	} else {
		raw = m["protocol"]
	}
	var protocols []string
	add := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			protocols = append(protocols, value)
		}
	}
	switch value := raw.(type) {
	case string:
		add(value)
	case []any:
		for _, item := range value {
			if text, ok := item.(string); ok {
				add(text)
			}
		}
	}
	return protocols
}

// MaskURL hides credentials in API/UI output.
func MaskURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User == nil {
		return raw
	}
	if _, ok := u.User.Password(); ok {
		u.User = url.UserPassword(u.User.Username(), "__masked__")
	} else {
		u.User = url.User(u.User.Username())
	}
	return u.String()
}

// Checker probes one proxy by issuing a GET through it.
type Checker struct {
	ProbeURL    string
	Timeout     time.Duration
	Concurrency int
}

func (c Checker) Check(ctx context.Context, raw string) CheckResult {
	start := time.Now()
	res := CheckResult{URL: raw, CheckedAt: start, LatencyMS: -1}
	u, err := Normalize(raw, "http")
	if err != nil {
		res.Error = err.Error()
		return res
	}
	probeURL := strings.TrimSpace(c.ProbeURL)
	if probeURL == "" {
		probeURL = DefaultProbeURL
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	transport := &http.Transport{
		DialContext:       (&net.Dialer{Timeout: timeout, KeepAlive: 15 * time.Second}).DialContext,
		ForceAttemptHTTP2: false, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, DisableKeepAlives: true,
	}
	if u.Scheme == "socks5" {
		var auth *xproxy.Auth
		if u.User != nil {
			auth = &xproxy.Auth{User: u.User.Username()}
			auth.Password, _ = u.User.Password()
		}
		dialer, derr := xproxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: timeout})
		if derr != nil {
			res.Error = derr.Error()
			return res
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if cd, ok := dialer.(xproxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			return dialer.Dial(network, addr)
		}
	} else {
		transport.Proxy = http.ProxyURL(u)
	}
	client := &http.Client{Transport: transport, Timeout: timeout}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "PRAETOR-ProxyPool/1.0")
	resp, err := client.Do(req)
	if err != nil {
		res.Error = err.Error()
		res.Latency = time.Since(start)
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))
	res.Latency = time.Since(start)
	res.LatencyMS = res.Latency.Milliseconds()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		res.Error = fmt.Sprintf("探测返回 HTTP %d", resp.StatusCode)
		return res
	}
	res.OK = true
	res.ExitIP = extractIP(body)
	return res
}

func extractIP(body []byte) string {
	text := strings.TrimSpace(string(body))
	if m := ipPattern.FindStringSubmatch(text); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	for _, field := range strings.Fields(text) {
		field = strings.Trim(field, `"'{} ,`)
		if net.ParseIP(field) != nil {
			return field
		}
	}
	return ""
}

// CheckMany preserves input order and bounds concurrency. The caller is
// responsible for setting Checker.Timeout and can cancel through ctx.
func (c Checker) CheckMany(ctx context.Context, raws []string) []CheckResult {
	out := make([]CheckResult, len(raws))
	concurrency := c.Concurrency
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	if concurrency > len(raws) {
		concurrency = len(raws)
	}
	if concurrency <= 0 {
		return out
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, raw := range raws {
		i, raw := i, raw
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				out[i] = CheckResult{URL: raw, Error: ctx.Err().Error(), CheckedAt: time.Now(), LatencyMS: -1}
				return
			}
			out[i] = c.Check(ctx, raw)
		}()
	}
	wg.Wait()
	return out
}

// Score converts observed reliability into a 0..100 ranking value.
func Score(success, failure, consecutiveFailures int, latencyMS int64, lastChecked time.Time, now time.Time) int {
	total := success + failure
	score := 15.0
	if total > 0 {
		score += 30 * float64(success) / float64(total)
	}
	switch {
	case latencyMS >= 0 && latencyMS <= 250:
		score += 30
	case latencyMS <= 750:
		score += 24
	case latencyMS <= 1500:
		score += 17
	case latencyMS <= 3000:
		score += 10
	case latencyMS > 3000:
		score += 3
	}
	if !lastChecked.IsZero() {
		switch age := now.Sub(lastChecked); {
		case age <= time.Hour:
			score += 15
		case age <= 6*time.Hour:
			score += 10
		case age <= 24*time.Hour:
			score += 5
		}
	}
	score -= float64(consecutiveFailures * 12)
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return int(score)
}
