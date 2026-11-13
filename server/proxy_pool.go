package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	pgdb "github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/proxypool"
)

const (
	// A full refresh scrapes several public lists and then probes newly found
	// proxies. Doing that during Server.New would make tests and first paint pay
	// for network weather, so the loop waits one minute before its first pass.
	proxyPoolStartupDelay = 60 * time.Second
	proxyPoolTick         = time.Minute

	proxyPoolMaxSourceBytes     = 8 << 20
	proxyPoolSourceTimeout      = 45 * time.Second
	proxyPoolManualCheckLimit   = 500
	proxyPoolBackgroundCheckMax = 300
)

var errProxyPoolBusy = errors.New("代理池后台任务正在运行，请稍后重试")

// ProxyPoolActionResult is the observable outcome of a collect or check pass.
// The HTTP layer masks selected proxy URLs before returning them to the UI.
type ProxyPoolActionResult struct {
	Imported      int    `json:"imported"`
	Checked       int    `json:"checked"`
	Healthy       int    `json:"healthy"`
	Failed        int    `json:"failed"`
	Sources       int    `json:"sources"`
	Selection     string `json:"selection"`
	SelectionMask string `json:"selection_masked"`
}

// proxyPoolService owns the periodic collect/check loop. It deliberately keeps
// its own mutex instead of Manager.mu: a refresh can hold this for minutes while
// probes are in flight, and request handlers must keep reading config/egress.
type proxyPoolService struct {
	s *Server

	mu          sync.Mutex
	running     bool
	lastErr     string
	lastCollect time.Time
	lastCheck   time.Time
}

func newProxyPoolService(s *Server) *proxyPoolService { return &proxyPoolService{s: s} }

// Status reports whether a refresh/check is in flight and the last background
// error. The API exposes both so the UI can poll instead of blocking a request.
func (p *proxyPoolService) Status() (running bool, lastErr string) {
	if p == nil {
		return false, ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running, p.lastErr
}

func (p *proxyPoolService) begin() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return false
	}
	p.running = true
	p.lastErr = ""
	return true
}

func (p *proxyPoolService) end(err error) {
	p.mu.Lock()
	p.running = false
	if err != nil {
		p.lastErr = err.Error()
	}
	p.mu.Unlock()
}

func (p *proxyPoolService) markCollected() {
	p.mu.Lock()
	p.lastCollect = time.Now()
	p.mu.Unlock()
}

func (p *proxyPoolService) markChecked() {
	p.mu.Lock()
	p.lastCheck = time.Now()
	p.mu.Unlock()
}

// Run starts the background loop. It exits on the Server's root context, which
// Close cancels; every pass also checks ctx so a refresh never outlives shutdown.
func (p *proxyPoolService) Run(ctx context.Context) {
	if p == nil || p.s == nil || p.s.m == nil || p.s.m.pg == nil {
		return
	}
	timer := time.NewTimer(proxyPoolStartupDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	p.tick(ctx)
	ticker := time.NewTicker(proxyPoolTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.tick(ctx)
		}
	}
}

func (p *proxyPoolService) tick(ctx context.Context) {
	cfg := p.s.m.ProxyPoolConfig()
	if !cfg.Enabled {
		return
	}
	p.mu.Lock()
	lastCollect, lastCheck := p.lastCollect, p.lastCheck
	p.mu.Unlock()
	now := time.Now()

	if cfg.AutoCollect && (lastCollect.IsZero() || now.Sub(lastCollect) >= time.Duration(cfg.CollectMinutes)*time.Minute) {
		if _, err := p.Refresh(ctx); err != nil && !errors.Is(err, errProxyPoolBusy) {
			log.Printf("[proxy-pool] 自动采集失败: %v", err)
		}
		p.markCollected()
	}
	if cfg.AutoCheck && (lastCheck.IsZero() || now.Sub(lastCheck) >= time.Duration(cfg.CheckMinutes)*time.Minute) {
		if _, err := p.CheckDue(ctx); err != nil && !errors.Is(err, errProxyPoolBusy) {
			log.Printf("[proxy-pool] 自动检查失败: %v", err)
		}
		p.markChecked()
	}
}

func (p *proxyPoolService) pg() *pgdb.DB {
	if p == nil || p.s == nil || p.s.m == nil {
		return nil
	}
	return p.s.m.pg
}

// Refresh downloads every enabled source, imports new candidates, and probes
// the entries that still have no health signal. Source failures are isolated:
// one dead list must not prevent the remaining lists from being collected.
func (p *proxyPoolService) Refresh(ctx context.Context) (res ProxyPoolActionResult, retErr error) {
	if !p.begin() {
		return res, errProxyPoolBusy
	}
	defer func() { p.end(retErr) }()
	pg := p.pg()
	if pg == nil {
		return res, errors.New("数据库不可用")
	}
	cfg := p.s.m.ProxyPoolConfig()
	if !cfg.Enabled {
		return res, nil
	}

	runID, err := pg.StartProxyPoolRun(ctx, "collect", nil)
	if err != nil {
		return res, err
	}
	var sourceErrs []string
	defer func() {
		// Finish must survive a canceled refresh so the run row does not look
		// permanently in-flight. The DB is still open during Server.Close.
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := pg.FinishProxyPoolRun(c, runID, res.Imported, res.Checked, res.Healthy, res.Failed, strings.Join(sourceErrs, "; ")); err != nil {
			log.Printf("[proxy-pool] 记录采集结果失败: %v", err)
		}
	}()

	sources, err := pg.ListProxyPoolSources(ctx)
	if err != nil {
		return res, err
	}
	if len(sources) == 0 {
		// First run against a fresh database: seed the built-in public lists.
		if err := pg.EnsureProxyPoolSources(ctx); err != nil {
			return res, err
		}
		if sources, err = pg.ListProxyPoolSources(ctx); err != nil {
			return res, err
		}
	}
	successSources := 0
	for _, src := range sources {
		if !src.Enabled {
			continue
		}
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		imported, fetchErr := p.fetchSource(ctx, src, cfg)
		res.Imported += imported
		res.Sources++
		if fetchErr != nil {
			msg := fmt.Sprintf("%s: %v", src.Name, fetchErr)
			sourceErrs = append(sourceErrs, msg)
			if err := pg.MarkProxyPoolSourceFetch(ctx, src.ID, imported, fetchErr.Error()); err != nil {
				log.Printf("[proxy-pool] 记录来源 %s 抓取结果失败: %v", src.Name, err)
			}
			continue
		}
		successSources++
		if err := pg.MarkProxyPoolSourceFetch(ctx, src.ID, imported, ""); err != nil {
			log.Printf("[proxy-pool] 记录来源 %s 抓取结果失败: %v", src.Name, err)
		}
	}
	if successSources == 0 && len(sourceErrs) > 0 {
		retErr = errors.New(strings.Join(sourceErrs, "; "))
	} else if len(sourceErrs) > 0 {
		log.Printf("[proxy-pool] 部分来源抓取失败: %s", strings.Join(sourceErrs, "; "))
	}

	enabled := true
	unknown, err := pg.ListProxyPoolEntries(ctx, pgdb.ProxyPoolFilter{
		Status: "unknown", Enabled: &enabled, Limit: p.checkLimit(cfg),
	})
	if err != nil {
		if retErr == nil {
			retErr = err
		}
	} else {
		checked, healthy, failed := p.checkEntries(ctx, cfg, unknown)
		res.Checked += checked
		res.Healthy += healthy
		res.Failed += failed
	}
	if err := p.refreshSelection(ctx, &res); err != nil && retErr == nil {
		retErr = err
	}
	return res, retErr
}

// CheckAll probes every enabled entry, regardless of when it was last checked.
// It is intentionally synchronous for the caller (which runs it in a goroutine)
// so the returned counts describe exactly one pass.
func (p *proxyPoolService) CheckAll(ctx context.Context) (res ProxyPoolActionResult, retErr error) {
	if !p.begin() {
		return res, errProxyPoolBusy
	}
	defer func() { p.end(retErr) }()
	pg := p.pg()
	if pg == nil {
		return res, errors.New("数据库不可用")
	}
	cfg := p.s.m.ProxyPoolConfig()
	entries, err := pg.DueProxyPoolEntries(ctx, 0, proxyPoolManualCheckLimit)
	if err != nil {
		return res, err
	}
	if err := p.runCheck(ctx, "check", entries, cfg, &res); err != nil {
		return res, err
	}
	if err := p.refreshSelection(ctx, &res); err != nil {
		return res, err
	}
	return res, nil
}

// CheckDue is the periodic health pass. It only probes entries whose last check
// is older than the configured interval, bounding both traffic and proxy churn.
func (p *proxyPoolService) CheckDue(ctx context.Context) (res ProxyPoolActionResult, retErr error) {
	if !p.begin() {
		return res, errProxyPoolBusy
	}
	defer func() { p.end(retErr) }()
	pg := p.pg()
	if pg == nil {
		return res, errors.New("数据库不可用")
	}
	cfg := p.s.m.ProxyPoolConfig()
	interval := time.Duration(cfg.CheckMinutes) * time.Minute
	entries, err := pg.DueProxyPoolEntries(ctx, interval, p.checkLimit(cfg))
	if err != nil {
		return res, err
	}
	if err := p.runCheck(ctx, "check", entries, cfg, &res); err != nil {
		return res, err
	}
	if err := p.refreshSelection(ctx, &res); err != nil {
		return res, err
	}
	return res, nil
}

// CheckEntry probes one proxy synchronously. Manual checks are allowed even on
// disabled rows so an operator can verify a candidate before enabling it.
func (p *proxyPoolService) CheckEntry(ctx context.Context, id int64) (*pgdb.ProxyPoolEntry, proxypool.CheckResult, error) {
	pg := p.pg()
	if pg == nil {
		return nil, proxypool.CheckResult{}, errors.New("数据库不可用")
	}
	entry, err := pg.GetProxyPoolEntry(ctx, id)
	if err != nil {
		return nil, proxypool.CheckResult{}, err
	}
	cfg := p.s.m.ProxyPoolConfig()
	checker := proxypool.Checker{
		ProbeURL:    cfg.ProbeURL,
		Timeout:     time.Duration(cfg.TimeoutSeconds) * time.Second,
		Concurrency: cfg.Concurrency,
	}
	result := checker.Check(ctx, entry.URL)
	if ctx.Err() != nil {
		return entry, result, ctx.Err()
	}
	if err := pg.ApplyProxyPoolCheck(ctx, id, result, cfg.FailureThreshold); err != nil {
		return entry, result, err
	}
	var res ProxyPoolActionResult
	if err := p.refreshSelection(ctx, &res); err != nil {
		return entry, result, err
	}
	updated, err := pg.GetProxyPoolEntry(ctx, id)
	return updated, result, err
}

// FetchSource downloads exactly one configured list. It shares the same busy
// flag as a full refresh so two imports cannot race on the same source row.
func (p *proxyPoolService) FetchSource(ctx context.Context, id int64) (imported int, retErr error) {
	if !p.begin() {
		return 0, errProxyPoolBusy
	}
	defer func() { p.end(retErr) }()
	pg := p.pg()
	if pg == nil {
		return 0, errors.New("数据库不可用")
	}
	src, err := pg.GetProxyPoolSource(ctx, id)
	if err != nil {
		return 0, err
	}
	if src == nil {
		return 0, errors.New("来源不存在")
	}
	cfg := p.s.m.ProxyPoolConfig()
	imported, err = p.fetchSource(ctx, *src, cfg)
	if markErr := pg.MarkProxyPoolSourceFetch(ctx, src.ID, imported, errString(err)); markErr != nil {
		log.Printf("[proxy-pool] 记录来源 %s 抓取结果失败: %v", src.Name, markErr)
	}
	return imported, err
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (p *proxyPoolService) runCheck(ctx context.Context, kind string, entries []pgdb.ProxyPoolEntry, cfg proxypool.Config, res *ProxyPoolActionResult) error {
	if len(entries) == 0 {
		return nil
	}
	pg := p.pg()
	runID, err := pg.StartProxyPoolRun(ctx, kind, nil)
	if err != nil {
		return err
	}
	checked, healthy, failed := p.checkEntries(ctx, cfg, entries)
	res.Checked += checked
	res.Healthy += healthy
	res.Failed += failed
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pg.FinishProxyPoolRun(c, runID, 0, checked, healthy, failed, ""); err != nil {
		log.Printf("[proxy-pool] 记录检查结果失败: %v", err)
	}
	return ctx.Err()
}

func (p *proxyPoolService) checkEntries(ctx context.Context, cfg proxypool.Config, entries []pgdb.ProxyPoolEntry) (checked, healthy, failed int) {
	if len(entries) == 0 {
		return 0, 0, 0
	}
	raws := make([]string, 0, len(entries))
	for _, e := range entries {
		raws = append(raws, e.URL)
	}
	checker := proxypool.Checker{
		ProbeURL:    cfg.ProbeURL,
		Timeout:     time.Duration(cfg.TimeoutSeconds) * time.Second,
		Concurrency: cfg.Concurrency,
	}
	results := checker.CheckMany(ctx, raws)
	for i, result := range results {
		if ctx.Err() != nil {
			// Shutdown/canceled request: never persist synthetic probe errors as
			// real failures, or a restart would quarantine a healthy pool.
			break
		}
		if err := p.pg().ApplyProxyPoolCheck(ctx, entries[i].ID, result, cfg.FailureThreshold); err != nil {
			log.Printf("[proxy-pool] 写入代理 %d 检查结果失败: %v", entries[i].ID, err)
			continue
		}
		checked++
		if result.OK {
			healthy++
		} else {
			failed++
		}
	}
	return checked, healthy, failed
}

func (p *proxyPoolService) checkLimit(cfg proxypool.Config) int {
	n := cfg.Concurrency * 10
	if n < 100 {
		n = 100
	}
	if n > proxyPoolBackgroundCheckMax {
		n = proxyPoolBackgroundCheckMax
	}
	return n
}

// fetchSource downloads one list and imports its proxies. When SourcesViaSystem
// is enabled, the list itself is fetched through the configured global proxy;
// the candidate probes later still go directly to each candidate proxy.
func (p *proxyPoolService) fetchSource(ctx context.Context, src pgdb.ProxyPoolSource, cfg proxypool.Config) (int, error) {
	transport := &http.Transport{
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   proxyPoolSourceTimeout,
		ResponseHeaderTimeout: proxyPoolSourceTimeout,
		DisableKeepAlives:     true,
	}
	if cfg.SourcesViaSystem {
		if raw := strings.TrimSpace(p.s.m.GlobalProxy()); raw != "" {
			u, err := url.Parse(raw)
			if err != nil {
				return 0, fmt.Errorf("系统代理无效: %w", err)
			}
			transport.Proxy = http.ProxyURL(u)
		}
	}
	client := &http.Client{Transport: transport, Timeout: proxyPoolSourceTimeout}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "PRAETOR-ProxyPool/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("来源返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, proxyPoolMaxSourceBytes))
	if err != nil {
		return 0, err
	}
	candidates := proxypool.Parse(string(body), src.Protocol, src.Name, src.Region)
	if len(candidates) == 0 {
		return 0, errors.New("未从来源解析到代理")
	}
	imported, err := p.pg().ImportProxyPoolCandidates(ctx, candidates, cfg.MaxEntries)
	if err != nil {
		return 0, err
	}
	return imported, nil
}

// refreshSelection asks the DB for the best healthy proxy and points the MITM,
// sandbox and agent shells at it. The task-level egress pool still wins because
// sandboxEgressFor checks it before EffectiveEgress.
func (p *proxyPoolService) refreshSelection(ctx context.Context, res *ProxyPoolActionResult) error {
	pg := p.pg()
	if pg == nil {
		return errors.New("数据库不可用")
	}
	best, err := pg.SelectProxyPoolEntry(ctx)
	if err != nil {
		return err
	}
	raw := ""
	if best != nil {
		raw = best.URL
	}
	if res != nil {
		res.Selection = raw
		res.SelectionMask = proxypool.MaskURL(raw)
	}
	if p.s.m.SetProxyPoolSelection(raw) {
		p.reapplyEgressAgents()
	}
	return nil
}

// reapplyEgressAgents rebuilds agents so capture-off bash/WebFetch and the
// browser MCP pick up the newly selected proxy. Never hold cfgMu while calling
// applyLLM (it takes the same lock internally).
func (p *proxyPoolService) reapplyEgressAgents() {
	if p == nil || p.s == nil {
		return
	}
	p.s.cfgMu.Lock()
	cfg, on := p.s.llmCfg, p.s.llmOn
	p.s.cfgMu.Unlock()
	// Per-profile chat agents and task bundles bake the proxy in at build time.
	p.s.invalidateProfileAgents()
	if on {
		if err := p.s.applyLLM(cfg); err != nil {
			log.Printf("[proxy-pool] 重建 agent 出口失败: %v", err)
		}
	}
}
