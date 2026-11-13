package server

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	pgdb "github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/proxypool"
)

// proxyPoolConfigPatch is a partial update. Pointers distinguish "leave alone"
// from an explicit false/zero, so the UI can save one section without resetting
// the rest of the routing config.
type proxyPoolConfigPatch struct {
	Enabled          *bool   `json:"enabled"`
	RouteMode        *string `json:"route_mode"`
	FallbackMode     *string `json:"fallback_mode"`
	AutoCollect      *bool   `json:"auto_collect"`
	AutoCheck        *bool   `json:"auto_check"`
	SourcesViaSystem *bool   `json:"sources_via_system"`
	CollectMinutes   *int    `json:"collect_interval_minutes"`
	CheckMinutes     *int    `json:"check_interval_minutes"`
	ProbeURL         *string `json:"probe_url"`
	TimeoutSeconds   *int    `json:"timeout_seconds"`
	Concurrency      *int    `json:"concurrency"`
	MaxEntries       *int    `json:"max_entries"`
	FailureThreshold *int    `json:"failure_threshold"`
}

func (patch proxyPoolConfigPatch) apply(cfg proxypool.Config) proxypool.Config {
	if patch.Enabled != nil {
		cfg.Enabled = *patch.Enabled
	}
	if patch.RouteMode != nil {
		cfg.RouteMode = *patch.RouteMode
	}
	if patch.FallbackMode != nil {
		cfg.FallbackMode = *patch.FallbackMode
	}
	if patch.AutoCollect != nil {
		cfg.AutoCollect = *patch.AutoCollect
	}
	if patch.AutoCheck != nil {
		cfg.AutoCheck = *patch.AutoCheck
	}
	if patch.SourcesViaSystem != nil {
		cfg.SourcesViaSystem = *patch.SourcesViaSystem
	}
	if patch.CollectMinutes != nil {
		cfg.CollectMinutes = *patch.CollectMinutes
	}
	if patch.CheckMinutes != nil {
		cfg.CheckMinutes = *patch.CheckMinutes
	}
	if patch.ProbeURL != nil {
		cfg.ProbeURL = *patch.ProbeURL
	}
	if patch.TimeoutSeconds != nil {
		cfg.TimeoutSeconds = *patch.TimeoutSeconds
	}
	if patch.Concurrency != nil {
		cfg.Concurrency = *patch.Concurrency
	}
	if patch.MaxEntries != nil {
		cfg.MaxEntries = *patch.MaxEntries
	}
	if patch.FailureThreshold != nil {
		cfg.FailureThreshold = *patch.FailureThreshold
	}
	return cfg
}

func (s *Server) proxyPoolDB(w http.ResponseWriter) *pgdb.DB {
	if s == nil || s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "数据库不可用")
		return nil
	}
	return s.m.pg
}

func maskProxyPoolEntries(entries []pgdb.ProxyPoolEntry) []pgdb.ProxyPoolEntry {
	out := make([]pgdb.ProxyPoolEntry, len(entries))
	for i, e := range entries {
		e.URL = proxypool.MaskURL(e.URL)
		out[i] = e
	}
	return out
}

func maskProxyPoolSources(sources []pgdb.ProxyPoolSource) []pgdb.ProxyPoolSource {
	out := make([]pgdb.ProxyPoolSource, len(sources))
	for i, src := range sources {
		src.URL = proxypool.MaskURL(src.URL)
		out[i] = src
	}
	return out
}

func (s *Server) getProxyPool(w http.ResponseWriter, r *http.Request) {
	pg := s.proxyPoolDB(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 1)
	if page < 1 {
		page = 1
	}
	pageSize := atoiDefault(q.Get("page_size"), 50)
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}
	filter := pgdb.ProxyPoolFilter{
		Status: strings.TrimSpace(q.Get("status")),
		Query:  strings.TrimSpace(q.Get("q")),
		Source: strings.TrimSpace(q.Get("source")),
	}
	entries, err := pg.ListProxyPoolEntries(r.Context(), pgdb.ProxyPoolFilter{
		Status: filter.Status, Query: filter.Query, Source: filter.Source,
		Limit: pageSize, Offset: (page - 1) * pageSize,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	total, err := pg.CountProxyPoolEntries(r.Context(), filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	stats, err := pg.ProxyPoolStats(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sources, err := pg.ListProxyPoolSources(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	runs, err := pg.ListProxyPoolRuns(r.Context(), 20)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	running, lastErr := false, ""
	if s.proxyPool != nil {
		running, lastErr = s.proxyPool.Status()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":          maskProxyPoolEntries(entries),
		"total":            total,
		"page":             page,
		"page_size":        pageSize,
		"stats":            stats,
		"config":           s.m.ProxyPoolConfig(),
		"selected_proxy":   proxypool.MaskURL(s.m.ProxyPoolSelection()),
		"route_mode":       s.m.ProxyPoolConfig().RouteMode,
		"effective_egress": proxypool.MaskURL(s.m.EffectiveEgress()),
		"running":          running,
		"last_error":       lastErr,
		"sources":          maskProxyPoolSources(sources),
		"runs":             runs,
	})
}

func (s *Server) getProxyPoolConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"config":           s.m.ProxyPoolConfig(),
		"selected_proxy":   proxypool.MaskURL(s.m.ProxyPoolSelection()),
		"effective_egress": proxypool.MaskURL(s.m.EffectiveEgress()),
	})
}

func (s *Server) putProxyPoolConfig(w http.ResponseWriter, r *http.Request) {
	if s.proxyPoolDB(w) == nil {
		return
	}
	var patch proxyPoolConfigPatch
	if err := decode(r, &patch); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg := patch.apply(s.m.ProxyPoolConfig()).Normalize()
	if err := cfg.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.m.SetProxyPoolConfig(cfg); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Route mode / enabled can change the effective egress even when the selected
	// proxy is unchanged; agents bake the capture-off proxy at build time.
	if s.proxyPool != nil {
		s.proxyPool.reapplyEgressAgents()
		if err := s.proxyPool.refreshSelection(r.Context(), nil); err != nil {
			log.Printf("[proxy-pool] 重新选择代理失败: %v", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":           s.m.ProxyPoolConfig(),
		"selected_proxy":   proxypool.MaskURL(s.m.ProxyPoolSelection()),
		"effective_egress": proxypool.MaskURL(s.m.EffectiveEgress()),
	})
}

func (s *Server) refreshProxyPool(w http.ResponseWriter, r *http.Request) {
	if s.proxyPoolDB(w) == nil {
		return
	}
	if s.proxyPool == nil {
		writeErr(w, http.StatusServiceUnavailable, "代理池服务未启动")
		return
	}
	if running, _ := s.proxyPool.Status(); running {
		writeErr(w, http.StatusConflict, errProxyPoolBusy.Error())
		return
	}
	go func() {
		if _, err := s.proxyPool.Refresh(s.ctx); err != nil && !errors.Is(err, errProxyPoolBusy) {
			log.Printf("[proxy-pool] 手动采集失败: %v", err)
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

func (s *Server) checkProxyPool(w http.ResponseWriter, r *http.Request) {
	if s.proxyPoolDB(w) == nil {
		return
	}
	if s.proxyPool == nil {
		writeErr(w, http.StatusServiceUnavailable, "代理池服务未启动")
		return
	}
	if running, _ := s.proxyPool.Status(); running {
		writeErr(w, http.StatusConflict, errProxyPoolBusy.Error())
		return
	}
	go func() {
		if _, err := s.proxyPool.CheckAll(s.ctx); err != nil && !errors.Is(err, errProxyPoolBusy) {
			log.Printf("[proxy-pool] 手动检查失败: %v", err)
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

func (s *Server) importProxyPool(w http.ResponseWriter, r *http.Request) {
	pg := s.proxyPoolDB(w)
	if pg == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	var req struct {
		Text     string `json:"text"`
		Region   string `json:"region"`
		Protocol string `json:"protocol"`
		Source   string `json:"source"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Text) == "" {
		writeErr(w, http.StatusBadRequest, "导入内容为空")
		return
	}
	if strings.TrimSpace(req.Source) == "" {
		req.Source = "manual"
	}
	candidates := proxypool.Parse(req.Text, req.Protocol, req.Source, req.Region)
	if len(candidates) == 0 {
		writeErr(w, http.StatusBadRequest, "未解析到合法代理（支持 http/https/socks5 与 host:port）")
		return
	}
	cfg := s.m.ProxyPoolConfig()
	imported, err := pg.ImportProxyPoolCandidates(r.Context(), candidates, cfg.MaxEntries)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"parsed": len(candidates), "imported": imported,
	})
}

func (s *Server) patchProxyPoolEntry(w http.ResponseWriter, r *http.Request) {
	pg := s.proxyPoolDB(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "无效的代理 id")
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Enabled == nil {
		writeErr(w, http.StatusBadRequest, "缺少 enabled")
		return
	}
	if entry, err := pg.GetProxyPoolEntry(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	} else if entry == nil {
		writeErr(w, http.StatusNotFound, "代理不存在")
		return
	}
	if err := pg.SetProxyPoolEntryEnabled(r.Context(), id, *req.Enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Disabling the currently selected row must immediately rotate to another
	// healthy proxy instead of leaving traffic on a disabled entry.
	if s.proxyPool != nil {
		if err := s.proxyPool.refreshSelection(r.Context(), nil); err != nil {
			log.Printf("[proxy-pool] 重新选择代理失败: %v", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": *req.Enabled})
}

func (s *Server) deleteProxyPoolEntry(w http.ResponseWriter, r *http.Request) {
	pg := s.proxyPoolDB(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "无效的代理 id")
		return
	}
	if entry, err := pg.GetProxyPoolEntry(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	} else if entry == nil {
		writeErr(w, http.StatusNotFound, "代理不存在")
		return
	}
	if err := pg.DeleteProxyPoolEntry(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.proxyPool != nil {
		if err := s.proxyPool.refreshSelection(r.Context(), nil); err != nil {
			log.Printf("[proxy-pool] 重新选择代理失败: %v", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) checkProxyPoolEntry(w http.ResponseWriter, r *http.Request) {
	if s.proxyPoolDB(w) == nil {
		return
	}
	if s.proxyPool == nil {
		writeErr(w, http.StatusServiceUnavailable, "代理池服务未启动")
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "无效的代理 id")
		return
	}
	entry, result, err := s.proxyPool.CheckEntry(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entry != nil {
		masked := proxypool.MaskURL(entry.URL)
		entry.URL = masked
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entry": entry, "result": result,
		"selected_proxy": proxypool.MaskURL(s.m.ProxyPoolSelection()),
	})
}

func (s *Server) listProxyPoolSources(w http.ResponseWriter, r *http.Request) {
	pg := s.proxyPoolDB(w)
	if pg == nil {
		return
	}
	sources, err := pg.ListProxyPoolSources(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": maskProxyPoolSources(sources)})
}

func validSourceURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func (s *Server) createProxyPoolSource(w http.ResponseWriter, r *http.Request) {
	pg := s.proxyPoolDB(w)
	if pg == nil {
		return
	}
	var req struct {
		Name     string `json:"name"`
		URL      string `json:"url"`
		Region   string `json:"region"`
		Protocol string `json:"protocol"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !validSourceURL(req.URL) {
		writeErr(w, http.StatusBadRequest, "来源 URL 必须是 http/https 地址")
		return
	}
	id, err := pg.CreateProxyPoolSource(r.Context(), req.Name, req.URL, req.Region, req.Protocol)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	source, _ := pg.GetProxyPoolSource(r.Context(), id)
	if source != nil {
		source.URL = proxypool.MaskURL(source.URL)
	}
	writeJSON(w, http.StatusCreated, source)
}

func (s *Server) updateProxyPoolSource(w http.ResponseWriter, r *http.Request) {
	pg := s.proxyPoolDB(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "无效的来源 id")
		return
	}
	if source, err := pg.GetProxyPoolSource(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	} else if source == nil {
		writeErr(w, http.StatusNotFound, "来源不存在")
		return
	}
	var req struct {
		Name     *string `json:"name"`
		URL      *string `json:"url"`
		Region   *string `json:"region"`
		Protocol *string `json:"protocol"`
		Enabled  *bool   `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.URL != nil && !validSourceURL(*req.URL) {
		writeErr(w, http.StatusBadRequest, "来源 URL 必须是 http/https 地址")
		return
	}
	if req.Protocol != nil {
		v := strings.ToLower(strings.TrimSpace(*req.Protocol))
		if v != "http" && v != "https" && v != "socks5" {
			writeErr(w, http.StatusBadRequest, "默认协议必须是 http/https/socks5")
			return
		}
	}
	if err := pg.UpdateProxyPoolSource(r.Context(), id, req.Name, req.URL, req.Region, req.Protocol, req.Enabled); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	source, _ := pg.GetProxyPoolSource(r.Context(), id)
	if source != nil {
		source.URL = proxypool.MaskURL(source.URL)
	}
	writeJSON(w, http.StatusOK, source)
}

func (s *Server) deleteProxyPoolSource(w http.ResponseWriter, r *http.Request) {
	pg := s.proxyPoolDB(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "无效的来源 id")
		return
	}
	if source, err := pg.GetProxyPoolSource(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	} else if source == nil {
		writeErr(w, http.StatusNotFound, "来源不存在")
		return
	}
	if err := pg.DeleteProxyPoolSource(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (s *Server) fetchProxyPoolSource(w http.ResponseWriter, r *http.Request) {
	if s.proxyPoolDB(w) == nil {
		return
	}
	if s.proxyPool == nil {
		writeErr(w, http.StatusServiceUnavailable, "代理池服务未启动")
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "无效的来源 id")
		return
	}
	imported, err := s.proxyPool.FetchSource(r.Context(), id)
	if errors.Is(err, errProxyPoolBusy) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": imported})
}

func (s *Server) listProxyPoolRuns(w http.ResponseWriter, r *http.Request) {
	pg := s.proxyPoolDB(w)
	if pg == nil {
		return
	}
	limit := atoiDefault(r.URL.Query().Get("limit"), 20)
	runs, err := pg.ListProxyPoolRuns(r.Context(), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
}
