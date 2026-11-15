package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jintilm/praetor/agent/domain"
	"github.com/jintilm/praetor/config"
	db "github.com/jintilm/praetor/db"
	actool "github.com/jintilm/praetor/internal/norma/tool"
	"github.com/jintilm/praetor/traffic"
)

type miniAppToolSpec struct {
	name   string
	desc   string
	schema map[string]any
	run    func(*Server, int64, json.RawMessage) (actool.Result, error)
}

func miniAppToolSpecs() []miniAppToolSpec {
	return []miniAppToolSpec{
		{
			name: "miniapp_status",
			desc: "【小程序黑盒·默认授权】检查任务领域、assume 授权模式、Android 设备状态和 Burp MCP 连接。" +
				"不执行平台保护绕过；设备不可用时明确返回降级原因。",
			schema: objSchema(map[string]any{}),
			run:    runMiniAppStatus,
		},
		{
			name: "burp_sync",
			desc: "【小程序黑盒·默认授权】从 Burp MCP 的 Proxy HTTP History 同步请求到 PRAETOR 流量库。" +
				"只导入当前任务 Scope 内的后端域名；请求/响应正文由 traffic_search/traffic_get 读取，并可绑定 finding。" +
				"默认读取最近 20 条；regex 留空时自动按任务 Scope 域名过滤。",
			schema: objSchema(map[string]any{
				"count": map[string]any{
					"type":        "integer",
					"description": "同步条数，默认 20，范围 1..100",
				},
				"offset": map[string]any{
					"type":        "integer",
					"description": "Burp History 起始偏移，默认 0",
				},
				"regex":  strParam("可选：Burp 正则过滤，例如域名、路径或小程序 AppID"),
				"scheme": strParam("可选：auto(默认) | http | https；仅在 Burp 原始请求无法判断协议时使用"),
			}),
			run: runBurpSync,
		},
		{
			name: "miniapp_screenshot",
			desc: "【小程序黑盒·默认授权】对已授权 Android 真机截屏并保存到任务 /work/mobile/ 证据目录。" +
				"返回文件路径、大小和 SHA256；不会内联图片，也不会绕过微信保护。",
			schema: objSchema(map[string]any{}),
			run:    runMiniAppScreenshot,
		},
	}
}

func (s *Server) miniAppToolsFor(taskID int64) []actool.CoreTool {
	if s == nil || s.m == nil || taskID <= 0 {
		return nil
	}
	t := s.m.ResolveTask(strconv.FormatInt(taskID, 10))
	if t == nil || strings.TrimSpace(t.Domain) != string(domain.Miniapp) {
		return nil
	}
	g, err := s.effectiveMobileGrant(taskID)
	if err != nil || g == nil || !g.Active(time.Now()) {
		return nil
	}
	out := make([]actool.CoreTool, 0, len(miniAppToolSpecs()))
	for _, spec := range miniAppToolSpecs() {
		sp := spec
		id := taskID
		out = append(out, wrTool(sp.name, sp.desc, sp.schema,
			func(_ context.Context, in json.RawMessage) (actool.Result, error) {
				return sp.run(s, id, in)
			}))
	}
	return out
}

func runMiniAppStatus(s *Server, taskID int64, _ json.RawMessage) (actool.Result, error) {
	t := s.m.ResolveTask(strconv.FormatInt(taskID, 10))
	if t == nil || strings.TrimSpace(t.Domain) != string(domain.Miniapp) {
		return actool.Errorf("当前任务不是小程序黑盒领域"), nil
	}
	if g, err := s.effectiveMobileGrant(taskID); err != nil || g == nil || !g.Active(time.Now()) {
		if err != nil {
			return actool.Errorf("小程序授权校验失败：" + err.Error()), nil
		}
		return actool.Errorf("小程序任务没有生效的默认授权或任务级授权"), nil
	}
	out := map[string]any{
		"task_id":               strconv.FormatInt(taskID, 10),
		"domain":                t.Domain,
		"auth_mode":             mobileAuthMode(),
		"default_authorization": mobileAuthAssumed(),
		"mobile_device_mode":    config.Env("MOBILE_DEVICE_MODE") == "1",
		"burp":                  map[string]any{"connected": false},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	burp, burpErr := s.burpMCPStatus(ctx)
	if burpErr != nil {
		out["burp"] = map[string]any{"connected": false, "error": burpErr.Error()}
	} else {
		out["burp"] = burp
	}

	if serial, ok := s.mobileTaskContext(strconv.FormatInt(taskID, 10)); ok {
		probe := probeMobileDevice(ctx, serial)
		out["device"] = probe
	} else if config.Env("MOBILE_DEVICE_MODE") != "1" {
		out["device"] = map[string]any{
			"ready":  false,
			"reason": "真机设备模式未开启；Burp 同步仍可用，截图和移动端设备操作不可用",
		}
	} else {
		out["device"] = map[string]any{"ready": false, "reason": "没有可用的默认动态授权或目标设备"}
	}
	return jsonResult(out)
}

func (s *Server) burpMCPStatus(ctx context.Context) (map[string]any, error) {
	m, err := s.findMCPServer("burp")
	if err != nil {
		return nil, err
	}
	cl, err := connectMCP(ctx, m)
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	tools, err := cl.Tools(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(tools))
	required := map[string]bool{
		"mcp__burp__get_proxy_http_history":       false,
		"mcp__burp__get_proxy_http_history_regex": false,
	}
	for _, tool := range tools {
		names = append(names, tool.Name())
		if _, ok := required[tool.Name()]; ok {
			required[tool.Name()] = true
		}
	}
	return map[string]any{
		"connected":     true,
		"name":          m.Name,
		"url":           m.URL,
		"tool_count":    len(tools),
		"history_tools": required,
		"tools":         names,
	}, nil
}

func (s *Server) findMCPServer(name string) (*db.MCPServer, error) {
	servers, err := s.m.pg.ListMCP()
	if err != nil {
		return nil, err
	}
	for _, m := range servers {
		if m.Enabled && strings.EqualFold(strings.TrimSpace(m.Name), strings.TrimSpace(name)) {
			return m, nil
		}
	}
	return nil, fmt.Errorf("未找到启用的 %s MCP server", name)
}

type burpHistoryItem struct {
	Request  string `json:"request"`
	Response string `json:"response"`
	Notes    string `json:"notes"`
}

func runBurpSync(s *Server, taskID int64, in json.RawMessage) (actool.Result, error) {
	t := s.m.ResolveTask(strconv.FormatInt(taskID, 10))
	if t == nil || strings.TrimSpace(t.Domain) != string(domain.Miniapp) {
		return actool.Errorf("当前任务不是小程序黑盒领域"), nil
	}
	if g, err := s.effectiveMobileGrant(taskID); err != nil || g == nil || !g.Active(time.Now()) {
		if err != nil {
			return actool.Errorf("小程序授权校验失败：" + err.Error()), nil
		}
		return actool.Errorf("小程序任务没有生效的默认授权或任务级授权"), nil
	}
	if s.m.traffic == nil {
		return actool.Errorf("流量索引不可用，无法导入 Burp History"), nil
	}
	var a struct {
		Count  int    `json:"count"`
		Offset int    `json:"offset"`
		Regex  string `json:"regex"`
		Scheme string `json:"scheme"`
	}
	if len(in) > 0 {
		_ = json.Unmarshal(in, &a)
	}
	if a.Count <= 0 {
		a.Count = 20
	}
	if a.Count > 100 {
		a.Count = 100
	}
	if a.Offset < 0 {
		a.Offset = 0
	}
	scheme := strings.ToLower(strings.TrimSpace(a.Scheme))
	if scheme == "auto" || scheme == "" {
		scheme = ""
	} else if scheme != "http" && scheme != "https" {
		return actool.Errorf("scheme 只能是 auto | http | https"), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	m, err := s.findMCPServer("burp")
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	cl, err := connectMCP(ctx, m)
	if err != nil {
		return actool.Errorf("连接 Burp MCP 失败：" + err.Error()), nil
	}
	defer cl.Close()
	if strings.TrimSpace(a.Regex) == "" {
		a.Regex = s.miniAppScopeRegex(taskID)
	}
	tool := "get_proxy_http_history"
	args := map[string]any{"count": a.Count, "offset": a.Offset}
	if strings.TrimSpace(a.Regex) != "" {
		tool = "get_proxy_http_history_regex"
		args["regex"] = strings.TrimSpace(a.Regex)
	}
	raw, err := cl.Call(ctx, tool, args)
	if err != nil {
		return actool.Errorf("读取 Burp History 失败：" + err.Error()), nil
	}
	items, err := decodeBurpHistory(raw)
	if err != nil {
		return actool.Errorf("解析 Burp History 失败：" + err.Error()), nil
	}
	matcher := s.miniAppScopeMatcher(taskID)
	imported := 0
	duplicates := 0
	outOfScope := 0
	invalid := 0
	ids := make([]string, 0, len(items))
	hosts := make([]string, 0, len(items))
	for _, item := range items {
		host := rawRequestHost(item.Request)
		if host == "" || !matcher(host) {
			outOfScope++
			continue
		}
		meta, inserted, err := s.m.traffic.ImportRawExchange(ctx, traffic.RawExchangeImport{
			Source: "burp", Scheme: scheme, Request: item.Request, Response: item.Response, Notes: item.Notes,
		})
		if err != nil {
			invalid++
			continue
		}
		hosts = append(hosts, host)
		if inserted {
			imported++
			ids = append(ids, meta.ID)
		} else {
			duplicates++
		}
	}
	return jsonResult(map[string]any{
		"imported": imported, "duplicates": duplicates, "out_of_scope": outOfScope, "invalid": invalid,
		"traffic_ids": ids, "hosts": uniqueStrings(hosts),
		"burp_tool": tool, "offset": a.Offset, "count": a.Count,
		"note": "仅导入了任务 Scope 内的域名；请用 traffic_search / traffic_get 查看正文，再用 bind_finding_traffic 绑定漏洞证据。",
	})
}

func decodeBurpHistory(raw string) ([]burpHistoryItem, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	var out []burpHistoryItem
	for {
		var item burpHistoryItem
		err := dec.Decode(&item)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(item.Request) != "" {
			out = append(out, item)
		}
	}
	return out, nil
}

type miniAppScopeSet struct {
	roots          []string
	exact          map[string]bool
	ips            map[string]bool
	nets           []*net.IPNet
	companyDomains map[string]bool
}

func (s *Server) miniAppScopeSetFor(taskID int64) miniAppScopeSet {
	taskIDText := strconv.FormatInt(taskID, 10)
	scopes, _ := s.m.Assets().ListTaskScopeWithSources(taskID)
	set := miniAppScopeSet{
		exact:          map[string]bool{},
		ips:            map[string]bool{},
		companyDomains: map[string]bool{},
	}
	companyIDs := []int64{}
	for _, scope := range scopes {
		switch strings.ToLower(strings.TrimSpace(scope.Kind)) {
		case "root_domain":
			if d := strings.ToLower(strings.TrimSpace(scope.Domain)); d != "" {
				set.roots = append(set.roots, d)
			}
		case "subdomain":
			if d := strings.ToLower(strings.TrimSpace(scope.Domain)); d != "" {
				set.exact[d] = true
			}
		case "ip":
			if ip := strings.TrimSpace(scope.Value); ip != "" {
				set.ips[ip] = true
			}
		case "cidr":
			if _, n, err := net.ParseCIDR(strings.TrimSpace(scope.Net)); err == nil {
				set.nets = append(set.nets, n)
			}
		case "company":
			if scope.CompanyID != nil {
				companyIDs = append(companyIDs, *scope.CompanyID)
			}
		}
	}
	if len(scopes) == 0 {
		if t := s.m.ResolveTask(taskIDText); t != nil {
			for _, seed := range taskScopeSeedsFromText(t.Description + " " + t.Goal) {
				switch seed.Kind {
				case "root_domain":
					set.roots = append(set.roots, strings.ToLower(seed.Value))
				case "subdomain":
					set.exact[strings.ToLower(seed.Value)] = true
				case "ip":
					set.ips[seed.Value] = true
				case "cidr":
					if _, n, err := net.ParseCIDR(seed.Value); err == nil {
						set.nets = append(set.nets, n)
					}
				}
			}
		}
	}
	for _, companyID := range companyIDs {
		for _, typ := range []string{"root_domain", "subdomain"} {
			assets, _ := s.m.Assets().QueryByCompany(companyID, typ, 5000, 0)
			for _, asset := range assets {
				if d := strings.ToLower(strings.TrimSpace(asset.Domain)); d != "" {
					set.companyDomains[d] = true
				}
			}
		}
	}
	return set
}

func (s *Server) miniAppScopeMatcher(taskID int64) func(string) bool {
	set := s.miniAppScopeSetFor(taskID)
	return func(rawHost string) bool {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rawHost), "."))
		if host == "" {
			return false
		}
		if set.exact[host] || set.companyDomains[host] {
			return true
		}
		if set.ips[host] {
			return true
		}
		if ip := net.ParseIP(host); ip != nil {
			for _, n := range set.nets {
				if n.Contains(ip) {
					return true
				}
			}
		}
		for _, root := range set.roots {
			if host == root || strings.HasSuffix(host, "."+root) {
				return true
			}
		}
		for domain := range set.companyDomains {
			if host == domain || strings.HasSuffix(host, "."+domain) {
				return true
			}
		}
		return false
	}
}

func (s *Server) miniAppScopeRegex(taskID int64) string {
	set := s.miniAppScopeSetFor(taskID)
	terms := make([]string, 0, len(set.roots)+len(set.exact)+len(set.ips)+len(set.companyDomains))
	seen := map[string]bool{}
	add := func(term string) {
		term = strings.TrimSpace(term)
		if term == "" || seen[term] {
			return
		}
		seen[term] = true
		terms = append(terms, regexp.QuoteMeta(term))
	}
	for _, term := range set.roots {
		add(term)
	}
	for term := range set.exact {
		add(term)
	}
	for term := range set.ips {
		add(term)
	}
	for term := range set.companyDomains {
		add(term)
	}
	if len(terms) == 0 {
		return ""
	}
	return "(?i)(" + strings.Join(terms, "|") + ")"
}

func rawRequestHost(raw string) string {
	head, _ := splitRawHTTP(raw)
	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return ""
	}
	if fields := strings.Fields(lines[0]); len(fields) >= 2 {
		if strings.HasPrefix(fields[1], "http://") || strings.HasPrefix(fields[1], "https://") {
			if u, err := url.Parse(fields[1]); err == nil {
				return u.Hostname()
			}
		}
	}
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "host") {
			host := strings.TrimSpace(v)
			if h, _, err := net.SplitHostPort(host); err == nil {
				return h
			}
			return strings.Trim(host, "[]")
		}
	}
	return ""
}

func splitRawHTTP(raw string) (string, []byte) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return raw[:i], []byte(raw[i+2:])
	}
	return raw, nil
}

func runMiniAppScreenshot(s *Server, taskID int64, _ json.RawMessage) (actool.Result, error) {
	g, err := s.mobileAuthorization(taskID, "pull_data")
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	dir, err := s.mobileEvidenceDir(taskID)
	if err != nil {
		return actool.Errorf("准备证据目录失败：" + err.Error()), nil
	}
	stamp := time.Now().UTC().Format("20060102T150405.000000000")
	remote := mobileADBRemoteTmp + "shot-" + stamp + ".png"
	ctx, cancel := context.WithTimeout(context.Background(), mobileADBOpTimeout)
	defer cancel()
	if _, err := adbShellEx(ctx, mobileADBAddr(), g.DeviceSerial, "screencap -p "+remote, mobileADBOpTimeout, mobileADBMaxOutput); err != nil {
		return actool.Errorf("设备截屏失败：" + err.Error()), nil
	}
	data, err := adbSyncPull(ctx, mobileADBAddr(), g.DeviceSerial, remote)
	_, _ = adbShellEx(ctx, mobileADBAddr(), g.DeviceSerial, "rm -f "+remote, mobileADBOpTimeout, 4096)
	if err != nil {
		return actool.Errorf("拉取截图失败：" + err.Error()), nil
	}
	name := "miniapp-" + stamp + ".png"
	hostPath := filepath.Join(dir, name)
	if err := os.WriteFile(hostPath, data, 0o600); err != nil {
		return actool.Errorf("保存截图失败：" + err.Error()), nil
	}
	sum := sha256.Sum256(data)
	rec := MobileEvidence{
		File: "/work/mobile/" + name, Kind: "screenshot", Op: "miniapp_screenshot",
		Bytes: len(data), SHA256: hex.EncodeToString(sum[:]), Summary: "微信小程序真机截图",
		CreatedAt: time.Now().UTC(),
	}
	if err := s.appendMobileEvidenceIndex(taskID, rec); err != nil {
		return actool.Errorf("写入截图索引失败：" + err.Error()), nil
	}
	return jsonResult(map[string]any{
		"ok": true, "device": g.DeviceSerial, "evidence": rec.File,
		"bytes": rec.Bytes, "sha256": rec.SHA256,
		"note": "截图未内联到模型上下文；需要绑定漏洞时调用 attach_finding_attachment。",
	})
}

func uniqueStrings(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}
