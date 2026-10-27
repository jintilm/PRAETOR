package xbow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// HTTPClient 是 PRAETOR API 的实现，只需 JWT + 基地址。
type HTTPClient struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// NewHTTPClient 构造客户端；baseURL 形如 http://127.0.0.1:8797。
func NewHTTPClient(baseURL, token string) *HTTPClient {
	return &HTTPClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *HTTPClient) do(ctx context.Context, method, path string, body any, out io.Writer) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
	} else {
		_, _ = io.Copy(out, resp.Body)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s → HTTP %d", method, path, resp.StatusCode)
	}
	return nil
}

// CreateTask 创建任务并返回 id。
//
// 响应体形状在不同版本间有差异（{"id":..} / {"task":{"id":..}} / {"task_id":..}），
// 这里做容错解析——基准脚本不该因为外层包了一层就崩。
func (c *HTTPClient) CreateTask(ctx context.Context, in TaskInput) (int64, error) {
	payload := map[string]any{
		"name":              in.Name,
		"description":       in.Description,
		"goal":              in.Goal,
		"seed_first_intent": true, // 基准题通常一条意图能解，省掉首轮 planner 延迟
	}
	if in.Timeout > 0 {
		payload["timeout_seconds"] = int(in.Timeout.Seconds())
	}
	var buf bytes.Buffer
	if err := c.do(ctx, http.MethodPost, "/api/tasks", payload, &buf); err != nil {
		return 0, err
	}
	return extractID(buf.Bytes())
}

func extractID(b []byte) (int64, error) {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return 0, fmt.Errorf("解析创建任务响应: %w (%s)", err, snippet(b))
	}
	for _, k := range []string{"id", "task_id"} {
		if v, ok := m[k]; ok {
			if id, ok := toInt64(v); ok {
				return id, nil
			}
		}
	}
	for _, k := range []string{"task", "data"} {
		if inner, ok := m[k].(map[string]any); ok {
			for _, ik := range []string{"id", "task_id"} {
				if v, ok := inner[ik]; ok {
					if id, ok := toInt64(v); ok {
						return id, nil
					}
				}
			}
		}
	}
	return 0, fmt.Errorf("创建任务响应里没有 id: %s", snippet(b))
}

func toInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case string:
		id, err := strconv.ParseInt(t, 10, 64)
		return id, err == nil
	}
	return 0, false
}

// TaskDone 读 /api/tasks/{id}，判断状态是否终态。
func (c *HTTPClient) TaskDone(ctx context.Context, taskID int64) (bool, error) {
	var buf bytes.Buffer
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/tasks/%d", taskID), nil, &buf); err != nil {
		return false, err
	}
	return isTerminalStatus(findStatus(buf.Bytes())), nil
}

// isTerminalStatus 与 db/tasks.go 的终态定义**保持同一口径**：done / failed / timeout。
//
// 曾经这里自己猜了一串状态名（completed/finished/stopped…），结果漏了 timeout：
// 任务因超时结束时被当成「还在跑」，基准脚本白等到 wait-timeout 才判未解出。
// 终态只有一个来源，不要在调用侧重新发明。
func isTerminalStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "done", "failed", "timeout":
		return true
	}
	return false
}

// findStatus 在响应 JSON 里找第一个 status 字段（顶层或 task/data 下）。
func findStatus(b []byte) string {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return ""
	}
	if s, ok := m["status"].(string); ok {
		return s
	}
	for _, k := range []string{"task", "data"} {
		if inner, ok := m[k].(map[string]any); ok {
			if s, ok := inner["status"].(string); ok {
				return s
			}
		}
	}
	return ""
}

// FindingsText 返回该任务的漏洞列表原文（含 evidence/report），用于 flag 判分。
//
// 这里不解析结构：flag 是唯一串，直接在原文里找即可，避免依赖分页/字段名细节。
func (c *HTTPClient) FindingsText(ctx context.Context, taskID int64) (string, error) {
	var buf bytes.Buffer
	path := "/api/exploration/findings?task_id=" + strconv.FormatInt(taskID, 10) + "&page_size=500"
	if err := c.do(ctx, http.MethodGet, path, nil, &buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// TrafficText 拉取该任务目标主机上的流量正文，拼成可搜索文本（用于判分来源校验）。
//
// 为什么要按「目标 host」过滤，而不是全库找 flag：
//   - 流量库是全机共享的（所有任务/所有 host 一个索引）。不过滤会把**别的题目**
//     的 flag 算进来，等于判分串题；
//   - 被测目标就是本题那台容器（127.0.0.1:<port>），拿 host 过滤天然排除了
//     agent 访问题库目录 / pypi / 网关等无关流量。
//
// 注意限制：单次只取前若干页（默认 10 页 × 200 条），够覆盖一道题的量级；
// 拿不到就返回已取部分——判分侧对「拿不到流量」按不判解出处理（宁漏勿虚高）。
func (c *HTTPClient) TrafficText(ctx context.Context, taskID int64) (string, error) {
	taskRaw, err := c.taskDetail(ctx, taskID)
	if err != nil {
		return "", err
	}
	host, port := hostPortFromTask(taskRaw)
	if host == "" {
		return "", fmt.Errorf("任务 %d 详情里找不到目标 host", taskID)
	}
	var buf bytes.Buffer
	buf.WriteString(taskRaw)

	// 先按 host 拉（流量索引按 host 聚合，不含端口），再在判分侧按端口过滤——
	// 端口是区分「题目靶场」与「agent 自己起的容器」的关键：实测 agent 会
	// docker build+run 一个带 flag 的容器（换了个端口）再自己去访问它，
	// 只按 host 过滤会把这种自建靶场的流量也算成命中。
	pageURL := "/api/traffic?host=" + url.QueryEscape(host) + "&page=%d&page_size=200"
	for page := 1; page <= 10; page++ {
		var idx bytes.Buffer
		if err := c.do(ctx, http.MethodGet, fmt.Sprintf(pageURL, page), nil, &idx); err != nil {
			break
		}
		raw := idx.Bytes()
		if len(raw) == 0 {
			break
		}
		buf.Write(raw)
		items := trafficItems(raw)
		if len(items) == 0 {
			break
		}
		for _, it := range items {
			// 端口不匹配的直接丢掉（同一 host 上别的端口 = 别的容器）。
			if port != "" && it.Port != "" && it.Port != port {
				continue
			}
			var one bytes.Buffer
			// 端点必须用 /api/traffic/exchange?id=...（**不是** /api/traffic/{id}）。
			// 这条写错过一次：路径不对 → 404 → 取不到任何正文 → 判分把所有真解出
			// 都标成假阳性（实测 XBEN-006/019 明明解出却被判 0 分）。
			// 判分链路依赖的 API 路径要以真实路由为准，写完先 curl 一次。
			if err := c.do(ctx, http.MethodGet, trafficExchangePath+"?id="+url.QueryEscape(it.ID), nil, &one); err != nil {
				continue
			}
			buf.Write(one.Bytes())
		}
		if len(items) < 200 {
			break
		}
	}
	return buf.String(), nil
}

// trafficItem 是流量索引的一行（只取判分需要的字段）。
type trafficItem struct {
	ID   string
	Port string
}

// trafficExchangePath 是取单条流量正文的 API 路径。
// 抽成常量是为了让测试能断言它 —— 写错过一次（用了 /api/traffic/{id}），
// 结果是 404 → 取不到正文 → 所有真解出被判假阳性，而且**不报任何错**。
const trafficExchangePath = "/api/traffic/exchange"

// taskDetail 取任务详情原文（含 runner 写入的「目标地址：...」行）。
func (c *HTTPClient) taskDetail(ctx context.Context, taskID int64) (string, error) {
	var buf bytes.Buffer
	if err := c.do(ctx, http.MethodGet, "/api/tasks/"+strconv.FormatInt(taskID, 10), nil, &buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// targetURLRe 匹配 runner 写入任务描述的目标地址行。
var targetURLRe = regexp.MustCompile(`目标地址：(https?://[^\s"\\]+)`)

// hostPortFromTask 从任务详情里抽出目标 host 与端口。
//
// host 用于查流量索引（索引不含端口），port 用于在判分侧区分「题目靶场」与
// 「agent 自己 docker run 的容器」——后者换了端口，是常见的假阳性来源。
func hostPortFromTask(taskRaw string) (host, port string) {
	m := targetURLRe.FindStringSubmatch(taskRaw)
	if len(m) != 2 {
		return "", ""
	}
	u, err := url.Parse(m[1])
	if err != nil || u.Hostname() == "" {
		return "", ""
	}
	return u.Hostname(), u.Port()
}

// trafficItems 从 /api/traffic 响应里抽 (id, port)。port 由 url 解析得出。
func trafficItems(raw []byte) []trafficItem {
	var d struct {
		Exchanges []struct {
			ID  string `json:"id"`
			URL string `json:"url"`
		} `json:"exchanges"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil
	}
	out := make([]trafficItem, 0, len(d.Exchanges))
	for _, e := range d.Exchanges {
		if e.ID == "" {
			continue
		}
		it := trafficItem{ID: e.ID}
		if u, err := url.Parse(e.URL); err == nil {
			it.Port = u.Port()
		}
		out = append(out, it)
	}
	return out
}

// 编译期断言。
var _ Client = (*HTTPClient)(nil)
