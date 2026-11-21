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

// TrafficScan 是一次判分取正文的结果。
//
// 为什么是三态而不是 (string, error)：判分必须区分「确定没命中」与「没取全，不能下结论」。
// 把后者混成 false，会把真解出记成失败——「宁漏勿虚高」只对「确实取到了但没有 flag」成立。
type TrafficScan struct {
	Text       string
	Incomplete bool     // 有分页/单条正文/blob 没取全
	Missing    []string // 具体哪一步没取到，进报告
}

func (s *TrafficScan) note(format string, args ...any) {
	s.Incomplete = true
	s.Missing = append(s.Missing, fmt.Sprintf(format, args...))
}

const (
	trafficPageSize = 200
	trafficMaxPages = 10
)

// TrafficText 拉取该任务目标主机上的流量**响应正文**，拼成可搜索文本（用于判分来源校验）。
//
// 为什么只搜 resp，不搜整条 exchange：
//   - 判分口径是「flag 必须由目标返回」。把请求行/请求头/请求体一起拼进来，agent 只要
//     把 flag 发给目标（哪怕只是回显一次）就能被判解出；
//   - 旧实现还把任务详情 taskRaw 也塞进了搜索面，同样属于无关文本。
//
// 为什么按「目标 host」过滤：流量库是全机共享的（所有任务一个索引），不过滤会把别的
// 题目的 flag 算进来；端口用来排除 agent 自建容器（实测它换到 20699 自己起了个带 flag 的靶场）。
//
// 大正文：超过内联阈值的响应体在 exchange 里只是 `@blob sha256:<hash>` 指针，
// 必须再取一次 /api/traffic/blob。**少了这一步，大响应题会全部被判成没解出。**
func (c *HTTPClient) TrafficText(ctx context.Context, taskID int64) (TrafficScan, error) {
	var scan TrafficScan
	taskRaw, err := c.taskDetail(ctx, taskID)
	if err != nil {
		return scan, err
	}
	host, port := hostPortFromTask(taskRaw)
	if host == "" {
		return scan, fmt.Errorf("任务 %d 详情里找不到目标 host", taskID)
	}

	// 先按 host 拉（流量索引按 host 聚合，不含端口），再在判分侧按端口过滤。
	pageURL := "/api/traffic?host=" + url.QueryEscape(host) + "&page=%d&page_size=" + strconv.Itoa(trafficPageSize)
	var b strings.Builder
	for page := 1; page <= trafficMaxPages; page++ {
		var idx bytes.Buffer
		if err := c.do(ctx, http.MethodGet, fmt.Sprintf(pageURL, page), nil, &idx); err != nil {
			if page == 1 {
				// 第一页都拿不到 = 没有任何可用流量证据，交给判分侧按「取不到」处理。
				return scan, err
			}
			scan.note("流量索引第 %d 页取失败: %v", page, err)
			break
		}
		raw := idx.Bytes()
		if len(raw) == 0 {
			break
		}
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
			// 端点必须是 /api/traffic/exchange?id=...（**不是** /api/traffic/{id}）。
			// 这条写错过一次：路径不对 → 404 → 取不到任何正文 → 把所有真解出都标成假阳性。
			if err := c.do(ctx, http.MethodGet, trafficExchangePath+"?id="+url.QueryEscape(it.ID), nil, &one); err != nil {
				scan.note("流量 %s 正文取失败: %v", it.ID, err)
				continue
			}
			txt, terr := c.respText(ctx, one.Bytes())
			if txt != "" {
				b.WriteString(txt)
				b.WriteString("\n")
			}
			if terr != nil {
				// 前半段已取到就照常参与搜索，同时把本次记为不完整。
				scan.note("流量 %s 响应不完整: %v", it.ID, terr)
			}
		}
		if len(items) < trafficPageSize {
			break
		}
		if page == trafficMaxPages {
			scan.note("流量索引达到 %d 页上限，可能有未检查的记录", trafficMaxPages)
		}
	}
	scan.Text = b.String()
	return scan, nil
}

// Exchange 是 /api/traffic/exchange 的响应：一条流量的原样请求与响应。
type Exchange struct {
	Req  string `json:"req"`
	Resp string `json:"resp"`
}

// blobRe 匹配正文里的大文本指针（超过内联阈值的部分不在 exchange 里）。
var blobRe = regexp.MustCompile(`@blob sha256:([0-9a-f]{64})`)

// respText 只返回响应侧文本，并把 @blob 指针展开成完整正文。
//
// 返回的 text 即使伴随 error 也要用：可能前半段已取到、后半段 blob 失败。
func (c *HTTPClient) respText(ctx context.Context, exchangeJSON []byte) (string, error) {
	var ex Exchange
	if err := json.Unmarshal(exchangeJSON, &ex); err != nil {
		return "", fmt.Errorf("解析 exchange: %w", err)
	}
	if strings.TrimSpace(ex.Resp) == "" {
		return "", nil
	}
	var b strings.Builder
	b.WriteString(ex.Resp)
	for _, m := range blobRe.FindAllStringSubmatch(ex.Resp, -1) {
		blob, err := c.blob(ctx, m[1])
		if err != nil {
			return b.String(), fmt.Errorf("blob %s: %w", m[1], err)
		}
		b.WriteString("\n")
		b.Write(blob)
	}
	return b.String(), nil
}

// blob 取回一条超限正文的原字节（服务端直接流原始内容，不是 JSON）。
func (c *HTTPClient) blob(ctx context.Context, hash string) ([]byte, error) {
	var buf bytes.Buffer
	if err := c.do(ctx, http.MethodGet, trafficBlobPath+"?hash="+url.QueryEscape(hash), nil, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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

// trafficBlobPath 取回超过内联阈值的正文（exchange 里只留 `@blob sha256:<hash>` 指针）。
const trafficBlobPath = "/api/traffic/blob"

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
