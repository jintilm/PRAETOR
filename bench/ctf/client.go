package ctf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Client 是跑分器需要的 PRAETOR API 子集（抽成接口便于离线测试）。
type Client interface {
	// CreateTask 建一个 ctf 领域任务，返回任务 id。
	CreateTask(ctx context.Context, description, goal string, timeoutSeconds int) (int64, error)
	// ConfigureCTF 写入该任务的期望 flag 与题面目录。
	ConfigureCTF(ctx context.Context, taskID int64, expectedFlag, challengeDir string) error
	// Solved 报告该任务是否已有被判对的 flag（唯一判分口径）。
	Solved(ctx context.Context, taskID int64) (bool, error)
	// Done 报告任务是否已进入终态。
	Done(ctx context.Context, taskID int64) (bool, error)
	// Stats 返回该任务的累计 token 用量（报告要按题记成本，不能只记分数）。
	Stats(ctx context.Context, taskID int64) (Tokens, error)
}

// Tokens 是一道题烧掉的 token（含缓存命中，便于判断是不是重复读同一段上下文）。
type Tokens struct {
	Input      int64 `json:"input_tokens"`
	Output     int64 `json:"output_tokens"`
	CacheRead  int64 `json:"cache_read_tokens"`
	CacheWrite int64 `json:"cache_write_tokens"`
}

// HTTPClient 实现 Client。
type HTTPClient struct {
	Base  string
	Token string
	hc    *http.Client
}

// NewHTTPClient 用登录换来的 token 构造客户端。
func NewHTTPClient(base, token string) *HTTPClient {
	return &HTTPClient{
		Base:  strings.TrimRight(base, "/"),
		Token: token,
		hc:    &http.Client{Timeout: 30 * time.Second},
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
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		_, err = io.Copy(out, resp.Body)
		return err
	}
	return nil
}

// Login 换 JWT（用户名固定 PRAETOR）。
func Login(ctx context.Context, base, password string) (string, error) {
	body, _ := json.Marshal(map[string]string{"username": "PRAETOR", "password": password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(base, "/")+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("登录失败 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("登录响应没有 token")
	}
	return out.Token, nil
}

func (c *HTTPClient) CreateTask(ctx context.Context, description, goal string, timeoutSeconds int) (int64, error) {
	payload := map[string]any{
		"name":        truncate(description, 60),
		"description": description,
		"goal":        goal,
		"domain":      "ctf", // 关键：CTF 域 → race 调度 + ctf_* 工具
		// 种子意图：省掉开跑前的一轮 planner，CTF 常常一题一意图就能干完
		"seed_first_intent": true,
	}
	if timeoutSeconds > 0 {
		payload["timeout_seconds"] = timeoutSeconds
	}
	var buf bytes.Buffer
	if err := c.do(ctx, http.MethodPost, "/api/tasks", payload, &buf); err != nil {
		return 0, err
	}
	// 形状容错：不同版本的响应里 id 有的在顶层有的在 task 里
	var out struct {
		ID   json.RawMessage `json:"id"`
		Task struct {
			ID json.RawMessage `json:"id"`
		} `json:"task"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		return 0, fmt.Errorf("建任务响应解析失败: %w", err)
	}
	raw := out.ID
	if len(raw) == 0 {
		raw = out.Task.ID
	}
	var num int64
	if err := json.Unmarshal(raw, &num); err == nil && num > 0 {
		return num, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil && v > 0 {
			return v, nil
		}
	}
	return 0, fmt.Errorf("建任务响应里没有有效的 id: %s", truncate(buf.String(), 200))
}

func (c *HTTPClient) ConfigureCTF(ctx context.Context, taskID int64, expectedFlag, challengeDir string) error {
	payload := map[string]any{"expected_flag": expectedFlag, "challenge_dir": challengeDir}
	return c.do(ctx, http.MethodPost, fmt.Sprintf("/api/tasks/%d/ctf", taskID), payload, nil)
}

func (c *HTTPClient) Solved(ctx context.Context, taskID int64) (bool, error) {
	var buf bytes.Buffer
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/ctf/submissions?task_id=%d", taskID), nil, &buf); err != nil {
		return false, err
	}
	var out struct {
		Solved bool `json:"solved"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		return false, err
	}
	return out.Solved, nil
}

func (c *HTTPClient) Done(ctx context.Context, taskID int64) (bool, error) {
	var buf bytes.Buffer
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/tasks/%d", taskID), nil, &buf); err != nil {
		return false, err
	}
	var out struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(out.Status)) {
	case "done", "failed", "timeout":
		return true, nil
	}
	return false, nil
}

// Stats 读任务的累计 token 用量。
//
// 为什么要单独获取而不是从 SSE 里累加：token 账本在服务端（llm_usage 汇总到 tasks 上），
// 跨重连/重启都还在；跑分器自己数会漏掉 planner 那一半。
func (c *HTTPClient) Stats(ctx context.Context, taskID int64) (Tokens, error) {
	var buf bytes.Buffer
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/tasks/%d", taskID), nil, &buf); err != nil {
		return Tokens{}, err
	}
	var out struct {
		Tokens Tokens `json:"tokens"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		return Tokens{}, err
	}
	return out.Tokens, nil
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
