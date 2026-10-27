// Package caldera 是 MITRE Caldera 的 REST 客户端（P4-2）。
//
// 为什么是 REST 而不是 MCP：Caldera 的 MCP 会把整套工具面（abilities/agents/operations/
// planners/objectives…）塞进模型上下文，每轮都是固定成本；而红队域真正需要的只有三件事 ——
// 下发一条 ability、看这次 operation 的结果、确认环境在。三个动作走三个 REST 端点就够了。
//
// 纪律（与 P3 配方表同源）：**能力在工具面之外**。这里只封装"一次操作"，
// 不做 DAG 编排 —— 编排是 internal/campaign 的事，Caldera 只是执行器。
package caldera

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// apiKeyHeader 是 Caldera 的认证头（4.x 起使用）。
const apiKeyHeader = "KEY"

// Client 是一个 Caldera 服务端。
type Client struct {
	base string
	key  string
	http *http.Client
}

// New 构造客户端；baseURL 形如 http://127.0.0.1:8888。
func New(baseURL, apiKey string) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		return nil, errors.New("Caldera 地址为空：设 PRAETOR_CALDERA_URL（如 http://127.0.0.1:8888）")
	}
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		return nil, fmt.Errorf("Caldera 地址必须是 http(s) URL，当前 %q", base)
	}
	return &Client{base: base, key: strings.TrimSpace(apiKey), http: &http.Client{Timeout: 30 * time.Second}}, nil
}

// Ability 是 Caldera 里的一条原子能力。
type Ability struct {
	AbilityID string `json:"ability_id"`
	Name      string `json:"name"`
	Tactic    string `json:"tactic"`
	Technique string `json:"technique_id"`
}

// Operation 是一次下发后的执行记录。
type Operation struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	State   string `json:"state"` // running / finished / cleanup
	Group   string `json:"group"`
	Started string `json:"start"`
	Links   []Link `json:"links"`
}

// Link 是 operation 里的一条执行链（一条 ability 在一个 agent 上的执行）。
type Link struct {
	ID       string   `json:"id"`
	Ability  *Ability `json:"ability"`
	Status   int      `json:"status"` // 0 = 已下发未回收，>0 = 完成（-1..-6 为错误码）
	Command  string   `json:"command"`
	Output   string   `json:"output"`
	Paw      string   `json:"paw"` // 执行该链的 agent
	Executor string   `json:"executor"`
}

// Done 表示这条链已有结果（Caldera 用 status 0 表示"还在跑"）。
func (l Link) Done() bool { return l.Status != 0 }

// Abilities 列出 ability；filter 非空时按名字/id/战术做子串过滤（大小写不敏感）。
//
// 为什么过滤放在客户端而不是推给服务端查询：Caldera 的 abilities 端点没有稳定的
// 模糊查询参数，服务端过滤在不同版本上行为不一致；一次拉全量再本地筛更可预测。
func (c *Client) Abilities(ctx context.Context, filter string) ([]Ability, error) {
	var list []Ability
	if err := c.do(ctx, http.MethodGet, "/api/v2/abilities", nil, &list); err != nil {
		return nil, err
	}
	want := strings.ToLower(strings.TrimSpace(filter))
	if want == "" {
		return list, nil
	}
	out := make([]Ability, 0, len(list))
	for _, a := range list {
		hay := strings.ToLower(a.Name + " " + a.AbilityID + " " + a.Tactic + " " + a.Technique)
		if strings.Contains(hay, want) {
			out = append(out, a)
		}
	}
	return out, nil
}

// AbilityByName 按名字精确匹配一条 ability（用 SDK 名字下发比记 id 更可靠）。
func (c *Client) AbilityByName(ctx context.Context, name string) (*Ability, error) {
	want := strings.TrimSpace(name)
	if want == "" {
		return nil, errors.New("ability 名字为空")
	}
	list, err := c.Abilities(ctx, "")
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].Name == want || list[i].AbilityID == want {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("Caldera 里没有 ability %q（先用 action=list 看有哪些）", want)
}

// StartOperation 下发一次 operation：把 ability 派给 group 里的 agent。
//
// 返回的 operation 里 links 才是"结果"，需要轮询 Status 回收（见 Status）。
func (c *Client) StartOperation(ctx context.Context, abilityID, group, name string) (*Operation, error) {
	if strings.TrimSpace(abilityID) == "" {
		return nil, errors.New("ability_id 为空")
	}
	if strings.TrimSpace(group) == "" {
		group = "red"
	}
	body := map[string]any{
		"name":      defaultName(name, abilityID),
		"adversary": map[string]any{"adversary_id": "ad-hoc", "name": "praetor-adhoc", "atomic_ordering": []string{abilityID}},
		"group":     group,
		"planner":   map[string]any{"id": "aaa7c857-37a0-4c4a-85f7-4e9f7f30e40d", "name": "atomic"},
		"source":    map[string]any{"id": "ed32b9c3-0fa9-4a3a-8e6f-0f0f5b0d5d30", "name": "basic"},
	}
	var op Operation
	if err := c.do(ctx, http.MethodPost, "/api/v2/operations", body, &op); err != nil {
		return nil, err
	}
	return &op, nil
}

// Status 取一次 operation 的当前状态（含 links 的执行结果）。
func (c *Client) Status(ctx context.Context, id string) (*Operation, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("operation id 为空")
	}
	var op Operation
	if err := c.do(ctx, http.MethodGet, "/api/v2/operations/"+id, nil, &op); err != nil {
		return nil, err
	}
	return &op, nil
}

// Health 探测服务端是否可达（agent 列表为空也说明服务在，只是没 agent）。
func (c *Client) Health(ctx context.Context) error {
	var out json.RawMessage
	return c.do(ctx, http.MethodGet, "/api/v2/agents", nil, &out)
}

func defaultName(name, abilityID string) string {
	if n := strings.TrimSpace(name); n != "" {
		return n
	}
	return "praetor-" + abilityID
}

// do 发一次请求并把 JSON 解到 out。
//
// 错误信息里带上状态码与前 200 字节 body：Caldera 的报错常常是"400 + 一句原因"，
// 只回"请求失败"等于让模型去猜（它会反复重试同样的参数）。
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.key != "" {
		req.Header.Set(apiKeyHeader, c.key)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("连不上 Caldera（%s）：%w；确认服务在跑、地址是 %s", path, err, c.base)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Caldera %s %s 返回 %d：%s", method, path, resp.StatusCode, snippet(raw))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("Caldera 返回的不是预期 JSON（%s）：%s", path, snippet(raw))
	}
	return nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	if s == "" {
		return "(空响应)"
	}
	return s
}
