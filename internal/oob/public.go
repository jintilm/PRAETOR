package oob

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// 公网回连端点：平台按需申请一个一次性端点，目标打过来即可读明细。
//
// 为什么不在服务端做：渗透任务常跑在 NAT/办公网后面，没有公网入站；
// 把本机地址写进 payload 既不可移植，也等于把内网地址递给目标。
// 这里改为「运行时申请」，不依赖任何本地配置，换机器也不用改。

const (
	publicBase   = "https://webhook.site"
	publicCreate = publicBase + "/token"
)

// PublicHit 是一条回连记录（只取判定与取证需要的字段）。
type PublicHit struct {
	UUID    string          `json:"uuid"`
	Method  string          `json:"method"`
	IP      string          `json:"ip"`
	Country string          `json:"country"`
	URL     string          `json:"url"`
	Query   json.RawMessage `json:"query,omitempty"`
	Headers json.RawMessage `json:"headers,omitempty"`
}

type publicResp struct {
	Data []PublicHit `json:"data"`
}

// Public 是一个已申请的临时端点。
type Public struct {
	uuid   string
	base   string // 默认 publicBase；测试可替换
	client *http.Client
	poll   time.Duration
}

// NewPublic 申请端点。失败即返回错误，由调用方决定是否降级。
func NewPublic(ctx context.Context) (*Public, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, publicCreate, bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("oob: 申请公网端点失败 %d", resp.StatusCode)
	}
	var out struct {
		UUID string `json:"uuid"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, err
	}
	if out.UUID == "" {
		return nil, fmt.Errorf("oob: 公网端点未返回 id")
	}
	return &Public{uuid: out.UUID, base: publicBase, client: client, poll: 2 * time.Second}, nil
}

func (p *Public) UUID() string { return p.uuid }

func (p *Public) baseURL() string {
	if p.base != "" {
		return p.base
	}
	return publicBase
}

// URL 生成回连地址：路径里带一次性 token，便于和同一端点的其它回连区分。
func (p *Public) URL(token string) string {
	return p.baseURL() + "/" + p.uuid + "/" + token
}

// Hits 读当前回连列表（新到旧）。
func (p *Public) Hits(ctx context.Context) ([]PublicHit, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL()+"/token/"+p.uuid+"/requests?sorting=newest", nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oob: 读取回连失败 %d", resp.StatusCode)
	}
	var out publicResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// WaitHit 等到出现 token 对应的新回连。基线之外、且 URL 含该 token 才算本次命中，
// 避免同一端点上别的探测把结果算到这次头上。
func (p *Public) WaitHit(ctx context.Context, token string, baseline int) (*PublicHit, error) {
	tk := time.NewTicker(p.poll)
	defer tk.Stop()
	for {
		hits, err := p.Hits(ctx)
		if err == nil && len(hits) > baseline {
			for i := range hits {
				if strings.Contains(hits[i].URL, token) {
					return &hits[i], nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tk.C:
		}
	}
}
