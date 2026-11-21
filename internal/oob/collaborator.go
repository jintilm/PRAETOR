package oob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Burp Collaborator 轮询协议：GET /burpresults?biid=<域名的第一个标签>。
//
// 返回形态是判据：命中时是 `<html><body><id></body></html>`，
// 未命中时是整页落地说明文档。落地文档里混着长单词（burpcollaborator.net 等），
// 所以只认 body 内、且整段只有小写字母数字的那串 id。
var (
	bodyPattern  = regexp.MustCompile(`<body>\s*([^<]*)</body>`)
	idPattern    = regexp.MustCompile(`[a-z0-9]{20,40}`)
	plainPattern = regexp.MustCompile(`^[a-z0-9\s]+$`)
)

var ErrBadDomain = errors.New("oob: collaborator 域名格式应为 <标签>.oastify.com")

// Collaborator 轮询一个 Collaborator 域。server 由域名解析得到：
// 不同批次域名可能落在不同后端，写死 polling.burpcollaborator.net 会拿到空列表。
type Collaborator struct {
	domain string
	label  string
	server string // http://host[:port]
	poll   time.Duration
}

func NewCollaborator(domain string) (*Collaborator, error) {
	d := strings.Trim(strings.TrimSpace(domain), ".")
	parts := strings.Split(d, ".")
	if len(parts) < 2 || parts[0] == "" {
		return nil, ErrBadDomain
	}
	return &Collaborator{domain: d, label: parts[0], poll: 2 * time.Second}, nil
}

func (c *Collaborator) Domain() string { return c.domain }

// URL 生成回连地址。oastify 子域的证书只覆盖 burpcollaborator.net，
// 用 https 会让开了校验的目标直接失败，因此这类域一律走 http。
func (c *Collaborator) URL(token string) string {
	scheme := "https://"
	if strings.Contains(c.domain, "oastify") {
		scheme = "http://"
	}
	return scheme + token + "." + c.domain + "/"
}

func (c *Collaborator) serverURL(ctx context.Context) string {
	if c.server != "" {
		return c.server
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, c.domain)
	if err != nil || len(ips) == 0 {
		return "http://polling.burpcollaborator.net"
	}
	return "http://" + net.JoinHostPort(ips[0], "80")
}

// IDs 拉取当前交互 id。返回空表示该标签还没有回连。
func (c *Collaborator) IDs(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.serverURL(ctx)+"/burpresults?biid="+c.label, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oob: collaborator 轮询 %d", resp.StatusCode)
	}
	m := bodyPattern.FindSubmatch(body)
	if m == nil {
		return nil, nil
	}
	inner := strings.TrimSpace(string(m[1]))
	if inner == "" || !plainPattern.MatchString(inner) {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, id := range idPattern.FindAllString(inner, -1) {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

// WaitHit 轮询到出现新回连为止。基线里的历史 id 会被排除，迟到回连不算本次。
func (c *Collaborator) WaitHit(ctx context.Context, baseline int) (string, error) {
	tk := time.NewTicker(c.poll)
	defer tk.Stop()
	for {
		ids, err := c.IDs(ctx)
		if err == nil && len(ids) > baseline {
			return ids[len(ids)-1], nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-tk.C:
		}
	}
}
