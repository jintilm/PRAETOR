package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jintilm/praetor/agent"
	"github.com/jintilm/praetor/internal/oob"
	"github.com/jintilm/praetor/traffic"
)

const (
	settingOOBBaseURL = "oob_base_url"
	oobDefaultTTL     = 15
	oobMaxTTL         = 60
	oobPlaceholder    = "{{OOB}}"
)

// taskOOBProber 把「发请求 → 等回连」串起来。回连地址来自平台自身可被目标访问的
// /oob/<token> 路由；没配地址时工具直接报未启用，而不是静默超时。
type taskOOBProber struct {
	rt      http.RoundTripper
	scope   ScopeFunc
	traffic *traffic.Traffic
	catcher *oob.Catcher
	domain  string
	collab  *oob.Collaborator
	// public 是零配置的公网端点；未配置任何回连地址时走它。
	public func(context.Context) (*oob.Public, error)
	taskID int64
}

func NewTaskOOBProber(proxyAddr, caCertPath string, scope ScopeFunc, tr *traffic.Traffic, catcher *oob.Catcher, domain string, collab *oob.Collaborator, public func(context.Context) (*oob.Public, error), taskID int64) agent.OOBProber {
	return &taskOOBProber{rt: replayTransport(proxyAddr, caCertPath), scope: scope, traffic: tr, catcher: catcher, domain: domain, collab: collab, public: public, taskID: taskID}
}

func (p *taskOOBProber) ProbeOOB(ctx context.Context, in agent.OOBProbeRequest) (*agent.OOBProbeResult, error) {
	if p.catcher == nil && p.domain == "" && p.collab == nil && p.public == nil {
		return nil, errors.New("没有可用的回连通道")
	}
	ttl := in.TTLSec
	if ttl <= 0 {
		ttl = oobDefaultTTL
	}
	if ttl > oobMaxTTL {
		ttl = oobMaxTTL
	}
	if p.collab == nil && p.catcher == nil && p.public != nil {
		return p.probePublic(ctx, in)
	}
	if p.collab != nil {
		// Collaborator：先记基线，迟到回连不会算到本次头上。
		base, _ := p.collab.IDs(ctx)
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, err
		}
		return p.probeCollab(ctx, in, len(base), raw[:])
	}
	var probe oob.Probe
	if p.catcher != nil {
		var err error
		probe, err = p.catcher.Issue(fmt.Sprint(p.taskID), time.Duration(ttl)*time.Second)
		if err != nil {
			return nil, err
		}
	} else {
		// 外部回连域（interactsh 之类）：只用它收包，不依赖其 API。
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return nil, err
		}
		probe = oob.Probe{Token: hex.EncodeToString(raw[:]), URL: "https://" + hex.EncodeToString(raw[:]) + "." + p.domain + "/"}
	}
	// 占位符必须真的出现在 URL/头/体里，否则等于发了个普通请求。
	rawURL := strings.ReplaceAll(in.URL, oobPlaceholder, probe.URL)
	if p.scope != nil {
		if serr := p.scope(rawURL); serr != nil {
			return nil, fmt.Errorf("目标不在任务范围：%w", serr)
		}
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(strings.ReplaceAll(in.Body, oobPlaceholder, probe.URL)))
	if err != nil {
		return nil, err
	}
	for k, v := range in.Headers {
		req.Header.Set(k, strings.ReplaceAll(v, oobPlaceholder, probe.URL))
	}
	capture := &capturedTransport{traffic: p.traffic, base: p.rt}
	client := &http.Client{Transport: capture}
	resp, err := client.Do(req)
	out := &agent.OOBProbeResult{Token: probe.Token, CallbackURL: probe.URL}
	if err == nil {
		out.Status = resp.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	} else {
		out.Reason = "请求本身失败：" + err.Error()
	}
	out.TrafficID = capture.meta.ID

	if p.catcher == nil {
		out.State = "inconclusive"
		out.Reason = "已投递回连地址；外部回连域不回读明细，请到 interactsh 客户端核对有无命中"
		return out, nil
	}
	ev, werr := p.catcher.Wait(ctx, probe.Token)
	if werr != nil && !errors.Is(werr, context.DeadlineExceeded) && !errors.Is(werr, context.Canceled) {
		return out, werr
	}
	switch ev.Status {
	case oob.Hit:
		out.State = "confirmed"
		out.Reason = "有回连"
		if ev.Hit != nil {
			out.HitMethod, out.HitRemote = ev.Hit.Method, ev.Hit.RemoteAddr
			out.HitAt = ev.Hit.Time.UTC().Format(time.RFC3339)
		}
	default:
		out.State = "inconclusive"
		if out.Reason == "" {
			out.Reason = fmt.Sprintf("%ds 内没有回连；目标可能不出网，不等于不存在", ttl)
		}
	}
	return out, nil
}

// handler 暴露给 mux：/oob/<token>。
func (p *taskOOBProber) handler() http.Handler { return p.catcher.Handler() }

// oobDomain 把配置值归一成「外部回连域」：带 scheme 视为自建捕获器（返回空），
// 裸域名交给外部服务收包。
// oobBaseURL 读回连地址（空=未配置）。
// oobDomain 归一配置值：带 scheme=自建捕获器（捕获器负责收包），裸域名=外部域。
// oobCollaborator 把 Collaborator 类域名转成轮询器；其它裸域名返回 nil（只投递）。
func (s *Server) oobCollaborator(domain string) *oob.Collaborator {
	if domain == "" || !strings.Contains(domain, "oast") && !strings.Contains(domain, "collaborator") {
		return nil
	}
	c, err := oob.NewCollaborator(domain)
	if err != nil {
		return nil
	}
	return c
}

func (s *Server) oobDomain() string {
	v := strings.TrimSpace(s.oobBaseURL())
	if v == "" || strings.EqualFold(v, "off") || strings.Contains(v, "://") {
		return ""
	}
	return strings.Trim(strings.TrimPrefix(v, "."), ".")
}

func (s *Server) oobBaseURL() string {
	v, _, _ := s.m.pg.GetSetting(settingOOBBaseURL)
	return strings.TrimSpace(v)
}

// oobCatcher 按需构建捕获器；地址变了就重建。
func (s *Server) oobCatcher() *oob.Catcher {
	base, _, _ := s.m.pg.GetSetting(settingOOBBaseURL)
	base = strings.TrimSpace(base)
	if base == "" {
		return nil
	}
	if u, err := url.Parse(base); err != nil || u.Host == "" {
		return nil
	}
	s.oobMu.Lock()
	defer s.oobMu.Unlock()
	if s.oob != nil && s.oobBase == base {
		return s.oob
	}
	c, err := oob.New(base)
	if err != nil {
		return nil
	}
	s.oob, s.oobBase = c, base
	return c
}

// probeCollab 走 Collaborator：发请求后轮询新交互。
func (p *taskOOBProber) probeCollab(ctx context.Context, in agent.OOBProbeRequest, base int, tok []byte) (*agent.OOBProbeResult, error) {
	token := hex.EncodeToString(tok)
	callback := p.collab.URL(token)
	out := &agent.OOBProbeResult{Token: token, CallbackURL: callback}
	rawURL := strings.ReplaceAll(in.URL, oobPlaceholder, callback)
	if p.scope != nil {
		if serr := p.scope(rawURL); serr != nil {
			return nil, fmt.Errorf("目标不在任务范围：%w", serr)
		}
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = http.MethodGet
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(ttlOf(in.TTLSec))*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(strings.ReplaceAll(in.Body, oobPlaceholder, callback)))
	if err != nil {
		return nil, err
	}
	for k, v := range in.Headers {
		req.Header.Set(k, strings.ReplaceAll(v, oobPlaceholder, callback))
	}
	capture := &capturedTransport{traffic: p.traffic, base: p.rt}
	resp, err := (&http.Client{Transport: capture}).Do(req)
	if err == nil {
		out.Status = resp.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	} else {
		out.Reason = "请求本身失败：" + err.Error()
	}
	out.TrafficID = capture.meta.ID
	// 每次探测都用新标签，所以「有 id」就等于「本次有回连」。
	id, werr := p.collab.WaitHit(ctx, base)
	if werr == nil && id != "" {
		out.State = "confirmed"
		out.HitMethod = "collaborator"
		out.HitAt = time.Now().UTC().Format(time.RFC3339)
		out.Reason = "有回连（交互 " + id + "）"
		return out, nil
	}
	out.State = "inconclusive"
	if out.Reason == "" {
		out.Reason = fmt.Sprintf("%ds 内没有回连；目标可能不出网，不等于不存在", ttlOf(in.TTLSec))
	}
	return out, nil
}

func ttlOf(v int) int {
	if v <= 0 {
		return oobDefaultTTL
	}
	if v > oobMaxTTL {
		return oobMaxTTL
	}
	return v
}

// probePublic 走零配置公网端点：申请(或复用)端点 → 投递带 token 的回连地址 → 等待命中。
func (p *taskOOBProber) probePublic(ctx context.Context, in agent.OOBProbeRequest) (*agent.OOBProbeResult, error) {
	pub, err := p.public(ctx)
	if err != nil {
		return nil, err
	}
	base, _ := pub.Hits(ctx)
	var raw [16]byte
	if _, rerr := rand.Read(raw[:]); rerr != nil {
		return nil, rerr
	}
	token := hex.EncodeToString(raw[:])
	callback := pub.URL(token)
	out := &agent.OOBProbeResult{Token: token, CallbackURL: callback}
	rawURL := strings.ReplaceAll(in.URL, oobPlaceholder, callback)
	if p.scope != nil {
		if serr := p.scope(rawURL); serr != nil {
			return nil, fmt.Errorf("目标不在任务范围：%w", serr)
		}
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if method == "" {
		method = http.MethodGet
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(ttlOf(in.TTLSec))*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(strings.ReplaceAll(in.Body, oobPlaceholder, callback)))
	if err != nil {
		return nil, err
	}
	for k, v := range in.Headers {
		req.Header.Set(k, strings.ReplaceAll(v, oobPlaceholder, callback))
	}
	capture := &capturedTransport{traffic: p.traffic, base: p.rt}
	if resp, derr := (&http.Client{Transport: capture}).Do(req); derr != nil {
		out.Reason = "请求本身失败：" + derr.Error()
	} else {
		out.Status = resp.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}
	out.TrafficID = capture.meta.ID
	hit, werr := pub.WaitHit(ctx, token, len(base))
	if werr != nil || hit == nil {
		out.State = "inconclusive"
		if out.Reason == "" {
			out.Reason = fmt.Sprintf("%ds 内没有回连；目标可能不出网，不等于不存在", ttlOf(in.TTLSec))
		}
		return out, nil
	}
	out.State = "confirmed"
	out.HitMethod = hit.Method
	out.HitRemote = strings.TrimSpace(hit.IP + " " + hit.Country)
	out.HitAt = time.Now().UTC().Format(time.RFC3339)
	out.Reason = "有回连（" + hit.Method + " 来自 " + out.HitRemote + "）"
	return out, nil
}
