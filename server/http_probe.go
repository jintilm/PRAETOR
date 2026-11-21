package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jintilm/praetor/agent"
	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/internal/replay"
	"github.com/jintilm/praetor/traffic"
)

const (
	probeMaxBodyBytes   = 1 << 20 // 单次响应只留 1 MiB 做测量；取证要看全文请用流量页
	probeDefaultRuns    = 3
	probeMaxRuns        = 5
	probeDefaultTimeout = 10 * time.Second
	probeMaxTimeout     = 30 * time.Second
)

// taskHTTPProber 是 agent.HTTPProber 的生产实现。
//
// 三条硬约束（与验证器同口径，避免取证成为绕过范围检查的通道）：
//  1. 请求走记录代理 → 流量入库，返回 traffic_id 可绑证据；
//  2. 发送前逐条校验任务范围，一条不合规整次拒绝（不"打一半"）；
//  3. 不跟随重定向、响应体截断、单请求超时封顶。
type taskHTTPProber struct {
	rt      http.RoundTripper
	scope   ScopeFunc
	traffic *traffic.Traffic
	// store/taskID 用于把探针代发的流量记进 task_traffic：
	// 采集层（MITM）不知道任务身份，只有调用方知道，所以归属在这里打。
	store  *db.DB
	taskID int64
}

// NewTaskHTTPProber 构造任务级探针：proxyAddr/caCertPath 与验证器同一套记录代理。
func NewTaskHTTPProber(proxyAddr, caCertPath string, scope ScopeFunc, tr *traffic.Traffic, store *db.DB, taskID int64) agent.HTTPProber {
	return &taskHTTPProber{
		rt:      replayTransport(proxyAddr, caCertPath),
		scope:   scope,
		traffic: tr,
		store:   store,
		taskID:  taskID,
	}
}

func (p *taskHTTPProber) Probe(ctx context.Context, in agent.ProbeRequest) (*agent.ProbeResult, error) {
	if p == nil {
		return nil, errors.New("探针未就绪")
	}
	prim := strings.ToLower(strings.TrimSpace(in.Primitive))
	switch prim {
	case agent.ProbePrimitiveRequest, agent.ProbePrimitiveCompare, agent.ProbePrimitiveTiming:
	default:
		return nil, fmt.Errorf("未知原语 %q（request / compare / timing）", in.Primitive)
	}
	if strings.TrimSpace(in.A.URL) == "" {
		return nil, errors.New("url 必填")
	}

	runs := in.Runs
	if runs <= 0 {
		runs = probeDefaultRuns
	}
	if runs > probeMaxRuns {
		runs = probeMaxRuns
	}
	timeout := probeDefaultTimeout
	if in.TimeoutMS > 0 {
		timeout = time.Duration(in.TimeoutMS) * time.Millisecond
	}
	if timeout > probeMaxTimeout {
		timeout = probeMaxTimeout
	}

	targets := []agent.ProbeTarget{in.A}
	if prim != agent.ProbePrimitiveRequest {
		if strings.TrimSpace(in.B.URL) == "" {
			return nil, errors.New("compare / timing 需要 b_url")
		}
		targets = append(targets, in.B)
	}
	// 先全量校验范围：一条越界就整次拒绝，避免"打了 A 才发现 B 越界"。
	for _, t := range targets {
		if p.scope == nil {
			continue
		}
		if err := p.scope(t.URL); err != nil {
			return nil, fmt.Errorf("目标不在任务范围：%w", err)
		}
	}

	res := &agent.ProbeResult{Primitive: prim}
	if p.traffic == nil {
		res.Notes = append(res.Notes, "流量采集未开启：本次请求没有 traffic_id，无法绑定为证据")
	}

	var bodyA, bodyB []byte
	switch prim {
	case agent.ProbePrimitiveRequest, agent.ProbePrimitiveCompare:
		bodyA, _ = p.send(ctx, res, "a", in.A, timeout)
		if prim == agent.ProbePrimitiveCompare {
			bodyB, _ = p.send(ctx, res, "b", in.B, timeout)
		}
	case agent.ProbePrimitiveTiming:
		for i := 1; i <= runs; i++ {
			p.send(ctx, res, fmt.Sprintf("a%d", i), in.A, timeout)
		}
		for i := 1; i <= runs; i++ {
			p.send(ctx, res, fmt.Sprintf("b%d", i), in.B, timeout)
		}
	}

	if prim == agent.ProbePrimitiveCompare && len(res.Attempts) == 2 {
		a, b := res.Attempts[0], res.Attempts[1]
		res.StatusChanged = a.Status != b.Status
		if a.RespLen > 0 {
			res.LenRatio = float64(b.RespLen) / float64(a.RespLen)
		}
		if len(bodyA) > 0 && len(bodyB) > 0 {
			res.Similarity = replay.Similarity(bodyA, bodyB)
		}
		if a.Error != "" || b.Error != "" {
			res.Notes = append(res.Notes, "有一条请求失败：对比结论不完整")
		}
	}
	return res, nil
}

// send 发一次请求并记录测量结果；返回响应体（供相似度计算）。
func (p *taskHTTPProber) send(ctx context.Context, res *agent.ProbeResult, label string, t agent.ProbeTarget, timeout time.Duration) ([]byte, error) {
	start := time.Now()
	body, status, hash, trafficID, err := p.do(ctx, t, timeout)
	attempt := agent.ProbeAttempt{
		Label:     label,
		ElapsedMS: time.Since(start).Milliseconds(),
		TrafficID: trafficID,
	}
	if err != nil {
		attempt.Error = err.Error()
	} else {
		attempt.Status, attempt.RespLen, attempt.RespHash = status, len(body), hash
	}
	res.Attempts = append(res.Attempts, attempt)
	p.recordTraffic(ctx, attempt, t)
	if err == nil && trafficID == "" {
		res.Notes = append(res.Notes, "请求已完成，但缺少采集侧精确关联；流量暂未归属，请核对原始报文，勿仅按主机或时间绑定。")
	}
	return body, err
}

func (p *taskHTTPProber) do(ctx context.Context, t agent.ProbeTarget, timeout time.Duration) (body []byte, status int, hash, trafficID string, err error) {
	method := strings.ToUpper(strings.TrimSpace(t.Method))
	if method == "" {
		method = http.MethodGet
	}
	var rdr io.Reader
	if t.Body != "" {
		rdr = strings.NewReader(t.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.URL, rdr)
	if err != nil {
		return nil, 0, "", "", err
	}
	for k, v := range t.Headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	// Respect explicit content negotiation; identity is only the default.
	if _, provided := req.Header["Accept-Encoding"]; !provided {
		req.Header.Set("Accept-Encoding", "identity")
	}

	capture := &capturedTransport{traffic: p.traffic, base: p.rt}
	client := &http.Client{
		Transport: capture,
		Timeout:   timeout,
		// 不跟随重定向：302 本身就是一条测量结论，跟过去会污染对比。
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, "", "", err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, probeMaxBodyBytes))
	if err != nil {
		return nil, resp.StatusCode, "", "", err
	}
	sum := sha256.Sum256(body)
	return body, resp.StatusCode, hex.EncodeToString(sum[:]), capture.meta.ID, nil
}

// recordTraffic 把这次探针请求记进 task_traffic（归属）。
//
// 只在拿到 traffic_id 时写：对不上流量索引说明这次请求没被采集（capture 关闭或
// 未走代理），此时没有可归属的对象，硬写一条空 ID 只会污染归属表。
//
// 写失败只记日志：归属是辅助信息，不能让它把取证本身搞挂。
func (p *taskHTTPProber) recordTraffic(ctx context.Context, a agent.ProbeAttempt, t agent.ProbeTarget) {
	if p == nil || p.store == nil || p.taskID <= 0 || strings.TrimSpace(a.TrafficID) == "" {
		return
	}
	host := hostOfURL(t.URL)
	if err := p.store.RecordTaskTraffic(ctx, db.TaskTraffic{
		TaskID: p.taskID, TrafficID: a.TrafficID, Host: host,
		Method: methodOrGet(t.Method), URL: t.URL, Status: a.Status, Source: db.TaskTrafficProbe, AttributionKind: db.TaskTrafficCaptured,
	}); err != nil {
		log.Printf("[traffic] 记录任务 %d 的流量归属失败（%s）: %v", p.taskID, a.TrafficID, err)
	}
}

func methodOrGet(method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return http.MethodGet
	}
	return method
}
