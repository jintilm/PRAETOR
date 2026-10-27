package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/internal/replay"
)

// BodySource 是「按证据快照取回请求/响应体」的最小接口（由 evidence.Store 实现）。
// 用接口而不是直接依赖 *evidence.Store，是为了让本文件可以在没有 PG / 磁盘的情况下测试。
type BodySource interface {
	OpenBody(snapshot db.TrafficEvidenceSnapshot, side string) (*os.File, int64, error)
}

// VerifyBinding 重放一条已绑定的流量证据，给出确定性判定（是否仍复现）。
//
// 这是「降误报」的执行点：worker 报漏洞时绑定的是真实请求/响应，验证时原样重放并
// 比对状态码、长度与响应结构；模型的自述不参与判定。
//
// rt 传入走记录代理的 Transport（便于把复现流量也留痕）；nil = 直连。
func VerifyBinding(ctx context.Context, src BodySource, snap db.TrafficEvidenceSnapshot, rt http.RoundTripper, opt replay.Options) (replay.Verdict, error) {
	if src == nil {
		return replay.Verdict{}, errors.New("verify: nil body source")
	}
	if strings.TrimSpace(snap.URL) == "" {
		return replay.Verdict{}, errors.New("verify: snapshot 缺少 URL")
	}

	reqBody, err := readBody(src, snap, "request")
	if err != nil {
		return replay.Verdict{}, fmt.Errorf("verify: 读取请求体: %w", err)
	}
	// 响应体缺失不算错：replay 会退化为只比哈希/长度。
	respBody, err := readBody(src, snap, "response")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return replay.Verdict{}, fmt.Errorf("verify: 读取响应体: %w", err)
	}

	method := snap.Method
	if method == "" {
		method = http.MethodGet
	}

	return replay.Verify(ctx, rt, replay.Snapshot{
		Method:   method,
		URL:      snap.URL,
		Header:   ParseHeadHeaders(snap.ReqHead),
		Body:     reqBody,
		Status:   snap.Status,
		RespBody: respBody,
		RespHash: snap.RespHash,
		RespLen:  snap.RespLen,
	}, opt)
}

func readBody(src BodySource, snap db.TrafficEvidenceSnapshot, side string) ([]byte, error) {
	f, _, err := src.OpenBody(snap, side)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// 与 replay 的读取上限保持一致，避免把超大响应整个读进内存。
	return io.ReadAll(io.LimitReader(f, 4<<20))
}

// ParseHeadHeaders 从原始 head 文本里提取请求头。
//
// 兼容两种录制格式：带请求行的完整 head（"GET /x HTTP/1.1" 开头）与纯头块。
// 容错优先：解析失败的行直接跳过——宁可少带一个头，也不要让取证流程失败。
func ParseHeadHeaders(head string) http.Header {
	h := http.Header{}
	if strings.TrimSpace(head) == "" {
		return h
	}
	for _, line := range strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			break // 头块结束；后面是 body
		}
		if i := strings.Index(line, ":"); i > 0 {
			k := strings.TrimSpace(line[:i])
			v := strings.TrimSpace(line[i+1:])
			if k == "" || v == "" {
				continue
			}
			h.Add(k, v)
			continue
		}
		// 不是 Key: Value —— 形如 "GET /path HTTP/1.1" 的请求行，忽略。
	}
	// Host 由 URL 决定，带上会导致 Go 拒绝（Request.Host 与 Header 冲突）。
	h.Del("Host")
	h.Del("Content-Length")  // 由 Transport 按实际 body 重算
	h.Del("Accept-Encoding") // replay 统一用 identity，保证长度可比
	return h
}
