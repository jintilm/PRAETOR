// Package replay 是「确定性复现验证」的核心：拿一条已记录的证据，重新发一次请求，
// 用可量化的相似度判断漏洞是否仍然成立。
//
// 为什么不用 LLM 判：误报是自主渗透最致命的成本。模型说「看起来还能打」不算证据，
// 必须由程序给出「状态码一致 + 响应结构相似度 ≥ 阈值」的结论，人才敢信。
//
// 设计取舍：
//   - 不 import db / evidence：调用方把快照适配成 Snapshot，本包保持纯函数、可单测；
//   - 不比原始哈希：真实响应里会有 CSRF token、时间戳、请求 ID，逐字节相等会把
//     真实复现判成失败。改用「长度容差 + 归一化 shingle 相似度」；
//   - 相似度用 4-gram Jaccard：对插入/删除局部内容稳健，且 O(n) 可解释。
package replay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxBody 是读取响应的上限，防目标回一个几百 MB 的东西把内存打爆。
const maxBody = 4 << 20

// Snapshot 是「当时那条证据」的可重放形式。
// 由调用方从 TrafficEvidenceSnapshot + body 文件适配而来。
type Snapshot struct {
	Method   string
	URL      string
	Header   http.Header // 请求头（可直接取自记录的 ReqHead）
	Body     []byte      // 请求体（可空）
	Status   int         // 记录时的响应状态码；0 = 不校验
	RespBody []byte      // 记录时的响应体；为空时退化为只比哈希/长度
	RespHash string      // 记录时的响应体 sha256（hex）；RespBody 为空且有它时用于必中判断
	RespLen  int64       // 记录时的响应长度；0 = 不校验长度
}

// Options 控制判定松紧。
type Options struct {
	// MinSimilarity 归一化响应体的最低相似度，默认 0.85。
	// 越高越容易把真实复现判成失败（漏报），越低越容易把变化判成复现（误报）。
	MinSimilarity float64
	// LenTolerance 响应长度允许的相对偏差，默认 0.15（±15%）。
	LenTolerance float64
	// Timeout 单次重放超时，默认 20s。
	Timeout time.Duration
	// Header 允许在请求上额外覆盖的头（如当前登录态 Cookie）。
	ExtraHeaders http.Header
}

func (o Options) withDefaults() Options {
	if o.MinSimilarity <= 0 {
		o.MinSimilarity = 0.85
	}
	if o.LenTolerance <= 0 {
		o.LenTolerance = 0.15
	}
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	return o
}

// Verdict 是判定结果。
type Verdict struct {
	Reproduced bool
	Status     int     // 本次响应的状态码
	Similarity float64 // 归一化后的相似度（0~1）
	LenRatio   float64 // 本次长度 / 记录长度
	Reasons    []string
}

// Explain 返回单行可读结论，进日志与模型上下文。
func (v Verdict) Explain() string {
	state := "未复现"
	if v.Reproduced {
		state = "已复现"
	}
	return fmt.Sprintf("%s（status=%d similarity=%.2f len_ratio=%.2f）%s",
		state, v.Status, v.Similarity, v.LenRatio, strings.Join(v.Reasons, "; "))
}

// Verify 重放一次并判定是否复现。
//
// 判定规则（全部满足才算复现）：
//  1. 传输层成功（连得上、没超时）；
//  2. 状态码与记录一致（记录里 Status>0 时）；
//  3. 响应长度在容差内（记录里 RespLen>0 时）；
//  4. 响应体相似度 ≥ MinSimilarity（有记录响应体时）。
//
// 任一条不满足都会写进 Reasons —— 这是给人复核用的，不是给模型猜的。
func Verify(ctx context.Context, rt http.RoundTripper, snap Snapshot, opt Options) (Verdict, error) {
	opt = opt.withDefaults()
	if rt == nil {
		rt = http.DefaultTransport
	}
	if strings.TrimSpace(snap.URL) == "" {
		return Verdict{}, fmt.Errorf("replay: snapshot has empty URL")
	}

	method := snap.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, snap.URL, bytes.NewReader(snap.Body))
	if err != nil {
		return Verdict{}, fmt.Errorf("replay: build request: %w", err)
	}
	for k, vs := range snap.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for k, vs := range opt.ExtraHeaders {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	// 让服务端按原样回包：不自动解压（长度才对得上）、不带默认 UA 覆盖。
	req.Header.Set("Accept-Encoding", "identity")

	cctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	req = req.WithContext(cctx)

	resp, err := rt.RoundTrip(req)
	if err != nil {
		return Verdict{Reasons: []string{"重放请求失败: " + err.Error()}}, fmt.Errorf("replay: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return Verdict{Reasons: []string{"读取响应失败: " + err.Error()}}, fmt.Errorf("replay: read body: %w", err)
	}

	v := Verdict{Status: resp.StatusCode}
	ok := true

	if snap.Status > 0 && resp.StatusCode != snap.Status {
		ok = false
		v.Reasons = append(v.Reasons, fmt.Sprintf("状态码变化 %d→%d", snap.Status, resp.StatusCode))
	}

	if snap.RespLen > 0 {
		v.LenRatio = float64(len(body)) / float64(snap.RespLen)
		if v.LenRatio < 1-opt.LenTolerance || v.LenRatio > 1+opt.LenTolerance {
			ok = false
			v.Reasons = append(v.Reasons, fmt.Sprintf("长度偏差过大 %d→%d", snap.RespLen, len(body)))
		}
	}

	switch {
	case len(snap.RespBody) > 0:
		v.Similarity = Similarity(snap.RespBody, body)
		if v.Similarity < opt.MinSimilarity {
			ok = false
			v.Reasons = append(v.Reasons, fmt.Sprintf("响应结构相似度 %.2f < %.2f", v.Similarity, opt.MinSimilarity))
		}
	case snap.RespHash != "":
		// 没存原响应体：只能比哈希，退化为「必须完全一致」。
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != snap.RespHash {
			ok = false
			v.Reasons = append(v.Reasons, "响应哈希不一致（无原始响应体可比对）")
		} else {
			v.Similarity = 1
		}
	default:
		v.Reasons = append(v.Reasons, "证据缺少响应体/哈希，无法判定复现")
		ok = false
	}

	v.Reproduced = ok
	if ok {
		v.Reasons = append(v.Reasons, "状态、长度与响应结构均与记录一致")
	}
	return v, nil
}

// Similarity 返回两份响应体的相似度（0~1），4-gram Jaccard。
//
// 先归一化（小写、压缩空白、去掉明显的易变值），再切 4 字节 shingle 取集合交集。
// 对「插入一段提示」或「CSRF token 变了」这类改动稳健，对「整页换了」敏感。
func Similarity(a, b []byte) float64 {
	x, y := shingles(normalize(a)), shingles(normalize(b))
	if len(x) == 0 && len(y) == 0 {
		return 1
	}
	if len(x) == 0 || len(y) == 0 {
		return 0
	}
	inter := 0
	for s := range x {
		if _, ok := y[s]; ok {
			inter++
		}
	}
	union := len(x) + len(y) - inter
	if union == 0 {
		return 1
	}
	return float64(inter) / float64(union)
}

const shingleSize = 4

func shingles(s string) map[string]struct{} {
	out := make(map[string]struct{}, len(s)/shingleSize+1)
	if len(s) <= shingleSize {
		if s != "" {
			out[s] = struct{}{}
		}
		return out
	}
	for i := 0; i+shingleSize <= len(s); i++ {
		out[s[i:i+shingleSize]] = struct{}{}
	}
	return out
}

// volatilePattern 命中这些形态的片段会在归一化时抹掉，避免动态值拉低相似度：
// 常见的是 16~64 位 hex / base64、UUID、13/16 位时间戳。
func normalize(b []byte) string {
	s := strings.ToLower(string(b))
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); {
		if isAlnum(s[i]) {
			j := i
			for j < len(s) && isAlnum(s[j]) {
				j++
			}
			tok := s[i:j]
			if isVolatile(tok) {
				out.WriteByte('*')
			} else {
				out.WriteString(tok)
			}
			i = j
			continue
		}
		if s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' {
			out.WriteByte(' ')
			for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
				i++
			}
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

// isVolatile 判断一个 token 是否像「每次请求都会变」的值。
func isVolatile(tok string) bool {
	n := len(tok)
	switch {
	case n >= 8 && n <= 64 && isHex(tok):
		// 8 位以上纯 hex：hash / nonce / UUID 被切开的片段都会落在这里。
		// 阈值取 8 而不是 16：UUID 会被归一化按非字母数字切开（550e8400/e29b/…），
		// 每段都短；宁可多抹一点 hash 样内容，也别让动态值拉低相似度。
		return true
	case n == 36 && strings.Count(tok, "-") == 4:
		return true // uuid
	case (n == 13 || n == 16) && isDigits(tok):
		return true // 毫秒/微秒时间戳
	case n >= 20 && strings.ContainsAny(tok, "0123456789") && strings.ContainsAny(tok, "abcdefghijklmnopqrstuvwxyz"):
		return true // 长 base64-ish
	}
	return false
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
