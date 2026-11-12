package server

// Android 真机动态证据：落盘位置 + 入库/进模型上下文前的脱敏。
//
// 两条纪律来自报告模板设计定稿：
//  1. 允许账号（含口令）出现在材料里 —— 平台提交常需要复现账号，抹掉反而没法交材料；
//  2. Cookie / Token / Authorization / 完整 HTTP 报文 **不内联**：它们不是漏洞证据，
//     却足以让会话被劫持。落盘前替换成 [REDACTED#<hash8>]，保留可追溯的指纹，
//     工具返回给模型的是路径 + 短摘要，不是报文全文。
//
// 落盘目录选在 <workRoot>/<taskID>/mobile/：per-task 沙箱把 <workRoot>/<taskID>
// bind mount 成容器内 /work，所以宿主侧写的文件模型能用 /work/mobile/... 直接 Read，
// 容器销毁后宿主文件仍在（与上一轮"任务文件落点"的结论一致）。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const mobileEvidenceMaxInline = 4 << 10 // 返回给模型的最佳上限；全文始终落盘

var (
	// 敏感头：整行值替换，保留头名 + 原文指纹，便于事后核对「哪一份证据被改过」。
	reSensitiveHeader = regexp.MustCompile(`(?im)^(\s*)(cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token|x-csrf-token)(\s*:\s*)(.+)$`)
	reBearer          = regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{12,}`)
	reSecretKV        = regexp.MustCompile(`(?i)\b(token|access_token|refresh_token|session_id|secret|api_key|auth_sig|signature)(["']?\s*[:=]\s*["']?)[A-Za-z0-9._~+/=-]{12,}`)
	reOTP             = regexp.MustCompile(`(?i)((?:验证码|校验码|动态码|otp|verification\s*code)\s*(?:为|是|:|=|：)?\s*)\d{4,8}\b`)
	// 完整 HTTP 报文块（请求行/状态行 + 头 + 空行）：只留首行，正文不进内联上下文。
	// 结尾必须吃到第一个空行就停，否则贪婪匹配会把报文后面的普通日志一并吞掉。
	reHTTPBlock = regexp.MustCompile(`(?m)^(?:GET |POST |PUT |DELETE |PATCH |HEAD |OPTIONS |HTTP/1\.[01] )[^\n]*\n(?:[^\n]+\n)*\n`)
)

func redactFingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "[REDACTED#" + hex.EncodeToString(sum[:])[:8] + "]"
}

// sanitizeMobileEvidence 对即将落盘/返回模型的文本做行级脱敏。
// 刻意保留账号与口令（平台材料需要），只抹会话凭据与完整报文。
func sanitizeMobileEvidence(raw string) string {
	s := strings.ReplaceAll(raw, "\r\n", "\n")
	s = reSensitiveHeader.ReplaceAllStringFunc(s, func(line string) string {
		m := reSensitiveHeader.FindStringSubmatch(line)
		if len(m) < 5 {
			return line
		}
		return m[1] + m[2] + m[3] + redactFingerprint(strings.TrimSpace(m[4]))
	})
	s = reBearer.ReplaceAllString(s, "${1}[REDACTED]")
	s = reSecretKV.ReplaceAllStringFunc(s, func(v string) string {
		m := reSecretKV.FindStringSubmatch(v)
		if len(m) < 3 {
			return v
		}
		return m[1] + m[2] + "[REDACTED]"
	})
	s = reOTP.ReplaceAllString(s, "${1}[REDACTED_CODE]")
	s = reHTTPBlock.ReplaceAllStringFunc(s, func(block string) string {
		first, _, _ := strings.Cut(block, "\n")
		return first + "\n[完整 HTTP 报文已折叠，见落盘证据文件]\n"
	})
	return s
}

// MobileEvidence 是落盘证据的一条索引记录（append-only，写进 _index.jsonl）。
type MobileEvidence struct {
	File      string    `json:"file"` // 容器内可见路径 /work/mobile/<name>
	Kind      string    `json:"kind"` // logcat / pull / frida / shell / proxy / cleanup
	Op        string    `json:"op"`   // 触发它的授权 op
	Bytes     int       `json:"bytes"`
	SHA256    string    `json:"sha256"`   // 脱敏后内容的摘要（不是原始设备数据的哈希）
	Redacted  bool      `json:"redacted"` // 是否命中过脱敏规则
	Summary   string    `json:"summary"`  // 一行人读摘要
	CreatedAt time.Time `json:"created_at"`
}

var mobileEvidenceMu sync.Mutex

// mobileEvidenceDir 返回 <workRoot>/<taskID>/mobile，并保证目录存在。
func (s *Server) mobileEvidenceDir(taskID int64) (string, error) {
	if s == nil || s.m == nil || taskID <= 0 {
		return "", fmt.Errorf("无效的任务 ID")
	}
	root := localSandboxWorkRoot(s.m.DataDir())
	dir := filepath.Join(root, strconv.FormatInt(taskID, 10), "mobile")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建动态证据目录失败：%w", err)
	}
	return dir, nil
}

// saveMobileEvidence 把一份动态输出脱敏后落盘，返回索引记录与「给模型看的」短摘要。
// 全文永远落盘；inline 只回前 mobileEvidenceMaxInline 字节，避免一次 logcat 把上下文撑爆。
func (s *Server) saveMobileEvidence(taskID int64, kind, op, name, summary, raw string) (MobileEvidence, string, error) {
	dir, err := s.mobileEvidenceDir(taskID)
	if err != nil {
		return MobileEvidence{}, "", err
	}
	clean := sanitizeMobileEvidence(raw)
	redacted := clean != strings.ReplaceAll(raw, "\r\n", "\n")
	stamp := time.Now().UTC().Format("20060102T150405.000000000")
	base := regexp.MustCompile(`[^A-Za-z0-9_.-]`).ReplaceAllString(name, "_")
	if base == "" {
		base = kind
	}
	file := base + "-" + stamp + ".txt"
	if err := os.WriteFile(filepath.Join(dir, file), []byte(clean), 0o600); err != nil {
		return MobileEvidence{}, "", fmt.Errorf("写入动态证据失败：%w", err)
	}
	sum := sha256.Sum256([]byte(clean))
	rec := MobileEvidence{
		File: "/work/mobile/" + file, Kind: kind, Op: op,
		Bytes: len(clean), SHA256: hex.EncodeToString(sum[:]),
		Redacted: redacted, Summary: summary, CreatedAt: time.Now().UTC(),
	}
	// 索引用 JSONL 追加：并发的多个 worker 各写一行，不需要重写整个文件。
	// 单条写入用进程内互斥保护，跨进程由 O_APPEND 保证行级原子。
	mobileEvidenceMu.Lock()
	defer mobileEvidenceMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, "_index.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return MobileEvidence{}, "", fmt.Errorf("写入证据索引失败：%w", err)
	}
	defer f.Close()
	b, _ := json.Marshal(rec)
	if _, err := f.Write(append(b, '\n')); err != nil {
		return MobileEvidence{}, "", fmt.Errorf("追加证据索引失败：%w", err)
	}
	inline := clean
	truncated := false
	if len(inline) > mobileEvidenceMaxInline {
		inline = inline[:mobileEvidenceMaxInline]
		truncated = true
	}
	return rec, mobileInlineView(rec, inline, truncated), nil
}

func mobileInlineView(rec MobileEvidence, inline string, truncated bool) string {
	var b strings.Builder
	b.WriteString("证据文件: " + rec.File + "\n")
	b.WriteString("类型: " + rec.Kind + " | 字节: " + strconv.Itoa(rec.Bytes) +
		" | SHA256: " + rec.SHA256[:16] + "… | 脱敏: " + strconv.FormatBool(rec.Redacted) + "\n")
	if rec.Summary != "" {
		b.WriteString("摘要: " + rec.Summary + "\n")
	}
	if truncated {
		b.WriteString("（以下为前 " + strconv.Itoa(mobileEvidenceMaxInline) + " 字节，全文用 Read 读证据文件）\n")
	}
	b.WriteString("---\n")
	b.WriteString(inline)
	return b.String()
}

// listMobileEvidence 返回任务已有的证据索引（最近优先），供收尾与报告引用。
func (s *Server) listMobileEvidence(taskID int64, limit int) ([]MobileEvidence, error) {
	dir, err := s.mobileEvidenceDir(taskID)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(dir, "_index.jsonl"))
	if os.IsNotExist(err) {
		return []MobileEvidence{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []MobileEvidence{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec MobileEvidence
		if json.Unmarshal([]byte(line), &rec) == nil {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
