package binfmt

import (
	"fmt"
	"strings"
)

// Render 把分析结果渲染成**给模型看的紧凑摘要**，并严格限制字节数。
//
// 为什么要有上限：工具输出会留在上下文里、每轮重发。实测一条 30KB 的 tool_result
// 会吃掉 ~10K tokens，且之后每一轮都要再付一次。摘要目标 ≤1400 字节（≈450 tokens），
// 完整 JSON 由调用方落盘，模型需要细节再用 Read 读。
//
// 渲染顺序即**信息优先级**：格式/架构 → 安全标志 → 加壳依据 → 段 → 依赖 → 可疑项。
// 预算不够时从尾部丢，而不是把每条都截断成看不懂的样子。
func Render(rep Report, maxBytes int) string {
	if maxBytes <= 0 {
		maxBytes = 1400
	}
	var lines []string

	head := fmt.Sprintf("%s %s %dbit %s size=%s sha=%s",
		strings.ToUpper(string(rep.Format)), rep.Arch, rep.Bits, orDash(rep.Kind),
		humanSize(rep.Size), shortSHA(rep.SHA256))
	lines = append(lines, head)
	lines = append(lines, fmt.Sprintf("entry=%s sections=%d imports=%d (%s) exports=%d",
		rep.Entry, len(rep.Sections), rep.Imports.Count, strings.Join(clip(rep.Imports.DLLs, 4), ", "), rep.Exports))

	if sec := securityLine(rep.Security); sec != "" {
		lines = append(lines, "mitigations: "+sec)
	}
	if rep.Packer.Suspected {
		lines = append(lines, "packer: 疑似 —— "+strings.Join(rep.Packer.Reasons, "; "))
	} else if len(rep.Sections) > 0 {
		lines = append(lines, "packer: 未命中已知特征（高熵段/壳段名/导入异常少/入口越界）")
	}

	// 段：只列可执行段 + 高熵段（其余对判断帮助小）
	var secLines []string
	for _, s := range rep.Sections {
		mark := ""
		if strings.Contains(s.Perm, "X") {
			mark = " *"
		}
		secLines = append(secLines, fmt.Sprintf("[%s %s v=%s raw=%s e=%.2f %s%s]",
			s.Name, hexAddr(s.VAddr), humanSize(int64(s.VSize)), humanSize(int64(s.RawSize)), s.Entropy, s.Perm, mark))
	}
	if len(secLines) > 0 {
		lines = append(lines, "sections: "+strings.Join(secLines, " "))
	}
	if len(rep.Imports.Suspicious) > 0 {
		lines = append(lines, "suspicious-api: "+strings.Join(rep.Imports.Suspicious, ", "))
	}
	if ss := stringsLine(rep.Strings); ss != "" {
		lines = append(lines, ss)
	}
	if len(rep.Warnings) > 0 {
		lines = append(lines, "warn: "+strings.Join(rep.Warnings, "; "))
	}

	// 逐行拼装，超预算就从尾部丢行；单行仍超预算则截断该行。
	var b strings.Builder
	for _, ln := range lines {
		if b.Len() >= maxBytes {
			break
		}
		room := maxBytes - b.Len()
		if len(ln)+1 > room {
			if room > 24 {
				b.WriteString(ln[:room-4])
				b.WriteString("…")
			}
			break
		}
		b.WriteString(ln)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func securityLine(s SecurityFlags) string {
	var on []string
	if s.ASLR {
		on = append(on, "ASLR")
	}
	if s.DEP || s.NX {
		on = append(on, "DEP/NX")
	}
	if s.CFG {
		on = append(on, "CFG")
	}
	if s.PIE {
		on = append(on, "PIE")
	}
	if s.RELRO {
		on = append(on, "RELRO")
	}
	if len(on) == 0 {
		return ""
	}
	return strings.Join(on, " ")
}

func stringsLine(ss StringSummary) string {
	var parts []string
	if len(ss.URLs) > 0 {
		parts = append(parts, "url="+strings.Join(ss.URLs, ","))
	}
	if len(ss.IPs) > 0 {
		parts = append(parts, "ip="+strings.Join(ss.IPs, ","))
	}
	if len(ss.Paths) > 0 {
		parts = append(parts, "path="+strings.Join(ss.Paths, ","))
	}
	if len(ss.Suspicious) > 0 {
		parts = append(parts, "kw="+strings.Join(ss.Suspicious, ","))
	}
	if len(parts) == 0 {
		if ss.Total > 0 {
			return fmt.Sprintf("strings(%d): 无可分类特征", ss.Total)
		}
		return ""
	}
	return fmt.Sprintf("strings(%d): %s", ss.Total, strings.Join(parts, " | "))
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 3; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGT"[exp])
}

func shortSHA(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
