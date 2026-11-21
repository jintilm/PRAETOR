package agent

import (
	"fmt"
	"strings"
)

// 危害等级：与 verification_state 正交。
//
//	0 none        报告里只有结论
//	1 reproduced  同一请求能重放（当前的 verified 就停在这一级）
//	2 extracted   拿到了目标侧的具体数据/文件/回连（审核要的起点）
//	3 exploited   产生了业务副作用（改数据、拿权限、横向）
const (
	ImpactNone       = 0
	ImpactReproduced = 1
	ImpactExtracted  = 2
	ImpactExploited  = 3
)

// ImpactLevelName 给模型与报告用的人类可读名。
func ImpactLevelName(level int) string {
	switch level {
	case ImpactReproduced:
		return "reproduced（可复现）"
	case ImpactExtracted:
		return "extracted（已提取目标侧内容）"
	case ImpactExploited:
		return "exploited（已产生业务副作用）"
	}
	return "none（只有结论）"
}

// DeriveImpactLevel 按危害类别与提取物指标推导等级，并返回「离下一级还差什么」。
//
// 为什么等级必须由程序推导：模型自报的等级永远倾向于「我打穿了」。这里的原则是
// 每一级都要有**具体字段**撑着，缺字段就降级并把缺口回给模型——它会照着缺口去补取证，
// 而不是在报告里写形容词。
//
// artifactCount 是已绑定到该漏洞的流量证据条数：0 条时最多给到 1 级，
// 因为没有任何可从目标侧复核的提取物。
func DeriveImpactLevel(kind string, metrics map[string]any, artifactCount int) (int, []string) {
	var gaps []string
	level := ImpactNone

	switch kind {
	case "sqli":
		if metricString(metrics, "table") == "" {
			gaps = append(gaps, "缺 table：注出的是哪个库表（如 shop.orders）")
			break
		}
		if metricInt(metrics, "rows_read") < 1 {
			gaps = append(gaps, "缺 rows_read：实际读到的行数（只取样本，不要脱库）")
			break
		}
		level = ImpactExtracted
		if metricBool(metrics, "write_confirmed") {
			level = ImpactExploited
		}
	case "rce":
		if metricString(metrics, "marker") == "" {
			gaps = append(gaps, "缺 marker：命令回显里的随机算式结果（证明真执行）")
			break
		}
		if metricString(metrics, "fingerprint") == "" {
			gaps = append(gaps, "缺 fingerprint：目标指纹（hostname/uname/uid），用来排除中间层回显")
			break
		}
		level = ImpactExtracted
		if metricString(metrics, "privilege") != "" {
			level = ImpactExploited
		}
	case "ssrf":
		if metricString(metrics, "internal_target") == "" && metricString(metrics, "oob_source") == "" {
			gaps = append(gaps, "缺 internal_target 或 oob_source：打到的内网端点，或带外回连的源 IP")
			break
		}
		level = ImpactExtracted
		if metricString(metrics, "metadata_credential") != "" {
			level = ImpactExploited
		}
	case "idor":
		if metricString(metrics, "victim_canary") == "" {
			gaps = append(gaps, "缺 victim_canary：响应里出现的**受害者**私有字段（邮箱/手机/订单号）")
			break
		}
		level = ImpactExtracted
		if metricBool(metrics, "state_changed") {
			level = ImpactExploited
		}
	case "upload":
		if metricString(metrics, "landing_url") == "" {
			gaps = append(gaps, "缺 landing_url：文件落地后的访问 URL")
			break
		}
		if metricString(metrics, "exec_marker") == "" {
			gaps = append(gaps, "缺 exec_marker：访问该 URL 时回显的随机算式结果")
			break
		}
		level = ImpactExtracted
		if metricString(metrics, "privilege") != "" {
			level = ImpactExploited
		}
	case "disclosure":
		if len(metricStrings(metrics, "sensitive_fields")) == 0 && metricInt(metrics, "rows_read") < 1 {
			gaps = append(gaps, "缺 sensitive_fields 或 rows_read：泄露的字段名（手机号/身份证/密钥）或行数")
			break
		}
		level = ImpactExtracted
		if metricInt(metrics, "rows_read") >= 1000 {
			level = ImpactExploited
		}
	case "logic":
		if !metricBool(metrics, "state_changed") {
			gaps = append(gaps, "缺 state_changed=true：业务状态真的变了（0 元下单成功/余额增加/券被复用）")
			break
		}
		if metricString(metrics, "invariant") == "" {
			gaps = append(gaps, "缺 invariant：被破坏的业务不变量（如「实付金额 >= 商品价」）")
			break
		}
		level = ImpactExtracted
		if metricString(metrics, "business_loss") != "" {
			level = ImpactExploited
		}
	default:
		gaps = append(gaps, fmt.Sprintf("未知危害类别 %q", kind))
	}

	// 没有任何可从目标复核的提取物：最高只能算「可复现」。
	if level >= ImpactExtracted && artifactCount == 0 {
		level = ImpactReproduced
		gaps = append(gaps, "缺 artifact_traffic_ids：提取物必须来自绑定到该漏洞的真实流量，否则无法复核")
	}

	if level < ImpactExploited && len(gaps) == 0 {
		gaps = append(gaps, "已到 2 级；要升 3 级需证明业务副作用（改状态/拿权限/横向）")
	}
	return level, gaps
}

func metricString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		switch t := v.(type) {
		case string:
			return strings.TrimSpace(t)
		case fmt.Stringer:
			return strings.TrimSpace(t.String())
		}
	}
	return ""
}

func metricInt(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch t := m[key].(type) {
	case float64:
		return int(t)
	case int:
		return t
	case int64:
		return int(t)
	case string:
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(t), "%d", &n); err == nil {
			return n
		}
	}
	return 0
}

func metricBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	switch t := m[key].(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "true")
	}
	return false
}

func metricStrings(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	switch t := m[key].(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, v := range t {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}
