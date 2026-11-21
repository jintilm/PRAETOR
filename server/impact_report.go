package server

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jintilm/praetor/db"
)

// impactSectionMarker 是「影响面」小节的识别标记。
//
// 用它做幂等：模型可能自己写了一个同名小节，也可能同一份报告被重写两次。
// 只要报告里已经出现这个标题，就不再追加——否则每次 update 都会多一截。
const impactSectionMarker = "## 影响面（系统按取证记录生成）"

// renderImpactSection 把取证记录渲染成确定性的「影响面」小节。
//
// 为什么由服务端生成而不是让报告 Agent 写：审核打回的是「危害写成形容词」。
// 模型能自由发挥的部分越少，报告的可核验性越高；这里每个数字都能回到
// impact_metrics 与绑定流量。
func renderImpactSection(imp *db.FindingImpact) string {
	if imp == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(impactSectionMarker)
	b.WriteString("\n\n")
	b.WriteString("> 本节由平台根据 record_impact 的取证记录生成，非模型撰写；指标与提取物可在「关联流量」中复核。\n\n")
	fmt.Fprintf(&b, "- 危害类别：`%s`\n", imp.Kind)
	fmt.Fprintf(&b, "- 危害等级：**%d** · %s\n", imp.Level, db.ImpactLevelLabel(imp.Level))
	if !imp.RecordedAt.IsZero() && imp.RecordedAt.Year() > 1970 {
		fmt.Fprintf(&b, "- 取证时间：%s\n", imp.RecordedAt.Local().Format(time.RFC3339))
	}
	if len(imp.Metrics) > 0 {
		b.WriteString("- 提取物指标：\n")
		keys := make([]string, 0, len(imp.Metrics))
		for k := range imp.Metrics {
			keys = append(keys, k)
		}
		sort.Strings(keys) // 稳定输出：同一份记录每次渲染完全一致
		for _, k := range keys {
			fmt.Fprintf(&b, "  - `%s`：%s\n", k, formatMetric(imp.Metrics[k]))
		}
	}
	if len(imp.Artifacts) > 0 {
		ids := make([]string, 0, len(imp.Artifacts))
		for _, id := range imp.Artifacts {
			ids = append(ids, "`"+id+"`")
		}
		fmt.Fprintf(&b, "- 证据流量：%s\n", strings.Join(ids, "、"))
	} else {
		b.WriteString("- 证据流量：无（该结论无法从报文复核，审核会被打回）\n")
	}
	return b.String()
}

func formatMetric(v any) string {
	switch t := v.(type) {
	case string:
		return "`" + t + "`"
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	case nil:
		return ""
	}
	if b, err := json.Marshal(v); err == nil {
		return "`" + string(b) + "`"
	}
	return fmt.Sprintf("%v", v)
}

// appendImpactSection 幂等追加影响面小节。
//
// 报告为空时不追加——否则会生成一份「只有影响面」的报告，反而更难读。
func appendImpactSection(report string, imp *db.FindingImpact) string {
	if imp == nil || imp.Level < 1 {
		return report
	}
	if strings.Contains(report, impactSectionMarker) {
		return report
	}
	section := renderImpactSection(imp)
	if section == "" {
		return report
	}
	trimmed := strings.TrimRight(report, " \t\r\n")
	if trimmed == "" {
		return section
	}
	return trimmed + "\n\n---\n\n" + section
}
