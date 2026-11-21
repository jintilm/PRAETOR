package bench

import (
	"fmt"
	"sort"
	"time"
)

// Finding 是一次可审计的发现记录。ConfirmedAt 对应首条通过 oracle 的验证历史时间，
// 应由 finding_verifications 的 pass 事件生成，而非信任模型自述或现态 verified_at。
type Finding struct {
	ID          string      `json:"id"`
	Oracle      OracleState `json:"oracle"`
	Conclusion  Conclusion  `json:"conclusion"`
	ConfirmedAt time.Time   `json:"confirmed_at"`
}

// Result 是一次 case 的原始结果快照。输入/输出 token 为该 case 整个任务的账本和，
// 不按 finding 重复计费；StartedAt 为任务创建时间，findings 可为空。
type Result struct {
	Case         Case      `json:"case"`
	StartedAt    time.Time `json:"started_at"`
	Findings     []Finding `json:"findings"`
	InputTokens  int64     `json:"input_tokens"`
	OutputTokens int64     `json:"output_tokens"`
	// Executed 标记该 case 是否真的被跑过。为 nil 表示结果文件没记这件事：
	// 此时「没有上报漏洞」既可能是正确拒绝，也可能是根本没跑，只能算证据不足。
	// 明确标了才允许把负例的空结果记成正确拒绝，避免白拿分。
	Executed *bool `json:"executed,omitempty"`
}

// Metric 中 Precision=Confirmed/(Confirmed+FP)，Recall=确认的正样本数/正样本总数。
// 未定论上报仅进入 Reported；两种分母为零时相应比率为 nil（非 0%）。
// TimeToConfirm 为通过验证的发现从任务创建到首次确认的平均时间，单位毫秒。
type Metric struct {
	Class            string   `json:"class"`
	Cases            int      `json:"cases"`
	PositiveCases    int      `json:"positive_cases"`
	RecalledCases    int      `json:"recalled_cases"`
	Reported         int      `json:"reported"`
	Confirmed        int      `json:"confirmed"`
	FP               int      `json:"fp"`
	Inconclusive     int      `json:"inconclusive"`
	Precision        *float64 `json:"precision"`
	Recall           *float64 `json:"recall"`
	TimeToConfirmMS  *int64   `json:"time_to_confirm_ms"`
	InputTokens      int64    `json:"input_tokens"`
	OutputTokens     int64    `json:"output_tokens"`
	Tokens           int64    `json:"tokens"`
	CostPerConfirmed *float64 `json:"cost_per_confirmed"`
	totalConfirmMS   int64
}

// ComputeMetrics 接受逐 case 的完整结果，不进行 IO；重复 case、时间逆序、
// 不可信真值、负 token 或重复 finding ID 报错，以免算出不可复核的数字。
// 返回每类按字典序排列，最后附 TOTAL；空输入返回空表。
func ComputeMetrics(results []Result) ([]Metric, error) {
	byClass := map[string]*Metric{}
	seen := map[string]bool{}
	for _, r := range results {
		if err := r.Case.Validate(); err != nil {
			return nil, err
		}
		key := r.Case.Class + "/" + r.Case.ID
		if seen[key] {
			return nil, fmt.Errorf("重复结果 %s", key)
		}
		seen[key] = true
		if r.StartedAt.IsZero() || r.InputTokens < 0 || r.OutputTokens < 0 {
			return nil, fmt.Errorf("%s: 任务时间或 token 无效", key)
		}
		m := byClass[r.Case.Class]
		if m == nil {
			m = &Metric{Class: r.Case.Class}
			byClass[r.Case.Class] = m
		}
		m.Cases++
		m.InputTokens += r.InputTokens
		m.OutputTokens += r.OutputTokens
		m.Tokens += r.InputTokens + r.OutputTokens
		if r.Case.Kind == Positive {
			m.PositiveCases++
		}
		ids := map[string]bool{}
		caseRecalled := false
		for _, f := range r.Findings {
			if f.ID == "" || ids[f.ID] {
				return nil, fmt.Errorf("%s: finding id 为空或重复", key)
			}
			ids[f.ID] = true
			m.Reported++
			j := Judge(r.Case, true, f.Oracle, f.Conclusion)
			if j.Inconclusive {
				m.Inconclusive++
				continue
			}
			if j.Confirmed {
				if f.ConfirmedAt.IsZero() || f.ConfirmedAt.Before(r.StartedAt) {
					return nil, fmt.Errorf("%s/%s: 确认时间无效", key, f.ID)
				}
				m.Confirmed++
				caseRecalled = true
				m.totalConfirmMS += f.ConfirmedAt.Sub(r.StartedAt).Milliseconds()
			} else if j.FalsePositive || f.Conclusion == Confirmed {
				m.FP++
			}
			// 误报带着「确认时间」是真实会发生的情况：模型把陷阱当成漏洞并记了时刻。
			// 这种必须照常计入 FP 并出报告，不能因为输入前后矛盾就把整份评测打回；
			// 只有既非确认、也非误报却带确认时间，才是真的记录不一致。
			if !j.Confirmed && !j.FalsePositive && !f.ConfirmedAt.IsZero() {
				return nil, fmt.Errorf("%s/%s: 未确认却提供确认时间", key, f.ID)
			}
		}
		if caseRecalled {
			m.RecalledCases++
		}
	}
	if len(byClass) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(byClass))
	for k := range byClass {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Metric, 0, len(keys)+1)
	total := Metric{Class: "TOTAL"}
	for _, key := range keys {
		m := byClass[key]
		finishMetric(m)
		out = append(out, *m)
		total.Cases += m.Cases
		total.PositiveCases += m.PositiveCases
		total.RecalledCases += m.RecalledCases
		total.Reported += m.Reported
		total.Confirmed += m.Confirmed
		total.FP += m.FP
		total.Inconclusive += m.Inconclusive
		total.InputTokens += m.InputTokens
		total.OutputTokens += m.OutputTokens
		total.Tokens += m.Tokens
		total.totalConfirmMS += m.totalConfirmMS
	}
	finishMetric(&total)
	out = append(out, total)
	return out, nil
}
func finishMetric(m *Metric) {
	if denom := m.Confirmed + m.FP; denom > 0 {
		v := float64(m.Confirmed) / float64(denom)
		m.Precision = &v
	}
	if m.PositiveCases > 0 {
		v := float64(m.RecalledCases) / float64(m.PositiveCases)
		m.Recall = &v
	}
	if m.Confirmed > 0 {
		v := m.totalConfirmMS / int64(m.Confirmed)
		m.TimeToConfirmMS = &v
		t := float64(m.Tokens) / float64(m.Confirmed)
		m.CostPerConfirmed = &t
	}
}
