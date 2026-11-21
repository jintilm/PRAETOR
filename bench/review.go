package bench

import (
	"errors"
	"fmt"
	"sort"
)

// Outcome 是一条 case 的最终评语。它与 Pipeline 的 oracle 状态不同：
// oracle 只回答「这一次判定说了什么」，Outcome 回答「对照真值，这次判定算不算数」。
type Outcome string

const (
	OutcomeConfirmed    Outcome = "confirmed"      // 正例被确认为漏洞
	OutcomeCorrectlyNeg Outcome = "correctly_neg"  // 负例/陷阱被正确拒绝
	OutcomeFalsePos     Outcome = "false_positive" // 负例/陷阱被当成漏洞
	OutcomeMissed       Outcome = "missed"         // 正例没被确认（漏报）
	OutcomeInconclusive Outcome = "inconclusive"   // 证据不足，不算对也不算错
)

// CaseReview 是单条 case 的评语，保留原始观测值便于人工复核。
type CaseReview struct {
	Class      string      `json:"class"`
	ID         string      `json:"id"`
	Kind       CaseKind    `json:"kind"`
	Reported   bool        `json:"reported"`
	Oracle     OracleState `json:"oracle"`
	Conclusion Conclusion  `json:"conclusion"`
	Outcome    Outcome     `json:"outcome"`
	Note       string      `json:"note,omitempty"`
}

// ReviewCase 把「真值 + 观测」折成一个评语。
//
// 三条硬规矩：
//  1. 观测缺失或 inconclusive → inconclusive，既不算对也不算错；
//  2. 只有 positive 且 oracle pass 且结论 confirmed 才算真确认；
//  3. negative / trap 只要被报成 confirmed 就是误报——这是最贵的一类错误。
func ReviewCase(c Case, reported bool, oracle OracleState, conclusion Conclusion) CaseReview {
	r := CaseReview{Class: c.Class, ID: c.ID, Kind: c.Kind, Reported: reported, Oracle: oracle, Conclusion: conclusion}
	if oracle == "" || conclusion == "" || oracle == OracleInconclusive || conclusion == Inconclusive {
		r.Outcome = OutcomeInconclusive
		r.Note = "未取得完整判定（未执行/采集不完整/判据不确定）"
		return r
	}
	promoted := reported && oracle == OraclePass && conclusion == Confirmed
	if c.Kind == Positive {
		if promoted {
			r.Outcome = OutcomeConfirmed
			return r
		}
		r.Outcome = OutcomeMissed
		if !reported {
			r.Note = "正例未上报"
		} else {
			r.Note = "正例上报但未被确定性判定确认"
		}
		return r
	}
	if promoted {
		r.Outcome = OutcomeFalsePos
		r.Note = "负例/陷阱被当成漏洞确认"
		return r
	}
	if oracle == OracleFail && conclusion == Rejected {
		r.Outcome = OutcomeCorrectlyNeg
		return r
	}
	r.Outcome = OutcomeInconclusive
	r.Note = "负例既未确认也未明确拒绝"
	return r
}

// Answer 是一次运行的原始输入（从已保存的结果反序列化得到）。
type Answer struct {
	Name    string   `json:"name"`
	Results []Result `json:"results"`
}

// Report 是一次运行的完整评语：逐条结论 + 汇总指标。
type Report struct {
	Name    string          `json:"name"`
	Cases   []CaseReview    `json:"cases"`
	Metrics []Metric        `json:"metrics"`
	Counts  map[Outcome]int `json:"counts"`
}

// BuildReport 只做纯计算：不联网、不连库、不执行样本 payload。
func BuildReport(a Answer) (*Report, error) {
	if len(a.Results) == 0 {
		return nil, errors.New("结果为空：没有可评分的 case")
	}
	rep := &Report{Name: a.Name, Counts: map[Outcome]int{}}
	for _, r := range a.Results {
		if err := r.Case.Validate(); err != nil {
			return nil, err
		}
		if len(r.Findings) == 0 {
			// 没有上报时，结论完全取决于该 case 是否真的被执行过：
			//   executed=true  正例=漏报；负例/陷阱=正确拒绝
			//   executed=false 一律证据不足，不参与打分
			//   未标注        无法区分，同样不算对，也不冤枉成错
			cr := ReviewCase(r.Case, false, "", "")
			switch {
			case r.Executed == nil:
				cr.Note = "未上报且未标注是否执行，无法区分「未执行」与「正确拒绝」"
			case !*r.Executed:
				cr.Note = "样本未执行，本次不参与打分"
			case r.Case.Kind == Positive:
				cr.Outcome, cr.Note = OutcomeMissed, "正例未上报"
			default:
				cr.Outcome, cr.Note = OutcomeCorrectlyNeg, "未上报漏洞：负例/陷阱的正确结果"
			}
			rep.Cases = append(rep.Cases, cr)
			rep.Counts[cr.Outcome]++
			continue
		}
		// 一个 case 可能上报多条：每条都单独出评语，误报不会被合并掩盖。
		for _, f := range r.Findings {
			cr := ReviewCase(r.Case, true, f.Oracle, f.Conclusion)
			rep.Cases = append(rep.Cases, cr)
			rep.Counts[cr.Outcome]++
		}
	}
	metrics, err := ComputeMetrics(a.Results)
	if err != nil {
		return nil, err
	}
	rep.Metrics = metrics
	sort.SliceStable(rep.Cases, func(i, j int) bool {
		if rep.Cases[i].Class == rep.Cases[j].Class {
			return rep.Cases[i].ID < rep.Cases[j].ID
		}
		return rep.Cases[i].Class < rep.Cases[j].Class
	})
	return rep, nil
}

// total 取汇总行（ComputeMetrics 把 TOTAL 放在最后）。
func (r *Report) total() *Metric {
	if r == nil || len(r.Metrics) == 0 {
		return nil
	}
	last := r.Metrics[len(r.Metrics)-1]
	if last.Class != "TOTAL" {
		return nil
	}
	return &last
}

// Comparison 是两次运行的成本/质量对照。
type Comparison struct {
	Baseline        string   `json:"baseline"`
	Candidate       string   `json:"candidate"`
	TokensBefore    int64    `json:"tokens_before"`
	TokensAfter     int64    `json:"tokens_after"`
	TokenChangePct  *float64 `json:"token_change_pct"`
	ConfirmedBefore int      `json:"confirmed_before"`
	ConfirmedAfter  int      `json:"confirmed_after"`
	CostBefore      *float64 `json:"cost_before"`
	CostAfter       *float64 `json:"cost_after"`
	CostChangePct   *float64 `json:"cost_change_pct"`
	PrecisionBefore *float64 `json:"precision_before"`
	PrecisionAfter  *float64 `json:"precision_after"`
	RecallBefore    *float64 `json:"recall_before"`
	RecallAfter     *float64 `json:"recall_after"`
	// Regressions 是变差的 case（原先对、现在错），回归门禁直接看它。
	Regressions  []string `json:"regressions,omitempty"`
	Improvements []string `json:"improvements,omitempty"`
}

func pct(before, after int64) *float64 {
	if before <= 0 {
		return nil
	}
	v := (float64(after) - float64(before)) / float64(before) * 100
	return &v
}

func outcomeByKey(rep *Report) map[string]Outcome {
	out := map[string]Outcome{}
	for _, c := range rep.Cases {
		key := c.Class + "/" + c.ID
		// 同一 case 多条记录时，取最差的一条：宁可把回归看清楚。
		prev, ok := out[key]
		if !ok || outcomeRank(c.Outcome) > outcomeRank(prev) {
			out[key] = c.Outcome
		}
	}
	return out
}

func outcomeRank(o Outcome) int {
	switch o {
	case OutcomeConfirmed, OutcomeCorrectlyNeg:
		return 0
	case OutcomeInconclusive:
		return 1
	case OutcomeMissed:
		return 2
	case OutcomeFalsePos:
		return 3
	}
	return 0
}

// Compare 对照两次运行。Token 与质量分开看：成本涨了但确认数涨得更多，是值得的。
func Compare(baseline, candidate *Report) (*Comparison, error) {
	if baseline == nil || candidate == nil {
		return nil, errors.New("对照需要两份报告")
	}
	bt, ct := baseline.total(), candidate.total()
	if bt == nil || ct == nil {
		return nil, errors.New("报告缺少 TOTAL 汇总行")
	}
	cmp := &Comparison{
		Baseline: baseline.Name, Candidate: candidate.Name,
		TokensBefore: bt.Tokens, TokensAfter: ct.Tokens,
		ConfirmedBefore: bt.Confirmed, ConfirmedAfter: ct.Confirmed,
		CostBefore: bt.CostPerConfirmed, CostAfter: ct.CostPerConfirmed,
		PrecisionBefore: bt.Precision, PrecisionAfter: ct.Precision,
		RecallBefore: bt.Recall, RecallAfter: ct.Recall,
	}
	cmp.TokenChangePct = pct(cmp.TokensBefore, cmp.TokensAfter)
	if cmp.CostBefore != nil && cmp.CostAfter != nil && *cmp.CostBefore > 0 {
		v := (*cmp.CostAfter - *cmp.CostBefore) / *cmp.CostBefore * 100
		cmp.CostChangePct = &v
	}
	before, after := outcomeByKey(baseline), outcomeByKey(candidate)
	keys := make([]string, 0, len(before))
	for k := range before {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b, ok := before[k]
		if !ok {
			continue
		}
		a, ok := after[k]
		if !ok {
			continue
		}
		if outcomeRank(a) > outcomeRank(b) {
			cmp.Regressions = append(cmp.Regressions, fmt.Sprintf("%s: %s -> %s", k, b, a))
		} else if outcomeRank(a) < outcomeRank(b) {
			cmp.Improvements = append(cmp.Improvements, fmt.Sprintf("%s: %s -> %s", k, b, a))
		}
	}
	return cmp, nil
}
