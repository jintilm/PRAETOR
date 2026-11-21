// Command reviewmetrics 对「已保存的评测结果」出离线报告：
// 逐条判出误报/漏报/证据不足，汇总 precision/recall/成本，并可对照两次运行。
// 它只读 JSON 文件，不联网、不连库、不执行任何样本 payload。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/jintilm/praetor/bench"
)

func load(path string) (bench.Answer, error) {
	var a bench.Answer
	f, err := os.Open(path)
	if err != nil {
		return a, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return a, fmt.Errorf("%s: %w", path, err)
	}
	if a.Name == "" {
		a.Name = path
	}
	return a, nil
}

func pct(p *float64) string {
	if p == nil {
		return "n/a"
	}
	return fmt.Sprintf("%+.0f%%", *p)
}

func rate(p *float64) string {
	if p == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.2f", *p)
}

func printReport(rep *bench.Report) {
	fmt.Printf("## %s\n\n", rep.Name)
	fmt.Println("| class | cases | reported | confirmed | fp | inconclusive | precision | recall | tokens |")
	fmt.Println("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
	for _, m := range rep.Metrics {
		fmt.Printf("| %s | %d | %d | %d | %d | %d | %s | %s | %d |\n",
			m.Class, m.Cases, m.Reported, m.Confirmed, m.FP, m.Inconclusive, rate(m.Precision), rate(m.Recall), m.Tokens)
	}
	fmt.Println()
	fmt.Println("评语分布：")
	for _, o := range []bench.Outcome{bench.OutcomeConfirmed, bench.OutcomeCorrectlyNeg, bench.OutcomeFalsePos, bench.OutcomeMissed, bench.OutcomeInconclusive} {
		fmt.Printf("- %s: %d\n", o, rep.Counts[o])
	}
	var bad []bench.CaseReview
	for _, c := range rep.Cases {
		if c.Outcome == bench.OutcomeFalsePos || c.Outcome == bench.OutcomeMissed {
			bad = append(bad, c)
		}
	}
	if len(bad) > 0 {
		fmt.Println("\n需要人工复核：")
		for _, c := range bad {
			fmt.Printf("- %s/%s [%s] %s\n", c.Class, c.ID, c.Outcome, c.Note)
		}
	}
}

func printCompare(c *bench.Comparison) {
	fmt.Printf("\n## 对照：%s -> %s\n\n", c.Baseline, c.Candidate)
	fmt.Printf("- Token 总量：%d -> %d（%s）\n", c.TokensBefore, c.TokensAfter, pct(c.TokenChangePct))
	fmt.Printf("- 确认漏洞：%d -> %d\n", c.ConfirmedBefore, c.ConfirmedAfter)
	fmt.Printf("- 每个已确认漏洞的 Token：%s -> %s（%s）\n", rate(c.CostBefore), rate(c.CostAfter), pct(c.CostChangePct))
	fmt.Printf("- precision：%s -> %s\n", rate(c.PrecisionBefore), rate(c.PrecisionAfter))
	fmt.Printf("- recall：%s -> %s\n", rate(c.RecallBefore), rate(c.RecallAfter))
	for _, s := range c.Improvements {
		fmt.Printf("- 变好 %s\n", s)
	}
	for _, s := range c.Regressions {
		fmt.Printf("- 回归 %s\n", s)
	}
}

func main() {
	baseline := flag.String("baseline", "", "基线结果 JSON（必填）")
	candidate := flag.String("candidate", "", "候选结果 JSON（可选；给了就做对照）")
	asJSON := flag.Bool("json", false, "以 JSON 输出报告")
	gate := flag.Bool("gate", false, "有回归或误报时以非零码退出（给 CI 用）")
	flag.Parse()

	if *baseline == "" {
		fmt.Fprintln(os.Stderr, "缺少 -baseline <results.json>；本工具只读已保存结果，不会去跑目标")
		os.Exit(2)
	}
	ba, err := load(*baseline)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	base, err := bench.BuildReport(ba)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(base)
	} else {
		printReport(base)
	}

	failed := false
	var cmp *bench.Comparison
	if *candidate != "" {
		ca, err := load(*candidate)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		cand, err := bench.BuildReport(ca)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		cmp, err = bench.Compare(base, cand)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if !*asJSON {
			printCompare(cmp)
		}
		if len(cmp.Regressions) > 0 {
			failed = true
		}
	}
	if *gate {
		if base.Counts[bench.OutcomeFalsePos] > 0 {
			fmt.Fprintf(os.Stderr, "门禁未通过：%s 有 %d 条误报\n", base.Name, base.Counts[bench.OutcomeFalsePos])
			failed = true
		}
		if cmp != nil && len(cmp.Regressions) > 0 {
			fmt.Fprintf(os.Stderr, "门禁未通过：%d 条回归\n", len(cmp.Regressions))
		}
	}
	if failed && *gate {
		os.Exit(1)
	}
}
