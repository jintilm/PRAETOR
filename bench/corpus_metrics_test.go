package bench

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCorpusFixtures(t *testing.T) {
	cases, err := LoadCorpus("corpus")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 10 {
		t.Fatalf("got %d fixtures", len(cases))
	}
	kindCount := map[CaseKind]int{}
	for _, c := range cases {
		kindCount[c.Kind]++
		if !Judge(c, true, c.ExpectedOracle, c.ExpectedConclusion).Match && c.ExpectedOracle != OracleInconclusive {
			t.Fatalf("mismatch %+v", c)
		}
	}
	if kindCount[Positive] != 3 || kindCount[Negative] != 3 || kindCount[Trap] != 3 || kindCount[Boundary] != 1 {
		t.Fatalf("kinds: %+v", kindCount)
	}
}
func TestCorpusStrictParsing(t *testing.T) {
	valid := `id: sample
class: sqli
kind: positive
fixture: v1
url: http://fixture.test/path
payload: q=1
expected_oracle: pass
expected_conclusion: confirmed
`
	if _, err := ParseCase(strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []string{valid + `typo: 1
`, valid + `id: duplicate
`, valid + `---
foo: bar
`, strings.Replace(valid, "kind: positive", "kind: trap", 1), strings.Replace(valid, "expected_oracle: pass", "expected_oracle: fail", 1)} {
		if _, err := ParseCase(strings.NewReader(tc)); err == nil {
			t.Fatalf("accepted invalid corpus: %s", tc)
		}
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sqli"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sqli", "wrong.yaml"), []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCorpus(root); err == nil {
		t.Fatal("accepted filename/id mismatch")
	}
}
func TestJudgeTrap(t *testing.T) {
	c := Case{ID: "trap", Class: "sqli", Kind: Trap, Fixture: "trap", URL: "http://fixture.test/", Payload: "q=x", ExpectedOracle: OracleFail, ExpectedConclusion: Rejected}
	if j := Judge(c, true, OraclePass, Confirmed); j.Match || j.Confirmed || !j.FalsePositive {
		t.Fatalf("trap pass counted as true positive: %+v", j)
	}
	if j := Judge(c, true, OracleInconclusive, Inconclusive); !j.Inconclusive || j.FalsePositive {
		t.Fatalf("inconclusive: %+v", j)
	}
}
func TestComputeMetrics(t *testing.T) {
	cases, err := LoadCorpus("corpus")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	var rows []Result
	for _, c := range cases {
		r := Result{Case: c, StartedAt: start, InputTokens: 100, OutputTokens: 50}
		switch c.Kind {
		case Positive:
			r.Findings = []Finding{{ID: "f1", Oracle: OraclePass, Conclusion: Confirmed, ConfirmedAt: start.Add(2 * time.Minute)}}
		case Trap:
			// 陷阱被误报成 confirmed 才是误报；正确拒绝不算 FP（见 Judge 注释）。
			r.Findings = []Finding{{ID: "f1", Oracle: OraclePass, Conclusion: Confirmed}}
		case Boundary:
			r.Findings = []Finding{{ID: "f1", Oracle: OracleInconclusive, Conclusion: Inconclusive}}
		}
		rows = append(rows, r)
	}
	stats, err := ComputeMetrics(rows)
	if err != nil {
		t.Fatal(err)
	}
	total := stats[len(stats)-1]
	if len(stats) != 4 || total.Class != "TOTAL" || total.Cases != 10 || total.Reported != 7 || total.Confirmed != 3 || total.FP != 3 || total.Inconclusive != 1 || total.RecalledCases != 3 || total.Precision == nil || *total.Precision != 0.5 || total.Recall == nil || *total.Recall != 1 || total.Tokens != 1500 || total.TimeToConfirmMS == nil || *total.TimeToConfirmMS != 120000 || total.CostPerConfirmed == nil || *total.CostPerConfirmed != 500 {
		t.Fatalf("metrics %+v", total)
	}
	// 未上报正例应降低 recall，但不得影响 precision 的分母。
	rows[0].Findings = nil
	stats, err = ComputeMetrics(rows)
	if err != nil {
		t.Fatal(err)
	}
	total = stats[len(stats)-1]
	if total.Recall == nil || *total.Recall != 2.0/3 || total.Precision == nil || *total.Precision != 0.4 {
		t.Fatalf("missed positive: %+v", total)
	}
	rows[0].Findings = []Finding{{ID: "f1", Oracle: OraclePass, Conclusion: Confirmed, ConfirmedAt: start.Add(-time.Second)}}
	if _, err := ComputeMetrics(rows); err == nil {
		t.Fatal("accepted confirmation before task start")
	}
}
func TestComputeMetricsUndefinedRatesAndDuplicate(t *testing.T) {
	c := Case{ID: "fixed", Class: "authz", Kind: Negative, Fixture: "fixed", URL: "http://fixture.test/", Payload: "GET /", ExpectedOracle: OracleFail, ExpectedConclusion: Rejected}
	r := Result{Case: c, StartedAt: time.Now()}
	m, err := ComputeMetrics([]Result{r})
	if err != nil {
		t.Fatal(err)
	}
	if m[0].Precision != nil || m[0].Recall != nil || m[0].TimeToConfirmMS != nil {
		t.Fatalf("zero denominators must be undefined: %+v", m[0])
	}
	if _, err := ComputeMetrics([]Result{r, r}); err == nil {
		t.Fatal("duplicate cases accepted")
	}
}
