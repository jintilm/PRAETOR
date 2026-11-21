package bench

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func mkCase(class, id string, kind CaseKind) Case {
	oracle, concl := OracleFail, Rejected
	if kind == Positive {
		oracle, concl = OraclePass, Confirmed
	}
	if kind == Boundary {
		oracle, concl = OracleInconclusive, Inconclusive
	}
	return Case{ID: id, Class: class, Kind: kind, Fixture: "vuln", URL: "http://fixture.test/x", Payload: "q=1", ExpectedOracle: oracle, ExpectedConclusion: concl}
}

func mkResult(c Case, tokens int64, findings ...Finding) Result {
	ran := true
	return Result{Case: c, StartedAt: t0, Findings: findings, InputTokens: tokens, OutputTokens: 0, Executed: &ran}
}

func TestReviewCaseOutcomes(t *testing.T) {
	pos := mkCase("sqli", "pos", Positive)
	neg := mkCase("sqli", "neg", Negative)
	trap := mkCase("sqli", "trap", Trap)
	conf := Finding{ID: "f", Oracle: OraclePass, Conclusion: Confirmed, ConfirmedAt: t0.Add(time.Second)}
	rej := Finding{ID: "f", Oracle: OracleFail, Conclusion: Rejected}

	cases := []struct {
		name string
		c    Case
		rep  bool
		o    OracleState
		cl   Conclusion
		want Outcome
	}{
		{"正例真确认", pos, true, OraclePass, Confirmed, OutcomeConfirmed},
		{"正例被拒是漏报", pos, true, OracleFail, Rejected, OutcomeMissed},
		{"正例未上报是漏报", pos, false, "", "", OutcomeInconclusive},
		{"负例正确拒绝", neg, true, OracleFail, Rejected, OutcomeCorrectlyNeg},
		{"陷阱被确认是误报", trap, true, OraclePass, Confirmed, OutcomeFalsePos},
		{"负例被确认是误报", neg, true, OraclePass, Confirmed, OutcomeFalsePos},
		{"判定不确定", trap, true, OracleInconclusive, Inconclusive, OutcomeInconclusive},
	}
	for _, tc := range cases {
		got := ReviewCase(tc.c, tc.rep, tc.o, tc.cl)
		if got.Outcome != tc.want {
			t.Errorf("%s: got %s want %s", tc.name, got.Outcome, tc.want)
		}
	}
	// 未上报正例在 BuildReport 里必须升级成「漏报」，不能混进「证据不足」。
	rep, err := BuildReport(Answer{Name: "r", Results: []Result{mkResult(pos, 10)}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Cases[0].Outcome != OutcomeMissed || rep.Counts[OutcomeMissed] != 1 || rep.Counts[OutcomeInconclusive] != 0 {
		t.Fatalf("unreported positive: %+v %+v", rep.Cases[0], rep.Counts)
	}
	// 没标 executed 的空结果不许记成正确拒绝，也不许算漏报，只能报证据不足。
	unknown := Result{Case: neg, StartedAt: t0}
	rep2, err := BuildReport(Answer{Name: "r2", Results: []Result{unknown}})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Cases[0].Outcome != OutcomeInconclusive || rep2.Counts[OutcomeCorrectlyNeg] != 0 {
		t.Fatalf("unmarked empty result must stay inconclusive: %+v", rep2.Cases[0])
	}
	_ = conf
	_ = rej
}

func TestBuildReportCounts(t *testing.T) {
	pos, neg, trap, bnd := mkCase("sqli", "pos", Positive), mkCase("authz", "neg", Negative), mkCase("authz", "trap", Trap), mkCase("xss", "bnd", Boundary)
	conf := Finding{ID: "f", Oracle: OraclePass, Conclusion: Confirmed, ConfirmedAt: t0.Add(time.Minute)}
	rep, err := BuildReport(Answer{Name: "run1", Results: []Result{
		mkResult(pos, 100, conf),
		mkResult(neg, 100),
		mkResult(trap, 100, conf),
		mkResult(bnd, 100, Finding{ID: "f", Oracle: OracleInconclusive, Conclusion: Inconclusive}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts[OutcomeConfirmed] != 1 || rep.Counts[OutcomeFalsePos] != 1 || rep.Counts[OutcomeCorrectlyNeg] != 1 || rep.Counts[OutcomeInconclusive] != 1 {
		t.Fatalf("counts: %+v", rep.Counts)
	}
	if rep.Cases[0].Class > rep.Cases[len(rep.Cases)-1].Class {
		t.Fatal("cases not sorted by class")
	}
	if rep.Metrics[len(rep.Metrics)-1].Tokens != 400 {
		t.Fatalf("tokens: %+v", rep.Metrics[len(rep.Metrics)-1])
	}
}

func TestCompareDetectsRegressionAndTokenCost(t *testing.T) {
	pos := mkCase("sqli", "pos", Positive)
	conf := Finding{ID: "f", Oracle: OraclePass, Conclusion: Confirmed, ConfirmedAt: t0.Add(time.Minute)}
	before, err := BuildReport(Answer{Name: "before", Results: []Result{mkResult(pos, 100, conf)}})
	if err != nil {
		t.Fatal(err)
	}
	after, err := BuildReport(Answer{Name: "after", Results: []Result{mkResult(pos, 150)}})
	if err != nil {
		t.Fatal(err)
	}
	cmp, err := Compare(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmp.Regressions) != 1 || !strings.Contains(cmp.Regressions[0], "sqli/pos") {
		t.Fatalf("regressions: %+v", cmp.Regressions)
	}
	if cmp.TokenChangePct == nil || *cmp.TokenChangePct != 50 {
		t.Fatalf("token change: %+v", cmp.TokenChangePct)
	}
	if cmp.CostAfter != nil {
		t.Fatalf("no confirmed finding means undefined cost, got %v", *cmp.CostAfter)
	}
	// 反向：同样的结果 token 变多但确认数不变 → 成本变差，不能算进步。
	after2, err := BuildReport(Answer{Name: "after2", Results: []Result{mkResult(pos, 300, conf)}})
	if err != nil {
		t.Fatal(err)
	}
	cmp2, err := Compare(before, after2)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmp2.Regressions) != 0 || len(cmp2.Improvements) != 0 {
		t.Fatalf("quality unchanged should not regress: %+v", cmp2)
	}
	if cmp2.CostChangePct == nil || *cmp2.CostChangePct != 200 {
		t.Fatalf("cost change: %+v", cmp2.CostChangePct)
	}
}

func TestCompareRequiresTotals(t *testing.T) {
	pos := mkCase("sqli", "pos", Positive)
	rep, err := BuildReport(Answer{Name: "r", Results: []Result{mkResult(pos, 10)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compare(rep, &Report{Name: "empty"}); err == nil {
		t.Fatal("accepted report without TOTAL")
	}
	if _, err := BuildReport(Answer{}); err == nil {
		t.Fatal("accepted empty results")
	}
}
