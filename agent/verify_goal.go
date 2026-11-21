package agent

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/jintilm/praetor/agent/domain"
	"github.com/jintilm/praetor/db"
)

// verifyGoalEvidence 用域声明的确定性验收器判断「这个证据能不能证明目标达成」。
//
// 返回 (verdict, enforced)：
//   - enforced=false：该域还没有可用证据源，调用方按旧行为放行（只记日志）；
//   - enforced=true 且 verdict.Done=false：调用方**必须拒绝**标记 met，并把 Reason 回给模型。
//
// 为什么必须有这条接线（2026-10-30 task 198）：ctf 任务的 done 变成了「planner 自称达成」——
// 4 个 goal 全部 met，但 ctf_submissions 0 行、findings 0 个、没有任何 flag。
// 根因是 domain.DomainPack.Verifier() 在生产代码里从来没被调用过（声明了、没接线），
// 而 ctfVerifier 的注释恰恰写着「模型自述解出一律不计分」。
// 这和 P0-2 是同一种失效：一个看起来已经实现的能力，实际上没有任何消费方。
//
// 为什么现在只接 ctf：四个域里只有 ctf 的证据源是**已经落库且唯一**的
// （ctf_submissions.verdict=accepted，离线判分也会写入）。其他域接错方向的代价是
// "所有任务都无法 prove_goal"，比误报更糟：
//   - pentest 需要 traffic 绑定 + PoC 重放，现有 finding 未必带这些字段；
//   - reverse 需要 xref/trace 证据，同样取决于模型写了什么；
//   - redteam 需要 cleanup 断言，属战役域。
//
// 这三域要接，得先把各自的数据源补齐，而不是在判定点上硬加一个"总是拒绝"。
func (t *ToolSet) verifyGoalEvidence(ctx context.Context, ev *db.Node) (domain.Verdict, bool) {
	// 空域按 pentest 处理：与 db.Task.Domain 的口径一致（老任务没有 domain 列）。
	// 不归一化的话 daemon 里 domain="" 的老任务会绕过整个闸门。
	key := domain.Key(strings.TrimSpace(t.domain))
	if key == "" {
		key = domain.Pentest
	}
	pack, ok := domain.Get(key)
	if !ok || pack.Verifier() == nil {
		return domain.Verdict{}, false
	}
	switch key {
	case domain.CTF:
		flag, accepted, err := t.ts.AcceptedFlagForTask(t.taskID)
		if err != nil {
			// 读不到判题记录 ≠ 没通过，但在"能不能宣布完成"这件事上必须 fail closed：
			// 让一个查不到证据的任务继续跑，远比让它误判完成便宜。
			return domain.Verdict{Reason: "读取 flag 判题记录失败: " + err.Error()}, true
		}
		if !accepted {
			return domain.Verdict{Reason: "本任务没有任何通过平台判题的 flag" +
				"（ctf_submit 未被调用，或提交全部被拒），不得标记目标达成"}, true
		}
		v, err := pack.Verifier().Verify(ctx, domain.Evidence{
			Kind:    "flag",
			Summary: "flag 已被平台判题接受",
			Meta:    map[string]any{"flag": flag, "accepted": true},
		})
		if err != nil {
			return domain.Verdict{Reason: "确定性验收执行失败: " + err.Error()}, true
		}
		return v, true
	case domain.Pentest:
		// 闸门形态：默认 strict。advisory 只可能来自显式配置，用于存量任务过渡。
		if strings.EqualFold(strings.TrimSpace(t.accept.Mode), "advisory") {
			if acc, aerr := t.lookupAcceptance(ctx); aerr == nil && (acc == nil || acc.Latest == nil) {
				log.Printf("[verify] 任务 %d：渗透域完成判定被放行（advisory），但没有任何 verified 漏洞", t.taskID)
			}
			return domain.Verdict{}, false
		}
		acc, aerr := t.lookupAcceptance(ctx, ev)
		if aerr != nil {
			// 与 ctf 同口径：读不到证据 ≠ 没达成，但在「能不能宣布完成」这件事上必须 fail closed。
			return domain.Verdict{Reason: "读取漏洞验证记录失败: " + aerr.Error()}, true
		}
		if acc == nil || acc.Latest == nil {
			total := 0
			if acc != nil {
				total = acc.Total
			}
			log.Printf("[verify] 任务 %d 的 prove_goal 被拒：%d 个漏洞里 0 个 verified", t.taskID, total)
			return domain.Verdict{Reason: fmt.Sprintf(
				"本任务有 %d 个漏洞，但没有一个通过确定性验证："+
					"先用 report_finding 上报并 bind_finding_traffic 绑定真实流量，再调用 verify_finding"+
					"（结论必须是 verified）。没有可重放证据的结论不能作为目标达成的依据。"+
					"若这是「确认不存在」的负结论任务，需由操作员把 agents.pentest_acceptance 设为 advisory 后收尾。", total)}, true
		}
		candidate := acc.Ready
		if candidate == nil {
			candidate = acc.Latest
		}
		if ev != nil && (ev.Kind != db.KindFinding || ev.Inherited || candidate.NodeID != ev.ID) {
			return domain.Verdict{Reason: "该证明节点尚未对应本任务的一条可验收发现，保留为待复核；请使用已验证发现的 finding_node_id"}, true
		}
		v, verr := pack.Verifier().Verify(ctx, domain.Evidence{
			Kind:       "poc",
			Summary:    fmt.Sprintf("finding #%d（%s）已通过确定性重放验证", candidate.ID, firstNonEmpty(candidate.Name, candidate.VulnClass)),
			SHA256:     candidate.ProofHash,
			Reproduced: true,
			Meta: map[string]any{
				"traffic_id": candidate.ProofTrafficID,
				"finding_id": candidate.ID,
			},
		})
		if verr != nil {
			return domain.Verdict{Reason: "确定性验收执行失败: " + verr.Error()}, true
		}
		if !v.Done {
			return v, true
		}
		// 可复现 != 有危害：审核打回的绝大多数不是「漏洞是假的」，而是「只证明了存在」。
		// 这一级必须在系统内拦住，否则报告发出去还是会被退回。
		if acc.Ready == nil || !candidate.ImpactCurrent || candidate.ImpactLevel < 2 || len(candidate.ImpactArtifacts) == 0 {
			log.Printf("[verify] 任务 %d 的 prove_goal 被拒：%d 个 verified 漏洞里 0 个达到 2 级危害", t.taskID, acc.Verified)
			return domain.Verdict{Reason: impactGapReason(acc)}, true
		}
		return v, true
	}
	return domain.Verdict{}, false
}

// lookupAcceptance 取本任务的漏洞验收事实：优先用注入的实现（单测），否则走 t.ts。
func (t *ToolSet) lookupAcceptance(ctx context.Context, evidenceNodes ...*db.Node) (*db.FindingAcceptance, error) {
	var nodeID int64
	if len(evidenceNodes) > 0 && evidenceNodes[0] != nil {
		ev := evidenceNodes[0]
		if ev.Kind != db.KindFinding || ev.Inherited {
			return nil, fmt.Errorf("该事实或继承证据尚未对应本任务当前版本的可验收发现，保留为待复核")
		}
		nodeID = ev.ID
	}
	if t.accept.Lookup != nil {
		return t.accept.Lookup(ctx, t.taskID)
	}
	if t.ts == nil {
		return nil, fmt.Errorf("缺少探索存储，无法读取漏洞验证记录")
	}
	return t.ts.TaskFindingAcceptance(ctx, t.taskID, nodeID)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// impactGapReason 把「离危害证明还差什么」说清楚。
//
// 只说「没有危害证明」模型会继续写形容词；这里直接给出它缺的字段（table/rows_read/marker/...），
// 它就能照着去补一次取证，而不是在报告里加形容词。
func impactGapReason(acc *db.FindingAcceptance) string {
	var b strings.Builder
	fmt.Fprintf(&b, "本任务已有 %d 个通过验证的漏洞，但没有一个达到「实质危害」（2 级）", acc.Verified)
	if acc.Best != nil && strings.TrimSpace(acc.Best.ImpactKind) != "" {
		level, gaps := DeriveImpactLevel(acc.Best.ImpactKind, acc.Best.ImpactMetrics, len(acc.Best.ImpactArtifacts))
		fmt.Fprintf(&b, "；当前最高 %d 级（%s）", level, ImpactLevelName(level))
		if !acc.Best.ImpactCurrent {
			b.WriteString("；该危害记录与当前证据版本不一致或引用已失效，保留为待复核。重新核对并 record_impact")
		}
		if len(gaps) > 0 {
			b.WriteString("，还差：" + strings.Join(gaps, "；"))
		}
	} else {
		b.WriteString("；还没有任何 record_impact 记录")
	}
	b.WriteString("。用 record_impact 把从目标提取到的数据/文件/回连/状态变更落库后再收尾（可复现只能算 1 级）。")
	return b.String()
}

func (t *ToolSet) strictPentestAcceptance() bool {
	key := strings.TrimSpace(t.domain)
	return (key == "" || key == string(domain.Pentest)) && !strings.EqualFold(strings.TrimSpace(t.accept.Mode), "advisory")
}
