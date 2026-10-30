package agent

import (
	"context"

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
	pack, ok := domain.Get(domain.Key(t.domain))
	if !ok || pack.Verifier() == nil {
		return domain.Verdict{}, false
	}
	switch domain.Key(t.domain) {
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
	}
	return domain.Verdict{}, false
}
