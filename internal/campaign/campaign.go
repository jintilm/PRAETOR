// Package campaign 是红队战役的阶段 DAG：**前置未满足不下发，收尾必须清理**。
//
// 为什么这件事要单独一个纯包：这是红队域与渗透域唯一的结构性差别。渗透是"想到哪打到哪"，
// 红队是一条有顺序的攻击链（侦察 → 初始访问 → 执行 → 持久化 → 提权 → 横向 → 收集 → 外传），
// 每一步都依赖前一步的事实；而且**每一步都可能留下痕迹**，所以"清理"不是一个可选动作，
// 是战役的一部分。
//
// 这里只做判定，不碰 DB、不碰调度：判定是纯函数，才能被穷举测试；
// 调度侧（server/campaign_gate.go）只负责把判定接到意图下发口上。
//
// 设计参考（**只读思路，不复制代码**）：m-sec-org/BreachWeave 的 Manager/Observer/Solver
// 职责切分（Manager 管节奏与回收、Solver 执行、Observer 纠偏）。本项目只取"谁决定下一阶段"
// 这一层，落到阶段 DAG；三角色的并发形态不引入 —— 本项目已有 planner/worker 拓扑，
// 再加一层角色会重复付常驻提示词的钱。
package campaign

import (
	"fmt"
	"strings"
)

// Phase 是 ATT&CK 战术阶段（本项目只取红队战役里可判定完成的那几步）。
type Phase string

const (
	Recon               Phase = "recon"
	InitialAccess       Phase = "initial-access"
	Execution           Phase = "execution"
	Persistence         Phase = "persistence"
	PrivilegeEscalation Phase = "privilege-escalation"
	LateralMovement     Phase = "lateral-movement"
	Collection          Phase = "collection"
	Exfiltration        Phase = "exfiltration"
	Cleanup             Phase = "cleanup"
)

// Nodes 是一条战役的阶段节点。
type Node struct {
	Phase    Phase
	Requires []Phase // 前置阶段：全部完成后本阶段才可下发
	// Dirty 表示该阶段会在目标上留下痕迹（持久化/账号/文件/服务），
	// 决定"收尾清理"的必做范围 —— 只打了侦察的战役不需要清理。
	Dirty bool
}

// Plan 是一条战役的阶段 DAG。
type Plan struct {
	Nodes []Node
}

// Default 返回标准战役 DAG。
//
// 顺序按 ATT&CK 战术推进，但刻意保留两条并行入口：
//   - execution 不强制依赖 initial-access（钓鱼/社工落地也算执行），
//     这样"只做钓鱼演练"的战役不会被卡死；
//   - collection 与 lateral-movement 互不依赖（先横向再收集、或先收集再横向都成立）。
//
// 依赖关系的判定标准只有一条：**前一步是否产出了后一步必须用的事实**。
// 不为好看而连线。
func Default() Plan {
	return Plan{Nodes: []Node{
		{Phase: Recon},
		{Phase: InitialAccess, Requires: []Phase{Recon}},
		{Phase: Execution, Requires: []Phase{Recon}},
		{Phase: Persistence, Requires: []Phase{Execution}, Dirty: true},
		{Phase: PrivilegeEscalation, Requires: []Phase{InitialAccess}},
		{Phase: LateralMovement, Requires: []Phase{PrivilegeEscalation}},
		{Phase: Collection, Requires: []Phase{LateralMovement}},
		{Phase: Exfiltration, Requires: []Phase{Collection}, Dirty: true},
		// 清理依赖所有脏阶段：漏一个就等于把后门留在目标上。
		{Phase: Cleanup, Requires: []Phase{Persistence, Exfiltration}},
	}}
}

// Validate 检查 DAG 的基本性质；配置写错时要在启动期就炸，而不是等战役跑到一半。
func (p Plan) Validate() error {
	if len(p.Nodes) == 0 {
		return fmt.Errorf("战役计划为空")
	}
	seen := map[Phase]bool{}
	for _, n := range p.Nodes {
		if n.Phase == "" {
			return fmt.Errorf("阶段名为空")
		}
		if seen[n.Phase] {
			return fmt.Errorf("阶段 %q 重复", n.Phase)
		}
		seen[n.Phase] = true
	}
	for _, n := range p.Nodes {
		for _, r := range n.Requires {
			if !seen[r] {
				return fmt.Errorf("阶段 %q 依赖了不存在的阶段 %q", n.Phase, r)
			}
			if r == n.Phase {
				return fmt.Errorf("阶段 %q 依赖自己", n.Phase)
			}
		}
	}
	// 环检测：反复剥离"前置已齐"的节点，剥不完就是有环。
	done := map[Phase]bool{}
	for progress := true; progress; {
		progress = false
		for _, n := range p.Nodes {
			if done[n.Phase] || !p.requiresMet(n, done) {
				continue
			}
			done[n.Phase] = true
			progress = true
		}
	}
	for _, n := range p.Nodes {
		if !done[n.Phase] {
			return fmt.Errorf("阶段 %q 在环上（或依赖了环上的阶段）", n.Phase)
		}
	}
	if !seen[Cleanup] {
		return fmt.Errorf("战役计划必须包含 %q 阶段：红队行为会留痕，清理不能是可选动作", Cleanup)
	}
	return nil
}

func (p Plan) requiresMet(n Node, done map[Phase]bool) bool {
	for _, r := range n.Requires {
		if !done[r] {
			return false
		}
	}
	return true
}

// Ready 返回当前可下发的阶段（前置全满足且本身未完成）。
func (p Plan) Ready(done map[Phase]bool) []Phase {
	var out []Phase
	for _, n := range p.Nodes {
		if done[n.Phase] || !p.requiresMet(n, done) {
			continue
		}
		out = append(out, n.Phase)
	}
	return out
}

// Blocked 回答"这个阶段为什么还不能下发"；返回空串表示可以。
//
// 报错要列出**缺了哪些前置**，否则模型会反复重试同一阶段（它不知道自己在等什么）。
func (p Plan) Blocked(done map[Phase]bool, phase Phase) string {
	var node *Node
	for i := range p.Nodes {
		if p.Nodes[i].Phase == phase {
			node = &p.Nodes[i]
			break
		}
	}
	if node == nil {
		return fmt.Sprintf("不是本战役的阶段：%q；可用：%s", phase, strings.Join(p.Phases(), "/"))
	}
	if done[phase] {
		return fmt.Sprintf("阶段 %q 已完成", phase)
	}
	var miss []string
	for _, r := range node.Requires {
		if !done[r] {
			miss = append(miss, string(r))
		}
	}
	if len(miss) > 0 {
		return fmt.Sprintf("阶段 %q 的前置未完成：缺 %s。先推进前置，不要跳到后续阶段"+
			"（跳步会让后面的结论失去事实支撑，也无法判断清理范围）",
			phase, strings.Join(miss, "、"))
	}
	return ""
}

// Phases 按 DAG 顺序列出全部阶段名（给报错与提示词共用）。
func (p Plan) Phases() []string {
	out := make([]string, 0, len(p.Nodes))
	for _, n := range p.Nodes {
		out = append(out, string(n.Phase))
	}
	return out
}

// DirtyPhases 返回会留痕的阶段（按 DAG 顺序）。
func (p Plan) DirtyPhases() []string {
	var out []string
	for _, n := range p.Nodes {
		if n.Dirty {
			out = append(out, string(n.Phase))
		}
	}
	return out
}

// PendingCleanup 在战役收尾时判定"能不能结束"：
// 只要有一个留痕阶段完成过、而清理没完成，就不能结束。
//
// 为什么用"完成过"而不是"当前有痕迹"：痕迹是否还在要现场核验，而**能不能结束**
// 是调度层的判断，必须先按最坏情况拦住 —— 让战役在没有清理的情况下收尾，
// 等于把后门留在目标上还写了个"任务完成"。
func (p Plan) PendingCleanup(done map[Phase]bool, cleanupDone bool) (bool, []string) {
	if cleanupDone {
		return false, nil
	}
	var need []string
	for _, n := range p.Nodes {
		if n.Dirty && done[n.Phase] {
			need = append(need, string(n.Phase))
		}
	}
	return len(need) > 0, need
}
