package server

import (
	"fmt"
	"log"
	"strings"

	"github.com/jintilm/praetor/agent"
	"github.com/jintilm/praetor/agent/domain"
	"github.com/jintilm/praetor/config"
)

// 本文件是「领域包 → 引擎调度拓扑」的唯一接缝（P0-5）。
//
// 目的：让 Engine.Run 不再硬编码「1 个 planner + N 个 worker」，而是先问领域包
// 「你要哪种调度器」，再由这里翻译成并发拓扑。
//
// 当前只有 explore 实现（复用既有 plannerLoop + workerLoop，行为与改造前完全一致）；
// campaign / race / evidence 明确返回错误而不是悄悄退回 explore —— 半成品静默跑歪
// 比直接失败难查一百倍。对应实现分别在 P4 / P2 / P3。

// SchedulerPlan 是一次任务的调度拓扑。
type SchedulerPlan struct {
	Kind     domain.SchedulerKind
	Planners int // planner 循环数（explore 固定 1）
	Workers  int // worker 循环数
}

// errSchedulerNotImplemented 是「域已注册但调度器还没写」的统一错误。
type errSchedulerNotImplemented struct {
	pk   domain.Key
	kind domain.SchedulerKind
}

func (e errSchedulerNotImplemented) Error() string {
	// 文案里不再引用阶段编号（P2/P3/P4）：逆向域已移出执行计划，evidence 调度器暂无排期，
	// 阶段号会随排期变化、写死必然过期。这里只讲「哪个调度器缺」和「不会启动」。
	return fmt.Sprintf("领域 %q 的调度器 %q 尚未实现"+
		"（race=CTF 竞速 / evidence=逆向证据链 / campaign=红队战役；逆向域已暂缓，evidence 暂无排期）；"+
		"为避免行为错误，本任务不会启动", e.pk, e.kind)
}

// DomainPackFor 返回任务所属的领域包。
//
// 任务带 domain 列（2026-10-27 起，默认 pentest）：调度器/预算按任务领域选，
// 未注册值回落 pentest 并记日志。
// 既有的探索流程。P1 增加 domain 列后，这里改为读任务字段并回落到 Pentest。
// DomainPackFor 返回任务所属的领域包。
//
// 任务自 2026-10-27 起带 `domain` 列（默认 pentest）：调度器与预算都按它选。
// 空值/未注册值一律回落 pentest 并记一条日志——配置写错不该让任务起不来，
// 但也绝不能静默换成别的领域（那会悄悄改变执行语义）。
func DomainPackFor(t *Task) domain.DomainPack {
	key := ""
	if t != nil {
		key = strings.TrimSpace(t.Domain)
	}
	if key != "" && domain.Key(key) != domain.Pentest {
		if p, ok := domain.Get(domain.Key(key)); ok {
			return p
		}
		log.Printf("[domain] 任务 %s 的领域 %q 未注册，回落 pentest", t.ID, key)
	}
	if p, ok := domain.Get(domain.Pentest); ok {
		return p
	}
	return nil
}

// SchedulerPlanFor 把领域包的 Scheduler() 翻译成并发拓扑。
//
// workers 是管理器配置的 worker 数（管理端可调），只有 explore 会用它；
// 其它调度器按自己的语义决定并发，不吃这个值。
func SchedulerPlanFor(p domain.DomainPack, workers int) (SchedulerPlan, error) {
	if p == nil {
		return SchedulerPlan{}, fmt.Errorf("任务没有可用的领域包（domain registry 未注册渗透域？）")
	}
	if workers <= 0 {
		workers = 1 // 与既有 workerLoop 的下限保持一致，避免 0 并发任务假死
	}
	switch p.Scheduler() {
	case domain.ScheduleExplore:
		return SchedulerPlan{Kind: domain.ScheduleExplore, Planners: 1, Workers: workers}, nil
	case domain.ScheduleEvidence:
		// 证据链要求**串行**：一条结论验证完再下一条，并行会重复付"理解样本"的成本
		// 且让证据顺序变得不可解释。所以这里**刻意忽略传入的 workers**。
		return SchedulerPlan{Kind: domain.ScheduleEvidence, Planners: 1, Workers: 1}, nil
	default:
		return SchedulerPlan{}, errSchedulerNotImplemented{pk: p.Key(), kind: p.Scheduler()}
	}
}

// enabledDomainKeys 解析启用中的领域：环境变量 PRAETOR_DOMAINS（逗号分隔），
// 默认只有 pentest。未注册的 key 会被忽略并记一条日志——配置写错不该让进程起不来。
func enabledDomainKeys() []domain.Key {
	raw := strings.TrimSpace(config.Env("DOMAINS"))
	if raw == "" {
		return []domain.Key{domain.Pentest}
	}
	var out []domain.Key
	seen := map[domain.Key]bool{}
	for _, part := range strings.Split(raw, ",") {
		k := domain.Key(strings.TrimSpace(part))
		if k == "" || seen[k] {
			continue
		}
		if _, ok := domain.Get(k); !ok {
			log.Printf("[domain] PRAETOR_DOMAINS 中的 %q 未注册，已忽略", k)
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	if len(out) == 0 {
		return []domain.Key{domain.Pentest}
	}
	return out
}

// WarnUnresolvedDomainTools 对启用中的域打一条「声明了但还没接入」的工具告警。
//
// 领域包里不少 key（ghidra_decompile / sliver_session / pwntools_run …）要等对应
// MCP 接进来才存在。静默缺失会让 agent 手里没工具却照常开跑，是最难查的一类问题，
// 所以在启动日志里显式列出来。未启用的域不打，避免刷屏。
func WarnUnresolvedDomainTools() {
	for _, k := range enabledDomainKeys() {
		p, ok := domain.Get(k)
		if !ok {
			continue
		}
		miss := agent.UnresolvedDomainTools(p)
		if len(miss) == 0 {
			continue
		}
		log.Printf("[domain] %s 域有 %d 个工具声明尚未接入（对应 MCP 未连）：%s",
			p.Key(), len(miss), strings.Join(miss, ", "))
	}
}

// domainKeys 返回已注册的领域 key（排序由 domain.All 保证），用于错误提示与 UI 选项。
func domainKeys() []string {
	packs := domain.All()
	out := make([]string, 0, len(packs))
	for _, p := range packs {
		out = append(out, string(p.Key()))
	}
	return out
}
