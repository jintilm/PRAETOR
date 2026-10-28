// Package domain 定义「领域包（Domain Pack）」抽象。
//
// 背景：PRAETOR 目前是单域（渗透）系统，角色 mainagent/planner/worker 写死在
// agent/ 里。要扩到渗透 / 红队 / CTF / 逆向四域，四者的执行模型差异极大：
//
//	渗透  深度优先，单链推进（frontier 领取意图）
//	红队  阶段 DAG，有前置依赖与 cleanup 义务（campaign）
//	CTF   广度并发，多解竞速抢旗（race）
//	逆向  长时程串行 + 分支递归，产出必须是可复核证据链（evidence）
//
// 所以差异必须收敛到接口里，engine 只认 DomainPack，新增第五个板块 = 新增一个
// 实现，不改调度核心。
//
// 设计约束（P0 阶段刻意保持的克制）：
//   - 本包【零业务依赖】：不 import agent / db / norma。工具、角色、技能一律用
//     字符串 key 声明，由 engine 在装配期解析成真实 tool.CoreTool / subagent.Definition。
//     这样 agent → domain 单向依赖成立，永不产生 import cycle。
//   - 本包【不改变现有行为】：当前尚未被 engine 引用，仅作为 P0 骨架与自检目标。
package domain

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Key 是领域标识，与 DB / 前端 / API 里出现的字符串保持一致。
type Key string

const (
	Pentest Key = "pentest" // 渗透测试
	RedTeam Key = "redteam" // 红队 / 对手模拟
	CTF     Key = "ctf"     // CTF 竞赛
	Reverse Key = "reverse" // 逆向工程
)

// SchedulerKind 决定「意图怎么派、并发多少、何时收敛」——四域差异最大的地方。
type SchedulerKind string

const (
	// ScheduleExplore 复用 PRAETOR 现有 plannerLoop + frontier：图变唤醒 planner，
	// planner 派意图，worker 领取执行写回。适用于渗透。
	ScheduleExplore SchedulerKind = "explore"
	// ScheduleCampaign 按阶段 DAG 派发，前置未满足不下发；收尾必须执行 cleanup。
	ScheduleCampaign SchedulerKind = "campaign"
	// ScheduleRace 同一目标并行多解法/多模型，首个命中即收敛，失败题回退换模型。
	ScheduleRace SchedulerKind = "race"
	// ScheduleEvidence 串行推进 + 可中断续跑，产出必须挂证据。
	ScheduleEvidence SchedulerKind = "evidence"
)

// ModelTier 决定该域走哪类模型（混合部署：敏感域本地，其余走 API）。
type ModelTier string

const (
	TierCloud ModelTier = "cloud" // 云 API（Claude / GPT / GLM …）
	TierLocal ModelTier = "local" // 本地开源模型（数据不出域）
)

// ModelPolicy 是「按域路由模型」的声明。敏感域（逆向样本、客户资产）强制本地。
type ModelPolicy struct {
	Tier        ModelTier // 默认档位
	Reason      string    // 为什么这么选，会进 prompt 与审计日志
	LocalOnly   bool      // true = 该域任何情况下都不允许走云 API（硬约束）
	PreferLarge bool      // 需要强推理（如逆向伪代码理解、多步利用链）
}

// Budget 是单次 DomainTask 的硬上限，超限即 wrapup，不做静默放宽。
type Budget struct {
	MaxTokens    int           // 该任务累计 token 上限（0 = 继承全局）
	MaxWall      time.Duration // 墙钟上限
	MaxToolCalls int           // 工具调用次数上限（防死循环探测）
	MaxDepth     int           // 子 agent 递归深度（透传 norma/subagent.MaxDepth）
	MaxParallel  int           // 该域并发 specialist 上限
}

// RoleKind 区分层级：Lead 只规划/派发，Specialist 才动手。
type RoleKind string

const (
	RoleLead       RoleKind = "lead"
	RoleSpecialist RoleKind = "specialist"
)

// ApprovalMode 声明角色的审批档位（域内抽象，避免 pack 直接依赖 norma 类型）。
// 具体含义映射到 norma/permission.Mode：default / auto / plan。
type ApprovalMode string

const (
	// ApprovalDefault 非只读工具默认需要确认（与 norma ModeDefault 一致）。
	ApprovalDefault ApprovalMode = ""
	// ApprovalAuto 不打断执行，放行工具自身的 allow 判定。仅用于隔离环境
	// （CTF 容器），绝不能用在真实目标上。
	ApprovalAuto ApprovalMode = "auto"
	// ApprovalPlan 只读，用于纯规划/侦察阶段的角色。
	ApprovalPlan ApprovalMode = "plan"
)

// RoleSpec 声明一个角色。engine 装配时把它翻译成 subagent.Definition +
// 工具白名单 + 预算，不需要为每个角色写一份 Go 代码。
type RoleSpec struct {
	Key string // 角色唯一 key，同时是 Agent 工具的 agent_type；
	// 也是 agents 表的行 key（须满足 ^[a-z][a-z0-9_]*$，用下划线不用连字符）
	Kind          RoleKind     // lead / specialist
	Name          string       // 展示名（Agent 管理页）；空 = 不播种进 agents 表
	Description   string       // 给父 agent 看的一句话（进 Agent 工具提示词）
	PromptSection string       // 追加到系统提示词的片段
	ToolKeys      []string     // 允许的工具 key（空 = 继承该域 Tools()）
	Skills        []string     // 允许加载的 SKILL.md 目录
	MaxTurns      int          // 单次运行最大轮次
	Approval      ApprovalMode // 审批档位；空 = ApprovalDefault
	Budget        Budget       // 该角色预算；零值 = 继承域预算
}

// PolicyAction 对齐 norma/permission 的三态语义。
type PolicyAction string

const (
	ActionAllow PolicyAction = "allow"
	ActionAsk   PolicyAction = "ask"
	ActionDeny  PolicyAction = "deny"
)

// PolicyRule 把「动作危险度 → 审批」显式化。deny 优先于 allow，与 norma 一致。
// Match 用工具 key 或动作名（如 shell.exec / c2.deploy / sample.upload）。
type PolicyRule struct {
	Match  string
	Action PolicyAction
	Reason string
}

// PolicySpec 是域级安全边界，四域都必须显式声明，不允许留空继承。
type PolicySpec struct {
	ScopeRequired   bool // true = 目标必须命中 scope 表，否则工具层 fail-closed
	Rules           []PolicyRule
	MaxReqPerTarget int      // 单目标请求上限（0 = 不限）
	CleanupRequired bool     // true = 任务收尾必须执行并记录 cleanup（红队）
	AllowEgress     []string // 网络出口白名单；空 = 仅走记录代理
}

// ArtifactKind 描述该域会产出哪类物证，决定存储与脱敏策略。
type ArtifactKind struct {
	Key         string
	Description string
	Sensitive   bool // true = 可能含客户数据/凭据，需加密与访问审计
	LocalOnly   bool // true = 禁止外传（含禁止整包塞进 LLM 请求）
	MaxBytes    int64
}

// GraphSpec 声明该域在双图上新增的节点/边类型。
// 渗透沿用现有 goal/intent/fact/finding/hint；其余域按需扩展。
type GraphSpec struct {
	NodeKinds []string // 如 binary / function / sample / evidence / flag
	EdgeKinds []string // 如 calls / references / proves / patches
}

// Evidence 是产出物摘要，交给 Verifier 做确定性校验。
type Evidence struct {
	Kind       string         // 对应 ArtifactKind.Key
	Summary    string         // 人可读结论
	Ref        string         // 存储引用（对象 key / 路径 / URL）
	SHA256     string         // 内容哈希（可复核的前提）
	Meta       map[string]any // 结构化附加信息（CVE、函数地址、flag 等）
	Reproduced bool           // 是否被独立重放验证过
}

// Verdict 是校验结论。done=false 时 Reason 会作为 hint 回灌给 Lead。
type Verdict struct {
	Done   bool
	Reason string
}

// Verifier 是【非 LLM】的确定性验收器——这是压误报的唯一可靠手段。
//
// 四域口径不同：
//
//	渗透  PoC 可复现（重放请求、比对响应差异）
//	红队  目标达成（域控/数据到手）且 cleanup 完整
//	CTF   flag 正确且未被其他 solver 先交
//	逆向  结论有证据支撑（交叉引用/动态 trace 对齐），不是"看起来像"
type Verifier interface {
	// Verify 判定单条产出是否成立。
	Verify(ctx context.Context, ev Evidence) (Verdict, error)
	// Name 进日志与报告，便于区分误报来源。
	Name() string
}

// DomainPack 是一个板块的全部「可变部分」。
type DomainPack interface {
	Key() Key
	// Title 是给人看的中文名（前端选择器 / 报告标题）。
	Title() string

	// Prompt 返回该域的系统提示词片段与角色总述。
	Prompt() []string
	// Roles 返回该域的角色定义；必须恰好包含 1 个 RoleLead。
	Roles() []RoleSpec
	// Tools 返回该域自有的工具 key（engine 从既有 toolcatalog 解析）。
	Tools() []string
	// MCP 返回该域的 MCP server 声明（如 hexstrike / ctfd）。
	//
	// 注意：**没有任何消费点**（`grep '\.MCP()'` 为空），当前纯声明。
	// 而且逆向域刻意返回空 —— MCP 的工具面会全量进上下文，几百个工具等于把固定成本翻倍（见 reverse.go 头注）。
	MCP() []MCPRef
	// Skills 返回默认加载的 SKILL.md 目录名。
	//
	// 同样**没有消费点**：技能不会因为这里写了名字而被加载，写了不存在的名字也不会报错。
	Skills() []string

	Policy() PolicySpec
	Graph() GraphSpec
	Artifacts() []ArtifactKind
	Model() ModelPolicy
	Budget() Budget

	Scheduler() SchedulerKind
	Verifier() Verifier
}

// MCPRef 声明一个 MCP server 的接入方式。engine 装配期据此建 mcp client，
// 工具名会加 mcp__<Name>__ 前缀（与 norma/mcp 约定一致）。
type MCPRef struct {
	Name      string            // 命名空间，如 ghidra / rea / hexstrike
	Transport string            // "stdio" | "http"
	Command   string            // stdio 时的可执行
	Args      []string          // stdio 参数
	URL       string            // http 时的地址
	Env       map[string]string // 环境变量
	Allowed   []string          // 工具白名单；空 = 全部
	LocalOnly bool              // true = 该 MCP 只能连本地实例
}

// registry 是全局注册表。四域在各自 init 里注册，engine 只按 key 取。
var registry = map[Key]DomainPack{}

// Register 注册一个领域包。重复注册 panic——这是装配期错误，早崩早修。
func Register(p DomainPack) {
	if p == nil {
		panic("domain: Register(nil)")
	}
	k := p.Key()
	if k == "" {
		panic("domain: pack has empty Key()")
	}
	if _, dup := registry[k]; dup {
		panic(fmt.Sprintf("domain: duplicate registration for %q", k))
	}
	if err := validate(p); err != nil {
		panic(fmt.Sprintf("domain: invalid pack %q: %v", k, err))
	}
	registry[k] = p
}

// Get 按 key 取领域包。
func Get(k Key) (DomainPack, bool) {
	p, ok := registry[k]
	return p, ok
}

// All 返回全部已注册领域包，按 Key 排序保证输出稳定。
func All() []DomainPack {
	keys := make([]string, 0, len(registry))
	for k := range registry {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	out := make([]DomainPack, 0, len(keys))
	for _, k := range keys {
		out = append(out, registry[Key(k)])
	}
	return out
}

// validate 是装配期自检。宁可启动即失败，也不要在跑到一半时发现没有 Lead。
func validate(p DomainPack) error {
	var leads int
	seen := map[string]bool{}
	for _, r := range p.Roles() {
		if r.Key == "" {
			return fmt.Errorf("role with empty Key")
		}
		if seen[r.Key] {
			return fmt.Errorf("duplicate role %q", r.Key)
		}
		seen[r.Key] = true
		if r.Kind == RoleLead {
			leads++
		}
		if r.Description == "" {
			return fmt.Errorf("role %q has empty Description", r.Key)
		}
	}
	if leads != 1 {
		return fmt.Errorf("want exactly 1 lead role, got %d", leads)
	}
	if p.Scheduler() == "" {
		return fmt.Errorf("Scheduler() is empty")
	}
	if p.Verifier() == nil {
		return fmt.Errorf("Verifier() is nil: 没有确定性验收就无法压误报")
	}
	if p.Verifier().Name() == "" {
		return fmt.Errorf("Verifier().Name() is empty")
	}
	for _, a := range p.Artifacts() {
		if a.Key == "" {
			return fmt.Errorf("artifact with empty Key")
		}
	}
	return nil
}
