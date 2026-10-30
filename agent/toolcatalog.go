package agent

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/jintilm/praetor/agent/domain"
	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// 本文件把「内置工具」从纯代码变成可枚举、可被 DB 覆盖的目录：
//   - BuiltinToolSeeds()：把平台 agent 的内置工具集展开成 seed 记录（key +
//     描述 + 参数 schema + 默认绑定的 agent），供服务端开机幂等播种进 tools 表。
//   - DomainToolSeeds(pack)：把一个领域包的角色展开成同样的记录，只在装配该域时用；
//     领域包的 agent 不参与全局播种，避免往库里塞用不到的绑定。
//   - ToolResolve 钩子：运行时按 DB 里的 tools 行对已装配的工具做「按 agent 过滤 +
//     覆盖描述/schema + 注入参数默认值」。key/handler 仍在代码层，DB 只改「散文与默认值」。
// handler（Call 行为）永远来自代码——DB 改不了它，只能改模型看到的说明与缺省入参。

// ToolSeed 是一个内置工具的可播种快照：key 即 CoreTool.Name()（与 handler 死绑，
// UI 只读），Desc/Schema 取自代码里的工具定义，Agents 是代码默认把它给了哪些 agent。
type ToolSeed struct {
	Key    string         // = CoreTool.Name()，主键，不可改
	Desc   string         // 顶层描述（可在 UI 覆盖）
	Schema map[string]any // 参数 JSON-Schema（结构只读，description/default 可在 UI 改）
	Agents []string       // 默认绑定的 agent key（worker/planner/mainagent）
}

// builtinToolsByAgent 用一个「只读空壳」ToolSet（nil stores）构造每个执行 agent 的
// 领域工具集。工具构造函数只把闭包塞进 Spec、构造期不解引用 store，所以 nil 安全——
// 这些工具在这里只用来读 Name()/Description()/InputSchema()，绝不 Call。
//
// 刻意【不含】SDK 通用工具 actool.DefaultTools()（Read/Write/Edit/MultiEdit/LS/Glob/
// Grep/Bash）：它们每个 agent 都固定拥有、没有「绑定到谁」的取舍，且说明大多在 Prompt()
// 里（本表只覆盖 Description()，会造成半覆盖误导）。不 seed → 无 DB 行 → ToolResolve
// 原样放行、不覆盖，行为与从前一致。只有 praetor 自己的领域工具入表可管。
func builtinToolsByAgent() map[string][]actool.CoreTool {
	ts := NewToolSet(nil, "")
	return map[string][]actool.CoreTool{
		"mainagent": ts.MainAgentTools(),
		"planner":   ts.PlannerTools(),
		"worker":    ts.WorkerTools(),
		// goals（目标拆解器）默认绑 set_goals + set_constraints：靠它们把拆出的目标、
		// 抽出的操作约束写进库。与 mainagent 共用同一受管工具，web 端可改描述/schema、按 agent 勾选。
		"goals": {ts.setGoals(), ts.setConstraints()},
		// auto 默认绑漏洞上报 + 资产管理工具，其他域工具可在 UI 按需勾选。
		// 新库由此 seed 写入；老库由 seedAutoDefaultBindings 迁移。
		"auto": {ts.addFinding(), ts.insertAssets(), ts.addCompanyScope(), ts.listAssets(), ts.listCompanies()},
		// pentest（独立渗透 agent）默认绑：查资产 / 插资产 / 报漏洞 / 查漏洞 / 查企业。
		// 新库由此 seed 写入；老库由 seedPentestDefaultBindings 迁移。
		"pentest": {ts.listAssets(), ts.insertAssets(), ts.addFinding(), ts.listFindings(), ts.listCompanies()},
	}
}

// defaultUnbound：这些 system 工具会照常入目录（web 端可见、可手动按 agent 勾选），但
// 默认【不绑任何 agent】——ToolResolve 对空绑定的工具对所有 agent 一律丢弃,须显式 opt-in。
// 之所以仍留在某个 agent 的 base 工具集里(如 goal_met 在 PlannerTools):一是让 seed 能
// 构造它拿到 desc/schema,二是用户手动绑回后运行时 base 里有它、ToolResolve 才留得住。
//
// goal_met：绕过逐个 prove_goal、直接从全局宣布【整个任务完成】,权重大且有误判风险,又与
// 「prove_goal 标记最后一个目标 → 自动收官」重复,故默认不给任何 agent,需要时再手动绑。
var defaultUnbound = map[string]bool{"goal_met": true}

// platformAgentOrder 是「平台级 agent」的固定维度，顺序决定 seed 的稳定顺序。
//
// 这些 agent 与具体领域无关：mainagent 是人在环路，goals 是目标拆解，auto/pentest
// 是独立任务型 agent；planner/worker 虽是渗透域角色，但它们的默认绑定必须与存量库
// 逐条一致（见 toolcatalog_seeds_test.go 的 golden），所以在 P1 逐域切换之前仍留在
// 平台侧。领域包新增的角色由 DomainToolSeeds 单独展开，不参与这里。
var platformAgentOrder = []string{"mainagent", "goals", "planner", "worker", "auto", "pentest"}

// BuiltinToolSeeds 把各平台 agent 的内置工具集去重合并成 seed 列表：同名工具（如
// list_assets 多个 agent 都有）合成一条，Agents 取并集；defaultUnbound 里的工具则
// 强制绑定为空。
//
// 领域包（红队/CTF/逆向）的 agent 不在这里播种：它们只在对应任务形态下才存在，
// 全量播种会往库里塞一堆用不到的绑定。装配某域时用 DomainToolSeeds 单独取。
func BuiltinToolSeeds() []ToolSeed {
	return mergeSeeds(builtinToolsByAgent(), platformAgentOrder)
}

// DomainToolSeeds 把一个领域包的角色展开成 seed 记录（语义与 BuiltinToolSeeds 一致：
// 同名工具合并、Agents 取并集、defaultUnbound 强制留空）。
//
// 只解析「当前装配得出来」的工具：领域包里大量 key 要等对应 MCP 接进来才存在，
// 静默丢弃会让 worker 手里没工具却照常开跑，所以缺失项由 UnresolvedDomainTools
// 显式报出来（P0-5 装配期打警告）。
func DomainToolSeeds(p domain.DomainPack) []ToolSeed {
	if p == nil {
		return nil
	}
	idx := platformToolIndex()
	byAgent := make(map[string][]actool.CoreTool, len(p.Roles()))
	order := make([]string, 0, len(p.Roles()))
	for _, r := range p.Roles() {
		seen := make(map[string]bool, len(r.ToolKeys))
		var tools []actool.CoreTool
		for _, k := range domain.EffectiveTools(p, r) {
			t, ok := idx[k]
			if !ok || seen[k] {
				continue
			}
			seen[k] = true
			tools = append(tools, t)
		}
		byAgent[r.Key] = tools
		order = append(order, r.Key)
	}
	return mergeSeeds(byAgent, order)
}

// optionalSDKTools 是「由宿主按配置装配、不归 tools 表管」的 SDK 工具名。
//
// WebFetch/WebSearch 不在 actool.DefaultTools 里，要靠 EnableWebFetch / SetWebSearch
// 显式打开（PRAETOR 在 chat.go 里开，并指向记录代理）。它们对领域包是合法声明，
// 但既不该被播种进 tools 表，也不该被报成「缺失」。
var optionalSDKTools = map[string]bool{"WebFetch": true, "WebSearch": true}

// UnresolvedDomainTools 返回该域「声明了、但当前工具集里没有」的 key，排序去重。
// 供装配期告警：这类 key 通常要等 MCP server 接进来。
func UnresolvedDomainTools(p domain.DomainPack) []string {
	if p == nil {
		return nil
	}
	idx := platformToolIndex()
	seen := map[string]bool{}
	var out []string
	for _, r := range p.Roles() {
		for _, k := range domain.EffectiveTools(p, r) {
			// MCP 工具（mcp__server__tool）由运行时按可见性注入，平台索引里永远没有；
			// 把它们算作"未接入"会让任何声明了浏览器的角色都报红。
			if strings.HasPrefix(k, "mcp__") {
				continue
			}
			if _, ok := idx[k]; ok || optionalSDKTools[k] || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// platformToolIndex 把「当前装配得出来的工具」铺平成 key→CoreTool，供领域包按 key 取 handler。
//
// 两个来源：
//  1. 平台 agent 的领域工具实例（builtinToolsByAgent）——handler 永远来自代码；
//  2. SDK 默认工具（Read/Write/Edit/Bash/…）——它们刻意不进 tools 表（每个 agent 都有），
//     但对领域包来说是完全合法的声明，所以也要能解析，否则会被误报成「缺失」。
func platformToolIndex() map[string]actool.CoreTool {
	idx := make(map[string]actool.CoreTool, 64)
	for _, t := range actool.DefaultTools() {
		idx[t.Name()] = t
	}
	byAgent := builtinToolsByAgent()
	for _, tools := range byAgent {
		for _, t := range tools {
			if _, ok := idx[t.Name()]; !ok {
				idx[t.Name()] = t
			}
		}
	}
	// 领域专属工具（如逆向域 re_triage）必须能被领域角色解析到，但**不能**进平台 agent 的
	// 绑定表 —— 否则每个装 PRAETOR 的库都会给 worker 多出几个用不到的工具，每轮多付 schema。
	for name, t := range domainOwnedTools() {
		if _, ok := idx[name]; !ok {
			idx[name] = t
		}
	}
	// 按领域裁剪的 worker 工具（re_evidence / ctf_submit）也必须可解析：
	// 它们不在无领域的 WorkerTools 里（那样会污染渗透任务的工具面），
	// 所以这里按域各建一次 ToolSet 把它们收集进来。
	for name, t := range domainScopedTools() {
		if _, ok := idx[name]; !ok {
			idx[name] = t
		}
	}
	return idx
}

// domainOwnedTools 是「只服务领域包」的工具集合：可解析、不播种给平台 agent。
//
// 它们都不依赖 store（只读文件系统/纯计算），所以这里可以用零值 ToolSet 构造。
// 一旦某个领域工具需要 DB，就不能放进来 —— 那时应该走每任务的 ToolSet 构造，
// 而不是在包级 init 时造一个没有 store 的实例。
func domainOwnedTools() map[string]actool.CoreTool {
	ts := &ToolSet{} // 零值即可：以下工具都不触碰 store 字段
	list := []actool.CoreTool{
		ts.reTriage(),
		ts.reRecipe(),
		calderaTool(),
	}
	m := make(map[string]actool.CoreTool, len(list))
	for _, t := range list {
		m[t.Name()] = t
	}
	return m
}

// mergeSeeds 是 BuiltinToolSeeds / DomainToolSeeds 的公共骨架：按 order 展开、
// 同名工具合并（Agents 取并集，保持出现顺序）、defaultUnbound 强制清空绑定。
func mergeSeeds(byAgent map[string][]actool.CoreTool, order []string) []ToolSeed {
	type acc struct {
		tool   actool.CoreTool
		agents []string
	}
	m := map[string]*acc{}
	var keys []string
	for _, ak := range order {
		for _, t := range byAgent[ak] {
			a, ok := m[t.Name()]
			if !ok {
				a = &acc{tool: t}
				m[t.Name()] = a
				keys = append(keys, t.Name())
			}
			a.agents = append(a.agents, ak)
		}
	}

	out := make([]ToolSeed, 0, len(keys))
	for _, k := range keys {
		a := m[k]
		agents := a.agents
		if defaultUnbound[k] {
			agents = []string{} // 入目录、可手动绑，但默认不给任何 agent（存 [] 而非 null，与其它工具一致）
		}
		out = append(out, ToolSeed{
			Key:    k,
			Desc:   a.tool.Description(),
			Schema: a.tool.InputSchema(),
			Agents: agents,
		})
	}
	return out
}

// ToolResolve, if set, post-processes an agent's fully-assembled tool list against
// the DB tools table: it drops tools not bound to this agent (or globally disabled)
// and wraps the rest so the model sees the DB-overridden description/schema and
// 缺省入参 get injected. Tools with no matching DB row (MCP/skill/host tools like
// traffic) pass through untouched. nil = tools unchanged. Wired in server/assembly.go.
var ToolResolve func(ctx context.Context, agentKey string, tools []actool.CoreTool) []actool.CoreTool

// DecorateTool wraps t so Description()/InputSchema() report the DB overrides and
// Call() injects scalar parameter defaults (from schema's "default" props) whenever
// the model omitted them. Name/Prompt/permission/scheduler flags delegate to t, so
// the tool's identity and handler are unchanged. Empty desc/schema fall back to t's.
func DecorateTool(t actool.CoreTool, desc string, schema map[string]any) actool.CoreTool {
	if desc == "" {
		desc = t.Description()
	}
	if len(schema) == 0 {
		schema = t.InputSchema()
	}
	return &overriddenTool{CoreTool: t, desc: desc, schema: schema}
}

// overriddenTool is a CoreTool decorator: it embeds the original (so all behavioral
// methods — Prompt/IsReadOnly/IsConcurrencySafe/CheckPermissions/Name — delegate)
// and overrides only the model-facing description/schema plus default injection.
type overriddenTool struct {
	actool.CoreTool
	desc   string
	schema map[string]any
}

func (o *overriddenTool) Description() string         { return o.desc }
func (o *overriddenTool) InputSchema() map[string]any { return o.schema }

func (o *overriddenTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	return o.CoreTool.Call(ctx, injectDefaults(in, o.schema), tc)
}

// injectDefaults fills scalar parameter defaults declared in the (possibly edited)
// schema into the input JSON whenever the model omitted the field or left it empty/
// null. Structure (names/types/required) is untouched — only缺省值 are merged in.
func injectDefaults(in json.RawMessage, schema map[string]any) json.RawMessage {
	defs := scalarDefaults(schema)
	if len(defs) == 0 {
		return in
	}
	m := map[string]json.RawMessage{}
	if len(in) > 0 {
		if err := json.Unmarshal(in, &m); err != nil {
			return in // non-object input: don't touch it
		}
	}
	changed := false
	for k, dv := range defs {
		if cur, ok := m[k]; !ok || isEmptyJSON(cur) {
			m[k] = dv
			changed = true
		}
	}
	if !changed {
		return in
	}
	b, err := json.Marshal(m)
	if err != nil {
		return in
	}
	return b
}

// scalarDefaults extracts properties[k]["default"] for scalar params (string/
// integer/number/boolean). Array/object defaults are skipped: merging them is
// ambiguous and not worth the surprise.
func scalarDefaults(schema map[string]any) map[string]json.RawMessage {
	props, _ := schema["properties"].(map[string]any)
	if len(props) == 0 {
		return nil
	}
	out := map[string]json.RawMessage{}
	for name, raw := range props {
		p, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		dv, ok := p["default"]
		if !ok || dv == nil {
			continue
		}
		switch p["type"] {
		case "string", "integer", "number", "boolean":
			if b, err := json.Marshal(dv); err == nil {
				out[name] = b
			}
		}
	}
	return out
}

func isEmptyJSON(raw json.RawMessage) bool {
	s := string(raw)
	return s == "null" || s == `""`
}

// domainScopedTools 收集所有领域专属的 worker 工具（name → 实例），供索引/播种解析。
//
// 与 domainOwnedTools 的区别：那些是"无 store 也能用"的工具（re_triage）；
// 这些是**需要任务上下文**、但名字要能被解析到的工具（re_evidence 要写探索图，
// ctf_submit 要提交后端）。这里只为了让名字可解析，实例本身不用于执行。
func domainScopedTools() map[string]actool.CoreTool {
	out := map[string]actool.CoreTool{}
	for _, key := range []string{"reverse", "ctf"} {
		ts := NewToolSet(nil, "")
		ts.SetDomain(key)
		for _, t := range ts.domainTools() {
			out[t.Name()] = t
		}
	}
	return out
}
