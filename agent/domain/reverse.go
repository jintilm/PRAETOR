package domain

import "time"

// 逆向域：不追求「一次对话给出结论」，而要求【可复核的证据链 + 可中断续跑】。
//
// 三条硬约束（来自样本治理要求）：
//  1. LocalOnly —— 样本与伪代码不出本机，模型也走本地；
//  2. 切片后再送模型 —— 大二进制先做函数级切片，不整包塞上下文；
//  3. 结论必须挂证据 —— 交叉引用或动态 trace，否则只能算「推测」。
func init() { Register(reversePack{}) }

type reversePack struct{}

func (reversePack) Key() Key      { return Reverse }
func (reversePack) Title() string { return "逆向工程" }

func (reversePack) Prompt() []string {
	return []string{
		"你是二进制分析者。目标不是「猜这段代码做什么」，而是产出一条别人能复核的证据链。",
		"每一步结论都要落到具体证据：函数地址、交叉引用、字符串、动态 trace、内存 dump。",
		"遇到无法确定的点，明确标注「未确认」并给出验证方法，禁止用看似合理的猜测填补空白。",
	}
}

func (reversePack) Roles() []RoleSpec {
	return []RoleSpec{
		{
			Key:         "re-lead",
			Kind:        RoleLead,
			Description: "拆解分析目标，决定静态/动态路线，维护证据链完整性，输出最终结论与置信度",
			PromptSection: "先摸清样本形态（架构/加壳/编译器/是否有反调试），再决定路线。" +
				"定期回看证据链：哪些结论只有推测支撑？缺证据的去补，补不到就降级标注。",
			ToolKeys: []string{"Read", "Bash", "file_identify", "ghidra_decompile", "add_intent", "add_hint"},
			MaxTurns: 30,
		},
		{
			Key:           "static-analyst",
			Kind:          RoleSpecialist,
			Description:   "静态分析：反汇编、反编译、符号恢复、调用图、字符串与常量",
			ToolKeys:      []string{"Bash", "Read", "Write", "ghidra_decompile", "ghidra_xrefs", "rizin_analyze", "ida_decompile"},
			MaxTurns:      60,
			PromptSection: "按「入口 → 关键分支 → 数据流」推进；每恢复一个函数就记录地址、用途、证据来源。",
		},
		{
			Key:           "dynamic-analyst",
			Kind:          RoleSpecialist,
			Description:   "动态分析：调试、断点、内存 dump、API/系统调用跟踪、frida hook",
			ToolKeys:      []string{"Bash", "gdb_run", "x64dbg_run", "frida_hook", "strace_run"},
			MaxTurns:      50,
			PromptSection: "先建基线（正常运行的行为），再逐个验证静态分析的假设；异常路径要留完整日志。",
		},
		{
			Key:           "malware-analyst",
			Kind:          RoleSpecialist,
			Description:   "恶意样本分析：行为定性、C2 提取、持久化机制、家族归类",
			ToolKeys:      []string{"Bash", "strings_run", "yara_scan", "capa_analyze", "tshark_run"},
			MaxTurns:      50,
			PromptSection: "只做隔离环境内的行为观察；任何网络回连一律不出网，用模拟器/黑洞地址接住。",
		},
		{
			Key:           "mobile-analyst",
			Kind:          RoleSpecialist,
			Description:   "移动端逆向：APK/IPA 解包、DEX/SO 分析、加固脱壳、SSL pinning 绕过",
			ToolKeys:      []string{"Bash", "apktool_run", "jadx_run", "frida_hook", "ghidra_decompile"},
			MaxTurns:      50,
			PromptSection: "先判断是否有加固/壳，再决定脱壳方案；关键校验逻辑要给出类名+方法名。",
		},
	}
}

func (reversePack) Tools() []string {
	return []string{"file_identify", "strings_run", "yara_scan", "capa_analyze", "ghidra_decompile", "ghidra_xrefs"}
}

func (reversePack) MCP() []MCPRef {
	return []MCPRef{
		// 一个 MCP 打通二进制/应用/运行时，接入成本最低。
		{Name: "rea", Transport: "stdio", Command: "rea-mcp", LocalOnly: true},
		// headless Ghidra：不需要开 GUI，适合服务化与批量任务。
		{Name: "ghidra", Transport: "stdio", Command: "pyghidra-mcp", LocalOnly: true},
		// 有 IDA 授权时启用（本机已装 IDA 9.4）。
		{Name: "ida", Transport: "stdio", Command: "ida-pro-mcp", LocalOnly: true},
	}
}

func (reversePack) Skills() []string { return []string{"mobile-re", "binary-triage"} }

func (reversePack) Policy() PolicySpec {
	return PolicySpec{
		ScopeRequired: false,
		// 逆向不出网：只允许访问本地分析服务与本机文件。
		AllowEgress: []string{"127.0.0.1", "localhost"},
		Rules: []PolicyRule{
			{Match: "Bash", Action: ActionAsk, Reason: "任意命令需确认，防止样本逃逸到宿主"},
			{Match: "artifact.upload", Action: ActionDeny, Reason: "样本与伪代码禁止外传（含禁止整包进 LLM 请求）"},
			{Match: "net.outbound", Action: ActionDeny, Reason: "分析环境默认无外网；回连用黑洞地址接住"},
			{Match: "sample.decrypt", Action: ActionAsk, Reason: "解密样本库需授权"},
		},
	}
}

func (reversePack) Graph() GraphSpec {
	return GraphSpec{
		NodeKinds: []string{"sample", "binary", "function", "string", "xref", "evidence", "conclusion"},
		EdgeKinds: []string{"calls", "references", "derived_from", "supports", "contradicts"},
	}
}

func (reversePack) Artifacts() []ArtifactKind {
	return []ArtifactKind{
		{Key: "sample", Description: "原始样本（加密存储 + 哈希索引）", Sensitive: true, LocalOnly: true, MaxBytes: 256 << 20},
		{Key: "decompiled_slice", Description: "函数级伪代码切片", Sensitive: true, LocalOnly: true, MaxBytes: 4 << 20},
		{Key: "memory_dump", Description: "进程内存镜像", Sensitive: true, LocalOnly: true, MaxBytes: 1 << 30},
		{Key: "analysis_report", Description: "结论 + 证据链 + 置信度", MaxBytes: 4 << 20},
	}
}

func (reversePack) Model() ModelPolicy {
	return ModelPolicy{
		Tier:        TierLocal,
		Reason:      "样本与伪代码属最高敏感级，强制本地模型（LocalOnly），宁可牺牲部分推理能力",
		LocalOnly:   true,
		PreferLarge: true,
	}
}

func (reversePack) Budget() Budget {
	return Budget{
		MaxTokens:    6_000_000, // 长时程分析，token 消耗高但并发低
		MaxWall:      12 * time.Hour,
		MaxToolCalls: 3000,
		MaxDepth:     3, // 允许「分析子函数」这类递归下沉
		MaxParallel:  2,
	}
}

func (reversePack) Scheduler() SchedulerKind { return ScheduleEvidence }
func (reversePack) Verifier() Verifier       { return reverseVerifier{} }
