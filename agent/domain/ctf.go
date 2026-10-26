package domain

import "time"

// CTF 域：执行模型是「广度并发 + 竞速抢旗」，与渗透的深度单链完全不同。
//
// 参考范式（verialabs/ctf-agent，BSidesSF 2026 52/52 全胜）：
// 一个 coordinator 管全场，每道题起多个 solver（不同模型）并行，先解出者提交，
// 被平台判为错误则回退换模型/换思路。
//
// 关键差异：CTF 的成功判据完全客观（flag 被判题系统接受），
// 所以 Verifier 必须接平台判题，不能靠模型自述"解出来了"。
func init() { Register(ctfPack{}) }

type ctfPack struct{}

func (ctfPack) Key() Key      { return CTF }
func (ctfPack) Title() string { return "CTF 竞赛" }

func (ctfPack) Prompt() []string {
	return []string{
		"你是 CTF 竞赛的协调者。你的首要目标是在时间预算内最大化解出的题目数，而不是把一道题做到完美。",
		"识别题目类型（web/pwn/rev/crypto/forensics/misc）后分派给对应 solver；同一题可并行多解法。",
		"任何结论都必须给出可验证的 flag 与完整利用/求解路径；不许猜 flag 硬凑格式。",
	}
}

func (ctfPack) Roles() []RoleSpec {
	return []RoleSpec{
		{
			Key:         "ctf-lead",
			Kind:        RoleLead,
			Description: "读取题面与附件，判类型、分配预算、竞速仲裁、决定放弃哪题",
			PromptSection: "先枚举全部题目并按「类型 × 预期难度 × 剩余时间」排序；" +
				"优先派能快速拿分的题。每题记录已尝试的思路，避免多个 solver 重复踩坑。",
			ToolKeys: []string{"Read", "Bash", "ctfd_list_challenges", "ctfd_submit_flag", "add_intent", "add_hint"},
			MaxTurns: 25,
			Approval: ApprovalAuto,
			Budget:   Budget{MaxParallel: 8},
		},
		{
			Key:           "solver-web",
			Kind:          RoleSpecialist,
			Description:   "Web 题：注入/SSRF/反序列化/模板/文件上传/JWT",
			ToolKeys:      []string{"Bash", "Read", "Write", "curl_run", "burp_repeater"},
			MaxTurns:      40,
			Approval:      ApprovalAuto,
			PromptSection: "先在容器内本地复现，再打远端实例；注意实例有重置次数限制。",
		},
		{
			Key:           "solver-pwn",
			Kind:          RoleSpecialist,
			Description:   "Pwn 题：栈/堆利用、格式化字符串、ROP、沙箱逃逸",
			ToolKeys:      []string{"Bash", "Read", "Write", "Edit", "pwntools_run", "gdb_run", "checksec"},
			MaxTurns:      60,
			Approval:      ApprovalAuto,
			PromptSection: "先 checksec 定性，再用 pwndbg 定位；写 exp 时保留调试日志作为证据。",
		},
		{
			Key:           "solver-rev",
			Kind:          RoleSpecialist,
			Description:   "逆向题：静态反编译 + 动态调试，还原校验逻辑",
			ToolKeys:      []string{"Bash", "Read", "Write", "ghidra_decompile", "rizin_analyze", "gdb_run"},
			MaxTurns:      60,
			Approval:      ApprovalAuto,
			PromptSection: "优先动态验证假设，别在反编译结果里空想；关键函数要留地址与伪代码片段。",
		},
		{
			Key:           "solver-crypto",
			Kind:          RoleSpecialist,
			Description:   "密码学题：古典密码、RSA/ECC 误用、格、PRNG 预测",
			ToolKeys:      []string{"Bash", "Write", "sagemath_run", "ciphey_decode"},
			MaxTurns:      50,
			Approval:      ApprovalAuto,
			PromptSection: "先判断是「实现错误」还是「数学困难」；前者写脚本，后者先降维试小参数。",
		},
		{
			Key:           "solver-forensics",
			Kind:          RoleSpecialist,
			Description:   "取证/流量/隐写/misc：pcap、内存镜像、文件格式、编码",
			ToolKeys:      []string{"Bash", "Read", "tshark_run", "binwalk_run", "zsteg_run", "volatility_run"},
			MaxTurns:      50,
			Approval:      ApprovalAuto,
			PromptSection: "先 file/binwalk 摸清格式，再决定深挖方向；保留每一步的命令与输出。",
		},
	}
}

func (ctfPack) Tools() []string {
	return []string{"ctfd_list_challenges", "ctfd_submit_flag", "ctfd_scoreboard"}
}

func (ctfPack) MCP() []MCPRef {
	return []MCPRef{
		// 判题/计分走 CTFd API，Verifier 依赖它做仲裁。
		{Name: "ctfd", Transport: "http", URL: "http://127.0.0.1:8000"},
		// 逆向题复用统一逆向工具面（见 reverse 域），避免两套实现。
		{Name: "rea", Transport: "stdio", Command: "rea-mcp", Allowed: []string{"decompile", "disasm", "strings", "xrefs"}},
	}
}

func (ctfPack) Skills() []string { return []string{"ctf-skills"} }

func (ctfPack) Policy() PolicySpec {
	return PolicySpec{
		ScopeRequired: false, // CTF 目标由平台给定，天然隔离
		Rules: []PolicyRule{
			{Match: "Bash", Action: ActionAllow, Reason: "CTF 全部在隔离容器内，允许自由执行"},
			{Match: "ctfd_submit_flag", Action: ActionAllow, Reason: "提交 flag 由仲裁器统一去重后发出"},
			{Match: "artifact.exfil", Action: ActionDeny, Reason: "禁止把题目附件外传"},
		},
	}
}

func (ctfPack) Graph() GraphSpec {
	return GraphSpec{
		NodeKinds: []string{"challenge", "intent", "fact", "flag", "hint", "writeup"},
		EdgeKinds: []string{"solves", "derived_from", "yields", "duplicates"},
	}
}

func (ctfPack) Artifacts() []ArtifactKind {
	return []ArtifactKind{
		{Key: "challenge_file", Description: "题目附件/镜像", MaxBytes: 512 << 20},
		{Key: "exp_script", Description: "利用或求解脚本", MaxBytes: 4 << 20},
		{Key: "writeup", Description: "解题路径（含命令与输出）", MaxBytes: 2 << 20},
	}
}

func (ctfPack) Model() ModelPolicy {
	return ModelPolicy{
		Tier:        TierCloud,
		Reason:      "pwn/rev 题对代码推理要求最高，竞速机制需要多模型并行（不同厂商互补）",
		PreferLarge: true,
	}
}

func (ctfPack) Budget() Budget {
	return Budget{
		MaxTokens:    4_000_000,
		MaxWall:      4 * time.Hour, // 单场 CTF 时长
		MaxToolCalls: 2000,
		MaxDepth:     1, // solver 不再派生，避免竞速时指数膨胀
		MaxParallel:  8,
	}
}

func (ctfPack) Scheduler() SchedulerKind { return ScheduleRace }
func (ctfPack) Verifier() Verifier       { return ctfVerifier{} }
