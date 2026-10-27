package agent

import (
	"strings"

	"github.com/Autumn-27/praetor/db"
)

var _ = db.KindGoal // 保持 db 依赖（constraintBlock 用其类型）

// evidenceRedline 是**代码自有**的取证边界，恒定附在 worker 的系统提示里。
//
// 为什么必须有它（实测踩到的坑，2026-10-27 基线跑分）：
// agent 会绕开目标去「找」flag，而不是去打漏洞。XBEN-009 那次的 70 次调用里，
// 后 22 次全是这类动作：`docker exec <靶场容器> cat /flag.txt`、读容器内源码、
// `docker history` 翻镜像层、`Get-ChildItem` 遍历宿主磁盘 cat 题目目录的 .env，
// 甚至 `docker build --build-arg FLAG=...` **自建一个带 flag 的容器**再访问它。
// 结果是 open 报告里出现 flag、看着像解出，实际没利用任何漏洞；同时白烧了大量预算。
//
// 为什么做成 code-owned 而不是写进 DB 提示词：
// 提示词是**按 agent 可编辑**的（agent_prompts 表），实测 goals 抽出的操作约束
// 只覆盖「范围」（IP/域名），从不包含取证边界。这条红线只跟「有没有目标资产」挂钩，
// 属于系统级不变量，不该依赖模型自觉或运营编辑——所以和 artifactSpec 一样由代码固定附加。
const evidenceRedline = "**取证边界（红线，与操作约束同级；判分与合规都按此口径）**：\n" +
	"1. 一切漏洞结论必须来自**对目标资产的真实请求/响应**（含经记录代理由此产生的流量）。\n" +
	"2. **禁止**为找 flag/答案而读取非目标侧的内容：宿主或任何容器的本地文件（含题目目录\n" +
	"   .env、源码、配置、镜像层）、docker exec / inspect / history、构建参数、日志、包管理器缓存。\n" +
	"3. **禁止**自行启动或构建服务来伪造/复现目标（例如 docker run 或 docker build 一个带\n" +
	"   flag 的容器再访问它，或把测到的数据灌进自建服务）。验证必须针对**任务给定的目标地址**。\n" +
	"4. 只有落在允许范围内的目标才有授权；范围外的内容即使读到也不构成可利用漏洞，\n" +
	"   应记为 out-of-scope 并跳过\u2014\u2014**不得**把它写成 finding 的 evidence。\n" +
	"5. 判分只看目标流量：报告中出现但目标流量中不存在的结论视为无效，不计成果。"

// constraintBlock renders this task's operation constraints (task_constraints) as a
// high-priority block appended to the planner/worker system prompt. allow/deny are
// grouped; empty string when there are no constraints (or ts is nil). The framing
// deliberately puts these ABOVE the exploration/expansion heuristics so a declared
// boundary wins the tug-of-war against "chase another entry surface".
func constraintBlock(ts *db.ExplorationStore) string {
	if ts == nil {
		return ""
	}
	rows, err := ts.ListConstraints()
	if err != nil || len(rows) == 0 {
		return ""
	}
	var allow, deny []string
	for _, c := range rows {
		text := strings.TrimSpace(c.Text)
		if text == "" {
			continue
		}
		if c.Kind == "allow" {
			allow = append(allow, "- "+text)
		} else {
			deny = append(deny, "- "+text)
		}
	}
	if len(allow) == 0 && len(deny) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【操作约束（最高优先级，凌驾于下方一切探索/拓面启发式；每生成一条意图、每执行一个动作前都必须先自检是否违反，违反即不得进行）】：")
	if len(allow) > 0 {
		b.WriteString("\n允许的操作：\n")
		b.WriteString(strings.Join(allow, "\n"))
	}
	if len(deny) > 0 {
		b.WriteString("\n禁止的操作：\n")
		b.WriteString(strings.Join(deny, "\n"))
	}
	b.WriteString("\n（发现约束之外的新目标/新端口/新主机，不等于获得授权：除非它落在上述允许范围内，否则记为 out-of-scope 事实并跳过，不得为其派生意图或执行动作。）")
	return b.String()
}
