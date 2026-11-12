package report

import (
	"fmt"
	"strings"
	"time"
)

// edusrc（教育漏洞报告平台）提交规范字段，依据 src.sjtu.edu.cn/announcement/4
// 《教育漏洞报告平台漏洞提交规范》（2024-02-06）。
//
// 官方 10 项：标题 / 分类 / 等级 / 漏洞单位 / 开发方 / 资产所在网段 /
// 是否需要账号认证 / 漏洞 URL / 内容 / 附件。
//
// 两条项目决策（2026-11-11）：
//  1. 官方要求「同单位同系统多漏洞点打包一个」，本项目按用户决定改为
//     **一漏洞点一份**，单位/系统只作为分组信息，绝不合并正文。
//  2. 报告不做证据脱敏，允许复测账号（含密码）原样输出；Cookie/Token/
//     完整 HTTP 报文不自动内联，仍走证据包单独导出。

// edusrcTitle 只返回单位名称。官方说明：标题公开可见，禁止写系统名/漏洞名。
func edusrcTitle(v View) string {
	if u := v.Unit(); u != "" {
		return u
	}
	return "【待补充：单位名称】"
}

func renderEdusrc(v View) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", edusrcTitle(v))
	fmt.Fprintf(&b, "> 模板：edusrc 平台 · finding #%d · 一漏洞点一份\n", v.ID)
	b.WriteString("> 标题公开可见，只填单位名称；系统名与漏洞名一律写进「内容」，不得出现在标题。\n")
	b.WriteString("> 官方规范要求同单位同系统多漏洞点打包提交，本项目按决策不打包，提交时若平台要求合并请自行处理。\n\n")

	// 标题
	b.WriteString("## 标题\n\n")
	fmt.Fprintf(&b, "%s\n\n", edusrcTitle(v))
	if v.Unit() == "" {
		b.WriteString(todo("单位名称（标题只能填单位名称）") + "\n\n")
	}

	// 分类
	b.WriteString("## 分类\n\n")
	if vc := strings.TrimSpace(v.VulnClass); vc != "" {
		fmt.Fprintf(&b, "- 参考：%s（项目漏洞类别，非平台分类枚举值）\n", vc)
	}
	b.WriteString(todo("按平台分类下拉选择；以上仅供参考") + "\n\n")

	// 等级
	fmt.Fprintf(&b, "## 等级\n\n- 建议：%s（项目等级 %s；平台由提交人初选、审核员终判）\n\n",
		v.SeverityLabel(), nz(v.Severity, "未评级"))

	// 漏洞单位
	b.WriteString("## 漏洞单位\n\n")
	if units := v.Units(); len(units) > 0 {
		fmt.Fprintf(&b, "- %s\n", strings.Join(units, " / "))
	} else {
		b.WriteString(todo("漏洞所属单位全称") + "\n")
	}
	b.WriteString("\n")

	// 开发方
	b.WriteString("## 开发方\n\n")
	b.WriteString(todo("系统开发方 / 厂商名称（若无则填「未知」或「自研」）") + "\n\n")

	// 资产所在网段
	b.WriteString("## 资产所在网段\n\n")
	if roots := v.RootDomains(); len(roots) > 0 {
		b.WriteString("- 资产线索：" + strings.Join(roots, " / ") + "\n")
	}
	b.WriteString(todo("资产所在网段（CIDR / IP 段），用于平台核验归属") + "\n\n")

	// 是否需要账号认证
	b.WriteString("## 是否需要账号认证\n\n")
	b.WriteString(todo("选择「是 / 否」") + "\n")
	b.WriteString("- 若选「是」：在下方「内容」中填写复测账号与密码。本项目不做证据脱敏，账号凭据按原文输出。\n")
	b.WriteString("- 若选「否」：说明无需登录即可复现。\n\n")

	// 漏洞URL
	b.WriteString("## 漏洞URL\n\n")
	if len(v.URLs) == 0 {
		b.WriteString(todo("漏洞 URL") + "\n\n")
	} else {
		for i, u := range v.URLs {
			fmt.Fprintf(&b, "%d. %s\n", i+1, u)
		}
		b.WriteString("\n")
	}

	// 内容
	b.WriteString("## 内容\n\n")
	b.WriteString("### 漏洞描述\n\n")
	if s := strings.TrimSpace(v.Summary); s != "" {
		fmt.Fprintf(&b, "%s\n\n", s)
	} else {
		b.WriteString(todo("漏洞描述") + "\n\n")
	}
	if vc := strings.TrimSpace(v.VulnClass); vc != "" {
		fmt.Fprintf(&b, "- 漏洞类别：%s\n", vc)
	}
	fmt.Fprintf(&b, "- 漏洞名称：%s\n", v.Title())
	fmt.Fprintf(&b, "- 发现时间：%s\n\n", stampOrTodo(v.CreatedAt))

	b.WriteString("### 复现步骤 / 数据包\n\n")
	repro := v.Section("复现", "重现", "利用过程", "验证过程", "PoC", "POC", "漏洞证明")
	poc := v.Section("PoC", "POC", "EXP", "Exploit", "利用", "Payload", "数据包")
	if repro != "" {
		b.WriteString(repro + "\n\n")
	} else if body := strings.TrimSpace(v.Report); body != "" {
		b.WriteString(body + "\n\n")
	} else {
		b.WriteString(todo("可复现的操作步骤") + "\n\n")
	}
	if poc != "" && poc != repro {
		b.WriteString("**PoC / 数据包：**\n\n" + poc + "\n\n")
	}
	if e := strings.TrimSpace(v.Evidence); e != "" {
		b.WriteString("**原始证据：**\n\n" + codeBlock(e))
	}
	b.WriteString(v.TrafficMarkdown)

	b.WriteString("### 复测账号与数据包（允许输出）\n\n")
	b.WriteString("- 本项目不做证据脱敏：复测账号、密码、请求参数可原样填写，便于审核员复现。\n")
	b.WriteString("- Cookie / Token / 完整 HTTP 报文不自动内联；需要时从项目证据包单独导出后作为附件上传。\n")
	b.WriteString(todo("若平台选择「需要账号认证」，在此填写复测账号与密码") + "\n\n")

	b.WriteString("### 影响与危害\n\n")
	if impact := v.Section("影响", "危害", "风险"); impact != "" {
		b.WriteString(impact + "\n\n")
	} else {
		b.WriteString(todo("影响范围与危害说明") + "\n\n")
	}

	b.WriteString("### 修复建议\n\n")
	if fix := v.Section("修复", "整改", "缓解", "建议"); fix != "" {
		b.WriteString(fix + "\n\n")
	} else {
		b.WriteString(todo("修复建议") + "\n\n")
	}

	// 附件
	b.WriteString("## 附件\n\n")
	b.WriteString(todo("复现截图、数据包、归属证明等材料") + "\n")
	b.WriteString("- 可复用本项目 md-zip 证据包中的截图与报文文件。\n\n")

	// 分组信息（只提示，不合并）
	b.WriteString("## 分组提示（不合并正文）\n\n")
	fmt.Fprintf(&b, "- 单位：%s\n", edusrcTitle(v))
	if roots := v.RootDomains(); len(roots) > 0 {
		fmt.Fprintf(&b, "- 系统 / 资产：%s\n", strings.Join(roots, " / "))
	}
	b.WriteString("- 官方规范要求「同单位同系统多漏洞点打包一个」；本项目按用户决策一漏洞点一份，\n")
	b.WriteString("  上面两项仅供人工判断是否需要合并，模板不会自动合并。\n\n")

	if missing := edusrcMissing(v); len(missing) > 0 {
		b.WriteString("## 待补充清单\n\n")
		for i, m := range missing {
			fmt.Fprintf(&b, "%d. %s\n", i+1, m)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func stampOrTodo(t time.Time) string {
	if t.IsZero() {
		return "（未提供）"
	}
	return t.Format("2006-01-02 15:04:05")
}

func edusrcMissing(v View) []string {
	var out []string
	if v.Unit() == "" {
		out = append(out, "标题 / 漏洞单位：单位名称（标题只能填单位名称）")
	}
	out = append(out,
		"分类：平台分类下拉",
		"开发方：系统开发方 / 厂商",
		"资产所在网段：CIDR / IP 段",
		"是否需要账号认证：是 / 否，若为「是」需填复测账号与密码",
		"附件：复现截图、数据包、归属证明",
	)
	if len(v.URLs) == 0 {
		out = append(out, "漏洞URL")
	}
	if strings.TrimSpace(v.Summary) == "" {
		out = append(out, "内容：漏洞描述")
	}
	if v.Section("复现", "重现", "利用过程", "验证过程", "PoC", "POC", "漏洞证明") == "" && strings.TrimSpace(v.Report) == "" {
		out = append(out, "内容：复现步骤 / 数据包")
	}
	if v.Section("影响", "危害", "风险") == "" {
		out = append(out, "内容：影响与危害")
	}
	if v.Section("修复", "整改", "缓解", "建议") == "" {
		out = append(out, "内容：修复建议")
	}
	if v.SeverityLabel() == "待定" {
		out = append(out, "等级：项目未评级，需人工初选")
	}
	return out
}
