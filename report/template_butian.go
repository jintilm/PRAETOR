package report

import (
	"fmt"
	"strings"
)

// 补天平台「公益 SRC / 事件型」提交表单字段与选项。
// 依据：2026-11-11 提交页截图（表单字段说明、细分类型下拉、行业所属下拉）。
// 平台改版时改这里，不要在渲染逻辑里硬编码字面量。
//
// 注意这里不是「通用 2.0」（后者要求 [厂商全称]+[产品名]+存在[漏洞名] 标题、
// 漏洞环境/版本证明/漏洞分析/漏洞复现/exp 脚本）。公益 SRC 是事件型表单，
// 两者字段几乎不重叠，本模板只覆盖前者。

const (
	ButianCategoryWeb = "Web漏洞"
	ButianCategoryIOT = "IOT漏洞"
)

// ButianVulnTypes 是「漏洞类型」的二选一（用户确认只有这两种）。
var ButianVulnTypes = []string{"事件型", "通用型"}

// ButianSubTypes 是「漏洞类型」下方那个无标签联动下拉的可见选项
// （截图从上到下：请选择 / XSS / … / 解析漏洞）。列表中「命令执行」为
// 截图高亮项。是否还有滚动区外的选项以平台实际下拉为准。
var ButianSubTypes = []string{
	"XSS", "配置错误", "弱口令", "入侵事件", "疑似被黑", "文件上传",
	"信息泄露", "存在后门", "逻辑漏洞", "代码执行", "命令执行", "SQL注入", "解析漏洞",
}

// ButianIndustries 是「行业所属」下拉中可见的国民经济行业门类（截图逐项抄录，
// 高亮项为「卫生和社会工作」）。截图上下可能有截断；标准 20 门类中的
// 「国际组织」未在图中确认，故不自动列为候选，以平台实际选项为准。
var ButianIndustries = []string{
	"建筑业",
	"居民服务、修理和其他服务业",
	"批发和零售业",
	"电力、热力、燃气及水生产和供应业",
	"制造业",
	"文化、体育和娱乐业",
	"卫生和社会工作",
	"交通运输、仓储和邮政业",
	"教育",
	"公共管理、社会保障和社会组织",
	"金融业",
	"信息传输、软件和信息技术服务业",
	"租赁和商务服务业",
	"房地产业",
	"住宿和餐饮业",
	"农、林、牧、渔业",
	"水利、环境和公共设施管理业",
	"采矿业",
	"科学研究和技术服务业",
}

// butianSubTypeRules 把项目的 vulnclass / 漏洞名映射到联动下拉选项。
// 顺序即优先级；显式关键词优先于笼统的 RCE。
var butianSubTypeRules = []struct {
	keys  []string
	value string
}{
	{[]string{"SQL注入", "SQL 注入", "sql injection", "sqli"}, "SQL注入"},
	{[]string{"XSS", "跨站脚本"}, "XSS"},
	{[]string{"解析漏洞", "解析错误"}, "解析漏洞"},
	{[]string{"命令执行", "命令注入", "OS 注入", "os injection"}, "命令执行"},
	{[]string{"代码执行", "RCE", "远程代码", "反序列化"}, "代码执行"},
	{[]string{"文件上传", "任意文件上傳", "上传漏洞", "upload"}, "文件上传"},
	{[]string{"弱口令", "弱密码", "默认口令", "默认密码", "爆破", "暴力破解"}, "弱口令"},
	{[]string{"信息泄露", "信息泄漏", "敏感信息", "泄露", "泄漏", "目录遍历", "未授权访问"}, "信息泄露"},
	{[]string{"后门", "webshell"}, "存在后门"},
	{[]string{"入侵", "失陷", "被植入"}, "入侵事件"},
	{[]string{"疑似被黑", "挂马", "篡改", "黑页"}, "疑似被黑"},
	{[]string{"配置错误", "错误配置", "默认配置", "不安全配置"}, "配置错误"},
	{[]string{"逻辑漏洞", "业务逻辑", "越权", "IDOR"}, "逻辑漏洞"},
}

func butianSubType(v View) string {
	hay := strings.ToLower(v.VulnClass + " " + v.Name + " " + v.Summary)
	for _, r := range butianSubTypeRules {
		for _, k := range r.keys {
			if strings.Contains(hay, strings.ToLower(k)) {
				return r.value
			}
		}
	}
	return ""
}

func butianCategory(v View) string {
	hay := strings.ToLower(v.VulnClass + " " + v.Name)
	for _, k := range []string{"iot", "物联网", "固件", "路由器", "摄像头", "工控", "智能设备", "硬件"} {
		if strings.Contains(hay, k) {
			return ButianCategoryIOT
		}
	}
	return ButianCategoryWeb
}

// butianTitle 按表单占位提示「单位名称+漏洞类型，如：某单位存在SQL注入漏洞」生成。
// 与 edusrc「标题只填单位名称」规则完全相反，所以标题生成器按模板各自独立。
func butianTitle(v View) string {
	unit := v.Unit()
	if unit == "" {
		unit = "【待补充：单位名称】"
	}
	// 优先用联动下拉的规范值（官方示例「某单位存在SQL注入漏洞」），
	// 而不是 findings 里可能很长的自由文本类别（如「未授权访问/敏感信息泄露」）。
	vuln := butianSubType(v)
	if vuln == "" {
		vuln = strings.TrimSpace(v.VulnClass)
	}
	if vuln == "" {
		vuln = "安全"
	}
	return fmt.Sprintf("%s存在%s漏洞", unit, vuln)
}

func renderButian(v View) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 补天平台 · 漏洞提交单（finding #%d）\n\n", v.ID)
	b.WriteString("> 一漏洞一提交。带「待补充」的字段请在平台表单人工确认或填写；平台下拉项不得由模板代选。\n\n")

	// 厂商名称 *（平台内下拉，只列候选不代选）
	b.WriteString("## 厂商名称 *\n\n")
	if units := v.Units(); len(units) == 0 {
		b.WriteString(todo("在平台下拉中选择厂商（任务未关联企业）") + "\n\n")
	} else {
		b.WriteString("- 候选项（来源：任务关联企业）：" + strings.Join(units, " / ") + "\n")
		b.WriteString("- [ ] 请在平台下拉中确认厂商全称，平台内不存在时需先新增\n\n")
	}
	b.WriteString("> 厂商资产范围：平台固定「无限制」，无需填写。\n\n")

	// 域名或IP *
	b.WriteString("## 域名或IP *\n\n")
	if roots := v.RootDomains(); len(roots) > 0 {
		b.WriteString("- 主域名候选：" + strings.Join(roots, " / ") + "\n")
	} else {
		b.WriteString(todo("主域名或 IP") + "\n")
	}
	b.WriteString("- [ ] 平台要求「域名请提供主域名」，请确认上面是主域名而非子域名\n\n")

	// 漏洞类别
	fmt.Fprintf(&b, "## 漏洞类别\n\n- 建议：%s（可选项：%s / %s，请按资产类型确认）\n\n",
		butianCategory(v), ButianCategoryWeb, ButianCategoryIOT)

	// 漏洞标题
	fmt.Fprintf(&b, "## 漏洞标题\n\n%s\n\n", butianTitle(v))
	b.WriteString("> 生成规则：单位名称 + 存在 + 漏洞类型 + 漏洞（表单占位提示原文）。\n\n")

	// 漏洞URL *
	b.WriteString("## 漏洞URL *\n\n")
	if len(v.URLs) == 0 {
		b.WriteString(todo("以 http:// 或 https:// 开头的漏洞 URL，可添加多个") + "\n\n")
	} else {
		for i, u := range v.URLs {
			fmt.Fprintf(&b, "%d. %s\n", i+1, u)
		}
		b.WriteString("\n- [ ] 逐条确认 URL 可直接访问且属于该厂商\n\n")
	}

	// 漏洞类型（事件型 / 通用型）
	fmt.Fprintf(&b, "## 漏洞类型\n\n- 建议：%s（可选项：%s，按实际情况选择；本模板按公益 SRC 事件型表单输出）\n\n",
		ButianVulnTypes[0], strings.Join(ButianVulnTypes, " / "))

	// 其下无标签的联动下拉（细分类型）
	b.WriteString("## 细分类型（漏洞类型下方联动下拉）\n\n")
	if sub := butianSubType(v); sub != "" {
		fmt.Fprintf(&b, "- 建议：%s\n", sub)
	} else {
		b.WriteString(todo("从联动下拉中选择细分类型") + "\n")
	}
	b.WriteString("- 可选项：" + strings.Join(ButianSubTypes, "、") + "\n")
	b.WriteString("- [ ] 请人工确认；截图未覆盖的选项以平台实际下拉为准\n\n")

	// 漏洞等级
	fmt.Fprintf(&b, "## 漏洞等级\n\n- 建议：%s（项目等级 %s；以平台实际选项为准）\n\n",
		v.SeverityLabel(), nz(v.Severity, "未评级"))

	// 参与活动 / 任务
	b.WriteString("## 参与活动 / 任务\n\n- 不选即默认不参与，模板不生成值；如需参与请在平台表单自行选择。\n\n")

	// 简要描述 *
	b.WriteString("## 简要描述 *\n\n")
	brief := stripURLs(v.Summary)
	if brief == "" {
		b.WriteString(todo("一句话概述漏洞及影响") + "\n\n")
	} else {
		fmt.Fprintf(&b, "%s\n\n", brief)
	}
	b.WriteString("> 表单硬约束：「请勿在此填写漏洞URL等其他漏洞信息」，模板已主动剔除 URL。\n\n")

	// 详细填写 *
	b.WriteString("## 详细填写 *\n\n")
	repro := v.Section("复现", "重现", "利用过程", "验证过程", "PoC", "POC")
	poc := v.Section("PoC", "POC", "EXP", "Exploit", "利用", "Payload")
	impact := v.Section("影响", "危害", "风险")
	fix := v.Section("修复", "整改", "缓解", "建议")
	body := strings.TrimSpace(v.Report)

	b.WriteString("### ① 复现过程与影响范围\n\n")
	if repro != "" {
		b.WriteString(repro + "\n\n")
	} else if body != "" {
		b.WriteString(body + "\n\n")
	} else {
		b.WriteString(todo("复现过程与影响范围") + "\n\n")
	}
	if impact != "" {
		b.WriteString("**影响范围：**\n\n" + impact + "\n\n")
	}
	if e := strings.TrimSpace(v.Evidence); e != "" {
		b.WriteString("**已有证据：**\n\n" + codeBlock(e))
	}
	b.WriteString(v.TrafficMarkdown)
	b.WriteString("\n")

	b.WriteString("### ② 复现过程截图 / 厂商归属证明截图\n\n")
	b.WriteString(todo("本地上传复现过程截图（勿复制粘贴图片链接）") + "\n")
	b.WriteString(todo("本地上传厂商归属证明截图；缺归属证明可能被驳回") + "\n\n")

	b.WriteString("### ③ 所用组件下载链接或附件\n\n")
	b.WriteString(todo("组件名称、版本与下载链接，或上传附件") + "\n\n")

	b.WriteString("### ④ PoC / Exploit（思路清晰、可复现）\n\n")
	if poc != "" {
		b.WriteString(poc + "\n\n")
	} else {
		b.WriteString(todo("PoC / Exploit 或可复现的验证步骤") + "\n\n")
	}

	// 附件
	b.WriteString("## 附件\n\n")
	b.WriteString(todo("打包为 zip / rar，单个不超过 50M；可复用本项目 md-zip 证据包中的截图与报文") + "\n\n")

	// 修复方案
	b.WriteString("## 修复方案\n\n")
	if fix != "" {
		b.WriteString(fix + "\n\n")
	} else {
		b.WriteString(todo("修复方案") + "\n\n")
	}

	// 行业所属 / 行业分类
	b.WriteString("## 行业所属 / 行业分类\n\n")
	b.WriteString(todo("从下拉选择所属行业（三级联动中的第一级），并确认后续行业分类") + "\n")
	b.WriteString("- 可见选项：" + strings.Join(ButianIndustries, "、") + "\n")
	b.WriteString("- [ ] 以平台实际下拉为准；截图可能未覆盖全部选项\n\n")

	// 所属地区（省 / 市 / 区）
	b.WriteString("## 所属地区\n\n")
	b.WriteString(todo("省") + "\n")
	b.WriteString(todo("市") + "\n")
	b.WriteString(todo("区 / 县（三级联动，逐级选择）") + "\n\n")

	// 待补清单
	if missing := butianMissing(v); len(missing) > 0 {
		b.WriteString("## 待补充清单\n\n")
		for i, m := range missing {
			fmt.Fprintf(&b, "%d. %s\n", i+1, m)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func butianMissing(v View) []string {
	var out []string
	if len(v.Units()) != 1 {
		out = append(out, "厂商名称：任务未关联唯一企业，需在平台下拉选择厂商全称")
	}
	if len(v.RootDomains()) == 0 {
		out = append(out, "域名或IP：主域名或 IP")
	}
	if len(v.URLs) == 0 {
		out = append(out, "漏洞URL：以 http:// 或 https:// 开头的漏洞地址")
	}
	if butianSubType(v) == "" {
		out = append(out, "细分类型：漏洞类型下方联动下拉的选项")
	}
	if v.SeverityLabel() == "待定" {
		out = append(out, "漏洞等级：项目未评级，需人工选定")
	}
	if stripURLs(v.Summary) == "" {
		out = append(out, "简要描述：一句话概述（勿含 URL）")
	}
	if v.Section("复现", "重现", "利用过程", "验证过程", "PoC", "POC") == "" && strings.TrimSpace(v.Report) == "" {
		out = append(out, "详细填写：复现过程与影响范围")
	}
	out = append(out,
		"复现过程截图（本地上传）",
		"厂商归属证明截图（本地上传，缺失可能被驳回）",
		"所用组件下载链接或附件",
		"PoC / Exploit（若详细填写中未覆盖）",
		"附件：zip / rar，≤50M",
	)
	if v.Section("修复", "整改", "缓解", "建议") == "" {
		out = append(out, "修复方案")
	}
	out = append(out,
		"行业所属 / 行业分类（下拉选择）",
		"所属地区：省 / 市 / 区（三级联动）",
	)
	return out
}
