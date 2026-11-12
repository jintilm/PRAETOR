// Package report 的报告输出模板层。
//
// 三套模板（praetor / butian / edusrc）共用一份归一化 View：渲染层只负责
// 「字段映射 + 章节布局 + 待补项清单」，不编造数据，也不改数据库。
//
// 设计决策（2026-11-11 确认）：
//   - 模板是内置常量，不做用户自定义编辑器；平台改版时改代码发版。
//   - 一漏洞一份：补天、edusrc 都是平台表单的「一漏洞一提交」，绝不打包。
//     edusrc 官方规范要求「同单位同系统多漏洞点打包一个」，用户明确要求
//     不打包，风险由提交人承担（模板里会提示）。
//   - 证据不做脱敏：允许复测账号（含密码）原样输出；Cookie/Token/完整
//     HTTP 报文不自动内联，仍走证据包单独导出。
//   - praetor 模板保持字节级兼容：server 层在 praetor 时继续调用原有的
//     Markdown / FindingsMarkdown / SingleFindingMarkdown，本文件不接管。
package report

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jintilm/praetor/db"
)

// Template 是报告输出模板标识。注意与已有的 task_templates（任务描述预设）
// 完全无关，命名一律用 report_template / ReportTemplate 避让。
type Template string

const (
	TemplatePraetor Template = "praetor" // 项目原有模板（默认）
	TemplateButian  Template = "butian"  // 补天平台（公益 SRC 事件型表单）
	TemplateEdusrc  Template = "edusrc"  // 教育漏洞报告平台（edusrc）
)

var templateLabels = map[Template]string{
	TemplatePraetor: "PRAETOR 原有模板",
	TemplateButian:  "补天平台",
	TemplateEdusrc:  "edusrc 平台",
}

// ParseTemplate 严格校验模板名，空串归一到默认模板。用于任务创建与导出参数。
// 未知值返回错误而不是悄悄回落，避免把拼错的模板名写进数据库。
func ParseTemplate(s string) (Template, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "praetor", "default":
		return TemplatePraetor, nil
	case "butian":
		return TemplateButian, nil
	case "edusrc":
		return TemplateEdusrc, nil
	default:
		return "", fmt.Errorf("未知报告模板 %q（可用：praetor / butian / edusrc）", s)
	}
}

// NormalizeTemplate 是宽松版：读存量数据（可能是旧版本写入的脏值）时用，
// 未知值一律回落 praetor，保证老任务输出不变。
func NormalizeTemplate(s string) Template {
	t, err := ParseTemplate(s)
	if err != nil {
		return TemplatePraetor
	}
	return t
}

func (t Template) Label() string {
	if l, ok := templateLabels[t]; ok {
		return l
	}
	return templateLabels[TemplatePraetor]
}

// AllTemplates 返回内置模板的稳定顺序（前端下拉同序）。
func AllTemplates() []Template {
	return []Template{TemplatePraetor, TemplateButian, TemplateEdusrc}
}

// MobileMeta 是移动端（APK / IPA / 真机）任务的结构化目标信息。
// 三套模板共用同一份数据：包名 / 版本由 server 从发现正文解析，设备序列号与
// APK 指纹来自任务动态授权记录（撤销或过期后仍是事实，可供溯源）。
type MobileMeta struct {
	Platform     string `json:"platform"`
	Package      string `json:"package"`
	Version      string `json:"version"`
	DeviceSerial string `json:"device_serial"`
	APKSha256    string `json:"apk_sha256"`
	Source       string `json:"source"`
	Present      bool   `json:"present"`
}

func (m MobileMeta) Any() bool { return m.Present }

// Markdown / SubMarkdown 是三套模板共用的「移动端目标」小节，只是标题层级不同：
// 补天与 praetor 作为独立二级章节，edusrc 的「内容」里用三级，避免跳级。
// 缺的字段列成待补项，不编造包名或版本；非移动端任务返回空串，存量报告字节不变。
func (m MobileMeta) Markdown() string    { return m.markdown("##") }
func (m MobileMeta) SubMarkdown() string { return m.markdown("###") }

func (m MobileMeta) markdown(heading string) string {
	if !m.Present {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s 移动端目标（App）\n\n", heading)
	row := func(k, val string) {
		if strings.TrimSpace(val) != "" {
			fmt.Fprintf(&b, "- %s：%s\n", k, val)
		}
	}
	row("平台", m.Platform)
	row("应用包名 / Bundle ID", m.Package)
	row("应用版本", m.Version)
	row("授权设备序列号", m.DeviceSerial)
	row("授权 APK SHA256", m.APKSha256)
	row("字段来源", m.Source)
	b.WriteString("\n")
	if m.Package == "" {
		b.WriteString(todo("应用包名 / Bundle ID") + "\n")
	}
	if m.Version == "" {
		b.WriteString(todo("应用版本") + "\n")
	}
	b.WriteString("\n")
	return b.String()
}

// View 是三套模板唯一的输入。字段要么来自 findings 表 / 探索图节点，要么由
// server 层补充（企业名、资产域名、移动端目标）。渲染器不得反向查库。
type View struct {
	// Template 是本次导出对该份漏洞实际生效的模板。server 层按
	// 「?template= 显式覆盖 > 任务 report_template > praetor」填好。
	// 零值按 TemplatePraetor 处理，方便单模板调用与测试。
	Template        Template
	ID              int64
	Name            string
	VulnClass       string
	Severity        string
	Status          string
	Summary         string
	Evidence        string
	Report          string
	TaskDescription string
	CompanyNames    []string // tasks.company_ids → companies.name
	Hosts           []string // 资产反查的域名/IP + 从 URL 提取的 host
	URLs            []string // 从正文/证据/流量绑定提取的 http(s) URL
	TrafficMarkdown string   // 原模板的「关联流量证据」段落
	Attachments     []AttachmentView
	CreatedAt       time.Time
	GeneratedAt     time.Time
	Mobile          MobileMeta // 移动端目标；非移动端任务为零值，模板不输出
}

// AttachmentView is the renderer-facing projection of a finding attachment.
// Link is relative inside an md-zip package; DataURI is set only for md-single.
type AttachmentView struct {
	ID       int64
	Kind     string
	Filename string
	MIMEType string
	Size     int64
	SHA256   string
	Caption  string
	Role     string
	Source   string
	Link     string
	DataURI  string
}

// ViewFromFinding 把发现页导出的 findings 表行归一成 View。
func ViewFromFinding(f *db.DBFinding, now time.Time) View {
	if f == nil {
		return View{GeneratedAt: now}
	}
	v := View{
		ID: f.ID, Name: f.Name, VulnClass: f.VulnClass, Severity: f.Severity,
		Status: f.Status, Summary: f.Summary, Evidence: f.Evidence,
		Report: f.Report, TaskDescription: f.TaskDescription,
		CreatedAt: f.CreatedAt, GeneratedAt: now,
	}
	parts := []string{v.Summary, v.Evidence, v.Report}
	for _, b := range f.TrafficBindings {
		parts = append(parts, b.Snapshot.URL)
	}
	v.URLs = extractURLs(parts...)
	for _, u := range v.URLs {
		if h := hostOf(u); h != "" {
			v.Hosts = append(v.Hosts, h)
		}
	}
	v.Hosts = dedupe(v.Hosts)
	v.TrafficMarkdown = findingTrafficMarkdown(f, false)
	for _, a := range f.Attachments {
		v.Attachments = append(v.Attachments, AttachmentView{
			ID: a.ID, Kind: a.Kind, Filename: a.Filename, MIMEType: a.MIMEType,
			Size: a.Size, SHA256: a.SHA256, Caption: a.Caption, Role: a.Role, Source: a.Source,
			Link: fmt.Sprintf("evidence/%d/attachments/%d-%s", f.ID, a.ID, safeAttachmentReportName(a.Filename)),
		})
	}
	return v
}

// ViewFromNode 把任务报告（探索图 KindFinding 节点）归一成 View。
func ViewFromNode(n *db.Node, now time.Time) View {
	v := View{GeneratedAt: now}
	if n == nil {
		return v
	}
	v.ID = n.ID
	f := parseFinding(n)
	v.Name, v.VulnClass, v.Severity, v.Summary = f.Name, f.VulnClass, f.Severity, f.Summary
	v.Evidence = f.PoC
	v.URLs = extractURLs(v.Summary, v.Evidence)
	for _, u := range v.URLs {
		if h := hostOf(u); h != "" {
			v.Hosts = append(v.Hosts, h)
		}
	}
	v.Hosts = dedupe(v.Hosts)
	// 图节点 payload 可能带 created_at，取不到也不影响渲染。
	var meta struct {
		CreatedAt string `json:"created_at"`
	}
	_ = json.Unmarshal(n.Payload, &meta)
	if ts, err := time.Parse(time.RFC3339, meta.CreatedAt); err == nil {
		v.CreatedAt = ts
	}
	return v
}

// WithCompanies / WithHosts 供 server 层补充外部关联数据。
func (v View) WithCompanies(names []string) View {
	v.CompanyNames = dedupe(names)
	return v
}

func (v View) WithHosts(hosts []string) View {
	v.Hosts = dedupe(append(append([]string(nil), hosts...), v.Hosts...))
	for _, u := range v.URLs {
		if h := hostOf(u); h != "" {
			v.Hosts = append(v.Hosts, h)
		}
	}
	v.Hosts = dedupe(v.Hosts)
	return v
}

// WithMobile 供 server 层补充移动端目标信息。
func (v View) WithMobile(m MobileMeta) View {
	v.Mobile = m
	return v
}

// Title 是漏洞的可读名称（不是平台提交标题）。
func (v View) Title() string { return nz(v.Name, nz(v.VulnClass, "未分类")) }

// Unit 是「单位名称」：第一个关联企业名。多企业时不替用户选，返回空。
func (v View) Unit() string {
	if len(v.CompanyNames) == 1 {
		return strings.TrimSpace(v.CompanyNames[0])
	}
	return ""
}

// Units 返回所有候选单位名（多企业时列出来让人选）。
func (v View) Units() []string { return dedupe(v.CompanyNames) }

// RootDomains 把 Hosts 折叠成主域名/IP 候选，用于「域名或IP」「资产所在网段」。
func (v View) RootDomains() []string {
	var out []string
	for _, h := range v.Hosts {
		if r := rootDomain(h); r != "" {
			out = append(out, r)
		}
	}
	return dedupe(out)
}

func (v View) FirstURL() string {
	if len(v.URLs) > 0 {
		return v.URLs[0]
	}
	return ""
}

func (v View) SeverityLabel() string { return severityLabel(v.Severity) }

// Sections 把自由文本 Report 按 Markdown 标题切成 标题→正文。
func (v View) Sections() map[string]string { return splitSections(v.Report) }

// Section 按关键词模糊命中的第一个章节正文。
func (v View) Section(keywords ...string) string { return pickSection(v.Sections(), keywords...) }

// RenderFinding 渲染单个漏洞为一份 Markdown（一漏洞一提交）。
// praetor 由调用方走原函数，这里兜底也返回原模板的单条渲染。
func RenderFinding(v View, t Template) string {
	switch t {
	case TemplateButian:
		return renderButian(v)
	case TemplateEdusrc:
		return renderEdusrc(v)
	default:
		return renderPraetorSingle(v)
	}
}

// RenderMany 渲染多份，每份独立（不打包、不合并），前面加一段提交须知。
func RenderMany(vs []View, t Template, heading string) string {
	if heading == "" {
		heading = "漏洞提交材料"
	}
	// edusrc 的标题公开可见、只填单位名称。汇总文件的最外层 # 标题也不能带
	// 任务描述（通常含系统名/单位业务信息），否则整份复制时等于泄露标题内容。
	if containsTemplate(vs, t, TemplateEdusrc) {
		heading = "漏洞提交材料"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s（%s）\n\n", heading, t.Label())
	fmt.Fprintf(&b, "> 生成时间：%s；模板：%s；共 %d 份。\n", timeStamp(vs), templateSetLabel(vs, t), len(vs))
	if notes := templateNotices(vs, t); len(notes) > 0 {
		for _, n := range notes {
			fmt.Fprintf(&b, "> %s\n", n)
		}
	}
	b.WriteString("\n")
	if len(vs) == 0 {
		b.WriteString("_无匹配的漏洞。_\n")
		return b.String()
	}
	for i, v := range vs {
		one := effectiveTemplate(v, t)
		fmt.Fprintf(&b, "<!-- 第 %d/%d 份提交 · finding #%d · %s -->\n\n", i+1, len(vs), v.ID, one.Label())
		b.WriteString(RenderFinding(v, one))
		if i < len(vs)-1 {
			b.WriteString("\n---\n\n")
		}
	}
	return b.String()
}

// effectiveTemplate 让一次跨任务导出可以按各自的模板渲染（显式覆盖优先）。
func effectiveTemplate(v View, fallback Template) Template {
	if v.Template != "" {
		return v.Template
	}
	if fallback != "" {
		return fallback
	}
	return TemplatePraetor
}

func containsTemplate(vs []View, fallback, want Template) bool {
	if fallback == want {
		return true
	}
	for _, v := range vs {
		if effectiveTemplate(v, fallback) == want {
			return true
		}
	}
	return false
}

func templateSetLabel(vs []View, fallback Template) string {
	seen := map[Template]bool{}
	var order []Template
	for _, v := range vs {
		t := effectiveTemplate(v, fallback)
		if !seen[t] {
			seen[t] = true
			order = append(order, t)
		}
	}
	if len(order) == 0 {
		return fallback.Label()
	}
	var labels []string
	for _, t := range order {
		labels = append(labels, t.Label())
	}
	return strings.Join(labels, " / ")
}

func templateNotices(vs []View, fallback Template) []string {
	seen := map[Template]bool{}
	var out []string
	add := func(t Template) {
		if seen[t] || t == TemplatePraetor {
			return
		}
		seen[t] = true
		out = append(out, templateNotice(t))
	}
	add(fallback)
	for _, v := range vs {
		add(effectiveTemplate(v, fallback))
	}
	return out
}

func timeStamp(vs []View) string {
	for _, v := range vs {
		if !v.GeneratedAt.IsZero() {
			return v.GeneratedAt.Format("2006-01-02 15:04:05")
		}
	}
	return time.Now().Format("2006-01-02 15:04:05")
}

func templateNotice(t Template) string {
	switch t {
	case TemplateButian:
		return "补天表单是「一漏洞一提交」。各份之间不要合并；带「待补充」的字段需在平台表单人工确认或填写。"
	case TemplateEdusrc:
		return "edusrc 官方规范要求「同单位同系统多漏洞点打包一个」，本项目按用户决策改为一漏洞点一份，提交时若平台要求合并请自行处理。标题公开可见，只填单位名称。"
	default:
		return "一漏洞一份。"
	}
}

// MissingFields 列出该份提交仍需人工补齐的平台字段。
func MissingFields(v View, t Template) []string {
	switch t {
	case TemplateButian:
		return butianMissing(v)
	case TemplateEdusrc:
		return edusrcMissing(v)
	default:
		return nil
	}
}

// Checklist 生成 md-zip 里的「提交清单」，逐份列待补项，便于打包前核对。
func Checklist(vs []View, t Template) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# 提交清单（%s）\n\n", templateSetLabel(vs, t))
	for _, n := range templateNotices(vs, t) {
		fmt.Fprintf(&b, "> %s\n", n)
	}
	b.WriteString("\n")
	if len(vs) == 0 {
		b.WriteString("_无匹配的漏洞。_\n")
		return b.String()
	}
	for i, v := range vs {
		one := effectiveTemplate(v, t)
		fmt.Fprintf(&b, "## %d. %s（finding #%d · %s）\n\n", i+1, platformTitle(v, one), v.ID, one.Label())
		missing := MissingFields(v, one)
		if len(missing) == 0 {
			b.WriteString("- 字段已齐备，仍需人工核对平台下拉选项。\n\n")
			continue
		}
		for _, m := range missing {
			fmt.Fprintf(&b, "- [ ] %s\n", m)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// PlatformTitle 暴露平台提交标题（标题规则三套互不相同）。
func PlatformTitle(v View, t Template) string { return platformTitle(v, t) }

func platformTitle(v View, t Template) string {
	switch t {
	case TemplateButian:
		return butianTitle(v)
	case TemplateEdusrc:
		return edusrcTitle(v)
	default:
		return v.Title()
	}
}

func renderPraetorSingle(v View) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# [%s] %s\n\n", strings.ToUpper(nz(v.Severity, "info")), v.Title())
	if v.VulnClass != "" {
		fmt.Fprintf(&b, "- **类别**：%s\n", v.VulnClass)
	}
	if s := strings.TrimSpace(v.Summary); s != "" {
		fmt.Fprintf(&b, "\n## 概述\n\n%s\n\n", s)
	}
	if e := strings.TrimSpace(v.Evidence); e != "" {
		fmt.Fprintf(&b, "## 证据\n\n```\n%s\n```\n\n", e)
	}
	if r := strings.TrimSpace(v.Report); r != "" {
		b.WriteString("## 详细报告\n\n")
		b.WriteString(r)
		b.WriteString("\n\n")
	}
	b.WriteString(v.Mobile.Markdown())
	b.WriteString(v.TrafficMarkdown)
	b.WriteString(renderAttachmentMarkdown(v))
	return b.String()
}

func renderAttachmentMarkdown(v View) string {
	if len(v.Attachments) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n## 证据附件\n\n")
	for _, a := range v.Attachments {
		label := strings.TrimSpace(a.Caption)
		if label == "" {
			label = a.Filename
		}
		imageURL := a.Link
		if a.DataURI != "" {
			imageURL = a.DataURI
		}
		if strings.HasPrefix(a.MIMEType, "image/") && imageURL != "" {
			fmt.Fprintf(&b, "![%s](%s)\n\n", strings.ReplaceAll(label, "]", "\\]"), imageURL)
		}
		fmt.Fprintf(&b, "- 文件：`%s`（%s，%d 字节）\n", a.Filename, nz(a.Role, "supporting"), a.Size)
		if a.Source != "" {
			fmt.Fprintf(&b, "  来源：%s\n", a.Source)
		}
	}
	b.WriteString("\n")
	return b.String()
}

func safeAttachmentReportName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\x00", "_")
	if name == "" || name == "." || name == ".." {
		return "attachment"
	}
	return name
}

// --- 公共工具 ---

var urlRe = regexp.MustCompile("https?://[^\\s<>\"'`\\)\\]\\}，。；]+")

func extractURLs(parts ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range parts {
		for _, raw := range urlRe.FindAllString(p, -1) {
			u := cleanURL(raw)
			if u == "" || seen[u] {
				continue
			}
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

func cleanURL(s string) string {
	s = strings.TrimRight(s, ".,;:!?、，。；：！?)】》\"'`<>")
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return ""
	}
	return s
}

func hostOf(rawURL string) string {
	// net/url 对 URL 编码/端口都处理得比手写 split 稳。
	if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

func rootDomain(host string) string {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if host == "" {
		return ""
	}
	if net.ParseIP(host) != nil {
		return host // IP 直接作为「域名或IP」候选
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	// 常见二级公共后缀（com.cn / edu.cn / co.jp ...）保留三段，其余取两段。
	second, last := parts[len(parts)-2], parts[len(parts)-1]
	if len(last) == 2 && (second == "com" || second == "net" || second == "org" || second == "gov" || second == "edu" || second == "ac" || second == "co") {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func severityLabel(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	default:
		return "待定"
	}
}

// splitSections 按 Markdown 标题切分自由文本报告；标题归一化后作 key。
func splitSections(s string) map[string]string {
	out := map[string]string{}
	var cur string
	var buf []string
	flush := func() {
		if cur == "" {
			return
		}
		body := strings.TrimSpace(strings.Join(buf, "\n"))
		if body != "" {
			out[cur] = body
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			flush()
			cur = normalizeHeading(line)
			buf = nil
			continue
		}
		if cur != "" {
			buf = append(buf, line)
		}
	}
	flush()
	return out
}

func normalizeHeading(line string) string {
	h := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(line), "#"))
	h = strings.TrimSpace(h)
	// 去掉「1. 」「一、」这类编号，便于关键词匹配。
	h = strings.TrimLeft(h, "0123456789. 、")
	return h
}

func pickSection(secs map[string]string, keywords ...string) string {
	// 先按标题精确包含关键词，再退到正文包含；顺序稳定（按 key 排序）。
	keys := make([]string, 0, len(secs))
	for k := range secs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, kw := range keywords {
		for _, k := range keys {
			if strings.Contains(k, kw) {
				return secs[k]
			}
		}
	}
	return ""
}

// stripURLs 用于补天「简要描述」：表单明确要求「请勿在此填写漏洞URL等其他
// 漏洞信息」，所以模板主动把 URL 从摘要里剔除。
func stripURLs(s string) string {
	s = urlRe.ReplaceAllString(s, "")
	s = regexp.MustCompile(`[ \t]{2,}`).ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

func todo(label string) string { return "- [ ] 待补充：" + label }

func codeBlock(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return "```\n" + strings.TrimSpace(s) + "\n```\n"
}
