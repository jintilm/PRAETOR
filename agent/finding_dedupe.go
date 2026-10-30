package agent

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/jintilm/praetor/db"
	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// 这一组函数实现 report_finding 的「同任务、同类、同位置」去重判定。
//
// 背景（2026-10-30 实测，task 206）：6 条 finding 实际只描述 3 个问题 ——
// 反射型 XSS 写了 3 遍（`反射型 XSS (Reflected Cross-Site Scripting)` /
// `跨站脚本（反射型 XSS）` / `Reflected XSS`），DEBUG 信息泄露写了 2 遍，SSTI 1 遍。
// 后果不是"多几行"：报表里同一问题出现三次、漏洞计数虚高、triager 要逐条核对。
// goal 的重复（task 198 的 4 个同文本 goal）已经用幂等解掉了，finding 不能照抄那套：
// **文本天然会变**（换个措辞就是一条），按字符串相等判会全漏。
//
// 设计取舍：只做「疑似」判定，命中时**不新增**并把已有编号回给模型，
// 由模型决定是否带 `distinct: true` 重新提交。
// 理由：合并错了会丢真实漏洞，比重复严重得多；而"同一参数上的同一类问题"这个条件足够窄，
// 误判时模型自己就能纠正（它知道自己是换了参数还是换了措辞）。

// findingFamilyAliases 把中英文混写的 vulnclass 归到粗粒度 family。
//
// 只收**公认叫法**，不做语义猜测：family 为空表示"没把握"，此时一律不去重
// （宁可留一条重复，也不要因为分类器认错而吞掉一个新漏洞）。
var findingFamilyAliases = []struct {
	family  string
	aliases []string
}{
	{"xss", []string{"xss", "跨站脚本", "crosssitescripting"}},
	{"sqli", []string{"sqli", "sql注入", "sqlinjection"}},
	{"ssti", []string{"ssti", "模板注入", "templateinjection"}},
	{"ssrf", []string{"ssrf", "服务端请求伪造", "server-siderequestforgery"}},
	{"rce", []string{"rce", "远程代码执行", "命令执行", "命令注入", "commandinjection", "codeexecution", "remotecodeexecution"}},
	{"lfi", []string{"lfi", "路径穿越", "目录穿越", "pathtraversal", "directorytraversal", "文件包含", "fileinclusion"}},
	{"xxe", []string{"xxe", "外部实体", "externalentity"}},
	{"csrf", []string{"csrf", "跨站请求伪造"}},
	{"deserialization", []string{"反序列化", "deserialization"}},
	{"fileupload", []string{"文件上传", "fileupload", "unrestrictedupload"}},
	{"openredirect", []string{"开放重定向", "openredirect"}},
	{"authbypass", []string{"认证绕过", "authbypass", "brokenauthentication", "未授权访问"}},
	{"idor", []string{"idor", "越权", "brokenaccesscontrol", "访问控制失效"}},
	{"infoleak", []string{"信息泄露", "informationdisclosure", "sensitiveinformation", "调试模式", "debug", "配置错误", "misconfiguration", "traceback", "infoleak"}},
	{"weakcred", []string{"弱口令", "weakpassword", "defaultcredential"}},
}

var (
	// 路径：先剥掉 scheme，避免把 http:// 里的 // 当成路径。
	findingSchemeRe = regexp.MustCompile(`(?i)https?://`)
	findingPathRe   = regexp.MustCompile(`(?:/[A-Za-z0-9_.\-]+)+`)
	// 参数名：覆盖 URL query、curl --data-urlencode 'name=…'、"name 参数"、"参数 name" 四种写法。
	findingParamRes = []*regexp.Regexp{
		regexp.MustCompile(`[?&]([A-Za-z][A-Za-z0-9_\-]*)=`),
		regexp.MustCompile(`['"]([A-Za-z][A-Za-z0-9_\-]*)=\s*[^'"\s]`),
		regexp.MustCompile(`([A-Za-z][A-Za-z0-9_\-]*)\s*参数`),
		regexp.MustCompile(`参数\s*[：:]?\s*([A-Za-z][A-Za-z0-9_\-]*)`),
	}
	// 参数名里常见的非参数词（出现在 URL/请求头上下文里，容易被上面几条正则误抓）。
	findingParamNoise = map[string]bool{
		"http": true, "https": true, "get": true, "post": true, "put": true,
		"host": true, "content": true, "type": true, "charset": true, "user-agent": true,
	}
)

// findingFeature 是一条 finding 用于比对的特征。
type findingFeature struct {
	family   string
	paths    map[string]bool
	params   map[string]bool
	shingles map[string]bool
}

// featureOf 从 vulnclass/name/summary/evidence 提取比对特征。
// vulnclass/name 只用来判 family；路径与参数从正文里找（模型通常写在 summary 或 PoC 里）。
func featureOf(vulnclass, name, summary, evidence string) findingFeature {
	return findingFeature{
		family:   findingFamily(vulnclass, name),
		paths:    findingPaths(summary, evidence),
		params:   findingParams(summary, evidence),
		shingles: textShingles(summary, 3),
	}
}

// normalizeFindingText 去掉空白与标点，只留字母数字（含 CJK）。
// 跨语言没法做词干，做到"标点与大小写不干扰"就够用了。
func normalizeFindingText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// findingFamily 返回粗粒度类别；空串 = 认不出（调用方应当放弃去重）。
func findingFamily(vulnclass, name string) string {
	norm := normalizeFindingText(vulnclass + " " + name)
	if norm == "" {
		return ""
	}
	for _, f := range findingFamilyAliases {
		for _, alias := range f.aliases {
			if strings.Contains(norm, alias) {
				return f.family
			}
		}
	}
	return ""
}

// findingPaths 抽出正文里出现的路径（小写、去尾斜杠），用于判断"是不是同一个位置"。
func findingPaths(texts ...string) map[string]bool {
	out := map[string]bool{}
	for _, t := range texts {
		if t == "" {
			continue
		}
		clean := findingSchemeRe.ReplaceAllString(t, " ")
		for _, m := range findingPathRe.FindAllString(clean, -1) {
			p := strings.ToLower(strings.TrimRight(m, "/"))
			// 只要看起来像资源路径的：至少两段或长度 ≥4，过滤掉 "/1"、"/x" 这类噪声。
			if len(p) < 4 && strings.Count(p, "/") < 2 {
				continue
			}
			out[p] = true
		}
	}
	return out
}

// findingParams 抽出正文里出现的参数名。
func findingParams(texts ...string) map[string]bool {
	out := map[string]bool{}
	for _, t := range texts {
		if t == "" {
			continue
		}
		for _, re := range findingParamRes {
			for _, m := range re.FindAllStringSubmatch(t, -1) {
				if len(m) < 2 {
					continue
				}
				p := strings.ToLower(m[1])
				if findingParamNoise[p] || len(p) < 1 {
					continue
				}
				out[p] = true
			}
		}
	}
	return out
}

// textShingles 生成字符 n-gram 集合（归一化后）。
func textShingles(s string, n int) map[string]bool {
	norm := normalizeFindingText(s)
	if norm == "" {
		return nil
	}
	// 超长文本只取前 4000 字符：finding 的摘要不该有这么大，截断是为了避免
	// 有人把整篇 PoC 塞进 summary 时把去重判断拖慢。
	if len(norm) > 4000 {
		norm = norm[:4000]
	}
	out := make(map[string]bool, len(norm))
	for i := 0; i+len([]rune("x")) <= len(norm); i++ {
		r := []rune(norm)
		if i+n > len(r) {
			break
		}
		out[string(r[i:i+n])] = true
	}
	return out
}

func intersects(a, b map[string]bool) bool {
	small, big := a, b
	if len(a) > len(b) {
		small, big = b, a
	}
	for k := range small {
		if big[k] {
			return true
		}
	}
	return false
}

func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if b[k] {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// likelyDuplicate 判断两条 finding 是不是"同一个问题的不同措辞"。
//
// 规则（从严到宽）：
//  1. family 必须相同且非空 —— 认不出类别就不去重；
//  2. 两边都识别出参数名时，**必须**有交集：不同参数是不同漏洞（同一 /greet 上的 name 与 msg）；
//  3. 两边都识别出路径且完全不交时，不是同一个位置；
//  4. 兜底看文本相似度（3-gram Jaccard ≥ 0.12）。
//
// 阈值 0.12 来自实测校准（task 206 的 6 条 finding）：真实重复对 0.19~0.32，
// 不同问题对 0.03~0.09。取 0.12 在两者之间，且只在"没有参数可比"时才用到。
func likelyDuplicate(a, b findingFeature) bool {
	if a.family == "" || a.family != b.family {
		return false
	}
	if len(a.params) > 0 && len(b.params) > 0 {
		return intersects(a.params, b.params)
	}
	if len(a.paths) > 0 && len(b.paths) > 0 && !intersects(a.paths, b.paths) {
		return false
	}
	return jaccard(a.shingles, b.shingles) >= 0.12
}

// findingNodePayload 是 kind=finding 节点 payload 里与去重相关的字段。
type findingNodePayload struct {
	VulnClass string          `json:"vulnclass"`
	Name      string          `json:"name"`
	Summary   string          `json:"summary"`
	Severity  string          `json:"severity"`
	Evidence  json.RawMessage `json:"evidence"`
}

// poc 取 evidence 里的 PoC 文本（evidence 是 {by,poc} 对象；老数据可能是纯字符串）。
func (p findingNodePayload) poc() string {
	if len(p.Evidence) == 0 {
		return ""
	}
	var obj struct {
		POC string `json:"poc"`
	}
	if err := json.Unmarshal(p.Evidence, &obj); err == nil && obj.POC != "" {
		return obj.POC
	}
	var s string
	if err := json.Unmarshal(p.Evidence, &s); err == nil {
		return s
	}
	return ""
}

// findDuplicateFinding 在本任务的已有 finding 里找一条与入参高度相似的。
// 返回 (节点, 已有条目的 vulnclass)；没有则返回 (nil, "")。
func (t *ToolSet) findDuplicateFinding(vulnclass, name, summary, evidence string) (*db.Node, string) {
	if t == nil || t.ts == nil {
		return nil, ""
	}
	cur := featureOf(vulnclass, name, summary, evidence)
	if cur.family == "" {
		return nil, ""
	}
	nodes, err := t.ts.ListByKind(db.KindFinding, 200)
	if err != nil || len(nodes) == 0 {
		return nil, ""
	}
	for _, n := range nodes {
		var p findingNodePayload
		if err := json.Unmarshal(n.Payload, &p); err != nil {
			continue
		}
		if likelyDuplicate(cur, featureOf(p.VulnClass, p.Name, p.Summary, p.poc())) {
			return n, p.VulnClass
		}
	}
	return nil, ""
}

// duplicateFindingNotice 是命中重复时回给模型的话。
//
// 必须同时给出三件事：已有编号、为什么判成重复、以及**怎么继续**——
// 只丢一句"已存在"会让模型不知道是该放弃还是该重试。句末保留 distinct 的用法，
// 因为那是唯一的破例通道，也是"这次真的不是同一个问题"时的正确动作。
func duplicateFindingNotice(n *db.Node, existingClass string) string {
	label := fmt.Sprintf("节点 #%d", n.ID)
	if n.FindingID > 0 {
		label = fmt.Sprintf("finding #%d（节点 #%d）", n.FindingID, n.ID)
	}
	return fmt.Sprintf(
		"未新增：本任务已有疑似同一问题的漏洞 %s（%s）。同一位置、同一参数上的同一类问题只登记一次，"+
			"避免报表重复计数。\n"+
			"如果本次确实是不同问题（不同参数、不同位置或不同利用方式），请带 \"distinct\": true 重新调用 report_finding；"+
			"否则请直接引用已有编号（例如 prove_goal / verify_finding）。",
		label, strings.TrimSpace(existingClass))
}

// findingReportLocks 按任务串行化 report_finding 的「查重 + 落库」两步。
//
// 为什么需要（task 206 的真实成因）：同一个任务的 3 个 worker 是**并行**跑的，
// 它们各自查重都查不到（别人还没写完），然后各插一条 —— 6 条重复里有 5 条是这样来的。
// 只做"先查后插"而不加临界区，单测能过、真机照样重复。
//
// 用进程内锁而不是 DB advisory lock：一个任务的 worker/planner 都在同一个进程里，
// 进程内锁足够；引入 DB 锁就要把"查重规则"搬进 db 层，而规则依赖 agent 侧的语义判断。
var findingReportLocks sync.Map // map[int64]*sync.Mutex

// findingLockKey 决定去重锁的分片键：优先用任务 id，没有任务时退到探索 id
// （取负数做命名空间，避免与任务 id 撞号）。两者都没有才返回 0 = 不加锁。
//
// 为什么不直接用 taskID：测试与部分内部流程里 ToolSet 只有探索上下文，
// 没有 tasks 行（强行设一个不存在的 taskID 会让 RecordFinding 查不到任务而报
// "no rows in result set"）。去重是"同一张探索图内"的事，用探索 id 分片同样正确。
func (t *ToolSet) findingLockKey() int64 {
	if t == nil {
		return 0
	}
	if t.taskID > 0 {
		return t.taskID
	}
	if t.ts != nil {
		return -t.ts.ID()
	}
	return 0
}

// findingReportLock 取该任务的写锁；key 为 0（无任务/无探索上下文）时返回 nil。
func findingReportLock(taskID int64) *sync.Mutex {
	if taskID == 0 { // 0 = 既无任务也无探索上下文；负数是被允许的探索命名空间
		return nil
	}
	v, _ := findingReportLocks.LoadOrStore(taskID, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// logDuplicateFinding 打一条可审计的日志：命中去重不是静默行为，排查时需要知道
// "模型报了 6 条为什么库里只有 3 条"。
func logDuplicateFinding(taskID int64, incoming string, n *db.Node, existingClass string) {
	log.Printf("[finding] task %d 未新增疑似重复：%q ← 已有 #%d（%s）",
		taskID, strings.TrimSpace(incoming), n.ID, strings.TrimSpace(existingClass))
}

// duplicateFindingResult 是命中重复时的完整动作：记日志 + 回给模型的文本。
// 收在这里是为了让 tools.go 不必为了打一行日志而引入 log 包。
func (t *ToolSet) duplicateFindingResult(incoming string, dup *db.Node, existingClass string) actool.Result {
	logDuplicateFinding(t.taskID, incoming, dup, existingClass)
	return actool.Text(duplicateFindingNotice(dup, existingClass))
}
