package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jintilm/praetor/agent/domain"
	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/intercept"
	"github.com/jintilm/praetor/internal/norma/agentcore"
	"github.com/jintilm/praetor/internal/norma/harness"
	"github.com/jintilm/praetor/internal/norma/llm"
	"github.com/jintilm/praetor/internal/norma/permission"
	"github.com/jintilm/praetor/internal/norma/subagent"
	"github.com/jintilm/praetor/internal/norma/tool"
	actool "github.com/jintilm/praetor/internal/norma/tool"
	"github.com/jintilm/praetor/internal/norma/transcript"
	"github.com/jintilm/praetor/llmrec"
)

// Worker is an LLM work agent (docs §4.4): it claims ONE intent, completes it
// with real tools (Bash: kali tooling through the recording proxy), writes the
// FACTS it found back into the graph, and stops. It does NOT generate new
// directions (that is the planner's job) and does NOT keep exploring toward the
// goal on its own. Multiple workers run concurrently as goroutines.
// WebSearchOpts is the web-search backend selection the server pushes into each
// agent (planner/worker/main). Enabled=false leaves the web_search tool off.
// Backend is "ddgs" (no key), "brave-free" (BraveKey required), "tavily"
// (TavilyKey required), or "deepseek" (DeepSeek* required, filled from the
// active LLM profile). It maps directly onto agentcore.Options.
// Proxy is a dedicated egress proxy for the search request (http/https/socks5),
// independent of the traffic-recording MITM proxy — set it when the search endpoint
// is only reachable via a VPN/SOCKS proxy. Empty = direct.
//
// 注意 deepseek 后端与其它三个的性质不同：DeepSeek 没有可直接调用的搜索接口，
// 搜索只存在于其 Anthropic 兼容 messages 接口内部(web_search_20250305 server
// tool)，因此每次搜索会消耗一次模型调用，且搜索请求由 DeepSeek 服务端发出——
// 不经过本机 Proxy，也不会进流量留痕。
type WebSearchOpts struct {
	Enabled   bool
	Backend   string
	BraveKey  string
	TavilyKey string
	Proxy     string
	// DeepSeek* 来自当前激活的 LLM 配置(仅 anthropic 格式的 DeepSeek 官方端点)，
	// 不单独配置，随 LLM 配置切换而变。
	DeepSeekBaseURL string
	DeepSeekAPIKey  string
	DeepSeekModel   string
}

type Worker struct {
	findingRecorder FindingRecorder
	findingVerifier FindingVerifier // nil = 未启用确定性验证
	prov            llm.Provider
	model           string
	workDir         string
	proxyAddr       string
	proxyCACert     string            // recording proxy's CA cert path (for WebFetch HTTPS verify)
	webSearch       WebSearchOpts     // web_search tool backend selection (off by default)
	tx              *transcript.Store // raw LLM conversation persistence (nil = off)
	window          int               // context window in tokens (for compaction)
	windowFn        func() int        // optional dynamic task-chain minimum
	maxTurns        int               // max agent turns per run (0 = unlimited)
	// runTimeout is the wall-clock budget for the main exploration of one intent
	// (0 = unlimited). When it fires, the run is cut and a settlement round is
	// forced so already-identified facts get written back instead of being lost.
	runTimeout time.Duration
	// 沙箱容器内的任务工作根（如 /work）；空 = Bash 在宿主执行。
	//
	// 为什么需要它：宿主侧的 runDir 是 <data>/tasks/<taskID>/i<intentID>，而容器只挂了
	// <data>/work/<taskID> -> /work —— 两棵树毫无对应。把宿主路径写进系统提示词，
	// 模型开局第一件事就是 `cd E:\...\tasks\25\i141`，必然失败，然后它会在
	// /work 和那个不存在的路径之间反复试探，白白烧掉几轮上下文。
	sandboxWorkRoot string
	// sandboxPath 把容器内路径翻成宿主路径（仅沙箱模式注入；nil = 不在沙箱）。
	//
	// sandboxWorkRoot 解决的是「提示词里该写哪个路径」，这个解决的是「文件工具怎么打开它」。
	// 两者必须成对：只改提示词，模型会用 /chal/... 调 LS/Read，而文件工具跑在宿主进程里，
	// 于是报 ENOENT（Windows 上还会把 /chal 当相对路径，错信息里混进宿主 data 目录）。
	sandboxPath func(string) (string, bool)
	// subagentRoles 惰性提供本域的子 agent 角色表（nil = 该域不启用派生）。
	// 由 server 注入：CTF 域返回 lead 可派的 solver 定义；渗透/红队域不注入。
	// 惰性是因为角色表与任务领域挂钩，而 worker 实例可能在领域判定前创建。
	subagents func() (map[string]subagent.Definition, int, error)
	// toolFaceOnce 让「本 worker 的工具面」只打一行日志（与 planner.logToolFace 对称）。
	//
	// 为什么要专门记一行：P1-4 的失效表现不是报错，而是**工具面上少一个工具**。
	// 没有这一行，"模型没派子 agent" 与 "Agent 工具根本没给它" 在日志里长得一模一样，
	// 只能靠读代码猜（本轮 task 182 就是这么卡住的）。
	toolFaceOnce sync.Once
	// campaignGate 是红队战役的阶段闸门（nil = 不在战役域）。
	// 判定在 internal/campaign，server 注入一个"读进度 + 判定"的闭包。
	campaignGate func(string) error
	// cleanupGuard 是收尾前的清理判定（nil = 不在战役域）。
	cleanupGuard func() (bool, []string)
	// sandboxWriteDeny 回答「沙箱模式下这个路径能不能写」：空串 = 可以，非空 = 拒绝理由。
	//
	// 与 sandboxPath 成对：路径能翻过去，不等于能写 —— 容器里 /chal 是 ro，
	// 而未挂载的 /tmp、/etc 会落到宿主上，两者都必须在写入口挡住。
	sandboxWriteDeny func(string) string
	// extraTools are host-provided tools (e.g. traffic query, oast) appended to
	// the worker's graph write-back tools.
	// domain 是任务领域（pentest/reverse/ctf），用于裁剪 worker 工具面。
	domain string
	// ctfSubmitter 是 CTF 判题后端（仅 ctf 域注入）。
	ctfSubmitter CTFSubmitter
	// ctfChallenge 是题面来源（仅 ctf 域注入）。
	ctfChallenge CTFChallengeSource
	// ctfBoard 是题目看板/放弃记录（仅 ctf 域注入）。
	ctfBoard   CTFBoardProvider
	extraTools []actool.CoreTool
	// injectConstraints resolves whether this task's operation constraints get
	// injected into the worker system prompt. Read per run so the settings toggle
	// takes effect without rebuilding the agent. nil = inject (default).
	injectConstraints func() bool
	// nonStreamingFn resolves whether this run uses the non-streaming (Complete)
	// path. Read per run so a profile/task toggle takes effect without rebuilding
	// the agent. nil = streaming (default).
	nonStreamingFn func() bool
	// noaEnabledFn resolves whether this run uses the experimental noa context-
	// compression mechanism. Read per run, like nonStreaming. nil = off (built-in
	// compaction).
	noaEnabledFn func() bool
	// maxTokensFn resolves the per-reply output cap in tokens, on the same
	// per-run basis. nil or 0 = send no cap and let the endpoint decide.
	maxTokensFn func() int
}

// WorkerSessionID returns the stable transcript key used by a worker intent.
// Worker slots are reusable, so the intent id (rather than work#N) is the
// session identity. Keep this helper public so the Worker message API and UI
// can refer to exactly the conversation that will be resumed.
func WorkerSessionID(explorationID, intentID int64) string {
	return fmt.Sprintf("exp%d-worker-i%d", explorationID, intentID)
}

const workerChatMarkerPrefix = "<!-- PRAETOR_WORKER_CHAT:"

func workerChatMarker(requestID string) string {
	return workerChatMarkerPrefix + requestID + " -->"
}

func hasWorkerChatMessage(messages []llm.Message, requestID string) bool {
	marker := workerChatMarker(requestID)
	for _, message := range messages {
		if message.Role == llm.RoleUser && strings.Contains(message.Text(), marker) {
			return true
		}
	}
	return false
}

// SetNonStreaming wires a resolver deciding whether runs use the non-streaming
// model path (true = non-streaming). nil/unset = streaming (default). Read per
// run so a profile or task-chain toggle takes effect without rebuilding.
// SetDomain 设置任务领域：worker 的工具面按领域裁剪（逆向/CTF 专属工具不进渗透任务）。
func (w *Worker) SetDomain(domainKey string) { w.domain = domainKey }

// SetCTFSubmitter 注入 CTF 判题后端（nil = ctf_submit 明确报不可用）。
func (w *Worker) SetCTFSubmitter(s CTFSubmitter) { w.ctfSubmitter = s }

// SetSandboxWorkRoot 告知"Bash 跑在容器里、容器内的任务工作根在哪"（如 /work）。
//
// 传空 = 宿主执行，提示词继续用宿主绝对路径。由装配层按沙箱实际状态注入，
// 不要在 agent 内部猜环境——猜错的方向有两种，都会让模型拿到打不开的路径。
func (w *Worker) SetSandboxWorkRoot(dir string) { w.sandboxWorkRoot = strings.TrimSpace(dir) }

// SetSandboxPath 注入「容器内路径 → 宿主路径」的翻译器（nil = 不在沙箱）。
func (w *Worker) SetSandboxPath(fn func(string) (string, bool)) { w.sandboxPath = fn }

// SetSubagentRoles 注入本域的子 agent 角色表（nil = 不启用 Agent 派生工具）。
// 返回 (角色定义表, 最大派生深度, 错误)；构造失败时 execute 降级为不注册 Agent 工具
// 并打日志 —— 子 agent 是加速器，配置坏了不该让任务起不来。
func (w *Worker) SetSubagentRoles(fn func() (map[string]subagent.Definition, int, error)) {
	w.subagents = fn
}

// SetCampaignGate 注入红队战役的阶段闸门（nil = 不在战役域）。
func (w *Worker) SetCampaignGate(fn func(string) error) { w.campaignGate = fn }

// SetCleanupGuard 注入"战役欠不欠清理"的判定（nil = 不在战役域）。
func (w *Worker) SetCleanupGuard(fn func() (bool, []string)) { w.cleanupGuard = fn }

// SetSandboxWriteDeny 注入「这个容器路径能不能写」的判断（nil = 不在沙箱）。
func (w *Worker) SetSandboxWriteDeny(fn func(string) string) { w.sandboxWriteDeny = fn }

// promptRunDir 返回**写进系统提示词**的工作目录。
//
// 容器模式下映射到 <sandboxWorkRoot>/i<intentID>：容器里只挂了任务的工作根，
// 宿主 tasks/<id>/i<id> 那棵树根本不存在（详见 sandboxWorkRoot 字段的注释）。
func (w *Worker) promptRunDir(runDir string, intentID int64) string {
	if w.sandboxWorkRoot == "" {
		return runDir
	}
	if intentID <= 0 {
		return w.sandboxWorkRoot
	}
	return path.Join(w.sandboxWorkRoot, "i"+strconv.FormatInt(intentID, 10))
}

// SetCTFChallengeSource 注入题面来源（nil = ctf_challenge 明确报不可用）。
func (w *Worker) SetCTFChallengeSource(s CTFChallengeSource) { w.ctfChallenge = s }

// SetCTFBoard 注入题目看板（nil = ctf_board 明确报不可用）。
func (w *Worker) SetCTFBoard(b CTFBoardProvider) { w.ctfBoard = b }

func (w *Worker) SetNonStreaming(fn func() bool) { w.nonStreamingFn = fn }

func (w *Worker) nonStreaming() bool { return w.nonStreamingFn != nil && w.nonStreamingFn() }

// SetNoaEnabled wires a resolver deciding whether runs use the experimental noa
// context-compression mechanism. nil/unset = off (built-in compaction). Read per
// run so the settings toggle takes effect without rebuilding the agent.
func (w *Worker) SetNoaEnabled(fn func() bool) { w.noaEnabledFn = fn }

// SetMaxTokens wires a resolver for the per-reply output cap. nil/unset or 0 =
// send no cap and let the endpoint decide. Read per run, like nonStreaming.
func (w *Worker) SetMaxTokens(fn func() int) { w.maxTokensFn = fn }

func (w *Worker) maxTokens() int {
	if w.maxTokensFn == nil {
		return 0
	}
	return w.maxTokensFn()
}

// SetConstraintInject wires a resolver deciding whether this task's operation
// constraints get injected into the worker system prompt. nil = inject (default).
func (w *Worker) SetConstraintInject(fn func() bool) { w.injectConstraints = fn }

// wantConstraints reports whether constraint injection is enabled (default yes).
func (w *Worker) wantConstraints() bool { return w.injectConstraints == nil || w.injectConstraints() }

// SetRunTimeout configures the per-intent wall-clock budget for the main
// exploration (0 = unlimited). When it fires, the SDK settlement phase still runs
// so facts are never lost to a timeout. Safe to call before Execute.
func (w *Worker) SetRunTimeout(run time.Duration) {
	w.runTimeout = run
}

// settleWrapUpPrompt is injected by the SDK settlement phase when a worker hits its
// turn/time budget: stop probing, write back what was found, then end with a
// plain-text one-liner (which becomes this run's displayed result).
const settleWrapUpPrompt = "你即将因预算耗尽被终止。不要再运行任何命令/探测。请依次：(1) 把你上面已识别但还没写回的内容逐条写回——新资产用 insert_assets、探索结论/事实用 record_fact、确认漏洞用 report_finding；(2) **最后单独用一句话纯文本**总结你做了什么、得到哪些关键结论（这句会作为本次运行的结果展示，务必输出）。"

func NewWorker(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int, extra ...actool.CoreTool) *Worker {
	return &Worker{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns, extraTools: extra}
}

// defaultToolsExcept returns actool.DefaultTools() minus the named tools (by
// CoreTool.Name()). Used to trim SDK default tools an agent shouldn't have.
func defaultToolsExcept(exclude ...string) []actool.CoreTool {
	drop := make(map[string]bool, len(exclude))
	for _, n := range exclude {
		drop[n] = true
	}
	all := actool.DefaultTools()
	out := make([]actool.CoreTool, 0, len(all))
	for _, t := range all {
		if !drop[t.Name()] {
			out = append(out, t)
		}
	}
	return out
}

func (w *Worker) SetCompactionWindowResolver(fn func() int) { w.windowFn = fn }

func (w *Worker) compactionWindow() int {
	if w.windowFn != nil {
		return w.windowFn()
	}
	return w.window
}

// SetProxy configures the recording proxy address that workers route target
// traffic through, plus the CA cert path WebFetch trusts to verify HTTPS through
// that MITM proxy. Empty addr disables the hint.
func (w *Worker) SetProxy(addr, caCert string) { w.proxyAddr, w.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for this worker (off by default).
func (w *Worker) SetWebSearch(o WebSearchOpts) { w.webSearch = o }

// proxyEnv builds the Bash-subprocess env that routes child-command HTTP through
// the egress proxy (the recording MITM when capture is on, or the global proxy
// directly when it is off) and, only when a MITM CA is present, makes the common
// toolchain trust it — so tools need no manual -x/--proxy/-k. Each ecosystem reads
// a different CA var (verified empirically): SSL_CERT_FILE→curl/urllib/Go/openssl,
// REQUESTS_CA_BUNDLE→python requests (it ignores SSL_CERT_FILE), CURL_CA_BUNDLE→curl,
// GIT_SSL_CAINFO→git, NODE_EXTRA_CA_CERTS→node; NODE_USE_ENV_PROXY makes Node 24+
// honor the proxy vars. ALL_PROXY is set too so a socks5 egress proxy (which curl
// only reads from ALL_PROXY, not HTTP(S)_PROXY) works in the capture-off path.
// Empty proxyAddr → nil (direct, unchanged env).
func proxyEnv(proxyAddr, caCert string) []string {
	if proxyAddr == "" {
		return nil
	}
	env := []string{
		"HTTP_PROXY=" + proxyAddr, "HTTPS_PROXY=" + proxyAddr,
		"http_proxy=" + proxyAddr, "https_proxy=" + proxyAddr,
		"ALL_PROXY=" + proxyAddr, "all_proxy=" + proxyAddr, // socks5 egress: curl reads only this
		"NODE_USE_ENV_PROXY=1", // Node 24+: honor HTTP(S)_PROXY in built-in fetch/http
	}
	if caCert != "" {
		env = append(env,
			"SSL_CERT_FILE="+caCert,
			"CURL_CA_BUNDLE="+caCert,
			"REQUESTS_CA_BUNDLE="+caCert,
			"GIT_SSL_CAINFO="+caCert,
			"NODE_EXTRA_CA_CERTS="+caCert,
		)
	}
	return env
}

// workerDefaultTmpl is the built-in EDITABLE body (段 [A]) of the worker system
// prompt, seeded into agent_prompts. The trafficTool block and the 中间产物输出规约
// are NOT here — they are code-owned and appended by workerSystem after rendering
// (段 [B]/[C]), so editing the DB body can never drop them.
const workerDefaultTmpl = `你是一个网络安全平台授权渗透测试系统的"执行者"(work agent)。你领到【一条意图】(一句话探索方向)，唯一职责：**完成这一条意图、把发现写回知识图谱、然后停止返回。**

**边界（红线）**：
1. **只做你领到的这一条意图**。**探本意图时若瞥见本意图之外值得深挖的线索**（报错泄露的路径、可能与其它资产联动的点、疑似另一条利用链的入口），**在 fact 的 summary 里点一句交给规划者**。
2. 初次受阻（payload 被过滤 / 404 / 注入无回显）不代表已探透——把本意图的所有绕过手段走完再输出结论；
3. 只在授权范围内操作。系统提示顶部若附【操作约束】，那是最高优先级红线：每条命令/探测执行前先自检，违反即不做（哪怕它落在你领到的意图里）。

**边发现边写回**（写进图才算数，脑子/文字里的不算；每得一个结果立刻写，别攒到最后被步数耗尽丢掉）。三种写回，别串图：
- **新资产/资源 → insert_assets（资产图）**：子域 / service / endpoint / 指纹 / 凭据 等一切资产【本身】。**这里只登记资产；探索结论/判断不写这里，用 record_fact。**
- **探索结论/事实 → record_fact（探索图，传 intent_id）**：都用它。**多个观察汇总成【一条】事实**（summary 一句总结 + detail写对总结的拓展，依靠真实的执行过程），不要一个属性一条、一意图通常只一条，拆碎会让图谱无限膨胀——**默认就写一条，能并进 detail 的都并进去**；仅当确有【彼此完全独立、无法归并】的结论时才用 facts 数组分条，这是极少数例外，不是常规。**只写增量**：只记这次【新得到】的，别把已有事实换措辞重记（只印证已有、无新增就不必记）。**只写真实看到的**：给 evidence（一行：命令+最能证明的一两行输出，简洁，细节在 detail）、标 confidence（observed=直接看到 / inferred=据现象推断）。
- **确认漏洞 → report_finding（探索图，含 PoC，传 intent_id）**：**只有你本次真实触发过、拿到可复现证据（请求/响应或命令输出）才用**。严禁把"版本/指纹匹配到 CVE""参数看起来可注入""外部漏洞库/更新日志/代码 diff 推断"当已确认，也不要用查 CVE 库或对比补丁版本替代实际触发。触发不了但有嫌疑 → 用 record_fact 记一条 inferred 事实（嫌疑点+为何未触发）交规划者，别硬记成 finding。


完成本意图后用一句话总结你做了什么、写回了哪些事实。`

// workerTrafficBlock is 段 [B]: the traffic-tool note, code-injected only when
// traffic capture (recording) is on — i.e. the traffic_* tools actually exist.
// Gated on recording, NOT on the egress proxy: a global proxy with capture off
// routes traffic but records nothing, so the tools would not be there. Not stored,
// not editable.
func workerTrafficBlock(recording bool) string {
	if !recording {
		return ""
	}
	return "\n\n**流量工具**：\n- traffic_search / traffic_get / traffic_blob：回看响应、找已访问过的资源，**先查流量、不要重复 curl 同一 URL**。traffic_search **必须指定 host**、默认只回 3 条极轻量索引(id/method/url/status/resp_len，无响应内容)，需要更多显式调大 limit；可用 body_contains 在请求/响应正文里做全文搜索(至少 3 字符，支持子串和中文，如找密码/密钥/报错/内网地址)；要看某条原文用 traffic_get(id)，其中超大正文显示为 @blob sha256:<hash>，用 traffic_blob(hash) 分段取全文。"
}

// artifactSpec is 段 [C]: the code-owned, non-editable tail appended to every
// pentest agent's prompt — intermediate artifacts must land in the shared work
// dir, never /tmp. Guaranteed present regardless of how the DB body is edited.
func artifactSpec(dir string) string {
	return "\n\n**中间产物输出规约**：脚本、payload、抓到的响应体、临时数据等一切中间产物，**一律写到本任务工作目录 " + dir + "**（相对路径即写在这里，也可用该绝对路径）——**不要写 /tmp、不要用其它绝对路径**。"
}

// workerArtifactSpec is the worker's 段 [C]: its per-intent run dir is pre-created
// by the engine (ensureRunDir), so it just writes relative paths there — no manual
// mkdir, no cross-worker name collisions.
func workerArtifactSpec(runDir string) string {
	return "\n\n**中间产物输出规约**：脚本、payload、抓到的响应体、临时数据等一切中间产物，**一律写到本次意图的专属工作目录 " + runDir + "**（已自动建好，直接用相对路径写在这里即可，无需再手动建目录）——**不要写 /tmp、不要用其它绝对路径**。"
}

// ensureRunDir builds and creates an agent's working directory under base:
// <base>/tasks/<taskID> for planner/main; <base>/tasks/<taskID>/i<intentID> for a
// worker (intentID<=0 → task dir only). The "tasks/" segment groups per-task dirs
// symmetrically with the chat agent's "sessions/<sessionID>". Best-effort mkdir — on
// failure, writes fail the same way an unwritable CWD would.
func ensureRunDir(base string, taskID, intentID int64) string {
	dir := filepath.Join(base, "tasks", strconv.FormatInt(taskID, 10))
	if intentID > 0 {
		dir = filepath.Join(dir, "i"+strconv.FormatInt(intentID, 10))
	}
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// cmdOutDir is the SDK large-tool-output spill dir under an agent's run dir.
func cmdOutDir(dir string) string { return filepath.Join(dir, "cmd-output") }

// logToolFace 把本 worker 实际装配出的工具面打一行（每 worker 进程内一次）。
//
// 与 planner.logToolFace 对称。P1-4 的失效模式是「工具面上少一个工具」而没有任何报错，
// 这一行是唯一能在日志里区分「模型没派子 agent」和「Agent 工具根本没给它」的证据。
func (w *Worker) logToolFace(taskID int64, tools []actool.CoreTool) {
	w.toolFaceOnce.Do(func() {
		names := make([]string, len(tools))
		for i, t := range tools {
			names[i] = t.Name()
		}
		sort.Strings(names)
		dom := w.domain
		if dom == "" {
			dom = "默认"
		}
		log.Printf("[tools] task %d worker 工具面(%s, 共 %d): %s",
			taskID, dom, len(names), strings.Join(names, " "))
	})
}

// sortedKeys 返回排序后的角色名。排序是为了让提示词与日志在多次 run 之间稳定
// （map 迭代顺序随机，不排序会让同一段提示词每次都不一样，既干扰阅读也让缓存失效）。
func sortedKeys(defs map[string]subagent.Definition) []string {
	keys := make([]string, 0, len(defs))
	for k := range defs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// subagentBrief 拼出「可派给谁、什么时候该派」的提示词段落。
//
// 为什么必须有：Agent 工具只有一句通用的英文描述（"Delegates a self-contained
// sub-task…"），而 worker 的其余指令全是中文、围绕单一意图展开。没有这一段，模型会
// 沿着既有习惯自己往下做 —— task 182 的 69 次 Bash / 0 次 Agent 就是这么来的。
// 角色说明用的是域自己声明的 Description（谁擅长什么），不在这里重复硬编码领域知识。
func subagentBrief(defs map[string]subagent.Definition) string {
	if len(defs) == 0 {
		// 空表返回空串：不能承诺"有子 agent 可派"却一个角色都不给 ——
		// 模型会照着这段去调 Agent，然后拿到 unknown agent_type。
		return ""
	}
	keys := sortedKeys(defs)
	var b strings.Builder
	b.WriteString("\n\n【可派生的子 agent（Agent 工具）】\n")
	b.WriteString("你有一个 Agent 工具：把「自成一体的子任务」交给隔离的子 agent 执行。它有自己的上下文和工具集，" +
		"只把最终结论交回给你 —— 它跑出来的大量中间输出不会堆进你的上下文，你只需要读那一句结论。\n")
	b.WriteString("可用角色（agent_type）：\n")
	for _, k := range keys {
		b.WriteString("- " + k + "：" + defs[k].Description + "\n")
	}
	b.WriteString("该派的时候：子任务边界清晰、能独立完成、且会产生大量中间输出（起服务、扫目录、爆破、" +
		"写脚本反复调参、长时间抓包）。这类活自己干会把上下文堆满，派出去只回一句结论。\n")
	// "默认先派"这一句是实测补上的：只写"该派的时候"，模型会把它读成「可选优化」，
	// 于是继续沿既有习惯自己从第一条命令做起（task 183：侦察 15 次 Bash 后才想起可以派，
	// 那时父 run 的剩余时间已不够，派发被压到极短）。提示词的默认值必须写明，否则默认永远是
	// "自己干" —— 自己干在单轮里永远是最省事的那个选择。
	b.WriteString("默认动作：接到一条完整挑战/整条链路时，**先判断它属于哪个角色，然后派给对应子 agent 去做**，" +
		"你自己负责拆解、验收、写回结论。不要从第一条侦察命令开始把整件事自己做完 —— " +
		"你的上下文是这次 run 里最稀缺的资源，中间过程的噪音应该留在子 agent 那边。\n")
	b.WriteString("不该派的时候：一两步就能答的、必须你亲自读全局态势判断的、或者本轮剩余时间连两分钟都不到" +
		"（派发前有预算检查；剩余不够时会自动压缩子任务的墙钟，连最小可用时间都不够才会拒绝）。\n")
	b.WriteString("派发要点：子 agent 看不到你的上下文，prompt 里要写清「从哪开始、做什么、什么算完成、要带回什么产物」。\n")
	return b.String()
}

// leadPromptFor 返回「当 worker 就是本域 lead 时」要追加的下半段提示词。
//
// 只有声明了 LeadRunner 且 WorkerIsLead() 为真的域才有内容（CTF / 逆向）。渗透与红队
// 的 lead 是 planner，worker 只是执行者 —— 给它们注入「你负责统筹、把活派出去」会让
// worker 去规划，破坏既有秩序，所以那里必须返回 nil。
//
// 提示词正文取 RolePrompt（域约束 + lead 角色段），与子 agent 读到的是同一份：
// 以前它只喂给 solver 自己，真正做决策的 lead 反而读不到。task 182（69 次 Bash、
// 0 次 Agent）就是这条链的结果，见 docs §5.5(6)。
func leadPromptFor(domainKey string) []string {
	p, ok := domain.Get(domain.Key(domainKey))
	if !ok {
		return nil
	}
	lr, ok := p.(domain.LeadRunner)
	if !ok || !lr.WorkerIsLead() {
		return nil
	}
	for _, r := range p.Roles() {
		if r.Kind == domain.RoleLead {
			return domain.RolePrompt(p, r)
		}
	}
	return nil
}

func workerSystem(proxyAddr, caCert, dataDir, runDir string) string {
	body := renderSystem("worker", workerDefaultTmpl, WorkerVars{ProxyAddr: proxyAddr, DataDir: dataDir, Now: nowStr()})
	// caCert is present only when the recording MITM is on, which is exactly when
	// the traffic_* tools are registered — so it gates the traffic-tool note.
	// Optional finding guidance is added for every role after tool resolution.
	return body + workerTrafficBlock(caCert != "") + workerArtifactSpec(runDir)
}

// renderIntentTask formats the claimed intent for the worker's launch USER message:
// the intent is the worker's whole job. It used to live in the system prompt; it now
// rides in the first user turn (together with the situational overview) so the system
// prompt stays static/role-only — same move as the planner's situational block.
// intentAssetIDs pulls the intent's target asset ids out of its payload
// (planner's add_intent stores them as a numeric asset_ids array). nil on absence
// or malformed payload.
func intentAssetIDs(intent *db.Node) []int64 {
	if intent == nil {
		return nil
	}
	var p struct {
		AssetIDs []int64 `json:"asset_ids"`
	}
	if err := json.Unmarshal(intent.Payload, &p); err != nil {
		return nil
	}
	return p.AssetIDs
}

func renderIntentTask(intent *db.Node) string {
	return fmt.Sprintf("\n\n【你领到的意图（本次唯一任务：只做这一条、只产生事实、做完即停）】：\n%s\n意图 id: %d（写回 record_fact / report_finding 时传它）", string(intent.Payload), intent.ID)
}

// renderWorkerGraphOverview folds the global situational snapshot into the worker's
// launch USER message for AWARENESS ONLY. The framing is deliberately strong: the overview
// must NOT widen the worker's job — it still does only its assigned intent. Its sole
// purpose is letting the worker read context (existing facts/assets/hints)
// so it avoids redundant work and doesn't re-derive what others already found.
func renderWorkerGraphOverview(data map[string]any) string {
	// coverage 是给规划者判断「哪类测得少 / 要不要扩范围」的信号，与 worker「只做领到的
	// 那条意图、别追未覆盖的点」的职责边界相悖 → 从 worker 视图里剔除。data 是本次 worker
	// 专属的新 map，删键不影响 planner。
	delete(data, "coverage")
	b, err := json.Marshal(data)
	if err != nil {
		return "" // fall back silently: the worker just won't have the global context
	}
	return "\n\n【全局探索态势（只读，帮你把自己这条意图放进大局看）】：\n" +
		"下面是整个任务当前的探索概况。用途有两个：一是知道别人已发现什么，别重复；二是让你探自己这条意图时，能联想到它和全局的关系。\n" +
		"**发散是好事**：探本意图时尽管深想、多联想。唯一的界线是——别真的动手去执行别的意图（那是别的 worker 的事，由规划者调度）。但凡你联想到有价值的线索（跨资产的联动、疑似另一条利用链的入口、全局层面的可疑点），**务必写进 fact 交规划者**——这是你重要的产出，不是可有可无。宁可多报一条让规划者判断，也别自己咽下去。\n" +
		string(b)
}

// Execute runs one intent. hooks (the per-task Guard) gates every tool call; may
// be nil. emit, if non-nil, receives one ActivityRecord per execution step.
// notifyFinding, if non-nil, is called (intentID, summary) when this worker writes
// a finding (report_finding) so the task's planner wakes mid-flight — with context
// on which intent found what — instead of waiting for the worker to finish.
// Returns the terminal reason (so the engine can distinguish completed vs
// max_turns) and a per-kind breakdown of what was written back (so an intent that
// explored but persisted nothing isn't mistaken for done, and the engine can log
// facts/assets/findings separately instead of lumping them under "facts").
func (w *Worker) Execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string)) (harness.TerminalReason, WriteCounts, error) {
	return w.execute(ctx, name, taskID, as, ts, intent, hooks, emit, enr, notifyFinding, "", "")
}

// ExecuteWithMessage runs the next turn in the same intent conversation with a
// human-authored message. The HTTP handler does not edit the transcript;
// agentcore records the message as a normal user turn when this Worker starts.
// This keeps Worker continuation identical to the regular agent chat flow.
func (w *Worker) ExecuteWithMessage(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string), requestID, message string) (harness.TerminalReason, WriteCounts, error) {
	return w.execute(ctx, name, taskID, as, ts, intent, hooks, emit, enr, notifyFinding, strings.TrimSpace(requestID), strings.TrimSpace(message))
}

func (w *Worker) execute(ctx context.Context, name string, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, intent *db.Node, hooks harness.HookRunner, emit func(db.Activity), enr EnrichTrigger, notifyFinding func(int64, string), requestID, message string) (harness.TerminalReason, WriteCounts, error) {
	tsx := NewToolSet(ts, name)
	tsx.SetDomain(w.domain) // 领域专属工具按任务领域裁剪（逆向/CTF 工具不进渗透任务）
	tsx.SetCTFSubmitter(w.ctfSubmitter)
	tsx.SetCTFChallengeSource(w.ctfChallenge)
	tsx.SetCTFBoard(w.ctfBoard)
	tsx.SetFindingRecorder(w.findingRecorder)
	tsx.SetFindingVerifier(w.findingVerifier)
	tsx.SetTaskID(taskID)
	tsx.SetDefaultIntent(intent.ID)     // 图写回归口：子 agent（solver）没传 intent_id 时落到本意图
	tsx.SetCampaignGate(w.campaignGate) // 红队战役：前置未满足的意图不下发（nil = 非战役域）
	tsx.SetCleanupGuard(w.cleanupGuard) // 红队战役：欠清理不许收尾
	coverageEnabled := as == nil || as.CoverageEnabled(taskID)
	tsx.SetCoverageEnabled(coverageEnabled)
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetOwnerNode(intent.ID)         // assets this worker discovers anchor to its intent → visible to the task
	tsx.SetEnrich(enr)                  // async DNS/HTTP auto-completion for assets this worker writes
	tsx.SetNotifyFinding(notifyFinding) // report_finding 落库时当场唤醒 planner，带上「哪个意图+finding」
	// base = built-in worker tools ∪ host tools (traffic) ∪ default tools (incl. Bash);
	// then augment with the agent's visible skills/MCP. During the SDK settlement
	// phase, Bash is hidden via Settlement.DisabledTools (no local gating needed).
	base := append(tsx.WorkerTools(), w.extraTools...)
	// worker 刻意不给 MultiEdit/Glob/Grep：文件精改用 Edit、检索走 Bash(grep/find)，
	// 收敛工具面、减少低价值调用。其余 SDK 默认工具(Read/Write/Edit/LS/Bash/Sleep)照常。
	base = append(base, defaultToolsExcept("MultiEdit", "Glob", "Grep")...)
	// Worker 名一并带进去：竞速拓扑下两路要跑不同模型（server/llm_lane.go），
	// 而 runinfo 是唯一能跨到 LLM 解析层的每-run 身份。
	ctx = WithRunInfo(ctx, RunInfo{TaskID: taskID, ExplorationID: explorationID(ts), IntentID: intent.ID, Worker: name, Domain: w.domain})
	// emitWrap 先于 Agent 工具注册定义：子 agent 的 activity tap 也要走同一归口
	// （NodeID = 本意图，Worker = 本 worker 名），不然子代理动作在图上无归属。
	intentID := intent.ID
	emitWrap := func(r db.Activity) {
		if emit != nil {
			r.NodeID, r.Worker = &intentID, name
			emit(r)
		}
	}
	tools, fullTools, def, cleanup := AugmentTools(ctx, "worker", base)
	defer cleanup()

	// Linux 域的 Bash 必须真能跑 Linux：沙箱未就绪时用「永远拒绝」的 Bash 顶替。
	//
	// 为什么不在启动期直接让任务失败：任务还能跑（Read/Write/Grep/图谱写回都在宿主），
	// 只是跑不了命令。让它在第一条 Bash 上拿到一句可读的原因，比烧 20 分钟超时、
	// 或者让模型对着 PowerShell 的语法错误反复"修正"要便宜得多。判据见 bashRefusalReason。
	if needsPOSIXDomain(w.domain) {
		if reason, refuse := bashRefusalReason(SandboxState(), actool.HostShellIsPOSIX()); refuse {
			log.Printf("[worker] task %d 域 %s 需要 Linux 环境，Bash 已替换为拒绝执行（sandbox=%s）", taskID, w.domain, SandboxState())
			tools = refuseTool(tools, "Bash", reason)
		}
	}

	// 子 agent 派生（CTF 第一批、逆向第二批，渗透/红队刻意不接 —— planner/worker
	// 与战役闸门是既有秩序，再叠一层是重复建设）。worker 就是域 lead：
	//   - CTF：lead 按题型把「解一道题」派给 solver-*（web/pwn/rev/crypto/forensics）；
	//   - 逆向：re-lead 把「验证一条假设」派给 re-analyst，串行（证据链纪律），见 reversePack.Budget。
	// 每个 solver 独立上下文 —— lead 的上下文不会堆满所有尝试记录；产物经共享
	// ToolSet 归口回本意图（SetDefaultIntent）。
	// 域开关在 server 侧（subagentsEnabledFor / PRAETOR_SUBAGENTS 灰度），
	// 这里只看角色表有没有注入 —— 判定权集中一处，避免两边各写一套域列表。
	// 权限继承父（ModeBypass）：solver 在沙箱里跑，逐调用审批会卡死无人的后台任务。
	// 降级语义：角色表构造失败只记日志，任务照常 —— 子 agent 是加速器不是依赖。
	// 但"只记日志"必须真的记：原来这里是 `if err == nil && len(rawDefs) > 0`，
	// 失败与"角色表为空"挤进同一个 else 且**什么都不打**，于是 Agent 工具从工具面
	// 静默消失 —— 排查时只能看到"模型没派子 agent"，看不到"工具根本没给它"。
	// 这条链正是 P1-4 想解决的失效模式（静默降级），所以失败必须出声。
	// 派生角色表在 execute 期展开（惰性）。成功时把 defs 提到外层：
	// 下面还要用它拼「可派给谁」的提示词段落 —— 工具注册与提示词必须是同一份角色表，
	// 两处各读一次会在"页面上刚改过角色"的窗口里给出不一致的答案。
	var subagentDefs map[string]subagent.Definition
	if w.subagents != nil {
		rawDefs, maxDepth, err := w.subagents()
		if err != nil {
			log.Printf("[subagent] task %d 角色表构造失败，本次不注册 Agent 派生工具（任务继续）: %v", taskID, err)
		} else if len(rawDefs) == 0 {
			log.Printf("[subagent] task %d 角色表为空（领域 %s 未声明角色？），本次不注册 Agent 派生工具", taskID, w.domain)
		} else {
			defs := make(map[string]subagent.Definition, len(rawDefs))
			for k, d := range rawDefs {
				// 权限继承父（ModeBypass）：solver 在沙箱里跑，逐调用审批会卡死无人的后台任务。
				d.PermissionMode = permission.ModeBypass
				defs[k] = d
			}
			subagentDefs = defs
			// ParentTools 用组装后的完整工具集：solver 的白名单（如 Bash/Read/Write/ctf_submit）
			// 从中过滤；Agent 自身也在 registry 里，但 solver 白名单不含它 —— 不会递归派生。
			//
			// baseCtx 是【子 agent 的根上下文】：worker 自己的 ctx（engine 的 workCtx 派生），
			// 它**没有本次 run 的墙钟 deadline** —— 那个 deadline 是 harness 给 toolCtx 加的，
			// 而 run() 拿到的正是 toolCtx。以前子 agent 直接从 toolCtx 派生，于是父 run 的
			// 20 分钟到点，所有在飞的 solver 一起被 DeadlineExceeded 硬砍（无收尾、无部分产出，
			// 整段派发作废后重派；task 35 就是这么烧掉两倍的）。
			//
			// 取消权一点没丢：workCtx 在 pause / kill_work / 任务删除 / Execute 返回时都会被
			// 取消，子 agent 跟着死。子 agent 本来就不该活过父 run —— 父 run 结束后没人收它的
			// 结果，活着只是继续烧 token。
			// 刻意忽略传入的 parent 参数：父 toolCtx 正是要去掉 deadline 的那个。
			baseCtx := ctx
			agentTool := subagent.NewTool(subagent.Config{
				Provider:    w.prov,
				ParentTools: tool.NewRegistry(fullTools...),
				Agents:      defs,
				MaxDepth:    maxDepth,
				BaseCtx:     func(context.Context) context.Context { return baseCtx },
				// 派生的每个角色都带 agent_type 进用量账本(worker 泳道不变)。不接的话
				// solver/re_analyst 的消耗全混在 worker 行里,"哪个角色贵"只能猜 ——
				// 实测窗口里这类无法归因的调用占了 17.5% 的计费输入。见 docs §6 (P1-5)。
				TagCtx: llmrec.WithAgentType,
				// 子 agent 的中间过程镜像进 activity：不接的话 solver 在 UI 上是黑盒
				//（task 35 真机验证确认的缺口）。见 subagentActivityTap。
				OnEvent: subagentActivityTap(emitWrap),
			})
			tools = append(tools, agentTool)
		}
	}
	// 工具面落一行日志（每 worker 一次）。这条与 planner 的同名日志对称，
	// 是「Agent 到底有没有进工具面」的唯一直接证据。
	w.logToolFace(taskID, tools)

	// 意图是 worker 的【唯一职责、贯穿整个 run 的不变量】→ 连同启动指令、意图锚定的目标资产
	// 原始数据一起放进 system prompt：system 每次 run 都重新拼一遍、绝不会被 compaction 压掉，
	// 长 run 里意图永远在场，续跑时也不依赖 transcript 历史是否留住那条首消息。代价是 system
	// 混入 per-intent 易变数据、失去跨意图缓存复用；这是刻意的取舍（意图丢失比省 token 严重得多）。
	// 与 planner「态势块放 user turn」分叉是有意的：planner 本身是产意图的那个、没有单一 mandate，
	// worker 有。仅【全局态势 overview】留在启动 user 消息里——它可降级、容忍 stale，压掉无碍。
	// 本次意图的专属工作目录 <workDir>/tasks/<taskID>/i<intentID>，引擎侧先建好。
	runDir := ensureRunDir(w.workDir, taskID, intent.ID)
	// The run-wide intent is not the current tool action. Do not forward it or
	// inherit a parent run's background into the action reviewer.
	ctx = intercept.WithReviewContext(ctx, runDir, intercept.ReviewBackground{})
	overview := renderWorkerGraphOverview(tsx.graphOverviewData())
	sysBody := workerSystem(w.proxyAddr, w.proxyCACert, w.workDir, w.promptRunDir(runDir, intent.ID))
	if w.wantConstraints() {
		sysBody += constraintBlock(ts) // 操作约束(若有)注入系统提示,worker 执行时严格遵守
	}
	// 意图块 → 意图锚定资产块 → 启动指令，依次追加到 system 尾部（与 constraintBlock 同一套追加法）。
	// 取证红线独立于 DB 提示词与「约束注入」开关：它是系统级不变量（实测 agent 会去
	// cat 题目目录、翻镜像层、甚至自建带 flag 的容器），不随运营配置增减。
	sysBody += evidenceRedline
	sysBody += renderIntentTask(intent)
	if as != nil {
		if ids := intentAssetIDs(intent); len(ids) > 0 {
			if assets, err := as.GetByIDs(ids); err == nil && len(assets) > 0 {
				if b, err := json.Marshal(assets); err == nil {
					sysBody += "\n\n本意图 asset_ids 对应的目标资产：\n" + string(b)
				}
				// 意图明确针对的这些资产 → 自动纳入任务测试范围（与 insertAssets 同一套
				// 保守粒度）。upsertTaskScope 的 ON CONFLICT DO NOTHING + uq_task_scope
				// 唯一索引保证不会重复添加；重跑/重试同样是幂等 no-op。
				// 资产覆盖度功能关闭时不再累积测试范围(分母)。
				if coverageEnabled {
					for _, a := range assets {
						_ = as.AddAutoScope(taskID, a.Type, a.Domain, a.URL, a.IP)
					}
				}
			}
		}
	}
	// 派生能力必须写进提示词，不能只靠工具描述。
	//
	// 实测依据（task 182，P1-4 真机验证）：Agent 工具已在工具面上，账号日志里能看到
	// 69 次 Bash、0 次 Agent —— lead 自己把活全干了。原因不是工具缺失，而是**没人告诉它
	// 该派活**：worker 读到的是通用 worker 模板（workerSystem），而「识别题型后分派给
	// 对应 solver」这句只写在 ctfPack.Prompt() 里，那个函数只喂给子 agent 自己的系统提示，
	// 从来不给 lead 读。于是模型手上有一个英文工具，却没有一条中文指令要求它用。
	// 角色清单来自同一份 defs（与工具注册同源），避免两处各读一次角色表。
	if len(subagentDefs) > 0 {
		sysBody += subagentBrief(subagentDefs)
		// 与工具面日志成对：一个说"工具给了"，一个说"也告诉它怎么用了"。
		// 少了后者，排查时无法区分「模型不知道能派」与「模型知道但选择不派」。
		log.Printf("[subagent] task %d 已注入派生提示（%d 个角色: %s）",
			taskID, len(subagentDefs), strings.Join(sortedKeys(subagentDefs), " "))
		// 本域 lead 职责（CTF / 逆向的 lead 就是 worker；渗透/红队返回空）。
		// 放在 subagentBrief 之后：先讲"能派给谁"，再讲"作为 lead 该怎么推进"。
		// 只在有 Agent 工具时注入 —— 没有派发能力却要求"交给 analyst 验证"，
		// 模型会反复尝试一个不存在的动作。
		if lead := leadPromptFor(w.domain); len(lead) > 0 {
			sysBody += "\n\n【本域 lead 职责】\n" + strings.Join(lead, "\n")
			log.Printf("[subagent] task %d 已注入域 lead 提示（%s）", taskID, w.domain)
		}
	}
	sysBody += "\n\n开始执行上面这条意图：只做它、只产生事实、assets、finding、做完即停。"
	system, boundary := deferredSystem(sysBody, def)
	// 任务级 deadline(经 ctx 注入)夹逼本 run 的墙钟预算 + 决定收尾词(见 taskclock.go)。
	tc := taskClockFrom(ctx)
	maxDur, clamped := clampMaxDuration(tc.DeadlineUnix, w.runTimeout)
	settle := wrapupSettlement("worker", []string{"Bash"})
	if tc.DeadlineUnix > 0 {
		settle = wrapupSettlementForTask("worker", []string{"Bash"}, clamped)
	}
	opts := agentcore.Options{
		Provider:        w.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		// WebFetch 走记录代理，其 HTTP 与 curl 一样被留痕；载入代理 CA 让经 MITM
		// 重签的 HTTPS 证书能【正常校验通过】（而非关掉校验）。proxy 空则直连。
		EnableWebFetch: true,
		WebFetchProxy:  w.proxyAddr,
		WebFetchCACert: w.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立的出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:       w.webSearch.Enabled,
		WebSearchBackend:      w.webSearch.Backend,
		BraveSearchAPIKey:     w.webSearch.BraveKey,
		TavilySearchAPIKey:    w.webSearch.TavilyKey,
		DeepSeekSearchBaseURL: w.webSearch.DeepSeekBaseURL,
		DeepSeekSearchAPIKey:  w.webSearch.DeepSeekAPIKey,
		DeepSeekSearchModel:   w.webSearch.DeepSeekModel,
		WebSearchProxy:        w.webSearch.Proxy,
		// Bash 子命令的 HTTP 默认走记录代理 + 信任其 CA（工具无需 -x/-k）。
		BashEnv:          proxyEnv(w.proxyAddr, w.proxyCACert),
		WorkingDir:       runDir,
		SandboxPath:      w.sandboxPath,
		SandboxWriteDeny: w.sandboxWriteDeny,
		MaxTurns:         w.maxTurns, // 0 = unlimited (configurable in agent management)
		// 墙钟预算,轮边界判,不打断半路;0 = 不限。有任务级 deadline 时夹逼到 min(自身预算,
		// 距 deadline 剩余),让本 run 在任务到点时自然进收尾(见 taskclock.go)。
		MaxDuration: maxDur,
		// 每 N 轮把「还剩多少轮 / 多少墙钟」作为一条 user 消息注入（P2-8）。
		// 用同一对 (maxTurns, maxDur) 构造：提醒的数字必须与 SDK 真正判定用的上限同源，
		// 否则会出现"提示说还有 10 轮、第 3 轮就被砍"这种比不提示更坏的误导。
		BudgetNotice: newBudgetNotice(w.maxTurns, maxDur),
		// 命中预算(轮次 OR 时长)→ SDK 跑一轮收尾(隐藏 Bash),把已识别的写回,避免烂尾。
		// clamped(被任务 deadline 夹逼)时用 PromptByReason:因超时=任务到点→任务超时词,
		// 因步数=夹逼窗口内步数先耗尽→回落 per-run 词。非 clamped 维持纯 per-run。
		Settlement: settle,
		// large tool output spills to cmd-output/ with a head + pointer (SDK tool.Capture);
		// full output preserved on disk.
		//
		// 上限收紧到 12000 字符（SDK 默认 30000）——这是实测算出来的账：
		// benchmark 里 agent 最爱干的一件事是 `curl http://target/`，一个整页 HTML
		// 就有 30KB≈10K tokens。而**工具输出会留在对话里，之后每一轮都重发**，
		// 一次抓页面按 20 轮算就是 200K tokens 的输入账单（实测 XBEN-019 单题
		// 368K input，其中 30KB 那一条占了工具输出的 64%）。
		// 12000 字符仍够看清一个页面的结构/表单/链接（真正需要全文时 agent 可以
		// Read 落盘的 cmd-output 文件——spill 保留了全文，只是不塞进上下文）。
		ToolOutputDir:      cmdOutDir(runDir),
		MaxToolOutputChars: 12000,
		Compaction:         compactionConfig(w.compactionWindow()), // long tool-heavy runs stay within the window
		Todos:              actool.NewTodoStore(),                  // 会话级临时待办（TodoWrite），纯规划用，退出即丢
		NonStreaming:       w.nonStreaming(),                       // 该 profile 选非流式时走 Provider.Complete
		MaxTokens:          w.maxTokens(),                          // 0 = 不发上限,由服务端默认值决定
	}
	if hooks != nil { // typed-nil guard: only set when concrete (avoids harness panic)
		opts.Hooks = hooks
	}
	if w.tx != nil { // persist raw LLM conversation; one file per worked intent
		opts.Transcript = w.tx
		opts.SessionID = WorkerSessionID(ts.ID(), intent.ID)
	}
	// 意图 / 启动指令 / 意图锚定资产已随 system prompt 下发（见上方 sysBody 组装）。
	// 这条启动 user 消息只承载【全局态势 overview】——可降级的了解大局信息，压掉无碍。
	// overview 罕见地 marshal 失败为空时，回退一句启动词，避免首轮出现空 user 消息。
	input := overview
	if strings.TrimSpace(input) == "" {
		input = "开始执行 system 里领到的意图：只做它、只产生事实、assets、finding、做完即停。"
	}

	// 实验功能:开启后由 noa 接管上下文压缩(归档集中在 <workDir>/noa/<SessionID> 下,持久)。
	noaSession := WorkerSessionID(ts.ID(), intent.ID)
	enableNoa(&opts, w.noaEnabledFn, w.workDir, noaSession, noaWarn(noaSession))
	ctx = attachSideCapture(ctx, &opts)
	s := agentcore.NewSession(opts)
	defer s.Close() // release the session's background-task manager (temp dir + processes)

	// Resume prior conversation if this intent was paused/blocked/exhausted and is
	// being re-run. The transcript ID is deterministic per intent, so if a prior
	// session exists the worker continues from where it left off instead of
	// restarting from scratch.
	alreadyRecorded := false
	if w.tx != nil {
		_ = s.Resume(opts.SessionID)
		alreadyRecorded = requestID != "" && hasWorkerChatMessage(s.Messages(), requestID)
		if len(s.Messages()) > 0 && message == "" {
			seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
			input = "继续执行。"
		} else if len(s.Messages()) > 0 {
			seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
		}
	}
	if message != "" {
		if alreadyRecorded {
			input = "继续执行上一次人工对话输入的新意图。不要重复已经完成的动作。"
		} else if len(s.Messages()) > 0 {
			input = workerChatMarker(requestID) + "\n【人工对话输入的新意图】\n" + message +
				"\n\n请立即按这条人工输入执行，完成后再根据上下文决定原任务是否需要继续。"
		} else {
			input += "\n\n" + workerChatMarker(requestID) + "\n【人工对话输入的新意图】\n" + message +
				"\n\n请优先执行这条人工输入。"
		}
	}

	// Budgets + settlement are owned by the SDK (MaxTurns/MaxDuration + Settlement):
	// on hit it runs a wrap-up turn and finishes with ReasonMaxTurns/ReasonTimeout.
	// MaxDuration now interrupts an in-flight tool at the wall-clock deadline and
	// enters the wrap-up phase on the live ctx, so a run whose tool overran the budget
	// still settles (no external hard-timeout backstop needed). ctx itself carries only
	// pause / planner kill / shutdown, which the engine distinguishes and re-queues/stops.
	_, reason, err := captureRunSession(ctx, s, input, emitWrap)
	return reason, tsx.Writes(), err
}
