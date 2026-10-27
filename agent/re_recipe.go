package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jintilm/praetor/agent/domain"
	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// 这个文件实现 re_recipe：**一个 schema 覆盖全部外部能力**。
//
// 设计约束（见 domain/reverse.go 头注与 P3 设计表）：
//   - 模型只看到 3 个工具，接新能力 = 加一行配方，schema 不变；
//   - 配方只做「单命令、可 JSON 化、确定性输出」的事，长交互/GUI/全家桶一律不进表；
//   - 缺依赖时明确报「缺 X」，**不静默降级**（与沙箱 required 同一条纪律）；
//   - 单次返回有硬上限，超出部分落盘，细节让模型用 Read 按需取 —— 输出的成本结构
//     比输出本身更重要（留在上下文里的每个字节之后每轮都要重发）。
const (
	reRecipePageLines = 60      // disasm/xrefs/strings/capability 每页条数
	reRecipePageBytes = 2000    // 单次返回字节上限（decompile 另算）
	reRecipeDecompCap = 4000    // decompile 单次返回上限
	reRecipeRawCap    = 4 << 20 // 单条命令最多收多少输出
	reRecipeTimeout   = 90 * time.Second
	reRecipeHeadless  = 10 * time.Minute // Ghidra headless 启动就要几十秒
	reRecipeTrace     = 120 * time.Second
	reRecipeMobile    = 5 * time.Minute
)

// reRecipe 描述一条配方怎么执行：单命令 + 分页规则。
//
// 命令是 argv 切片而不是 shell 字符串：配方参数来自模型，拼 shell 等于把样本名
// 变成命令注入入口（样本名完全可能是 `x; rm -rf ~`）。
type reRecipe struct {
	argv func(target, sel string) ([]string, error)
	// run 用于"一条命令不够"或需要清理的配方（mobile 要解包、trace 要授权检查）。
	// 与 argv 二选一：两条路都保持"单次外部调用 + 确定性输出"的纪律。
	run     func(ctx context.Context, target, sel string) (string, error)
	perPage int           // 每页行数
	limit   int           // 单次返回字节上限
	timeout time.Duration // 单次执行超时
}

// reRecipeHints 是缺依赖时给模型看的装法。模型不需要读文档才知道下一步做什么，
// 但必须知道「这条路线现在走不通」——空结果会让它以为样本里没东西。
var reRecipeHints = map[string]string{
	"rizin":           "pip install rizin-og（或 apt install rizin）",
	"analyzeHeadless": "装 Ghidra 后把 <ghidra>/support 加进 PATH",
	"floss":           "pip install flare-floss",
	"capa":            "pip install flare-capa",
	"diec":            "下载 Detect-It-Easy 后把 diec 加进 PATH",
	"gdb":             "apt install gdb",
	"apktool":         "apt install apktool",
	"jadx":            "下载 jadx release 后加进 PATH",
}

// reDecompileScript 是 Ghidra headless 的单函数反编译脚本（Java，运行时编译）。
//
// 为什么不用 MCP：GhidraMCP 那类方案会把几百个工具塞进 schema，每轮固定成本翻倍
// （见 P3 设计表的成本账）。headless + 一个脚本只做一件事，能力一样，成本是常数。
var reDecompileScript = `import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class PraetorDecompile extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String want = args.length > 0 ? args[0] : "";
        Function f = getCurrentProgram().getFunctionManager().getFunction(want);
        if (f == null) {
            FunctionIterator it = getCurrentProgram().getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                Function c = it.next();
                if (c.getName().equals(want) || c.getEntryPoint().toString().equalsIgnoreCase(want)) { f = c; break; }
            }
        }
        if (f == null) { println("PRAETOR: 未找到函数 " + want); return; }
        DecompInterface d = new DecompInterface();
        d.openProgram(getCurrentProgram());
        DecompileResults r = d.decompileFunction(f, 60, monitor);
        println("PRAETOR: " + f.getName() + " @ " + f.getEntryPoint());
        println(r.getDecompiledFunction() == null ? "PRAETOR: 反编译无结果" : r.getDecompiledFunction().getC());
    }
}
`

// reRecipeRun 是配方的执行体，命令与分页都在这里定死。
//
// 注意：这里只**声明**命令，不判断依赖存在与否 —— 依赖检查在调用前统一做，
// 这样"缺 X"的报错只有一处，不会因为某条配方忘了检查而变成空结果。
func reRecipeRun(recipe string) (reRecipe, bool) {
	switch recipe {
	case "disasm":
		return reRecipe{
			perPage: reRecipePageLines, limit: reRecipePageBytes, timeout: reRecipeTimeout,
			argv: func(target, sel string) ([]string, error) {
				if sel == "" {
					return nil, errors.New("disasm 需要 select：函数名或地址（如 main / 0x401136）")
				}
				// aa = 全量分析，pdf = 反汇编当前函数；scr.color=0 保证输出可解析、可比对。
				return []string{"rizin", "-q", "-e", "scr.color=0", "-e", "asm.lines=false",
					"-c", "aa", "-c", "s " + sel, "-c", "pdf", "-c", "q", "--", target}, nil
			},
		}, true
	case "xrefs":
		return reRecipe{
			perPage: reRecipePageLines, limit: reRecipePageBytes, timeout: reRecipeTimeout,
			argv: func(target, sel string) ([]string, error) {
				if sel == "" {
					return nil, errors.New("xrefs 需要 select：地址、函数名或字符串")
				}
				return []string{"rizin", "-q", "-e", "scr.color=0",
					"-c", "aa", "-c", "axt " + sel, "-c", "q", "--", target}, nil
			},
		}, true
	case "decompile":
		return reRecipe{
			perPage: reRecipePageLines, limit: reRecipeDecompCap, timeout: reRecipeHeadless,
			argv: func(target, sel string) ([]string, error) {
				if sel == "" {
					return nil, errors.New("decompile 需要 select：函数名或地址")
				}
				// 工程目录放在临时目录：headless 必须有个 project，用完即弃。
				proj, err := os.MkdirTemp("", "praetor-ghidra-")
				if err != nil {
					return nil, err
				}
				if err := os.WriteFile(filepath.Join(proj, "PraetorDecompile.java"),
					[]byte(reDecompileScript), 0o644); err != nil {
					return nil, err
				}
				return []string{"analyzeHeadless", proj, "praetor",
					"-import", target, "-scriptPath", proj,
					"-postScript", "PraetorDecompile.java", sel, "-deleteProject"}, nil
			},
		}, true
	case "strings":
		return reRecipe{
			perPage: reRecipePageLines, limit: reRecipePageBytes, timeout: reRecipeTimeout,
			argv: func(target, _ string) ([]string, error) {
				// -n 6：短串噪声极大；-q 去掉进度条，保证输出可解析。
				return []string{"floss", "-q", "-n", "6", target}, nil
			},
		}, true
	case "capability":
		return reRecipe{
			perPage: reRecipePageLines, limit: reRecipePageBytes, timeout: reRecipeTimeout,
			argv: func(target, _ string) ([]string, error) {
				return []string{"capa", "-q", target}, nil
			},
		}, true
	case "packer":
		return reRecipe{
			perPage: reRecipePageLines, limit: reRecipePageBytes, timeout: reRecipeTimeout,
			argv: func(target, _ string) ([]string, error) {
				return []string{"diec", target}, nil
			},
		}, true
	case "trace":
		return reRecipe{
			perPage: reRecipePageLines, limit: reRecipePageBytes, timeout: reRecipeTrace,
			run: func(ctx context.Context, target, sel string) (string, error) {
				if err := requireDynamic(); err != nil {
					return "", err
				}
				if strings.TrimSpace(sel) == "" {
					return "", errors.New("trace 需要 select：函数名或地址")
				}
				// batch + -nx：不读 ~/.gdbinit（用户配置会让输出不可复现）。
				// 断在目标函数上只取调用栈与关键寄存器 —— 配方契约是"只回序列不回全文"。
				argv := []string{"gdb", "-q", "-batch", "-nx",
					"-ex", "set pagination off", "-ex", "set confirm off",
					"-ex", "break " + sel, "-ex", "run",
					"-ex", "bt 20", "-ex", "info registers rsp rbp rip", "-ex", "kill",
					target,
				}
				return reRecipeExec(ctx, argv, reRecipeTrace)
			},
		}, true
	case "mobile":
		return reRecipe{
			perPage: reRecipePageLines, limit: reRecipePageBytes, timeout: reRecipeMobile,
			run: func(ctx context.Context, target, sel string) (string, error) {
				return runMobile(ctx, target, sel)
			},
		}, true
	}
	return reRecipe{}, false
}

// reRecipe 工具本身。
func (t *ToolSet) reRecipe() actool.CoreTool {
	names := make([]string, 0, 10)
	for _, r := range domain.ReverseRecipes() {
		names = append(names, r.Name)
	}
	return readTool("re_recipe",
		"按配方执行已固化的分析管道（外部 CLI），一次一页。可用配方："+strings.Join(names, "/")+"。\n"+
			"每条配方只做一件事且输出确定：disasm(反汇编函数/地址段) xrefs(交叉引用) decompile(单函数伪代码) "+
			"strings(还原混淆串) capability(能力命中) packer(编译器/壳判定) triage(全貌，等价 re_triage)。\n"+
			"缺依赖时会明确告诉缺哪个可执行文件 —— 那是环境问题，按提示记下来换路线，不要自己拼命令绕过。"+
			"输出超过一页就带 page 续取，全文同时落盘，需要细节用 Read 读落盘文件。",
		obj(map[string]any{
			"recipe": str("配方名：" + strings.Join(names, " / ")),
			"target": str("样本的本地路径"),
			"select": str("可选：函数名 / 地址 / 字符串，disasm、xrefs、decompile 必填"),
			"page":   intp("可选：页码，从 0 起；默认 0"),
		}, "recipe", "target"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Recipe string `json:"recipe"`
				Target string `json:"target"`
				Select string `json:"select"`
				Page   int    `json:"page"`
			}
			_ = json.Unmarshal(in, &a)
			name := strings.TrimSpace(a.Recipe)
			target := strings.TrimSpace(a.Target)
			if name == "" || target == "" {
				return actool.Errorf("recipe 与 target 都必填；可用配方：" + strings.Join(names, "/")), nil
			}
			if _, ok := domainRecipe(name); !ok {
				return actool.Errorf(fmt.Sprintf("没有配方 %q；可用：%s", name, strings.Join(names, "/"))), nil
			}
			// 样本库形态（sha256:…）先解密成临时文件，之后一律按普通路径处理。
			// 放在 stat 之前：样本库里本来就没有这个"路径"，先 stat 必然 ENOENT，
			// 报错还会误导成"文件不存在"，而不是"样本库没配"。
			target, cleanupTarget, err := resolveSampleTarget(target)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			defer cleanupTarget()

			fi, err := os.Stat(target)
			if err != nil {
				return actool.Errorf("读不到样本：" + err.Error()), nil
			}
			if fi.IsDir() {
				return actool.Errorf("target 是目录；配方要的是具体文件"), nil
			}

			// triage 不依赖外部命令：直接复用 re_triage，保证两条入口口径一致。
			if name == "triage" {
				payload, _ := json.Marshal(map[string]any{"path": target})
				return (&ToolSet{}).reTriage().Call(ctx, payload, nil)
			}

			spec, ok := reRecipeRun(name)
			if !ok {
				return actool.Errorf(fmt.Sprintf("配方 %q 还没有实现", name)), nil
			}
			if miss := missingTools(name); len(miss) > 0 {
				return actool.Errorf(fmt.Sprintf("缺 %s：这条配方要它才能跑。装法：%s。"+
					"先用 triage 和静态配方定方向，别在这条路上反复重试",
					strings.Join(miss, "、"), hintsFor(miss))), nil
			}

			var out string
			var runErr error
			if spec.run != nil {
				out, runErr = spec.run(ctx, target, strings.TrimSpace(a.Select))
			} else {
				argv, aerr := spec.argv(target, strings.TrimSpace(a.Select))
				if aerr != nil {
					return actool.Errorf(aerr.Error()), nil
				}
				out, runErr = reRecipeExec(ctx, argv, spec.timeout)
			}
			if runErr != nil && strings.TrimSpace(out) == "" {
				return actool.Errorf(fmt.Sprintf("配方 %s 执行失败：%v", name, runErr)), nil
			}

			page := a.Page
			if page < 0 {
				page = 0
			}
			body, total, err := paginateLines(out, page, spec.perPage, spec.limit)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("%s（共 %d 页）", err, total)), nil
			}

			spill, werr := spillRecipe(out, target, name, strings.TrimSpace(a.Select))
			head := fmt.Sprintf("[recipe=%s page=%d/%d lines=%d]", name, page+1, total, countLines(out))
			if runErr != nil {
				head += " 命令有告警：" + runErr.Error()
			}
			if werr == nil {
				head += " full: " + spill
			}
			return actool.Text(head + "\n" + body), nil
		})
}

// domainRecipe 在配方表里按名字查一条。
func domainRecipe(name string) (domain.Recipe, bool) {
	for _, r := range domain.ReverseRecipes() {
		if r.Name == name {
			return r, true
		}
	}
	return domain.Recipe{}, false
}

// missingTools 返回该配方缺哪些可执行文件（空 = 齐了）。
func missingTools(name string) []string {
	r, ok := domainRecipe(name)
	if !ok {
		return nil
	}
	var miss []string
	for _, need := range r.Needs {
		if _, err := reRecipeLookPath(need); err != nil {
			miss = append(miss, need)
		}
	}
	return miss
}

// hintsFor 把缺的工具翻成一句装法；没写提示的就说"见文档"。
func hintsFor(miss []string) string {
	var out []string
	for _, m := range miss {
		if h, ok := reRecipeHints[m]; ok {
			out = append(out, m+" → "+h)
			continue
		}
		out = append(out, m+" → 装法见执行文档 P3-3")
	}
	return strings.Join(out, "；")
}

// reRecipeExec / reRecipeLookPath 抽成变量便于测试注入。
//
// 不是为了"好测"而抽：这两处是唯一与外部世界接触的地方（进程 + PATH），
// 其余全是纯函数。注入点收在这里，测试就不必在本机真装 rizin/ghidra。
var (
	reRecipeExec     = runRecipeCmd
	reRecipeLookPath = exec.LookPath
)

// runRecipeCmd 跑一条配方命令，返回合并输出（stdout 优先，stderr 追加在后面）。
//
// 超时不靠 outer ctx 兜：headless 启动本来就慢，用配方的 timeout 单独管，
// 同时尊重上层 ctx 取消（任务到点要能立刻停）。
func runRecipeCmd(ctx context.Context, argv []string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = reRecipeTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, argv[0], argv[1:]...)
	var buf strings.Builder
	cmd.Stdout = &limitedWriter{w: &buf, left: reRecipeRawCap}
	cmd.Stderr = &limitedWriter{w: &buf, left: reRecipeRawCap / 4}
	err := cmd.Run()
	out := buf.String()
	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		return out, fmt.Errorf("超时（%s）", timeout)
	}
	return out, err
}

// limitedWriter 是一个只保留前 N 字节的 writer。
//
// 外部工具的日志可以无限长（capa 遇到大样本会刷几十 MB），而这些东西最终要进内存；
// 截断是必须的，但截断必须留痕（调用方把 err 写进 head）。
type limitedWriter struct {
	w    io.Writer
	left int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.left <= 0 {
		return len(p), nil
	}
	if len(p) > l.left {
		if _, err := l.w.Write(p[:l.left]); err != nil {
			return 0, err
		}
		n := l.left
		l.left = 0
		return n, nil
	}
	n, err := l.w.Write(p)
	l.left -= n
	return n, err
}

// paginateLines 按行切页并压到 limit 字节内。
//
// 为什么按行而不是按字节切：反汇编按指令、字符串列表按条目，切半个函数比不切更糟。
func paginateLines(out string, page, perPage, limit int) (string, int, error) {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
		return "(无输出)", 1, nil
	}
	if perPage <= 0 {
		perPage = reRecipePageLines
	}
	total := (len(lines) + perPage - 1) / perPage
	if page >= total {
		return "", total, fmt.Errorf("page 越界：只有 %d 页", total)
	}
	start := page * perPage
	end := start + perPage
	if end > len(lines) {
		end = len(lines)
	}
	body := strings.Join(lines[start:end], "\n")
	if limit > 0 && len(body) > limit {
		body = body[:limit] + "\n…（本页超上限，已截断；完整内容见 full 文件）"
	}
	return body, total, nil
}

func countLines(s string) int {
	if strings.TrimSpace(s) == "" {
		return 0
	}
	return strings.Count(strings.TrimRight(s, "\n"), "\n") + 1
}

var recipeSelSlug = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

// spillRecipe 把完整输出落盘，返回路径。
//
// 落盘而不是塞回上下文：配方输出动辄几十 KB，而它之后每一轮都会被重发。
// 路径里带样本哈希前缀，同一个样本的多条配方输出会落在同一目录，便于事后一起看。
func spillRecipe(out, target, recipe, sel string) (string, error) {
	dir := filepath.Join(filepath.Dir(target), ".praetor", "re")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	sum, err := sha256File(target)
	if err != nil {
		return "", err
	}
	name := sum[:8] + "-" + recipe
	if s := recipeSelSlug.ReplaceAllString(sel, "-"); s != "" {
		name += "-" + strings.Trim(s, "-")
	}
	path := filepath.Join(dir, name+".txt")
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
