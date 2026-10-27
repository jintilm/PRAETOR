package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jintilm/praetor/internal/binfmt"
	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// reTriageMaxRead 是单次读取上限。样本动辄几百 MB，全量读进内存既慢又可能打爆 worker；
// 128MB 足够覆盖 PE/ELF/常见固件片段，超出部分会明确告警（而不是静默截断）。
const reTriageMaxRead = 128 << 20

// reTriageSummaryBytes 是返回给模型的摘要上限。
//
// 1.4KB ≈ 450 tokens。这条输出会留在上下文里、之后每轮重发，所以它必须小；
// 完整报告落盘，需要细节时模型用 Read 按需读（这才是正确的成本结构）。
const reTriageSummaryBytes = 1400

// reTriage 是逆向域的入口工具：**一次调用拿到样本全貌**，纯本地解析、零外部依赖。
//
// 为什么不直接让模型跑 `file`/`strings`/`objdump`：
//   - 每条命令都是一次 LLM 调用 + 一次全上下文重发（本项目实测：贵在次数不在体积）；
//   - 外部工具在干净环境/容器里可能根本不存在（rizin/ghidra/jadx 都验证过缺席）；
//   - 手工命令的输出没有结构，模型要自己从几十行里挑重点，容易漏掉关键信号（如高熵段）。
//
// 这个工具把这些事合成一次调用，并强制"摘要进上下文、全文落盘"。
func (t *ToolSet) reTriage() actool.CoreTool {
	return writeTool("re_triage",
		"一次拿到可执行样本的全貌：格式/架构/位数/文件用途/入口/段表熵/导入表与可疑 API/字符串分类/加壳迹象（带依据）。\n"+
			"纯本地静态解析（PE / ELF / Mach-O / 压缩容器 / 脚本），**不执行样本，不依赖任何外部工具**。\n"+
			"返回 ≤1.4KB 摘要，并把完整 JSON 落盘（返回值末尾给出报告路径）；需要细节再用 Read 读报告。\n"+
			"用法：先用它定方向——是不是壳、什么语言写的、导入了哪些敏感能力、字符串里有没有 C2/路径/命令——"+
			"再决定要不要上反汇编或动态调试。不要用 strings/file/objdump 重复做同一件事。",
		obj(map[string]any{
			"path":    str("样本的本地路径（绝对路径，或相对当前工作目录）"),
			"out_dir": str("可选：报告落盘目录；默认 <样本目录>/.praetor"),
		}, "path"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Path   string `json:"path"`
				OutDir string `json:"out_dir"`
			}
			_ = json.Unmarshal(in, &a)
			path := strings.TrimSpace(a.Path)
			if path == "" {
				return actool.Errorf("path 必填：给出样本的本地路径"), nil
			}
			fi, err := os.Stat(path)
			if err != nil {
				return actool.Errorf("读不到样本：" + err.Error()), nil
			}
			if fi.IsDir() {
				return actool.Errorf("path 是目录，不是样本文件；先确认具体文件"), nil
			}

			f, err := os.Open(path)
			if err != nil {
				return actool.Errorf("打开样本失败：" + err.Error()), nil
			}
			defer f.Close()
			data, err := io.ReadAll(io.LimitReader(f, reTriageMaxRead+1))
			if err != nil {
				return actool.Errorf("读取样本失败：" + err.Error()), nil
			}
			truncated := len(data) > reTriageMaxRead
			if truncated {
				data = data[:reTriageMaxRead]
			}

			rep, err := binfmt.Analyze(data, filepath.Base(path))
			if err != nil {
				return actool.Errorf("分析失败：" + err.Error()), nil
			}
			if truncated {
				rep.Warnings = append(rep.Warnings,
					fmt.Sprintf("样本超过 %dMB，只分析了前 %dMB", reTriageMaxRead>>20, reTriageMaxRead>>20))
			}

			summary := binfmt.Render(rep, reTriageSummaryBytes)

			// 完整报告落盘：失败不影响摘要返回（摘要本身已经是可用结论）。
			reportPath, werr := writeTriageReport(rep, path, a.OutDir)
			if werr != nil {
				return actool.Text(summary + "\nreport: 落盘失败（" + werr.Error() + "），以上摘要可用"), nil
			}
			return actool.Text(summary + "\nreport: " + reportPath), nil
		})
}

// writeTriageReport 把完整 Report 写成 JSON，返回路径。
//
// 默认放在样本同级的 .praetor/ 下（而不是临时目录）：样本与报告要能一起被搬走，
// 也不能污染样本所在目录的根。
func writeTriageReport(rep binfmt.Report, samplePath, outDir string) (string, error) {
	dir := strings.TrimSpace(outDir)
	if dir == "" {
		dir = filepath.Join(filepath.Dir(samplePath), ".praetor")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	sha := rep.SHA256
	if len(sha) > 8 {
		sha = sha[:8]
	}
	out := filepath.Join(dir, "re-triage-"+sha+".json")
	body, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(out, body, 0o644); err != nil {
		return "", err
	}
	return out, nil
}
