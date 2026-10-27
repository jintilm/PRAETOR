// Package binfmt 用纯 Go 解析可执行文件格式，为逆向/CTF 提供**零外部依赖**的全貌分析。
//
// 为什么自己写而不调外部工具（rizin / objdump / readelf / Ghidra）：
//
//	本项目要求「开发完成后不依赖其他 GitHub 项目」。外部 CLI 在干净机器、CI 容器、
//	客户现场都可能缺席（本项目实测开发机上 rizin/ghidra/jadx 全都没有，objdump/readelf
//	只在 msys64 里），一旦核心能力依赖它们，工具就变成"看起来有、实际不可用"。
//
// 所以这里的分工是：
//   - **本包（纯 Go）**：格式识别、头/段表/导入表/安全标志/熵/字符串 —— 够做 triage 与大部分
//     静态判断，任何环境开箱可用；
//   - 外部 CLI（rizin / Ghidra headless / capa…）只作为**可选加速器**：反汇编大函数、
//     反编译伪代码这类确实需要重型引擎的事，装了就更好，没装也不影响核心路径。
//
// 设计约束：
//   - 只读、不执行样本；
//   - 解析失败不 panic：坏数据一律降级为 Warnings，让上层的模型看到"哪里没解析出来"；
//   - 输出有上限：段/导入/字符串都截断，完整结果由调用方落盘（上下文里只放摘要）。
package binfmt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
)

// Format 是可执行文件格式。
type Format string

const (
	FormatPE      Format = "pe"
	FormatELF     Format = "elf"
	FormatMachO   Format = "macho"
	FormatArchive Format = "archive" // ar / zip / apk 等容器（只报类型，不展开）
	FormatScript  Format = "script"  // #! 脚本
	FormatUnknown Format = "unknown"
)

// Report 是一次静态分析的结构化结果。
//
// 字段刻意保持"可 JSON 化 + 可比较"，方便落盘给后续分析用，也方便测试断言。
type Report struct {
	Path   string `json:"path,omitempty"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Format Format `json:"format"`
	// Arch 形如 amd64 / 386 / arm64 / mips；Bits 是 32 或 64。
	Arch   string `json:"arch"`
	Bits   int    `json:"bits"`
	Endian string `json:"endian"` // little / big
	// Kind 是文件用途：exe / dll / so / dylib / obj / lib。
	Kind  string `json:"kind"`
	Entry string `json:"entry"` // 十六进制，如 0x401000；0x0 表示无入口

	Sections []Section     `json:"sections,omitempty"`
	Imports  ImportSummary `json:"imports"`
	Exports  int           `json:"exports"`
	Security SecurityFlags `json:"security"`
	Packer   PackerHint    `json:"packer"`
	Strings  StringSummary `json:"strings"`

	// Warnings 记录"解析到哪里卡住了"，而不是让整个分析失败。
	Warnings []string `json:"warnings,omitempty"`
}

// Section 是一个段/节。
type Section struct {
	Name    string  `json:"name"`
	VAddr   uint64  `json:"vaddr"`
	VSize   uint64  `json:"vsize"`
	RawSize uint64  `json:"raw_size"`
	Entropy float64 `json:"entropy"` // 0~8
	Perm    string  `json:"perm"`    // 由 R/W/X 组成，如 "RX"、"RW"、"-"
}

// ImportSummary 是导入表摘要。只保留"模型真的会用来判断"的部分。
type ImportSummary struct {
	DLLs       []string `json:"dlls,omitempty"`
	Count      int      `json:"count"`
	Suspicious []string `json:"suspicious,omitempty"`
}

// SecurityFlags 是编译期缓解措施（PE: DllCharacteristics / ELF: PT_GNU_STACK、GNU_RELRO、PIE）。
type SecurityFlags struct {
	ASLR  bool `json:"aslr"`
	DEP   bool `json:"dep"`
	CFG   bool `json:"cfg"`
	PIE   bool `json:"pie"`
	NX    bool `json:"nx"`
	RELRO bool `json:"relro"`
}

// PackerHint 是加壳/混淆的启发式判断，**必须带依据**——只给结论会被模型当圣旨。
type PackerHint struct {
	Suspected bool     `json:"suspected"`
	Reasons   []string `json:"reasons,omitempty"`
}

// StringSummary 是字符串摘要（按类别挑重点，不返回全集）。
type StringSummary struct {
	Total      int      `json:"total"`
	URLs       []string `json:"urls,omitempty"`
	Paths      []string `json:"paths,omitempty"`
	IPs        []string `json:"ips,omitempty"`
	Suspicious []string `json:"suspicious,omitempty"`
}

// 输出上限（防止一次分析把上下文灌满 —— 单条 tool_result 超过 ~2K 字符就开始拖累每一轮）。
const (
	maxDLLs        = 8
	maxSuspicious  = 10
	maxSections    = 16
	maxURLs        = 4
	maxPaths       = 4
	maxIPs         = 4
	maxStrSample   = 6
	maxScanBytes   = 64 << 20 // 只扫前 64MB，超大样本按"头部 + 采样"处理
	maxStringsFrom = 8 << 20
)

// Analyze 分析一段可执行文件内容。name 只用于填充 Report.Path。
//
// 任何格式的解析失败都不会返回错误（除空输入）：降级为 warnings，
// 因为"这个样本解析不出来"本身就是一条有价值的结论。
func Analyze(data []byte, name string) (Report, error) {
	rep := Report{
		Path:   name,
		Size:   int64(len(data)),
		Format: FormatUnknown,
		Bits:   0,
	}
	if len(data) == 0 {
		return rep, fmt.Errorf("空文件")
	}
	sum := sha256.Sum256(data)
	rep.SHA256 = hex.EncodeToString(sum[:])

	switch {
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		rep.Format = FormatPE
		parsePE(data, &rep)
	case len(data) >= 4 && string(data[:4]) == "\x7fELF":
		rep.Format = FormatELF
		parseELF(data, &rep)
	case isMachO(data):
		rep.Format = FormatMachO
		parseMachO(data, &rep)
	case isArchive(data):
		rep.Format = FormatArchive
		rep.Kind = archiveKind(data)
		rep.Warnings = append(rep.Warnings, "容器格式（ar/zip/apk），未展开；解包后再分析具体 ELF/DEX")
	case isScript(data):
		rep.Format = FormatScript
		rep.Kind = "script"
	default:
		rep.Warnings = append(rep.Warnings, "未识别为可执行格式（PE/ELF/Mach-O），可能已加密、加壳或不是二进制")
	}

	// 字符串分析对所有格式都做（脚本/未知格式里也可能是关键线索）。
	rep.Strings = summarizeStrings(data)
	return rep, nil
}

func parseWarn(rep *Report, format string, args ...any) {
	if len(rep.Warnings) >= 8 {
		return
	}
	rep.Warnings = append(rep.Warnings, fmt.Sprintf(format, args...))
}

// entropy 返回字节分布的香农熵（0~8 bit/byte）。
// 高熵（>7.2）常意味着压缩/加密/壳；但正常的大代码段也可能 6.5~7.0，所以只作提示。
func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var hist [256]int
	for _, c := range b {
		hist[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range hist {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return math.Round(h*100) / 100
}

func hexAddr(v uint64) string { return fmt.Sprintf("0x%x", v) }

func sectionPerm(r, w, x bool) string {
	s := ""
	if r {
		s += "R"
	}
	if w {
		s += "W"
	}
	if x {
		s += "X"
	}
	if s == "" {
		return "-"
	}
	return s
}

// sortSections 让输出稳定（同名按地址），便于 diff 与测试。
func sortSections(secs []Section) {
	sort.SliceStable(secs, func(i, j int) bool {
		if secs[i].VAddr != secs[j].VAddr {
			return secs[i].VAddr < secs[j].VAddr
		}
		return secs[i].Name < secs[j].Name
	})
}

// trim 截断切片并去空。
func clip(items []string, n int) []string {
	out := make([]string, 0, n)
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, s)
		if len(out) >= n {
			break
		}
	}
	return out
}
