// Package components 管理「可选依赖」的清单与安装脚本。
//
// 设计前提（对应执行文档 R6）：这些都是**可选加速器**，核心能力不依赖它们；
// 装与不装都必须能用，只是能用得多深不同。
//
// 为什么装进**沙箱镜像**而不是宿主：
//   - 宿主安装要提权（apt 需 sudo、winget 可能弹 UAC）、卸载留残渣、三平台三套逻辑；
//   - 镜像层可回滚（切回 :latest 即可）、可复现（同一份 Dockerfile）、与"一任务一容器"一致。
//
// 单一数据源：本文件是唯一清单。Dockerfile 与探测脚本都由它**生成**，
// 不手写第二份 —— 否则清单和实现漂移，面板显示"已装"而容器里其实没有。
package components

import (
	"fmt"
	"sort"
	"strings"
)

// Item 是一个可选组件。
type Item struct {
	ID      string // 稳定标识（写进 settings，不要改）
	Group   string // pwn / rev / crypto / forensics / mobile
	Title   string
	Why     string
	License string
	SizeMB  int      // 粗略下载体积（用于 UI 提示，不精确）
	Install []string // 逐条 shell 命令，在镜像内以 `set -eux` 执行
	Probe   []string // argv，用来在镜像内探测是否已装并取版本
	// Needs 是"这项依赖谁"的提示（UI 用来提示顺序），不做强校验：
	// 装了 pwndbg 但没 gdb 也能构建成功，只是运行时才发现用不了。
	Needs []string
}

// 基础镜像：可选组件都叠在它之上（复用已构建的 sandbox:latest，构建快且不重装基础工具）。
const BaseImage = "praetor/sandbox:latest"

// 列出全部可选组件。
//
// 取舍：只收「apt 能装 / pip 能装」的确定性工具。凡是需要编译、需要外部服务、
// 或不同发行版差异巨大的（Ghidra GUI、IDA、Cutter）都不进来 —— 它们应该在"外部加速器"里
// 由用户自己处理，而不是让一个 Web 按钮去猜。
func All() []Item {
	return []Item{
		// ---------- pwn ----------
		{
			ID: "gdb", Group: "pwn", Title: "gdb", SizeMB: 40, License: "GPL-3.0",
			Why:     "动态调试基线；pwndbg 依赖它",
			Install: []string{"apt-get install -y --no-install-recommends gdb"},
			Probe:   []string{"gdb", "--version"},
		},
		{
			ID: "pwntools", Group: "pwn", Title: "pwntools", SizeMB: 30, License: "未标注（外部进程调用）",
			Why: "远程交互、打包解包、ELF 解析",
			// 用发行版包而不是 pip：基础镜像的系统 Python 是 3.14，pip 版要现场编译
			// 原生依赖（实测 ctypes/pwnlib 编译失败），而 Kali 的 python3-pwntools 已按
			// 这个解释器构建（实测 `import pwn` 可用）。
			Install: []string{"apt-get install -y --no-install-recommends python3-pwntools"},
			Probe:   []string{"python3", "-c", "from pwn import version;print(version)"},
		},
		{
			ID: "gef", Group: "pwn", Title: "GEF（gdb 增强）", SizeMB: 10, License: "MIT",
			// 原计划是 pwndbg，但它既不在 Kali 源也不在内网 pip 源里（实测
			// `pip install pwndbg` → No matching distribution）；GEF 提供同类的堆/栈/寄存器
			// 可视化，且是发行版包，装得上、可复现。
			Why:     "gdb 增强：堆可视化、栈回溯、寄存器视图",
			Install: []string{"apt-get install -y --no-install-recommends gef"},
			// 实测 Kali 的 gef 包装在 /usr/bin/gef（不是 /usr/share/gef/gef.py）：
			// 探针写错会稳定报"未安装"，而它其实装着 —— 面板撒谎比不显示更糟。
			Probe: []string{"test", "-x", "/usr/bin/gef"},
			Needs: []string{"gdb"},
		},
		{
			ID: "ropgadget", Group: "pwn", Title: "ROPgadget", SizeMB: 5, License: "未标注（外部进程调用）",
			Why:     "gadget 搜索",
			Install: []string{"pip3 install --no-cache-dir --break-system-packages ROPgadget"},
			Probe:   []string{"ROPgadget", "--version"},
		},
		{
			ID: "seccomp-tools", Group: "pwn", Title: "seccomp-tools", SizeMB: 80, License: "MIT",
			Why: "沙箱规则分析（判断能不能 execve）",
			Install: []string{
				"apt-get install -y --no-install-recommends ruby ruby-dev build-essential",
				"gem install seccomp-tools --no-document",
			},
			Probe: []string{"seccomp-tools", "--version"},
		},

		// ---------- rev ----------
		{
			ID: "rizin", Group: "rev", Title: "rizin", SizeMB: 80, License: "LGPL-3.0（外部进程调用）",
			Why:     "反汇编 / 交叉引用（脚本化）",
			Install: []string{"apt-get install -y --no-install-recommends rizin"},
			Probe:   []string{"rizin", "-v"},
		},
		{
			ID: "binwalk", Group: "rev", Title: "binwalk", SizeMB: 40, License: "MIT",
			Why:     "固件/嵌套文件识别与提取",
			Install: []string{"apt-get install -y --no-install-recommends binwalk"},
			Probe:   []string{"binwalk", "--version"},
		},

		// ---------- crypto ----------
		{
			ID: "z3", Group: "crypto", Title: "z3 (python3-z3)", SizeMB: 30, License: "MIT",
			Why:     "位运算/线性约束求解",
			Install: []string{"apt-get install -y --no-install-recommends python3-z3"},
			Probe:   []string{"python3", "-c", "import z3;print(z3.get_version_string())"},
		},
		{
			ID: "ciphey", Group: "crypto", Title: "ciphey", SizeMB: 60, License: "MIT",
			// CTFToolchain 一直声明了它，清单里却漏了（漂移）。
			// pip 的 ciphey 在 Python 3.14 上装不了（老版 absl-py 的 setup.py 直接
			// 拒绝新解释器），Kali 的 python3-ciphey 可以（实测 import 通过）。
			Why:     "常见编码/古典密码自动识别",
			Install: []string{"apt-get install -y --no-install-recommends python3-ciphey"},
			Probe:   []string{"python3", "-c", "import ciphey;print('ok')"},
		},
		{
			ID: "angr", Group: "crypto", Title: "angr（符号执行）", SizeMB: 1200, License: "BSD-2-Clause",
			Why:     "符号执行求解校验逻辑，体积大",
			Install: []string{"pip3 install --no-cache-dir --break-system-packages angr"},
			Probe:   []string{"python3", "-c", "import angr;print(angr.__version__)"},
		},
		{
			ID: "sage", Group: "crypto", Title: "sagemath（格/数论）", SizeMB: 3500, License: "GPL-3.0（外部进程调用）",
			Why:     "格与数论题的主力，镜像会显著变大",
			Install: []string{"apt-get install -y --no-install-recommends sagemath"},
			Probe:   []string{"sage", "--version"},
		},

		// ---------- forensics ----------
		{
			ID: "tshark", Group: "forensics", Title: "tshark", SizeMB: 120, License: "GPL-2.0（外部进程调用）",
			Why:     "pcap 解析与字段提取",
			Install: []string{"apt-get install -y --no-install-recommends tshark"},
			Probe:   []string{"tshark", "-v"},
		},
		{
			ID: "exiftool", Group: "forensics", Title: "exiftool", SizeMB: 20, License: "未标注（外部进程调用）",
			Why:     "元数据检查（隐写第一顺位）",
			Install: []string{"apt-get install -y --no-install-recommends libimage-exiftool-perl"},
			Probe:   []string{"exiftool", "-ver"},
		},
		{
			ID: "zsteg", Group: "forensics", Title: "zsteg", SizeMB: 40, License: "未标注（外部进程调用）",
			Why: "PNG/BMP 的 LSB 隐写",
			Install: []string{
				"apt-get install -y --no-install-recommends ruby ruby-dev",
				"gem install zsteg --no-document",
			},
			Probe: []string{"zsteg", "--version"},
		},
		{
			ID: "volatility3", Group: "forensics", Title: "volatility3", SizeMB: 60, License: "未标注（外部进程调用）",
			Why:     "内存镜像分析",
			Install: []string{"pip3 install --no-cache-dir --break-system-packages volatility3"},
			Probe:   []string{"python3", "-c", "import volatility3;print('ok')"},
		},

		// ---------- mobile ----------
		// 只放 apktool：mobile / mobile_scan 两条配方都需要它把二进制 AXML 解成明文。
		// 静态规则本身是纯 Go（读解包产物），不需要 androguard / jadx 之类的重依赖；
		// jadx 只影响「Java 源码 vs smali」的可读性，缺了会明确退回 smali，不进清单。
		{
			ID: "apktool", Group: "mobile", Title: "apktool", SizeMB: 60, License: "Apache-2.0（外部进程调用）",
			Why:     "APK 解包成明文 AndroidManifest 与 smali；mobile / mobile_scan 配方的唯一硬依赖",
			Install: []string{"apt-get install -y --no-install-recommends apktool"},
			// Kali 的 apktool 是 Java 包装脚本，各版本 CLI 参数不一致（有的只认无参数
			// 输出用法且退出码非 0）。赌 --version 会让面板把已装的显示成未装；
			// 用 test -x 探「文件在不在」，配方侧另有 LookPath 确认可执行性。
			Probe: []string{"test", "-x", "/usr/bin/apktool"},
		},
	}
}

// Get 按 ID 取组件。
func Get(id string) (Item, bool) {
	for _, it := range All() {
		if it.ID == id {
			return it, true
		}
	}
	return Item{}, false
}

// Validate 校验并规范化用户选择：去重、排序（保证镜像 tag 稳定）、拒绝未知 ID。
//
// 拒绝未知 ID 是**安全边界**：面板只允许勾选清单内的项，服务端不接受任何自由包名或命令，
// 否则这个接口等于给 Web 面板开了一个远程命令执行入口。
func Validate(ids []string) ([]Item, error) {
	seen := map[string]bool{}
	var out []Item
	var unknown []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		it, ok := Get(id)
		if !ok {
			unknown = append(unknown, id)
			continue
		}
		out = append(out, it)
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("未知组件：%s（只允许清单内的 ID）", strings.Join(unknown, ", "))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// TotalSizeMB 返回所选组件的体积估算。
func TotalSizeMB(items []Item) int {
	n := 0
	for _, it := range items {
		n += it.SizeMB
	}
	return n
}
