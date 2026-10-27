package components

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// 本文件把清单**生成**成两样东西：构建用的 Dockerfile、探测用的 shell 脚本。
//
// 为什么生成而不是手写：清单是会变的（加一项 angr 都要同时改 Dockerfile、探测命令、
// 前端文案），三处手写必然漂移，而漂移的表现是"面板说装了、容器里没有"——
// 这种错误没人会在测试里发现，只会在真正要用的时候才发现。

// KaliMirror 是 extras 层使用的 apt 源。
//
// http.kali.org 是「重定向器」，落到哪个镜像不可控；本项目实测本机被清华镜像 403 拒绝
// （同一网络下阿里云 / 中科大 / kali.download 都是 200）。基镜像已经改过源，
// 但 extras 层可能叠在旧基镜像上，所以这里再兜一次底。
const KaliMirror = "http://mirrors.aliyun.com/kali"

// ImageTag 由所选组件集合算出稳定镜像 tag：同一组选择永远得到同一个 tag（构建缓存命中），
// 换一组选择就是另一个 tag（旧镜像还在，切回去即可回滚）。
func ImageTag(items []Item) string {
	if len(items) == 0 {
		return BaseImage
	}
	ids := make([]string, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.ID)
	}
	sum := sha256.Sum256([]byte(strings.Join(ids, ",")))
	return "praetor/sandbox:custom-" + hex.EncodeToString(sum[:])[:8]
}

// RenderDockerfile 生成构建文件：基础镜像 + 每个组件一层。
//
// 每个组件单独一个 RUN 是为了**分层缓存**：以后再加 sage，不会因为 apt/pip 命令合并
// 在一层里而把 angr 也重装一遍（angr 那层 1.2GB，重装一次就是几分钟）。
func RenderDockerfile(items []Item) string {
	var b strings.Builder
	b.WriteString("# 由 PRAETOR 面板生成 —— 请勿手改（改 internal/components/catalog.go）\n")
	b.WriteString("FROM " + BaseImage + "\n")
	b.WriteString("ENV DEBIAN_FRONTEND=noninteractive\n")
	if len(items) == 0 {
		b.WriteString("# 未选择任何可选组件\n")
		return b.String()
	}
	// 基础准备层：源 + 重试 + **更新索引并保留**。三件事都必须在这一层做：
	//   1) 源：extras 可能叠在旧基镜像上，而官方源在本机被镜像 403 拒绝；
	//   2) 重试：镜像偶发 5xx 时 apt 默认不重试；
	//   3) apt-get update：基础镜像末尾删了 /var/lib/apt/lists/*，不在这里更新，
	//      后面的组件层会直接 "Unable to locate package"（实测踩到）。
	b.WriteString("\n# 基础准备：apt 源 + 重试 + 更新索引（保留给各组件层复用）\n")
	b.WriteString("RUN set -eux; \\\n")
	b.WriteString("    if [ -f /etc/apt/sources.list.d/kali.sources ]; then " +
		"sed -i 's|http://http.kali.org/kali|" + KaliMirror + "|g' /etc/apt/sources.list.d/kali.sources; fi; \\\n")
	b.WriteString("    printf 'Acquire::Retries \"5\";\\n' > /etc/apt/apt.conf.d/99praetor-retry; \\\n")
	b.WriteString("    apt-get update\n")

	for _, it := range items {
		fmt.Fprintf(&b, "\n# %s (%s, %dMB 约) — %s\n", it.Title, it.ID, it.SizeMB, it.Why)
		b.WriteString("RUN set -eux; \\\n")
		// 每条命令都必须以 `; \` 续行结尾 —— 否则下一条会变成独立指令。
		// 曾经只在"非最后一条"加分号，单命令组件就生成出以 `;` 开头的新行，
		// docker 直接报 `unknown instruction: ;`（实测踩到）。
		for _, cmd := range it.Install {
			b.WriteString("    " + cmd + "; \\\n")
		}
		b.WriteString("    true\n")
	}
	// 统一清理：索引在构建期要给每个组件层复用，最后再删，避免镜像白胖几十 MB。
	b.WriteString("\n# 清理：apt 缓存与包索引\n")
	b.WriteString("RUN set -eux; apt-get clean; rm -rf /var/lib/apt/lists/*\n")
	return b.String()
}

// ProbeScript 生成在镜像内执行的探测脚本。
//
// 用 shell 函数而不是"每条命令跑一个容器"：16 个组件各起一个容器要 16 秒以上，
// 而一次 `sh -c` 全跑完不到 2 秒 —— 面板刷新状态不该让人等。
//
// 关键点：用 `"$@"` 直接执行，**不经管道**。管道会把退出码替换成最后一个命令的状态，
// 于是"命令不存在"被 `| head -1` 掩盖成成功，面板就会把没装的东西显示成已装。
func ProbeScript(items []Item) string {
	var b strings.Builder
	b.WriteString("probe() { id=\"$1\"; shift; ")
	b.WriteString("if out=$(\"$@\" 2>&1); then ")
	b.WriteString("printf '%s|ok|%s\\n' \"$id\" \"$(printf '%s' \"$out\" | head -n1 | tr -d '\\r')\"; ")
	b.WriteString("else printf '%s|no|\\n' \"$id\"; fi; }\n")
	for _, it := range items {
		if len(it.Probe) == 0 {
			continue
		}
		parts := make([]string, 0, len(it.Probe)+1)
		parts = append(parts, "probe", it.ID)
		for _, a := range it.Probe {
			parts = append(parts, shellQuote(a))
		}
		b.WriteString(strings.Join(parts, " ") + "\n")
	}
	return b.String()
}

// ProbeResult 是单个组件的探测结果。
type ProbeResult struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"` // 版本号/首行输出；OK=false 时为空
}

// ParseProbe 解析 ProbeScript 的输出（一行一个 `id|ok|detail`）。
//
// 容错优先：解析不了的行直接跳过（镜像里可能混入其他输出，比如 pip 的警告），
// 让"没探测到"表现为 missing 而不是整体失败。
func ParseProbe(out string) map[string]ProbeResult {
	res := make(map[string]ProbeResult)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 2 {
			continue
		}
		id := strings.TrimSpace(parts[0])
		if id == "" {
			continue
		}
		// 只采信 ok/no 两种状态：其他取值说明脚本输出被污染（镜像里混入了别的输出），
		// 宁可当作"没探测到"，也不要猜成"已安装"。
		switch strings.TrimSpace(parts[1]) {
		case "ok", "no":
		default:
			continue
		}
		ok := strings.TrimSpace(parts[1]) == "ok"
		detail := ""
		if len(parts) == 3 {
			detail = truncate(strings.TrimSpace(parts[2]), 80)
		}
		res[id] = ProbeResult{OK: ok, Detail: detail}
	}
	return res
}

// shellQuote 单引号转义，保证参数里的空格/引号不会破坏命令。
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	// 已经安全就原样返回，保持生成脚本可读
	safe := true
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.ContainsRune("._-/:+=@,", c)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
