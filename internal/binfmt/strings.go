package binfmt

import (
	"regexp"
	"strings"
)

// 可疑 API / 字符串的判定。
//
// 原则：**只列"为什么会可疑"的短名单**，不做打分。
// 打分看起来聪明，实际会把"用了 VirtualAlloc 的正常程序"标成恶意软件，
// 反而误导模型。这里只把候选摊开，判断交给下一步的交叉引用/动态验证。

var suspiciousAPIs = []string{
	// 进程注入 / 内存执行
	"virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection",
	"queueuserapc", "setthreadcontext", "openprocess", "virtualprotect",
	// 反调试 / 反分析
	"isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstring",
	"ntqueryinformationprocess", "gettickcount",
	// 加载与执行
	"loadlibrarya", "loadlibraryw", "getprocaddress", "winexec",
	"shellexecutea", "shellexecutew", "createprocessa", "createprocessw",
	// 落地与下载
	"urldownloadtofile", "internetopen", "internetopenurl", "wsastartup", "connect",
	// 注册表持久化
	"regsetvalueexa", "regsetvalueexw", "regcreatekeyexa",
	// 提权 / 凭据
	"adjusttokenprivileges", "openprocesstoken", "cryptencrypt", "cryptdecrypt",
}

var suspiciousStrings = []string{
	"cmd.exe /c", "powershell -enc", "powershell -nop", "-windowstyle hidden",
	"hklm\\software\\microsoft\\windows\\currentversion\\run",
	"hkcuser\\software\\microsoft\\windows\\currentversion\\run",
	"/bin/sh -c", "chmod 777", "base64 -d",
	"mimikatz", "meterpreter", "beacon", "cobaltstrike",
	"-----begin rsa private key-----",
}

var (
	reURL    = regexp.MustCompile(`(?i)\b(?:https?|ftp|ws|wss)://[^\s"'<>]{4,120}`)
	reIPv4   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reWinPth = regexp.MustCompile(`(?i)\b[a-z]:\\\\?[^\s"'<>|]{2,100}`)
	reNixPth = regexp.MustCompile(`\b/(?:etc|tmp|var|usr|home|root|opt|proc)/[^\s"'<>]{2,100}`)
)

func isSuspiciousAPI(name string) bool {
	ln := strings.ToLower(strings.TrimSpace(name))
	if ln == "" {
		return false
	}
	// 去掉 A/W 后缀再比对（LoadLibraryA / LoadLibraryW 视为同一个）
	trimmed := strings.TrimSuffix(strings.TrimSuffix(ln, "a"), "w")
	for _, s := range suspiciousAPIs {
		if ln == s || trimmed == s {
			return true
		}
	}
	return false
}

// summarizeStrings 抽取可打印串并按类别归纳。
//
// 只扫前 maxStringsFrom 字节：真实样本常见几百 MB，全扫既慢又会把内存吃满；
// 而字符串通常集中在头部/资源区，前 8MB 的命中率已经够高（结论里会注明扫描范围）。
func summarizeStrings(data []byte) StringSummary {
	if len(data) > maxStringsFrom {
		data = data[:maxStringsFrom]
	}
	out := StringSummary{}
	urlSet := map[string]bool{}
	pathSet := map[string]bool{}
	ipSet := map[string]bool{}
	susSet := map[string]bool{}

	const minLen = 6
	buf := make([]byte, 0, 128)
	flush := func() {
		if len(buf) < minLen {
			buf = buf[:0]
			return
		}
		s := string(buf)
		buf = buf[:0]
		out.Total++
		ls := strings.ToLower(s)

		if len(out.URLs) < maxURLs {
			if m := reURL.FindString(s); m != "" && !urlSet[m] {
				urlSet[m] = true
				out.URLs = append(out.URLs, m)
			}
		}
		if len(out.IPs) < maxIPs {
			// 排除版本号噪声：只接受带点四段且每段都像 IP 的
			if m := reIPv4.FindString(s); m != "" && !isVersionLike(m) && !ipSet[m] {
				ipSet[m] = true
				out.IPs = append(out.IPs, m)
			}
		}
		if len(out.Paths) < maxPaths {
			if m := reWinPth.FindString(s); m != "" && !pathSet[m] {
				pathSet[m] = true
				out.Paths = append(out.Paths, m)
			} else if m := reNixPth.FindString(s); m != "" && !pathSet[m] {
				pathSet[m] = true
				out.Paths = append(out.Paths, m)
			}
		}
		if len(out.Suspicious) < maxSuspicious {
			for _, kw := range suspiciousStrings {
				if strings.Contains(ls, kw) && !susSet[kw] {
					susSet[kw] = true
					out.Suspicious = append(out.Suspicious, kw)
					break
				}
			}
		}
	}

	for _, c := range data {
		if c >= 0x20 && c < 0x7f {
			if len(buf) < 4096 { // 单串上限，防止把整段代码当字符串
				buf = append(buf, c)
			}
			continue
		}
		flush()
	}
	flush()
	return out
}

// isVersionLike 过滤 "1.2.3.4" 这种被误判成 IP 的版本号。
//
// 判据必须**窄**：最初写成"首段以 1 开头且每段 ≤2 位"，结果把 10.20.30.40
// 这种真实内网 IP 也当成版本号过滤掉了（漏报比误报更糟）。
// 现在只认「首段就是单个 0/1」的形态：1.2.3.4 / 0.9.1.2 → 版本；10.x / 192.x → IP。
func isVersionLike(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	if parts[0] != "0" && parts[0] != "1" {
		return false
	}
	for _, p := range parts {
		if len(p) > 2 {
			return false
		}
	}
	return true
}

func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
