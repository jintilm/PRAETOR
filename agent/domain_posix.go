package agent

import "strings"

// needsPOSIXDomain 报告某个任务领域是否**必须**拿到 POSIX/Linux shell。
//
// 判据不是"这个域要跑命令"，而是"这个域的命令在错的方言下必然失败"：
//   - ctf：pwn/crypto/forensics/misc 全在 Linux 语义里（ELF、python exploit、
//     nc、objdump），Windows 上交给 PowerShell 等于一条都跑不对；
//   - reverse：RE 分析脚本（angr、capstone、python 驱动）同样是 POSIX 生态，
//     虽然样本是 PE，但分析工具不是；
//   - redteam：战役动作（nmap/impacket/sliver 客户端）都按 Linux 打法写。
//
// pentest（默认域）刻意不在内：它在宿主执行是既有且可用的路径，动它是范围外的风险。
func needsPOSIXDomain(domain string) bool {
	switch strings.ToLower(strings.TrimSpace(domain)) {
	case "ctf", "reverse", "redteam":
		return true
	}
	return false
}
