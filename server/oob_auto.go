package server

import (
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/jintilm/praetor/config"

	"github.com/jintilm/praetor/db"
)

// oobAutoSentinel 让用户显式要求"自动探测"。
const oobAutoSentinel = "auto"

// ensureOOBBaseURL 在启动时把回连地址补全，省掉每次换网络都要手填。
//
// 规则：
//   - 已配置且不是 auto → 尊重用户配置，不动；
//   - 空 或 auto → 探测本机非回环 IPv4，拼成 http://<ip>:<port> 写入。
//
// 探测到的地址只对"内网可达的目标"有效；公网目标仍然需要公网入口，
// 那种情况由用户显式填一个域名/隧道地址覆盖。
func ensureOOBBaseURL(pg *db.DB, port int) {
	if pg == nil {
		return
	}
	cur, ok, err := pg.GetSetting(settingOOBBaseURL)
	if err != nil {
		return
	}
	cur = strings.TrimSpace(cur)
	// 显式环境变量是运维意图，任何时候都优先，并能纠正之前自动写坏的值。
	if env := strings.TrimRight(strings.TrimSpace(config.Env("OOB_BASE_URL")), "/"); env != "" {
		if env == cur {
			return
		}
		if err := pg.SetSetting(settingOOBBaseURL, env); err != nil {
			log.Printf("[oob] 写入 OOB_BASE_URL 失败: %v", err)
			return
		}
		log.Printf("[oob] 回连地址来自环境变量: %s", env)
		return
	}
	// 空 = 走零配置公网端点（默认）；只有显式写 auto 才探测本机地址。
	if !ok || cur == "" || !strings.EqualFold(cur, oobAutoSentinel) {
		return
	}
	ip := detectLanIP()
	if ip == "" {
		if cur == "" {
			log.Printf("[oob] 未探测到可用内网地址，带外回连保持关闭（可在设置里手填）")
		}
		return
	}
	base := "http://" + net.JoinHostPort(ip, itoa(port))
	if base == cur {
		return
	}
	if err := pg.SetSetting(settingOOBBaseURL, base); err != nil {
		log.Printf("[oob] 写入自动探测地址失败: %v", err)
		return
	}
	log.Printf("[oob] 已自动配置带外回连地址: %s（内网/靶场目标直接可用；公网目标请改填隧道地址）", base)
}

// detectLanIP 取第一个非回环、非链路本地的 IPv4。
func detectLanIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipn.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			return ip.String()
		}
	}
	return ""
}

// httpPort 读取本服务的 HTTP 端口，用于拼回连地址。
func httpPort() int {
	if v := strings.TrimSpace(config.Env("HTTP_PORT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return 8797
}

// itoa 避免为一行转换引入 strconv 依赖链噪音。
func itoa(v int) string {
	if v <= 0 {
		v = 8797
	}
	var b [8]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
		if v == 0 {
			break
		}
	}
	return string(b[i:])
}
