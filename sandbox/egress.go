package sandbox

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// EgressUpstream 是沙箱容器的全量出口上游（IP 层透明重定向的目标）。
//
// 与 Env 里的 HTTP_PROXY 是两回事：环境变量只覆盖"讲规矩"的客户端（curl、
// python requests…），nmap -sT、Go 写的工具、任何不读环境变量的程序都以真实
// IP 直连 —— 对渗透/红队作业这是漏风的隐身。透明层用 iptables 把容器全部
// 出站 TCP 重定向到本结构描述的上游，环境变量降级为优化路径。
type EgressUpstream struct {
	// Type 是 redsocks 的 relay 类型："socks5" 或 "http-connect"。
	// Clash/mihomo 混合端口与 gost 都是两者通吃；商业 HTTP 代理用 http-connect。
	Type string
	Host string // 上游地址；回环地址已在解析时翻译成容器可达形式
	Port int
	User string // 可选认证
	Pass string
	// Exclude 是额外要直连绕过的 host:port（如 SANDBOX_PROXY 指向的 MITM 录制代理
	// ——它有自己的上游=同一份全局代理，链路里不需要二跳，也不该被重定向截住）。
	Exclude []string
}

// ParseEgressUpstream 把全局出口代理的 URL 解析成容器侧的上游描述。
//
// loopbackOverride：raw 的 host 是回环（127.0.0.1/localhost/::1）时替换成该值
// （容器里 127.0.0.1 是它自己，宿主上的代理必须走 host.docker.internal 或网关 IP
// 才可达）；非回环地址原样保留（IP 或可解析的主机名）。
//
// scheme → redsocks 类型：socks5 → socks5；http/https → http-connect（明文 CONNECT，
// Clash 混合端口/gost/常见本地代理都是这个形态；"代理连接本身走 TLS"的场景 v1 不支持）。
func ParseEgressUpstream(raw, loopbackOverride string) (*EgressUpstream, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("egress: 解析代理 URL: %w", err)
	}
	var typ string
	switch strings.ToLower(u.Scheme) {
	case "socks5":
		typ = "socks5"
	case "http", "https":
		typ = "http-connect"
	default:
		return nil, fmt.Errorf("egress: 不支持的代理协议 %q（支持 http/https/socks5）", u.Scheme)
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" || port == "" {
		return nil, fmt.Errorf("egress: 代理 URL 缺 host 或端口: %q", raw)
	}
	if isLoopbackHost(host) {
		if strings.TrimSpace(loopbackOverride) == "" {
			return nil, fmt.Errorf("egress: 上游是回环地址 %q，但未提供容器可达的替代主机", host)
		}
		host = loopbackOverride
	}
	p, err := net.LookupPort("tcp", port)
	if err != nil {
		return nil, fmt.Errorf("egress: 端口无效 %q", port)
	}
	up := &EgressUpstream{Type: typ, Host: host, Port: p}
	if u.User != nil {
		up.User = u.User.Username()
		up.Pass, _ = u.User.Password()
	}
	return up, nil
}

// ParseEgressExclude 解析"额外直连绕过"列表（逗号分隔的 host:port 或 host）。
// 输入来自 SANDBOX_PROXY 这类部署方配置：它指向的 MITM 录制代理有自己的上游
// （同一份全局代理），透明层必须放行它，否则 env 抓包链路被截住后出口变成二跳。
func ParseEgressExclude(raw string) []string {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		// 允许传完整 URL（http://host:port），取 host:port
		if strings.Contains(item, "://") {
			if u, err := url.Parse(item); err == nil && u.Host != "" {
				item = u.Host
			}
		}
		if host := strings.Split(item, "/")[0]; host != "" {
			out = append(out, host)
		}
	}
	return out
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// env 生成注入容器的环境变量（K=V）。密码走 env 而不是 argv：
// argv 会进 docker inspect / ps，容器内任何能读 /proc 的进程都看得到。
func (u *EgressUpstream) env() []string {
	env := []string{
		"PRAETOR_EGRESS_TYPE=" + u.Type,
		"PRAETOR_EGRESS_HOST=" + u.Host,
		"PRAETOR_EGRESS_PORT=" + fmt.Sprint(u.Port),
	}
	if u.User != "" {
		env = append(env, "PRAETOR_EGRESS_USER="+u.User)
	}
	if u.Pass != "" {
		env = append(env, "PRAETOR_EGRESS_PASS="+u.Pass)
	}
	if len(u.Exclude) > 0 {
		env = append(env, "PRAETOR_EGRESS_EXCLUDE="+strings.Join(u.Exclude, ","))
	}
	return env
}
