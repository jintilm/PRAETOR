package sandbox

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// targetNetworkInspect 是 TargetNetwork 的 docker 调用，抽成变量便于测试注入。
var targetNetworkInspect = runDockerCLI

// ContainerNetworks 返回容器所在的所有 docker 网络与各自 IP（网络名 → IP）。
//
// 只对「本机存在同名容器」的主机名有意义：这是题面与靶场同机部署时最常见的情形
// （docker compose 起的 delulu / xben009-poc 之类）。
//
// 先按**容器名**查；查不到再按**主机名/别名**扫一遍本机容器。
// 后者是 2026-10-30 补的：题目容器常以 `--hostname labyrinth` 起、容器名却是 `chal-labyrinth`，
// 题面写的是 hostname。只按容器名查会查不到 → 不接网络 → 沙箱里解析失败 → 模型开始扫
// 172.17.0.0/24，打到同宿主上的**另一个靶机**并拿到它的 flag（task 209 实测）。
func ContainerNetworks(ctx context.Context, name string) (map[string]string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("sandbox: 空容器名")
	}
	out, stderr, code, err := targetNetworkInspect(ctx, []string{
		"inspect", "--format",
		`{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}`,
		name,
	}, "")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		if nets, ok := networksByHostname(ctx, name); ok {
			return nets, nil
		}
		return nil, fmt.Errorf("docker inspect %s: %s", name, strings.TrimSpace(stderr))
	}
	return parseNetworks(out), nil
}

// networksByHostname 在本机所有容器里按 Config.Hostname 或容器名匹配。
//
// 用它而不是 `docker inspect <name>`：inspect 只认容器名/ID，不认 hostname，
// 也不认 compose 给的服务别名。两个调用是必要的：先 `ps -aq` 拿 ID（不依赖名字解析），
// 再用一条 inspect 把全部容器的名字/hostname/网络一次取回。
func networksByHostname(ctx context.Context, want string) (map[string]string, bool) {
	ids, _, code, err := targetNetworkInspect(ctx, []string{"ps", "-aq"}, "")
	if err != nil || code != 0 || strings.TrimSpace(ids) == "" {
		return nil, false
	}
	args := append([]string{
		"inspect", "--format",
		`{{.Name}}|{{.Config.Hostname}}|{{range $k, $v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}`,
	}, strings.Fields(ids)...)
	out, _, code, err := targetNetworkInspect(ctx, args, "")
	if err != nil || code != 0 {
		return nil, false
	}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "|", 3)
		if len(parts) != 3 {
			continue
		}
		cname := strings.TrimPrefix(parts[0], "/")
		hostname := parts[1]
		if strings.EqualFold(cname, want) || (hostname != "" && strings.EqualFold(hostname, want)) {
			if nets := parseNetworks(parts[2]); len(nets) > 0 {
				return nets, true
			}
		}
	}
	return nil, false
}

// parseNetworks 解析 `name=ip name2=ip2`。空 IP 的条目丢弃（容器已停但仍挂着网络别名时
// inspect 会给空串，接进 --add-host 会写出 `host:` 这种非法条目）。
func parseNetworks(s string) map[string]string {
	out := map[string]string{}
	for _, f := range strings.Fields(s) {
		k, v, ok := strings.Cut(f, "=")
		if !ok || k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

// TargetNetwork 决定任务容器应该接入哪个 docker 网络，并给出 host→ip 的补充 hosts。
//
// 解决的是这一类问题：题面写 `http://delulu:1337`，而 delulu 跑在本机的自定义网络
// `praetor-ctf` 里；任务容器默认在 bridge，**Docker 内嵌 DNS 只解析同一自定义网络内的
// 容器名**，于是容器里 `curl delulu` 一律 `could not resolve`。实测后果（task 187 / 194
// 各一次）：模型先试 curl、再试 nc、再猜 172.17.0.1，**花 10~17 分钟才发现要用宿主 IP**，
// 而真正定位漏洞只用了 8 分钟 —— 这一项摩擦比题目本身更贵。
//
// 规则（刻意保守，宁可不接也不接错）：
//   - 只认「本机存在同名容器」的 host；远程域名一律返回空（那些用正常 DNS）；
//   - 找不到任何容器 → 返回空，调用方沿用 declared 网络；
//   - 多个 host 落在不同网络 → 取名字排序后的第一个，并把全部 host:ip 作为 add-host
//     兜底，同时由调用方记警告（不静默：接错网络的表现是"目标不可达"，很难排查）；
//   - declared 非空时**不覆盖**（部署方显式配了网络，以配置为准）。
func TargetNetwork(ctx context.Context, declared string, hosts []string) (network string, addHosts []string) {
	if strings.TrimSpace(declared) != "" || len(hosts) == 0 {
		return "", nil
	}
	type hit struct {
		host    string
		network string
		ip      string
	}
	var hits []hit
	seen := map[string]bool{}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		nets, err := ContainerNetworks(ctx, h)
		if err != nil || len(nets) == 0 {
			continue
		}
		// 同一容器可能在多个网络（compose 常见）。挑名字排序最小的那个，保证
		// 同一份配置每次选出同一个网络 —— 否则容器的网络会随 map 迭代顺序漂移。
		names := make([]string, 0, len(nets))
		for n := range nets {
			names = append(names, n)
		}
		sort.Strings(names)
		hits = append(hits, hit{host: h, network: names[0], ip: nets[names[0]]})
	}
	if len(hits) == 0 {
		return "", nil
	}
	// 选网络：同样按名字排序，避免"哪道题先解析就先赢"的随机结果。
	sort.Slice(hits, func(i, j int) bool { return hits[i].network < hits[j].network })
	network = hits[0].network
	for _, h := range hits {
		// 只对落在所选网络里的 host 加 hosts 条目；跨网络的 IP 在容器里不可路由，
		// 写进去只会把"解析失败"变成"连接超时"——对模型来说后者更难诊断。
		if h.network == network && h.ip != "" {
			addHosts = append(addHosts, h.host+":"+h.ip)
		}
	}
	sort.Strings(addHosts)
	return network, addHosts
}
