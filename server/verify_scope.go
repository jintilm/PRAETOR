package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jintilm/praetor/db"
)

// ScopeFunc 判定一个 URL 是否落在任务授权范围内。
//
// 返回 error 表示「不允许重放」，调用方会把结论落成 suspected 并写明原因，
// 而不是把请求发出去。返回 nil 表示放行。
type ScopeFunc func(rawURL string) error

// taskScopeGuard 用 task_scope 表构造重放前的范围校验。
//
// 为什么必须在重放前判：重放的目标 URL 来自**历史证据**（可能是几分钟前录的、
// 也可能是从别的任务继承来的），而 worker 自己的出网还有 scope/审批门。
// 验证器跑在宿主进程里，走的是另一条链路——不补这一刀，验证就成了「绕过范围
// 检查的唯一出口」。
//
// 判定口径（保守）：
//   - 范围里没有任何「主机维度」的行（只有 company/icp/keyword）→ 放行并记日志：
//     这类 scope 解析不出主机，硬拒会让所有企业级任务失去验证能力；
//   - 有主机维度的行 → 必须命中其一，未命中即拒绝；
//   - 读不到范围（DB 出错）→ 放行并记日志：验证失败不该由基础设施抖动导致。
func taskScopeGuard(assets *db.AssetStore, taskID int64) ScopeFunc {
	if assets == nil || taskID <= 0 {
		return nil
	}
	return func(rawURL string) error {
		rows, err := assets.ListTaskScope(taskID)
		if err != nil {
			// 基础设施抖动不该吞掉验证能力：放行并留下可查的日志。
			log.Printf("[verify] 读取任务 %d 的 scope 失败，本次跳过范围校验: %v", taskID, err)
			return nil
		}
		ok, reason := scopeAllowsHost(rows, rawURL)
		if ok {
			return nil
		}
		return fmt.Errorf("%s", reason)
	}
}

// scopeAllowsHost 是纯判定（不含 DB、不写日志），便于单测覆盖每一条匹配规则。
//
// 返回 (是否放行, 拒绝原因)。放行时原因为空。
func scopeAllowsHost(rows []db.TaskScope, rawURL string) (bool, string) {
	hostRows := make([]db.TaskScope, 0, len(rows))
	for _, row := range rows {
		if scopeRowHasHost(row) {
			hostRows = append(hostRows, row)
		}
	}
	if len(hostRows) == 0 {
		// 只有 company/icp/keyword 这类没有主机语义的范围：解析不出主机就硬拒，
		// 会让所有企业级任务失去验证能力，因此放行。
		return true, ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return false, fmt.Sprintf("证据 URL 无法解析出主机: %q", rawURL)
	}
	host := strings.ToLower(u.Hostname())
	for _, row := range hostRows {
		if scopeRowAllows(row, host) {
			return true, ""
		}
	}
	return false, fmt.Sprintf("%s 不在任务测试范围（%d 条主机维度 scope 均不匹配）；若该目标在授权内，先用 add_task_scope 登记再重试", host, len(hostRows))
}

// scopeRowHasHost 判断该 scope 行是否带主机语义（能用来匹配 URL 的 host）。
func scopeRowHasHost(row db.TaskScope) bool {
	switch row.Kind {
	case "ip", "cidr", "root_domain", "subdomain":
		return scopeValue(row) != ""
	}
	return false
}

// scopeValue 取该行的可匹配值。不同来源写不同列：播种写 Value，自动收录写 Domain。
func scopeValue(row db.TaskScope) string {
	for _, v := range []string{row.Value, row.Domain, row.Net} {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// scopeRowAllows 按 kind 匹配：ip 精确、cidr 网段、域名同域或子域。
func scopeRowAllows(row db.TaskScope, host string) bool {
	val := strings.ToLower(scopeValue(row))
	switch row.Kind {
	case "ip":
		return strings.EqualFold(strings.Trim(val, "[]"), host)
	case "cidr":
		_, network, err := net.ParseCIDR(val)
		if err != nil {
			return false
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		return ip != nil && network.Contains(ip)
	case "root_domain", "subdomain":
		val = strings.TrimPrefix(val, ".")
		return host == val || strings.HasSuffix(host, "."+val)
	}
	return false
}

// (s *Server) taskScopeGuard 是生产接线用的适配：把 server.Task 的字符串 ID 转成 int64。
func (s *Server) taskScopeGuard(t *Task) ScopeFunc {
	if s == nil || s.m == nil || t == nil {
		return nil
	}
	id, err := strconv.ParseInt(strings.TrimSpace(t.ID), 10, 64)
	if err != nil || id <= 0 {
		return nil
	}
	return taskScopeGuard(s.m.assets, id)
}

// replayTransport 构造「走记录代理」的重放 Transport。
//
// 为什么不能只用 http.DefaultTransport：那样复现流量不会进流量库，UI 上
// 「已验证」的漏洞看不到对应请求，而且重放会绕过 MITM 的出口策略。
// proxyAddr 为空表示当前没有记录代理/出口代理（直连），此时返回 nil 让
// replay 层回落默认传输——与旧行为一致，但至少不是「有代理却不用」。
func replayTransport(proxyAddr, caCertPath string) http.RoundTripper {
	addr := strings.TrimSpace(proxyAddr)
	if addr == "" {
		return nil
	}
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" {
		log.Printf("[verify] 记录代理地址不可用（%q），本次重放走直连: %v", proxyAddr, err)
		return nil
	}
	tr := &http.Transport{
		Proxy:              http.ProxyURL(u),
		DisableCompression: true, // 与 replay 的 Accept-Encoding: identity 口径一致
		IdleConnTimeout:    30 * time.Second,
		TLSClientConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if path := strings.TrimSpace(caCertPath); path != "" {
		pem, rerr := os.ReadFile(path)
		if rerr != nil {
			log.Printf("[verify] 读取记录代理 CA 失败（%s），HTTPS 证据可能因证书不受信而重放失败: %v", path, rerr)
			return tr
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Printf("[verify] 记录代理 CA 解析失败（%s），同上", path)
			return tr
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return tr
}

// classifyScope 判定一条证据 URL 与任务范围的匹配程度。**只分类，不拦截**。
//
// 为什么要区分来源：显式声明（add_task_scope / 操作员）才是授权意图；
// 从任务文本解析出来的 auto 行只是推断——用推断去硬拦，会误杀操作员写了但没解析到的目标。
func classifyScope(rows []db.TaskScope, rawURL string) string {
	host := hostOfURL(rawURL)
	if host == "" {
		return db.ScopeUnverified
	}
	hasHostRow, explicitHit, autoHit := false, false, false
	for _, row := range rows {
		if !scopeRowHasHost(row) {
			continue
		}
		hasHostRow = true
		if !scopeRowAllows(row, host) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(row.Source), "auto") {
			autoHit = true
		} else {
			explicitHit = true
		}
	}
	switch {
	case explicitHit:
		return db.ScopeIn
	case autoHit:
		return db.ScopeAssumed
	case !hasHostRow:
		// 只有 company/icp/keyword：解析不出主机，无法判定，不扣帽子。
		return db.ScopeUndeclared
	}
	return db.ScopeUnverified
}

// hostOfURL 取主机（小写）；解析不出来返回空。
func hostOfURL(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// scopeStateOf 取一组 URL 里最差的那个状态（worst-wins），并给出人类可读说明。
func scopeStateOf(rows []db.TaskScope, rawURLs []string) (string, string) {
	if len(rawURLs) == 0 {
		return db.ScopeUndeclared, ""
	}
	rank := map[string]int{db.ScopeIn: 0, db.ScopeUndeclared: 1, db.ScopeAssumed: 2, db.ScopeUnverified: 3}
	worst := db.ScopeIn
	var bad []string
	for _, raw := range rawURLs {
		st := classifyScope(rows, raw)
		if rank[st] > rank[worst] {
			worst = st
		}
		if st == db.ScopeUnverified || st == db.ScopeAssumed {
			if h := hostOfURL(raw); h != "" {
				bad = append(bad, h)
			}
		}
	}
	switch worst {
	case db.ScopeUnverified:
		return worst, "证据里有 " + strings.Join(uniqStrings(bad), ", ") +
			" 不在任务声明的范围内；报告会标注「范围未声明」。若已在授权内，用 add_task_scope 登记该目标后再绑定。"
	case db.ScopeAssumed:
		return worst, "证据目标只出现在任务文本的自动解析结果里（可能是操作员漏写）：" +
			strings.Join(uniqStrings(bad), ", ") + "；建议用 add_task_scope 显式登记。"
	}
	return worst, ""
}

func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// annotateBindingScope 在绑定流量后记录「证据来源与任务范围的匹配程度」。
//
// 关键取舍：**只标注，不拒绝**。
//   - scope 是任务文本解析 + agent 自加出来的推断，不是权威授权清单；
//   - 拿推断去拦，会把「操作员写了但没解析到」的合法目标一起打死，直接削弱渗透能力；
//   - 而审核真正需要的是「这条证据来自哪里」——把这个事实显性化就够了。
//
// 需要硬拦时走 egress 层（独立开关），不在证据链上做。
func (s *Server) annotateBindingScope(ctx context.Context, findingID int64, list *db.FindingTraffic) {
	if s == nil || s.m == nil || s.m.pg == nil || list == nil {
		return
	}
	taskID, err := s.m.pg.FindingTaskID(ctx, findingID)
	if err != nil || taskID <= 0 || s.m.assets == nil {
		return
	}
	rows, err := s.m.assets.ListTaskScope(taskID)
	if err != nil {
		log.Printf("[scope] 读取任务 %d 的 scope 失败，跳过标注: %v", taskID, err)
		return
	}
	urls := make([]string, 0, len(list.Bindings))
	for _, b := range list.Bindings {
		if u := strings.TrimSpace(b.Snapshot.URL); u != "" {
			urls = append(urls, u)
		}
	}
	state, note := scopeStateOf(rows, urls)
	list.ScopeState, list.ScopeNote = state, note
	if err := s.m.pg.SetFindingScopeState(ctx, findingID, state); err != nil {
		log.Printf("[scope] 记录 finding %d 的范围状态失败: %v", findingID, err)
	}
	if state == db.ScopeUnverified || state == db.ScopeAssumed {
		log.Printf("[scope] finding %d 的证据来自范围未显式声明的目标（%s）：%s", findingID, state, note)
	}
}

// taskID64 把 Task 的字符串 ID 转成 PG 用的 int64；解析失败返回 0（= 无任务归属）。
// 归属、scope、验收都要这个数，集中一处避免各自 ParseInt 后口径不一致。
func taskID64(t *Task) int64 {
	if t == nil {
		return 0
	}
	id, err := strconv.ParseInt(strings.TrimSpace(t.ID), 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}
