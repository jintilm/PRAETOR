package server

// 任务级 Android 动态授权的执行链：动态动作识别 → 短时令牌 → 设备锁 → 审计。
//
// 三条不可让步的边界（对应设计定稿）：
//  1. 授权由**人在创建任务时显式签发**（db.task_dynamic_grants），这里只传递与校验；
//     agent 无法签发、扩大、续期，服务端不信任任何来自 LLM 的授权字段。
//  2. 令牌完全在 Go 侧的 hook registry 旁路里流转，**不进 LLM 上下文**，模型看不到
//     也就无法伪造、写进日志或外发；每次工具调用由机器校验后自动放行。
//  3. 一切异常（读库失败、令牌过期、设备被占用、op 不在白名单）都 fail-closed，
//     并给出「改走静态」的明确引导，不会静默降级、也不会让任务空转。

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	pgdb "github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/guard"
)

const (
	// 令牌短时有效；续签仍受 DB 授权的 valid_until 与撤销状态约束。
	dynamicTicketTTL = 10 * time.Minute
	// 设备租约比令牌长：一次动态作业跨多次工具调用，不能每次都重新抢锁。
	dynamicLeaseTTL = 15 * time.Minute
	// DB 授权状态的缓存窗口。撤销接口会主动 Invalidate，不依赖这个窗口收敛。
	dynamicGrantCacheTTL = 30 * time.Second
	dynamicAuditTimeout  = 3 * time.Second
)

// Ensure the compiler keeps the guard contract honest: gate 必须实现硬闸接口，
// 且接口变更时这里会立刻报错，而不是等运行时才发现 hook 没接上。
var _ guard.DynamicGrantChecker = (*dynamicGrantGate)(nil)

// dynamicToolOps 是 P2 会实现的设备工具名 → 原子操作映射。
// 现在先把名字固定下来：授权签发、硬闸、工具实现共用同一套闭集词汇。
var dynamicToolOps = map[string]string{
	"mobile_install":   "install",
	"mobile_launch":    "launch",
	"mobile_shell":     "shell",
	"mobile_frida":     "frida",
	"mobile_hook":      "hook",
	"mobile_proxy":     "proxy",
	"mobile_logcat":    "logcat",
	"mobile_pull_data": "pull_data",
	"mobile_cleanup":   "cleanup",
}

var (
	// 只读的 adb 自省不算动态作业：探测设备列表/版本既不装包也不碰真实账号。
	reADBReadOnly = regexp.MustCompile(`(?i)\badb\s+(devices|version|help|get-state|get-serialno)\b`)
	reADBInstall  = regexp.MustCompile(`(?i)\badb\s+(install|install-multiple|install-multiple-package|uninstall)\b`)
	reADBLaunch   = regexp.MustCompile(`(?i)\badb\s+shell\b.*\b(am\s+start|monkey|start-activity)\b`)
	reADBLogcat   = regexp.MustCompile(`(?i)\badb\s+logcat\b`)
	reADBPull     = regexp.MustCompile(`(?i)\badb\s+pull\b`)
	reADBShell    = regexp.MustCompile(`(?i)\badb\s+(shell|root|remount|reboot|push|forward|reverse|tcpip|connect|disconnect|wait-for|emu|backup|restore)\b`)
	reADBAny      = regexp.MustCompile(`(?i)(^|[;&|\s(])adb\s+\S`)
	reFrida       = regexp.MustCompile(`(?i)\b(frida(?:-ps|-trace|-dump|-kill|-server|-ls)?|objection|gum-graft)\b`)
	reMITM        = regexp.MustCompile(`(?i)\b(mitmdump|mitmproxy)\b`)
)

// dynamicOpsForCall 判断一次工具调用是不是「真机动态作业」，返回它需要的 op 集合。
//
// 两条识别路径都要有：专用设备工具（P2 提供）与 Bash 直敲 adb/frida。只认前者会
// 让模型随手写一条 `adb shell` 就绕过整条授权链；只认后者则把工具名当成门禁，
// 新增工具时容易漏挂。命令串用的是**模式匹配而非语义判断**（与取证边界同一纪律）：
// 宁可误拦一条含 adb 字样的静态命令，也不能漏放一次真机操作。
func dynamicOpsForCall(tool string, input json.RawMessage) []string {
	if op, ok := dynamicToolOps[tool]; ok {
		return []string{op}
	}
	if tool != "Bash" && tool != "shell_open" && tool != "shell_send" {
		return nil
	}
	var cmd string
	switch tool {
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(input, &in)
		cmd = in.Text
	default:
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(input, &in)
		cmd = in.Command
	}
	if strings.TrimSpace(cmd) == "" {
		return nil
	}
	set := map[string]bool{}
	add := func(op string) { set[op] = true }
	if reADBInstall.MatchString(cmd) {
		add("install")
	}
	if reADBLaunch.MatchString(cmd) {
		add("launch")
	}
	if reADBLogcat.MatchString(cmd) {
		add("logcat")
	}
	if reADBPull.MatchString(cmd) {
		add("pull_data")
	}
	if reADBShell.MatchString(cmd) || reADBAny.MatchString(cmd) {
		add("shell")
	}
	if reFrida.MatchString(cmd) {
		add("frida")
	}
	if reMITM.MatchString(cmd) {
		add("proxy")
	}
	// 纯只读自省不触发授权；但若同一条命令还夹着别的动作，前面的命中必须保留。
	if len(set) == 1 && set["shell"] && reADBReadOnly.MatchString(cmd) && !reADBInstall.MatchString(cmd) {
		return nil
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for op := range set {
		out = append(out, op)
	}
	sort.Strings(out)
	return out
}

// dynamicTicket 是绑死 taskID / 设备 / APK / ops / 过期时间的短时 HMAC 票据。
// 完整票据只在内存里；库里只存它的 SHA256 摘要供事后核对。
type dynamicTicket struct {
	raw       string
	digest    string
	expiresAt time.Time
	bound     string // 绑定字段的规范化文本，用于续签时比对
}

type dynamicGrantGate struct {
	taskID int64
	pg     *pgdb.DB
	secret []byte
	now    func() time.Time

	mu       sync.Mutex
	cached   *pgdb.DynamicGrant
	cachedAt time.Time
	ticket   dynamicTicket
}

func (m *Manager) newDynamicGrantGate(taskID int64) *dynamicGrantGate {
	return &dynamicGrantGate{
		taskID: taskID,
		pg:     m.pg,
		secret: m.dynamicGrantSecret,
		now:    time.Now,
	}
}

// Invalidate 丢弃授权缓存与令牌。撤销授权、任务收尾时调用，
// 让「已撤销」立刻生效，不必等缓存窗口过期。
func (g *dynamicGrantGate) Invalidate() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cached = nil
	g.cachedAt = time.Time{}
	g.ticket = dynamicTicket{}
}

// Check 是 guard.PreToolUse 的硬闸实现。
func (g *dynamicGrantGate) Check(ctx context.Context, tool string, input json.RawMessage) error {
	ops := dynamicOpsForCall(tool, input)
	if len(ops) == 0 {
		return nil // 非动态调用：零开销放行
	}
	if g == nil || g.pg == nil || len(g.secret) == 0 {
		return errors.New("动态授权闸未装配（密钥或数据库不可用），本次动态操作拒绝执行")
	}
	grant, err := g.grant()
	if err != nil {
		return g.block(tool, ops, "", "读取任务动态授权失败，拒绝执行动态操作："+err.Error())
	}
	if grant == nil {
		return g.block(tool, ops, "", "任务未签发 Android 动态授权；授权须在创建任务时由人显式签发，不能由任务下发自动产生")
	}
	now := g.now()
	switch {
	case !grant.WrittenAuthorization:
		return g.block(tool, ops, grant.DeviceSerial, "授权未勾选书面授权确认")
	case grant.RevokedAt != nil:
		return g.block(tool, ops, grant.DeviceSerial, "授权已撤销："+grant.RevokeReason)
	case now.Before(grant.ValidFrom):
		return g.block(tool, ops, grant.DeviceSerial, "授权尚未生效")
	case !now.Before(grant.ValidUntil):
		return g.block(tool, ops, grant.DeviceSerial, "授权已过有效期（"+grant.ValidUntil.Format(time.RFC3339)+"）")
	}
	for _, op := range ops {
		if !grant.Allows(op) {
			return g.block(tool, ops, grant.DeviceSerial,
				fmt.Sprintf("操作 %q 不在本次签发范围内（已授权：%s）", op, strings.Join(grant.Ops, "/")))
		}
	}
	ticket, err := g.currentTicket(grant, now)
	if err != nil {
		return g.block(tool, ops, grant.DeviceSerial, "动态授权令牌不可用："+err.Error())
	}
	// 设备独占锁：真机是共享物理资源，多任务并发会互相装包/覆盖 frida 脚本。
	// 合成授权下可能没有序列号（未配 PRAETOR_MOBILE_DEVICE_SERIAL）：这时不锁——
	// 「没有具体设备」不该被独占，也就谈不上多任务互相打架。配了序列号就照常抢锁。
	if grant.DeviceSerial != "" {
		if err := g.pg.AcquireDeviceLease(ctx, grant.DeviceSerial, g.taskID, dynamicLeaseTTL); err != nil {
			if errors.Is(err, pgdb.ErrDeviceBusy) {
				return g.block(tool, ops, grant.DeviceSerial, "设备已被其它任务占用，请等待其租约到期或让对方收尾释放")
			}
			return g.block(tool, ops, grant.DeviceSerial, "设备锁不可用，拒绝执行动态操作："+err.Error())
		}
	}
	g.audit(pgdb.DynamicGrantAudit{
		TaskID: g.taskID, Action: "allow", Op: strings.Join(ops, ","), Tool: tool,
		DeviceSerial: grant.DeviceSerial, TicketDigest: ticket.digest,
	})
	return nil
}

func (g *dynamicGrantGate) block(tool string, ops []string, serial, reason string) error {
	g.audit(pgdb.DynamicGrantAudit{
		TaskID: g.taskID, Action: "block", Op: strings.Join(ops, ","), Tool: tool,
		DeviceSerial: serial, Reason: reason,
	})
	return errors.New(reason)
}

// loadGrant 取授权事实，规则与 Server.effectiveMobileGrant 完全一致（见 mobile_auth.go）：
// 签过且生效 → 用记录本身；签过但已撤销/过期 → 拒绝；从未签过 → 合成。
// 刻意不复用 Server 上的方法：gate 只持有 Manager，两处共用同一份模式判定与设备解析。
func (g *dynamicGrantGate) loadGrant() (*pgdb.DynamicGrant, error) {
	if mobileAuthAssumed() {
		real, err := g.pg.GetTaskDynamicGrant(g.taskID)
		if err != nil {
			return nil, err
		}
		if real != nil {
			if real.Active(g.now()) {
				return real, nil
			}
			// 撤销/过期必须真的停：绝不能在 assume 模式下回落到全量合成授权。
			return nil, errMobileGrantRevoked
		}
		serial, _ := mobileTargetSerialForTask(g.pg, g.taskID)
		return assumedMobileGrant(g.taskID, serial), nil
	}
	return g.pg.GetTaskDynamicGrant(g.taskID)
}

// grant 读取授权并做短缓存。缓存只影响性能：任何拒绝路径都在 Active 判定里，
// 撤销接口会主动 Invalidate，不会出现「撤销后还靠缓存放行一个长任务」的窗口。
func (g *dynamicGrantGate) grant() (*pgdb.DynamicGrant, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if g.cached != nil && now.Sub(g.cachedAt) < dynamicGrantCacheTTL {
		return g.cached, nil
	}
	grant, err := g.loadGrant()
	if err != nil {
		return nil, err
	}
	g.cached, g.cachedAt = grant, now
	return grant, nil
}

// currentTicket 取当前有效令牌；过期或绑定字段变化时按 DB 授权重新签发。
// 续签不是「agent 触发的续期」：它仍受 valid_until / revoked_at 约束，
// 且密钥与票据始终在 Go 侧，模型全程不可见。
func (g *dynamicGrantGate) currentTicket(grant *pgdb.DynamicGrant, now time.Time) (dynamicTicket, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	bound := ticketBinding(g.taskID, grant)
	if g.ticket.raw != "" && g.ticket.bound == bound && now.Before(g.ticket.expiresAt) {
		return g.ticket, nil
	}
	// 重新签发前再确认一次授权状态，避免缓存里的旧事实给已撤销的任务续命。
	fresh, err := g.loadGrant()
	if err != nil {
		return dynamicTicket{}, err
	}
	if fresh == nil || !fresh.Active(now) {
		return dynamicTicket{}, errors.New("授权已撤销或过期，不再签发调用令牌")
	}
	if ticketBinding(g.taskID, fresh) != bound {
		return dynamicTicket{}, errors.New("授权绑定字段发生变化，须重新签发任务授权")
	}
	t, err := issueDynamicTicket(g.secret, g.taskID, fresh, now)
	if err != nil {
		return dynamicTicket{}, err
	}
	g.ticket = t
	g.audit(pgdb.DynamicGrantAudit{
		TaskID: g.taskID, Action: "issue", DeviceSerial: fresh.DeviceSerial,
		TicketDigest: t.digest, Operator: fresh.Operator,
		Reason: "短时调用令牌签发（不进入模型上下文）",
	})
	return t, nil
}

func (g *dynamicGrantGate) audit(a pgdb.DynamicGrantAudit) {
	if g.pg == nil {
		return
	}
	// 审计刻意不继承 worker 的 ctx：任务被取消/超时时的那次调用，
	// 恰恰最需要留下「为什么没放行 / 放行了什么」。用独立短超时避免 DB 慢拖住工具调用。
	c, cancel := context.WithTimeout(context.Background(), dynamicAuditTimeout)
	defer cancel()
	if err := g.pg.AppendDynamicGrantAudit(c, a); err != nil {
		log.Printf("[dynamic-grant] 任务 %d 审计写入失败（不影响授权判定）：%v", g.taskID, err)
	}
}

// ticketBinding 把「令牌绑死的事实」规范化成一段文本。
// 任一字段变化都让旧令牌立即失效 —— 授权不可跨任务、跨设备、跨 APK 复用。
func ticketBinding(taskID int64, g *pgdb.DynamicGrant) string {
	ops := append([]string(nil), g.Ops...)
	sort.Strings(ops)
	return strings.Join([]string{
		fmt.Sprint(taskID), g.DeviceSerial, g.APKSha256, strings.Join(ops, ","),
		g.ValidFrom.UTC().Format(time.RFC3339Nano), g.ValidUntil.UTC().Format(time.RFC3339Nano),
	}, "|")
}

// issueDynamicTicket 生成 HMAC-SHA256 票据：base64url(payload) "." base64url(mac)。
// payload 含随机 nonce，同一任务每次续签得到不同票据，便于审计区分调用批次。
func issueDynamicTicket(secret []byte, taskID int64, g *pgdb.DynamicGrant, now time.Time) (dynamicTicket, error) {
	exp := now.Add(dynamicTicketTTL)
	if exp.After(g.ValidUntil) {
		exp = g.ValidUntil
	}
	if !exp.After(now) {
		return dynamicTicket{}, errors.New("授权剩余有效期不足，无法签发调用令牌")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return dynamicTicket{}, fmt.Errorf("生成令牌随机数失败：%w", err)
	}
	payload := strings.Join([]string{
		"v1", fmt.Sprint(taskID), g.DeviceSerial, g.APKSha256,
		strings.Join(g.Ops, ","), fmt.Sprint(exp.UnixNano()),
		hex.EncodeToString(nonce),
	}, "|")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	raw := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	sum := sha256.Sum256([]byte(raw))
	return dynamicTicket{
		raw: raw, digest: hex.EncodeToString(sum[:]),
		expiresAt: exp, bound: ticketBinding(taskID, g),
	}, nil
}

// loadDynamicGrantSecret 读/生成独立于 JWT 的授权密钥。
// 落在 data/（bind mount，容器重建不丢）；只读环境降级为进程内随机密钥 ——
// 令牌本来就是短时内存态，重启后重新签发，不降低安全性。
func loadDynamicGrantSecret(dir string) []byte {
	path := filepath.Join(dir, "dynamic_grant.key")
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b[:32]
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		log.Printf("[dynamic-grant] 密钥文件不可写，改用进程内随机密钥：%v", err)
	}
	return key
}
