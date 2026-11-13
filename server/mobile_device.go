package server

// 真机设备适配器：只读探测 + 明确降级。
//
// 架构边界（与「不用模拟器、用真机」的定稿一致）：平台**不碰 USB**。
// adb server 跑在宿主（`adb -a -P 5037 nodaemon server`），应用/沙箱容器里只放
// 客户端，通过 TCP 连过去。所以这里实现的是一个极小的 adb server 协议客户端，
// 不依赖容器内是否装了 adb 二进制 —— 换台机器、换全 Docker/宿主二进制部署都能复跑。
//
// 诚实原则：能机读的项才给 pass/fail；锁屏状态、系统 CA、真机到代理的可达性
// 在不同 ROM / 网络下无法从平台侧可靠判定，一律标 manual 交给签发人确认，
// 不假装「六项全绿」而给出一个不可信的 Ready。

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jintilm/praetor/config"
)

const (
	mobileADBDefaultHost = "host.docker.internal"
	mobileADBDefaultPort = 5037
	mobileProbeTimeout   = 4 * time.Second
)

// DeviceCheck 是一项探测结果。state: pass / fail / warn / manual。
type DeviceCheck struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// DeviceStatus 是一次设备探测的完整结论。
// Ready=false 时执行链必须降级到静态，Reason 写明是哪一项没过。
type DeviceStatus struct {
	Serial     string        `json:"serial"`
	ADBServer  string        `json:"adb_server"`
	Reachable  bool          `json:"reachable"`
	Ready      bool          `json:"ready"`
	Degraded   bool          `json:"degraded"`
	Reason     string        `json:"reason"`
	Checks     []DeviceCheck `json:"checks"`
	ProbedAt   time.Time     `json:"probed_at"`
	Devices    []string      `json:"devices,omitempty"` // 未指定 serial 时列出在线设备
	// SerialList 与 Devices 同一个来源，但只放**裸序列号**（不带 " (device)" 状态后缀）。
	// 任何要把序列号回写出去的界面都必须用这个：Devices 是给人看的展示串，
	// 拿它当序列号提交会拼出含空格括号的非法值。展示用 Devices，回写用 SerialList。
	SerialList []string `json:"serial_list,omitempty"`
	ManualNote string        `json:"manual_note,omitempty"`
}

func mobileADBAddr() string {
	host := strings.TrimSpace(config.Env("MOBILE_ADB_HOST"))
	if host == "" {
		host = mobileADBDefaultHost
	}
	port := mobileADBDefaultPort
	if raw := strings.TrimSpace(config.Env("MOBILE_ADB_PORT")); raw != "" {
		if p, err := strconv.Atoi(raw); err == nil && p > 0 && p < 65536 {
			port = p
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// adbRequest 发一条 host 服务请求并返回 payload。
// 协议：请求 = 4 位十六进制长度 + 命令；响应 = "OKAY"/"FAIL" +（有 payload 时）
// 4 位十六进制长度 + payload。见 AOSP adb/OVERVIEW.TXT。
func adbRequest(ctx context.Context, addr, cmd string) (string, error) {
	d := net.Dialer{Timeout: mobileProbeTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(mobileProbeTimeout))
	if _, err := io.WriteString(conn, fmt.Sprintf("%04x", len(cmd))+cmd); err != nil {
		return "", err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", err
	}
	switch string(head) {
	case "OKAY":
	case "FAIL":
		lenBuf := make([]byte, 4)
		_, _ = io.ReadFull(conn, lenBuf)
		n, _ := strconv.ParseUint(string(lenBuf), 16, 32)
		msg := make([]byte, min(int(n), 512))
		_, _ = io.ReadFull(conn, msg)
		return "", fmt.Errorf("adb server 拒绝了 %q：%s", cmd, strings.TrimSpace(string(msg)))
	default:
		return "", fmt.Errorf("adb server 返回了非预期状态 %q", string(head))
	}
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return "", err
	}
	n, err := strconv.ParseUint(string(lenBuf), 16, 32)
	if err != nil {
		return "", fmt.Errorf("adb 响应长度非法：%w", err)
	}
	if n > 1<<20 {
		return "", fmt.Errorf("adb 响应过大（%d 字节）", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// adbDevices 返回 serial → state。
func adbDevices(ctx context.Context, addr string) (map[string]string, error) {
	raw, err := adbRequest(ctx, addr, "host:devices")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 2 {
			out[f[0]] = f[1]
		}
	}
	return out, nil
}

// adbShell 在指定设备上执行一条只读命令并回收输出。
// transport 切换后通道变成 device 通道，shell 服务以 EOF 表示命令结束。
func adbShell(ctx context.Context, addr, serial, cmd string) (string, error) {
	d := net.Dialer{Timeout: mobileProbeTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(mobileProbeTimeout))
	writeCmd := func(c string) error {
		_, err := io.WriteString(conn, fmt.Sprintf("%04x", len(c))+c)
		return err
	}
	readStatus := func() error {
		head := make([]byte, 4)
		if _, err := io.ReadFull(conn, head); err != nil {
			return err
		}
		if string(head) == "OKAY" {
			return nil
		}
		lenBuf := make([]byte, 4)
		_, _ = io.ReadFull(conn, lenBuf)
		n, _ := strconv.ParseUint(string(lenBuf), 16, 32)
		msg := make([]byte, min(int(n), 512))
		_, _ = io.ReadFull(conn, msg)
		return fmt.Errorf("adb 返回 %s：%s", string(head), strings.TrimSpace(string(msg)))
	}
	if err := writeCmd("host:transport:" + serial); err != nil {
		return "", err
	}
	if err := readStatus(); err != nil {
		return "", err
	}
	if err := writeCmd("shell:" + cmd); err != nil {
		return "", err
	}
	if err := readStatus(); err != nil {
		return "", err
	}
	// shell 服务的输出没有长度前缀；读到 EOF/超时为止，上限 64KB。
	out, err := io.ReadAll(io.LimitReader(conn, 64<<10))
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(string(out), "\r\n", "\n"), nil
}

// mobileTaskContext 判断一个任务是否该拿到真机上下文（设备序列号）。
// 只有这类任务才该拿到 host.docker.internal 映射与设备环境变量 ——
// 不给所有任务无条件加，避免把宿主服务的可达面扩散到普通渗透任务。
// 授权模式决定判定门槛：required 看任务级授权记录，assume 视为已授权，
// 但两者都仍受 PRAETOR_MOBILE_DEVICE_MODE=1 这个部署级开关约束。
func (s *Server) mobileTaskContext(taskID string) (string, bool) {
	if config.Env("MOBILE_DEVICE_MODE") != "1" || s == nil || s.m == nil || s.m.pg == nil {
		return "", false
	}
	id, err := strconv.ParseInt(strings.TrimSpace(taskID), 10, 64)
	if err != nil || id <= 0 {
		return "", false
	}
	g, err := s.effectiveMobileGrant(id)
	if err != nil || g == nil || !g.Active(time.Now()) {
		return "", false
	}
	return g.DeviceSerial, true
}

func (s *Server) mobileHostGatewayFor(taskID string) bool {
	_, ok := s.mobileTaskContext(taskID)
	return ok
}

// mobileEnvFor 把设备事实交给任务容器里的 adb/frida 客户端。
// USB 仍留在宿主，容器拿到的只是 TCP 落点与目标序列号。
func (s *Server) mobileEnvFor(taskID string) []string {
	serial, ok := s.mobileTaskContext(taskID)
	if !ok {
		return nil
	}
	host := strings.TrimSpace(config.Env("MOBILE_ADB_HOST"))
	if host == "" {
		host = mobileADBDefaultHost
	}
	port := strings.TrimSpace(config.Env("MOBILE_ADB_PORT"))
	if port == "" {
		port = strconv.Itoa(mobileADBDefaultPort)
	}
	return []string{
		"PRAETOR_MOBILE_DEVICE_SERIAL=" + serial,
		"PRAETOR_MOBILE_ADB_HOST=" + host,
		"PRAETOR_MOBILE_ADB_PORT=" + port,
		"ADB_SERVER_HOST=" + host,
		"ADB_SERVER_PORT=" + port,
	}
}

// probeMobileDevice 只读探测一台真机。serial 为空时只做 adb server 连通性 +
// 列出设备，不谎报 Ready。
func probeMobileDevice(ctx context.Context, serial string) DeviceStatus {
	addr := mobileADBAddr()
	st := DeviceStatus{
		Serial: strings.TrimSpace(serial), ADBServer: addr,
		ProbedAt: time.Now(), Degraded: true,
		Checks:     []DeviceCheck{},
		ManualNote: "锁屏状态、Android 7+ 系统 CA 安装、证书绑定绕过、真机到录制代理的连通性需由签发人在设备上人工确认；平台不替人做这个判断。",
	}
	probeCtx, cancel := context.WithTimeout(ctx, mobileProbeTimeout)
	defer cancel()
	devices, err := adbDevices(probeCtx, addr)
	if err != nil {
		st.Checks = append(st.Checks, DeviceCheck{"adb_server", "fail", "无法连接宿主 adb server：" + err.Error()})
		st.Reason = "adb server 不可达：确认宿主已运行 `adb -a -P 5037 nodaemon server`，且容器能解析 host.docker.internal；本次动态分析降级为静态。"
		return st
	}
	st.Reachable = true
	st.Checks = append(st.Checks, DeviceCheck{"adb_server", "pass", addr + " 可达"})
	for s, state := range devices {
		st.Devices = append(st.Devices, s+" ("+state+")")
		st.SerialList = append(st.SerialList, s)
	}
	sort.Strings(st.Devices)
	sort.Strings(st.SerialList)
	if st.Serial == "" {
		st.Reason = "未指定设备序列号：仅列出在线设备，动态分析仍按未授权处理。"
		return st
	}
	state, found := devices[st.Serial]
	if !found || state != "device" {
		st.Checks = append(st.Checks, DeviceCheck{"device_online", "fail",
			fmt.Sprintf("设备 %s 状态=%q（期望 device）", st.Serial, state)})
		st.Reason = "设备不在线或未授权 adb：解锁设备、确认 USB 调试授权后重试；本次动态分析降级为静态。"
		return st
	}
	st.Checks = append(st.Checks,
		DeviceCheck{"device_online", "pass", st.Serial + " 状态 device"},
		DeviceCheck{"adb_authorized", "pass", "adb 已授权（非 unauthorized/offline）"},
	)
	// 下面两项只影响「动态能抓到多少」，不作为 Ready 的硬前置：无 root 仍可做
	// 安装/启动/日志/抓包，只是 frida hook 与系统证书装不上。
	st.Checks = append(st.Checks, probeRoot(probeCtx, addr, st.Serial))
	if out, err := adbShell(probeCtx, addr, st.Serial, "ps -A"); err == nil {
		state := "warn"
		detail := "未检测到 frida-server；hook 类操作不可用"
		if strings.Contains(strings.ToLower(out), "frida") {
			state, detail = "pass", "frida-server 进程可见"
		}
		st.Checks = append(st.Checks, DeviceCheck{"frida_server", state, detail})
	} else {
		st.Checks = append(st.Checks, DeviceCheck{"frida_server", "warn", "frida-server 状态无法判定：" + err.Error()})
	}
	st.Checks = append(st.Checks,
		DeviceCheck{"unlocked", "manual", "锁屏状态需人工确认"},
		DeviceCheck{"system_ca", "manual", "Android 7+ 系统 CA / networkSecurityConfig 需人工确认"},
		DeviceCheck{"proxy_reachable", "manual", "真机到录制代理的连通性需人工确认（WiFi 代理或 adb reverse 反向隧道两种接法都算通过）"},
	)
	st.Ready = true
	st.Degraded = false
	st.Reason = ""
	return st
}

// probeRoot 判定设备是否已 root。
//
// 这里原本的写法是执行 `adb shell id`，再看输出里有没有 uid=0 —— 那是错的：
// adb shell 默认以 shell(2000) 运行，`id` 在任何设备上都返回 uid=2000，
// 于是所有真机都会被判成「非 root」；而同一轮 `ps -A` 又能看见 root 起的
// frida-server，两条结论自相矛盾。判 root 必须显式看 su，不能拿默认身份自证。
//
// 顺序按「先快后慢」：which su 不需要授权、毫秒级返回；su -c id 在 Magisk 上
// 首次调用可能弹授权框，非交互场景会一直阻塞到超时，所以放在后面。
func probeRoot(ctx context.Context, addr, serial string) DeviceCheck {
	noRoot := "非 root：frida hook 与系统 CA 安装不可用，可用重打包 networkSecurityConfig 路线"
	// 1) su 存在即可认为 root 方案已就位（真正的提权由设备上的管理器授权）
	if out, err := adbShell(ctx, addr, serial, "which su"); err == nil {
		if p := strings.TrimSpace(out); p != "" && !strings.Contains(p, "not found") {
			return DeviceCheck{"root", "pass", "su 已安装（" + p + "），提权需在设备上授权"}
		}
	}
	// 2) 能直接拿到 uid=0 才算真提权成功
	if out, err := adbShell(ctx, addr, serial, "su -c id"); err == nil && strings.Contains(out, "uid=0") {
		return DeviceCheck{"root", "pass", "su -c id → uid=0，已取得 root"}
	}
	// 3) userdebug / eng 版本 adb shell 本身就是 root
	if out, err := adbShell(ctx, addr, serial, "id"); err == nil && strings.Contains(out, "uid=0") {
		return DeviceCheck{"root", "pass", "adb shell 自带 root（userdebug/eng 版本）"}
	}
	return DeviceCheck{"root", "warn", noRoot}
}

// mobileDeviceSerialHint 给创建任务表单与目标设备设置界面用的序列号格式说明，
// 避免把任意字符串（甚至一段注入文本）写进授权记录或 settings。
// 必须与下面的 validDeviceSerial 保持一字不差，否则提示与实际校验会漂移。
const mobileDeviceSerialHint = "只允许字母、数字与 . : - _ ，长度 1..128"

// validDeviceSerial 判定设备序列号是否合法。
func validDeviceSerial(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == ':' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func validAPKSha256(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
