package server

// P2 的真机动态工具面。9 个工具与 P1 的 dynamicToolOps 一一对应，
// 因此 guard.PreToolUse 会在工具执行**之前**完成授权校验；工具内部再校验一次，
// 防止跨任务/跨设备的调用（工具名只能被模型看见，taskID 由 Go 侧闭包捕获）。
//
// 三层纵深：
//   ① 注入层：设备模式未开 / 任务无生效授权 → 这些工具根本不出现在模型工具面；
//   ② guard 层：每次调用按 op 白名单 + 短时令牌 + 设备独占锁 fail-closed；
//   ③ 工具层：再查 DB 授权、校验 APK 哈希、限制 shell 命令与设备侧路径。
//
// 不提供「通用 adb 命令直通」工具：那会让 op 白名单退化成摆设。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jintilm/praetor/config"
	pgdb "github.com/jintilm/praetor/db"
	actool "github.com/jintilm/praetor/internal/norma/tool"
)

type mobileToolSpec struct {
	name   string
	desc   string
	schema map[string]any
	run    func(*Server, int64, json.RawMessage) (actool.Result, error)
}

// reMobileFilter 限制 logcat 的 tag 过滤串，避免把任意 shell 元字符带进设备命令。
var reMobileFilter = regexp.MustCompile(`^[A-Za-z0-9_:.*/\- ]{0,64}$`)
var reMobileHost = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,128}$`)
var reMobileAppData = regexp.MustCompile(`^[A-Za-z0-9_./\-]{1,200}$`)

// mobileToolSpecs 是静态规格：既用于 per-run 工具构造，也用于开机 seed 进 tools 表
// （默认绑 worker，用户可在工具面板调整绑定/描述）。
func mobileToolSpecs() []mobileToolSpec {
	return []mobileToolSpec{
		{
			name: "mobile_install",
			desc: "【真机动态·需任务级授权】把任务工作区里的 APK 安装到已授权真机。" +
				"会先校验文件 SHA256 与任务授权里签发的 APK 哈希完全一致，不一致直接拒绝（防止换成别的包）。" +
				"成功返回安装输出与证据文件路径。",
			schema: objSchema(map[string]any{
				"apk_path": strParam("APK 路径：容器内 /work/... 或宿主绝对路径，必须在本任务工作区内"),
			}, "apk_path"),
			run: runMobileInstall,
		},
		{
			name: "mobile_launch",
			desc: "【真机动态·需任务级授权】在已授权真机上启动目标 App（monkey 或 am start）。",
			schema: objSchema(map[string]any{
				"package":  strParam("目标包名，如 com.example.app"),
				"activity": strParam("可选：完整 Activity 名；留空则用 LAUNCHER 启动"),
			}, "package"),
			run: runMobileLaunch,
		},
		{
			name: "mobile_shell",
			desc: "【真机动态·需任务级授权】在已授权真机上执行一条**白名单内**的只读自省命令" +
				"（id / ps -A / getprop / pm list|path / dumpsys package / settings get / ls / stat / cat /proc/version / date / uptime）。" +
				"不接受任意命令、管道或重定向；需要复杂操作请在沙箱 Bash 里用 adb（同样受授权闸管控）。",
			schema: objSchema(map[string]any{
				"command": strParam("白名单内的 adb shell 命令"),
			}, "command"),
			run: runMobileShell,
		},
		{
			name: "mobile_frida",
			desc: "【真机动态·需任务级授权】frida 只读辅助：list 列出平台固定的脚本模板；ps 尝试列出设备进程。" +
				"平台不内置 frida 二进制，注入动作由沙箱容器里的 frida-tools 执行。",
			schema: objSchema(map[string]any{
				"action": strParam("list | ps"),
			}, "action"),
			run: runMobileFrida,
		},
		{
			name: "mobile_hook",
			desc: "【真机动态·需任务级授权】把一个**平台固定**的 frida 脚本模板写到任务工作区，" +
				"返回脚本路径与在沙箱容器里执行的命令。脚本是闭集模板（不接受自定义 JS），" +
				"只记录算法名/URL/路径/长度，不打印 Cookie、Token、完整报文或密钥明文。",
			schema: objSchema(map[string]any{
				"script":  strParam("模板名：ssl_pinning_bypass / root_detection_bypass / crypto_trace / http_trace / storage_trace"),
				"package": strParam("可选：目标包名，用于 -f spawn 启动"),
				"mode":    strParam("可选：attach（默认）| spawn"),
			}, "script"),
			run: runMobileHook,
		},
		{
			name: "mobile_proxy",
			desc: "【真机动态·需任务级授权】在已授权真机上设置 / 清除 / 查看全局 HTTP 代理（用于接入平台的录制代理）。" +
				"证书安装、Android 7+ 系统 CA 与证书绑定绕过仍需签发人在设备上人工确认。",
			schema: objSchema(map[string]any{
				"action": strParam("set | clear | get"),
				"host":   strParam("set 时必填：宿主 IP 或域名（真机可达）"),
				"port":   strParam("set 时必填：录制代理宿主端口"),
			}, "action"),
			run: runMobileProxy,
		},
		{
			name: "mobile_logcat",
			desc: "【真机动态·需任务级授权】读取设备 logcat 最近若干行，脱敏后落到 /work/mobile/ 证据目录，" +
				"返回前 4KB 与文件路径。Cookie/Token/完整 HTTP 报文在落盘前被替换成哈希指纹。",
			schema: objSchema(map[string]any{
				"lines":  strParam("可选：读取行数，默认 200，上限 2000"),
				"filter": strParam("可选：tag 过滤串，只允许字母数字与 . : * / - 空格"),
			}),
			run: runMobileLogcat,
		},
		{
			name: "mobile_pull_data",
			desc: "【真机动态·需任务级授权】从设备取一份证据到 /work/mobile/。" +
				"source=/data/local/tmp/<file> 走 adb sync 拉二进制；" +
				"source=appdata:<相对路径> 走 run-as <package> cat 读 App 私有文本（需 debuggable）。" +
				"文本证据入库前脱敏；工具只返回路径/大小/摘要，不内联完整内容。",
			schema: objSchema(map[string]any{
				"source":  strParam("证据来源：/data/local/tmp/<file> 或 appdata:<相对路径>"),
				"package": strParam("appdata: 模式必填：目标包名"),
			}, "source"),
			run: runMobilePullData,
		},
		{
			name: "mobile_cleanup",
			desc: "【真机动态·需任务级授权】收尾清理：清目标 App 数据、复位全局代理、释放设备独占锁，并写审计。" +
				"任务结束时平台也会自动执行；主动调用可在一个长任务的阶段之间复位环境。",
			schema: objSchema(map[string]any{
				"package": strParam("可选：要清数据的包名；留空只复位代理并释放设备锁"),
			}),
			run: runMobileCleanup,
		},
	}
}

// mobileToolsFor 按当前 run 的 taskID 决定要不要注入工具。
// 未开设备模式 / 无生效授权 → 返回 nil，模型连工具名都看不到。
func (s *Server) mobileToolsFor(taskID int64) []actool.CoreTool {
	if s == nil || s.m == nil || s.m.pg == nil || taskID <= 0 {
		return nil
	}
	if config.Env("MOBILE_DEVICE_MODE") != "1" {
		return nil
	}
	g, err := s.m.pg.GetTaskDynamicGrant(taskID)
	if err != nil || g == nil || !g.Active(time.Now()) {
		return nil
	}
	out := make([]actool.CoreTool, 0, 9)
	for _, sp := range mobileToolSpecs() {
		spec := sp
		id := taskID
		out = append(out, wrTool(spec.name, spec.desc, spec.schema,
			func(_ context.Context, in json.RawMessage) (actool.Result, error) {
				return spec.run(s, id, in)
			}))
	}
	return out
}

// mobileAuthorization 是工具层二次校验。guard 已经在 PreToolUse 拦过一次，
// 这里再读一次 DB：既防止跨任务调用，也让「撤销后正在排队的调用」立刻失败。
func (s *Server) mobileAuthorization(taskID int64, op string) (*pgdb.DynamicGrant, error) {
	if config.Env("MOBILE_DEVICE_MODE") != "1" {
		return nil, errors.New("真机设备模式未开启（PRAETOR_MOBILE_DEVICE_MODE=1），动态工具不可用；改走静态分析")
	}
	g, err := s.m.pg.GetTaskDynamicGrant(taskID)
	if err != nil {
		return nil, fmt.Errorf("读取任务动态授权失败：%w", err)
	}
	if g == nil {
		return nil, errors.New("任务未签发 Android 动态授权；改走静态分析")
	}
	if !g.Active(time.Now()) {
		return nil, errors.New("动态授权已撤销或过期；改走静态分析")
	}
	if !g.Allows(op) {
		return nil, fmt.Errorf("操作 %q 不在签发范围内；改走静态分析", op)
	}
	return g, nil
}

func mobileToolInput(in json.RawMessage, v any) error {
	if len(in) == 0 {
		return errors.New("缺少参数")
	}
	return json.Unmarshal(in, v)
}

// ---- 各原子操作 ----

func runMobileInstall(s *Server, taskID int64, in json.RawMessage) (actool.Result, error) {
	g, err := s.mobileAuthorization(taskID, "install")
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	var a struct {
		APKPath string `json:"apk_path"`
	}
	if err := mobileToolInput(in, &a); err != nil {
		return actool.Errorf("参数错误：" + err.Error()), nil
	}
	local, err := s.mobileAPKLocalPath(taskID, a.APKPath)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	f, err := os.Open(local)
	if err != nil {
		return actool.Errorf("读取 APK 失败：" + err.Error()), nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		_ = f.Close()
		return actool.Errorf("计算 APK 哈希失败：" + err.Error()), nil
	}
	_ = f.Close()
	sum := hex.EncodeToString(h.Sum(nil))
	// 关键约束：授权绑死 APK 哈希，装别的包 = 超出授权范围。
	if !strings.EqualFold(sum, g.APKSha256) {
		return actool.Errorf(fmt.Sprintf("APK SHA256 与任务授权不一致（文件=%s，授权=%s），拒绝安装；改走静态分析", sum, g.APKSha256)), nil
	}
	remote := mobileADBRemoteTmp + sum[:16] + ".apk"
	addr := mobileADBAddr()
	ctx, cancel := context.WithTimeout(context.Background(), mobileADBOpTimeout)
	defer cancel()
	n, err := adbSyncPush(ctx, addr, g.DeviceSerial, local, remote)
	if err != nil {
		return actool.Errorf("推送 APK 失败：" + err.Error()), nil
	}
	out, err := adbShellEx(ctx, addr, g.DeviceSerial, "pm install -r "+remote, mobileADBOpTimeout, mobileADBMaxOutput)
	if err != nil {
		return actool.Errorf("安装 APK 失败：" + err.Error()), nil
	}
	rec, view, eerr := s.saveMobileEvidence(taskID, "install", "install", "install",
		fmt.Sprintf("APK=%s sha256=%s 推送=%d 字节 设备=%s", filepath.Base(local), sum, n, g.DeviceSerial), out)
	if eerr != nil {
		return actool.Errorf("证据落盘失败：" + eerr.Error()), nil
	}
	return jsonResult(map[string]any{
		"ok": strings.Contains(strings.ToLower(out), "success"), "device": g.DeviceSerial,
		"apk_sha256": sum, "remote": remote, "pushed_bytes": n,
		"evidence": rec.File, "output_preview": view,
	})
}

func runMobileLaunch(s *Server, taskID int64, in json.RawMessage) (actool.Result, error) {
	g, err := s.mobileAuthorization(taskID, "launch")
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	var a struct {
		Package  string `json:"package"`
		Activity string `json:"activity"`
	}
	if err := mobileToolInput(in, &a); err != nil {
		return actool.Errorf("参数错误：" + err.Error()), nil
	}
	if !reMobilePackage.MatchString(a.Package) {
		return actool.Errorf("包名不合法"), nil
	}
	cmd := "monkey -p " + a.Package + " -c android.intent.category.LAUNCHER 1"
	if strings.TrimSpace(a.Activity) != "" {
		if !strings.Contains(a.Activity, "/") || strings.ContainsAny(a.Activity, " ;&|`$") {
			return actool.Errorf("activity 必须是 pkg/Class 形式且不含 shell 元字符"), nil
		}
		cmd = "am start -n " + a.Activity
	}
	ctx, cancel := context.WithTimeout(context.Background(), mobileADBOpTimeout)
	defer cancel()
	out, err := adbShellEx(ctx, mobileADBAddr(), g.DeviceSerial, cmd, mobileADBOpTimeout, mobileADBMaxOutput)
	if err != nil {
		return actool.Errorf("启动 App 失败：" + err.Error()), nil
	}
	rec, view, eerr := s.saveMobileEvidence(taskID, "launch", "launch", "launch",
		"启动 "+a.Package+" 命令="+cmd, out)
	if eerr != nil {
		return actool.Errorf("证据落盘失败：" + eerr.Error()), nil
	}
	return jsonResult(map[string]any{"ok": true, "command": cmd, "evidence": rec.File, "output_preview": view})
}

func runMobileShell(s *Server, taskID int64, in json.RawMessage) (actool.Result, error) {
	g, err := s.mobileAuthorization(taskID, "shell")
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	var a struct {
		Command string `json:"command"`
	}
	if err := mobileToolInput(in, &a); err != nil {
		return actool.Errorf("参数错误：" + err.Error()), nil
	}
	cmd := strings.TrimSpace(a.Command)
	if cmd == "" || reMobileShellMeta.MatchString(cmd) || !reMobileShellSafe.MatchString(cmd) {
		return actool.Errorf("命令不在白名单内；仅允许只读自省命令，复杂操作请用沙箱 Bash 里的 adb（同样受授权闸管控）"), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), mobileADBOpTimeout)
	defer cancel()
	out, err := adbShellEx(ctx, mobileADBAddr(), g.DeviceSerial, cmd, mobileADBOpTimeout, mobileADBMaxOutput)
	if err != nil {
		return actool.Errorf("adb shell 失败：" + err.Error()), nil
	}
	rec, view, eerr := s.saveMobileEvidence(taskID, "shell", "shell", "shell", "命令="+cmd, out)
	if eerr != nil {
		return actool.Errorf("证据落盘失败：" + eerr.Error()), nil
	}
	return jsonResult(map[string]any{"ok": true, "command": cmd, "evidence": rec.File, "output_preview": view})
}

func runMobileFrida(s *Server, taskID int64, in json.RawMessage) (actool.Result, error) {
	if _, err := s.mobileAuthorization(taskID, "frida"); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	var a struct {
		Action string `json:"action"`
	}
	if err := mobileToolInput(in, &a); err != nil {
		return actool.Errorf("参数错误：" + err.Error()), nil
	}
	switch strings.ToLower(strings.TrimSpace(a.Action)) {
	case "list", "":
		return actool.Text(mobileFridaScriptList()), nil
	case "ps":
		// 只读列进程。应用容器没有 frida 二进制时不假装成功，明确给出降级路径。
		bin, err := exec.LookPath("frida-ps")
		if err != nil {
			return actool.Text("应用容器内没有 frida-ps（正常：平台不内置 frida）。\n" +
				"请在沙箱容器里执行 `frida-ps -U`（需先应用 mobile-dynamic 预置）；" +
				"该 Bash 调用同样会经过 frida 授权校验。\n\n" + mobileFridaScriptList()), nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "-U")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return actool.Errorf("frida-ps 执行失败：" + err.Error() + "：" + string(out[:min(len(out), 512)])), nil
		}
		_, view, eerr := s.saveMobileEvidence(taskID, "frida", "frida", "frida-ps", "只读进程列表", string(out))
		if eerr != nil {
			return actool.Errorf("证据落盘失败：" + eerr.Error()), nil
		}
		return actool.Text(view), nil
	default:
		return actool.Errorf("action 只能是 list | ps"), nil
	}
}

func runMobileHook(s *Server, taskID int64, in json.RawMessage) (actool.Result, error) {
	if _, err := s.mobileAuthorization(taskID, "hook"); err != nil {
		return actool.Errorf(err.Error()), nil
	}
	var a struct {
		Script  string `json:"script"`
		Package string `json:"package"`
		Mode    string `json:"mode"`
	}
	if err := mobileToolInput(in, &a); err != nil {
		return actool.Errorf("参数错误：" + err.Error()), nil
	}
	if a.Package != "" && !reMobilePackage.MatchString(a.Package) {
		return actool.Errorf("包名不合法"), nil
	}
	mode := strings.ToLower(strings.TrimSpace(a.Mode))
	if mode == "" {
		mode = "attach"
	}
	if mode != "attach" && mode != "spawn" {
		return actool.Errorf("mode 只能是 attach | spawn"), nil
	}
	path, err := s.saveMobileFridaScript(taskID, a.Script)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	cmd := mobileFridaCommand(path, a.Package, mode)
	_, _, eerr := s.saveMobileEvidence(taskID, "frida", "hook", "hook-"+a.Script,
		"脚本模板="+a.Script+" mode="+mode+" package="+a.Package,
		"脚本路径: "+path+"\n执行命令: "+cmd+"\n模板为平台闭集脚本，不接受自定义 JS。")
	if eerr != nil {
		return actool.Errorf("证据落盘失败：" + eerr.Error()), nil
	}
	return jsonResult(map[string]any{
		"ok": true, "script": a.Script, "script_path": path, "mode": mode,
		"command": cmd,
		"note":    "在沙箱容器里用 Bash 执行上面的命令；该 Bash 调用会再过一次 frida/hook 授权闸。应用容器不内置 frida，不会自行注入。",
	})
}

func runMobileProxy(s *Server, taskID int64, in json.RawMessage) (actool.Result, error) {
	g, err := s.mobileAuthorization(taskID, "proxy")
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	var a struct {
		Action string `json:"action"`
		Host   string `json:"host"`
		Port   string `json:"port"`
	}
	if err := mobileToolInput(in, &a); err != nil {
		return actool.Errorf("参数错误：" + err.Error()), nil
	}
	var cmd string
	switch strings.ToLower(strings.TrimSpace(a.Action)) {
	case "set":
		if !reMobileHost.MatchString(a.Host) {
			return actool.Errorf("host 不合法（只允许域名/IP 字符）"), nil
		}
		p, perr := strconv.Atoi(strings.TrimSpace(a.Port))
		if perr != nil || p <= 0 || p > 65535 {
			return actool.Errorf("port 必须是 1~65535"), nil
		}
		cmd = "settings put global http_proxy " + a.Host + ":" + strconv.Itoa(p)
	case "clear":
		cmd = "settings put global http_proxy :0"
	case "get":
		cmd = "settings get global http_proxy"
	default:
		return actool.Errorf("action 只能是 set | clear | get"), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), mobileADBOpTimeout)
	defer cancel()
	out, err := adbShellEx(ctx, mobileADBAddr(), g.DeviceSerial, cmd, mobileADBOpTimeout, mobileADBMaxOutput)
	if err != nil {
		return actool.Errorf("设置代理失败：" + err.Error()), nil
	}
	rec, view, eerr := s.saveMobileEvidence(taskID, "proxy", "proxy", "proxy", "命令="+cmd, out)
	if eerr != nil {
		return actool.Errorf("证据落盘失败：" + eerr.Error()), nil
	}
	return jsonResult(map[string]any{"ok": true, "command": cmd, "evidence": rec.File, "output_preview": view,
		"note": "Android 7+ 需系统 CA 或重打包 networkSecurityConfig；证书绑定绕过属设备侧前置，平台不替人确认。"})
}

func runMobileLogcat(s *Server, taskID int64, in json.RawMessage) (actool.Result, error) {
	g, err := s.mobileAuthorization(taskID, "logcat")
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	var a struct {
		Lines  string `json:"lines"`
		Filter string `json:"filter"`
	}
	_ = mobileToolInput(in, &a)
	lines := 200
	if strings.TrimSpace(a.Lines) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(a.Lines))
		if err != nil || n <= 0 {
			return actool.Errorf("lines 必须是正整数"), nil
		}
		lines = min(n, 2000)
	}
	cmd := "logcat -d -t " + strconv.Itoa(lines)
	filter := strings.TrimSpace(a.Filter)
	if filter != "" {
		if !reMobileFilter.MatchString(filter) {
			return actool.Errorf("filter 含非法字符"), nil
		}
		cmd += " -s " + filter
	}
	ctx, cancel := context.WithTimeout(context.Background(), mobileADBOpTimeout)
	defer cancel()
	out, err := adbShellEx(ctx, mobileADBAddr(), g.DeviceSerial, cmd, mobileADBOpTimeout, mobileADBMaxOutput)
	if err != nil {
		return actool.Errorf("读取 logcat 失败：" + err.Error()), nil
	}
	rec, view, eerr := s.saveMobileEvidence(taskID, "logcat", "logcat", "logcat",
		fmt.Sprintf("logcat -d -t %d filter=%q 设备=%s", lines, filter, g.DeviceSerial), out)
	if eerr != nil {
		return actool.Errorf("证据落盘失败：" + eerr.Error()), nil
	}
	return jsonResult(map[string]any{"ok": true, "command": cmd, "evidence": rec.File,
		"bytes": rec.Bytes, "redacted": rec.Redacted, "output_preview": view})
}

func runMobilePullData(s *Server, taskID int64, in json.RawMessage) (actool.Result, error) {
	g, err := s.mobileAuthorization(taskID, "pull_data")
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	var a struct {
		Source  string `json:"source"`
		Package string `json:"package"`
	}
	if err := mobileToolInput(in, &a); err != nil {
		return actool.Errorf("参数错误：" + err.Error()), nil
	}
	src := strings.TrimSpace(a.Source)
	dir, err := s.mobileEvidenceDir(taskID)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), mobileADBOpTimeout)
	defer cancel()
	stamp := time.Now().UTC().Format("20060102T150405.000000000")

	// appdata: 用 run-as 读 App 私有文本（只回传文本，落盘前脱敏）。
	if strings.HasPrefix(src, "appdata:") {
		rel := strings.TrimPrefix(src, "appdata:")
		if !reMobilePackage.MatchString(a.Package) || !reMobileAppData.MatchString(rel) || strings.Contains(rel, "..") {
			return actool.Errorf("appdata: 模式下 package 与相对路径不合法"), nil
		}
		cmd := "run-as " + a.Package + " cat " + rel
		out, err := adbShellEx(ctx, mobileADBAddr(), g.DeviceSerial, cmd, mobileADBOpTimeout, mobileADBMaxOutput)
		if err != nil {
			return actool.Errorf("读取 App 数据失败（需 debuggable App）：" + err.Error()), nil
		}
		rec, view, eerr := s.saveMobileEvidence(taskID, "pull", "pull_data", "appdata", "命令="+cmd, out)
		if eerr != nil {
			return actool.Errorf("证据落盘失败：" + eerr.Error()), nil
		}
		return jsonResult(map[string]any{"ok": true, "command": cmd, "evidence": rec.File,
			"redacted": rec.Redacted, "output_preview": view})
	}

	// /data/local/tmp/ 下的文件走 adb sync，二进制原样落盘、不内联内容。
	if !reMobileRemote.MatchString(src) {
		return actool.Errorf("source 必须是 /data/local/tmp/<file> 或 appdata:<相对路径>"), nil
	}
	data, err := adbSyncPull(ctx, mobileADBAddr(), g.DeviceSerial, src)
	if err != nil {
		return actool.Errorf("拉取证据失败：" + err.Error()), nil
	}
	name := "pull-" + stamp + ".bin"
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		return actool.Errorf("证据落盘失败：" + err.Error()), nil
	}
	sum := sha256.Sum256(data)
	rec := MobileEvidence{
		File: "/work/mobile/" + name, Kind: "pull", Op: "pull_data", Bytes: len(data),
		SHA256: hex.EncodeToString(sum[:]), Redacted: false,
		Summary: "二进制证据 " + src + "（未内联）", CreatedAt: time.Now().UTC(),
	}
	if err := s.appendMobileEvidenceIndex(taskID, rec); err != nil {
		return actool.Errorf("写入证据索引失败：" + err.Error()), nil
	}
	return jsonResult(map[string]any{
		"ok": true, "evidence": rec.File, "bytes": rec.Bytes, "sha256": rec.SHA256,
		"note": "二进制内容未进模型上下文，也不做文本脱敏；用 Read 或沙箱里的文件工具查看。",
	})
}

// appendMobileEvidenceIndex 供二进制证据复用文本证据的索引格式。
func (s *Server) appendMobileEvidenceIndex(taskID int64, rec MobileEvidence) error {
	dir, err := s.mobileEvidenceDir(taskID)
	if err != nil {
		return err
	}
	mobileEvidenceMu.Lock()
	defer mobileEvidenceMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, "_index.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := json.Marshal(rec)
	_, err = f.Write(append(b, '\n'))
	return err
}

func runMobileCleanup(s *Server, taskID int64, in json.RawMessage) (actool.Result, error) {
	g, err := s.mobileAuthorization(taskID, "cleanup")
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	var a struct {
		Package string `json:"package"`
	}
	_ = mobileToolInput(in, &a)
	if a.Package != "" && !reMobilePackage.MatchString(a.Package) {
		return actool.Errorf("包名不合法"), nil
	}
	return s.mobileCleanupResult(taskID, g, a.Package, "工具调用")
}
