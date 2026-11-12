package agent

// APK 静态规则扫描（P0）。
//
// 设计约束与逆向域一致：
//   - 一条配方 = 一次确定性输出；不新增工具、不接 MCP、不引入 Java 反编译器；
//   - 每条命中都必须带「文件:行 + 原文依据」，规则只提示线索，不替模型下漏洞结论；
//   - 输出一行一条，交给 re_recipe 既有的按行分页 + 全文落盘机制，模型只拿第一页；
//   - 扫描有硬上限，超出必须留痕（truncated=true），不静默截断。
//
// 为什么不用 MobSF / androguard：它们各自带一套服务与大依赖，而这里要的只是
// 「解包后读明文 manifest + smali 字符串」—— 纯 Go 就够，容器里只多一个 apktool。

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	mobileScanMaxFiles    = 400
	mobileScanMaxFileSize = 2 << 20
	mobileScanMaxPerKind  = 8
	mobileScanEvidenceCap = 120
)

var mobileScanExt = map[string]bool{
	".smali": true, ".xml": true, ".json": true, ".properties": true,
	".txt": true, ".yml": true, ".yaml": true, ".js": true, ".html": true,
}

var mobileSevRank = map[string]int{"高": 0, "中": 1, "低": 2, "信息": 3}

type mobileHit struct {
	Sev  string
	Kind string
	File string
	Line int
	Why  string
}

// manifest 级规则。属性在 apktool 输出里可能换行，正则一律允许 \s*。
var (
	reMSAppOpen         = regexp.MustCompile(`(?s)<application\b[^>]*>`)
	reMSDebuggable      = regexp.MustCompile(`android:debuggable\s*=\s*"true"`)
	reMSBackupFalse     = regexp.MustCompile(`android:allowBackup\s*=\s*"false"`)
	reMSCleartext       = regexp.MustCompile(`android:usesCleartextTraffic\s*=\s*"true"`)
	reMSNSConfig        = regexp.MustCompile(`android:networkSecurityConfig\s*=\s*"@xml/([^"]+)"`)
	reMSComponentOpen   = regexp.MustCompile(`(?s)<(activity|activity-alias|service|receiver|provider)\b[^>]*>`)
	reMSExported        = regexp.MustCompile(`android:exported\s*=\s*"true"`)
	reMSPermissionAttr  = regexp.MustCompile(`android:permission\s*=`)
	reMSGrantURI        = regexp.MustCompile(`android:grantUriPermissions\s*=\s*"true"`)
	reMSScheme          = regexp.MustCompile(`android:scheme\s*=\s*"([^"]+)"`)
	reMSTargetSDK       = regexp.MustCompile(`(?m)^\s*targetSdkVersion:\s*['"]?(\d+)`)
	reMSUserCA          = regexp.MustCompile(`<certificates[^>]*src\s*=\s*"user"`)
	reMSDebugOverrides  = regexp.MustCompile(`<debug-overrides`)
	reMSCleartextNS     = regexp.MustCompile(`cleartextTrafficPermitted\s*=\s*"true"`)
	reMSPinSet          = regexp.MustCompile(`<pin-set\b`)
	reMSNetworkSecurity = regexp.MustCompile(`<network-security-config\b`)
)

// 代码/密钥特征。命中不等于漏洞，只是「值得去看一眼」的线索。
type mobilePattern struct {
	Sev, Kind, Note string
	Re              *regexp.Regexp
}

var mobileCodePatterns = []mobilePattern{
	{"高", "WebView JS 桥", "addJavascriptInterface：JS 可调用注入的 Java 对象", regexp.MustCompile(`addJavascriptInterface`)},
	{"中", "WebView 远程调试", "setWebContentsDebuggingEnabled：开启 WebView 调试", regexp.MustCompile(`setWebContentsDebuggingEnabled`)},
	{"中", "WebView 跨域文件访问", "允许 file:// 跨源读取", regexp.MustCompile(`setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs`)},
	{"中", "自定义 TrustManager", "checkServerTrusted：可能绕过证书校验", regexp.MustCompile(`checkServerTrusted`)},
	{"信息", "证书绑定线索", "动态抓包前需先绕过绑定", regexp.MustCompile(`CertificatePinner|certificatePinner|TrustKit`)},
	{"低", "敏感信息进日志", "日志语句含敏感字段", regexp.MustCompile(`(?i)Log\.[vdi]\(.*(password|token|secret|sms|card|身份证)`)},
}

var mobileSecretPatterns = []mobilePattern{
	{"高", "硬编码私钥", "PEM 私钥出现在包内", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"高", "疑似云密钥", "AKIA/ASIA 形态的访问密钥 ID", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"中", "疑似硬编码凭据", "键值形态的长凭据常量", regexp.MustCompile(`(?i)(api[_-]?key|secret|access[_-]?token|password)\s*[:=]\s*["'][A-Za-z0-9_/+=.-]{16,}["']`)},
}

var mobileDangerPerms = map[string]bool{
	"android.permission.READ_SMS":                 true,
	"android.permission.WRITE_SMS":                true,
	"android.permission.RECEIVE_SMS":              true,
	"android.permission.READ_CONTACTS":            true,
	"android.permission.READ_CALL_LOG":            true,
	"android.permission.ACCESS_FINE_LOCATION":     true,
	"android.permission.CAMERA":                   true,
	"android.permission.RECORD_AUDIO":             true,
	"android.permission.SYSTEM_ALERT_WINDOW":      true,
	"android.permission.REQUEST_INSTALL_PACKAGES": true,
	"android.permission.QUERY_ALL_PACKAGES":       true,
	"android.permission.WRITE_EXTERNAL_STORAGE":   true,
	"android.permission.READ_EXTERNAL_STORAGE":    true,
}

func lineAt(s string, idx int) int {
	if idx < 0 || idx > len(s) {
		return 1
	}
	return strings.Count(s[:idx], "\n") + 1
}

// clipText 把证据原文压成单行，避免破坏「一行一条」的分页契约。
func clipText(s string, n int) string {
	s = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(s))
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func msHit(sev, kind, file string, line int, evidence string) mobileHit {
	return mobileHit{Sev: sev, Kind: kind, File: file, Line: line, Why: clipText(evidence, mobileScanEvidenceCap)}
}

// scanMSManifest 只读明文 AndroidManifest.xml；apktool.yml 用来补 targetSdk。
func scanMSManifest(xml, dir string, m apkManifest) ([]mobileHit, string, string) {
	var hits []mobileHit
	app := reMSAppOpen.FindString(xml)
	if app == "" {
		hits = append(hits, msHit("信息", "manifest 无 application 节点", "AndroidManifest.xml", 1, "未能定位 <application>"))
	} else {
		line := lineAt(xml, strings.Index(xml, app))
		if reMSDebuggable.MatchString(app) {
			hits = append(hits, msHit("高", "应用可调试", "AndroidManifest.xml", line, app))
		}
		if !reMSBackupFalse.MatchString(app) {
			hits = append(hits, msHit("中", "备份未关闭", "AndroidManifest.xml", line, "allowBackup 未显式设为 false"))
		}
		if reMSCleartext.MatchString(app) {
			hits = append(hits, msHit("中", "允许明文流量", "AndroidManifest.xml", line, "usesCleartextTraffic=true"))
		}
	}

	for _, loc := range reMSComponentOpen.FindAllStringIndex(xml, -1) {
		tag := xml[loc[0]:loc[1]]
		if !reMSExported.MatchString(tag) || reMSPermissionAttr.MatchString(tag) {
			continue
		}
		hits = append(hits, msHit("高", "导出组件无权限保护", "AndroidManifest.xml", lineAt(xml, loc[0]), tag))
	}
	for _, loc := range reMSComponentOpen.FindAllStringIndex(xml, -1) {
		tag := xml[loc[0]:loc[1]]
		if reMSGrantURI.MatchString(tag) {
			hits = append(hits, msHit("中", "ContentProvider 授予 URI 权限", "AndroidManifest.xml", lineAt(xml, loc[0]), tag))
			break
		}
	}

	seen := map[string]bool{}
	for _, g := range reMSScheme.FindAllStringSubmatch(xml, -1) {
		if seen[g[1]] {
			continue
		}
		seen[g[1]] = true
		hits = append(hits, msHit("信息", "自定义 scheme / deeplink", "AndroidManifest.xml", lineAt(xml, strings.Index(xml, g[0])), g[0]))
		break // 面只提示一次，完整清单在落盘全文里靠后续复核
	}

	var danger []string
	for _, p := range m.Perms {
		if mobileDangerPerms[p] {
			danger = append(danger, p)
		}
	}
	if len(danger) > 0 {
		if len(danger) > 8 {
			danger = append(danger[:8], fmt.Sprintf("…(共 %d)", len(danger)))
		}
		hits = append(hits, msHit("信息", "敏感权限面", "AndroidManifest.xml", 1, strings.Join(danger, ", ")))
	}

	targetSDK := "-"
	if b, err := os.ReadFile(filepath.Join(dir, "apktool.yml")); err == nil {
		if g := reMSTargetSDK.FindSubmatch(b); len(g) == 2 {
			targetSDK = string(g[1])
		}
	}

	nsFile := ""
	if g := reMSNSConfig.FindStringSubmatch(xml); len(g) == 2 {
		candidate := "res/xml/" + g[1] + ".xml"
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(candidate))); err == nil {
			nsFile = candidate
		}
	}
	return hits, targetSDK, nsFile
}

// scanMSPayload 遍历解包产物里的文本类文件，按扩展名套规则。
// nsFile 单独走 network-security 规则，避免和通用 xml 规则重复命中。
func scanMSPayload(dir, nsFile string) ([]mobileHit, int, bool) {
	var hits []mobileHit
	files := 0
	truncated := false
	perKind := map[string]int{}
	overflow := map[string]int{}

	add := func(h mobileHit) {
		perKind[h.Kind]++
		if perKind[h.Kind] > mobileScanMaxPerKind {
			overflow[h.Kind]++
			return
		}
		hits = append(hits, h)
	}

	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == "AndroidManifest.xml" || rel == "apktool.yml" {
			return nil
		}
		if !mobileScanExt[strings.ToLower(filepath.Ext(p))] {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		if info.Size() > mobileScanMaxFileSize {
			truncated = true
			return nil
		}
		if files >= mobileScanMaxFiles {
			truncated = true
			return nil
		}
		files++
		body, rerr := os.ReadFile(p)
		if rerr != nil {
			truncated = true
			return nil
		}
		text := string(body)
		lines := strings.Split(text, "\n")

		matchLines := func(re *regexp.Regexp) (int, string) {
			for i, ln := range lines {
				if re.MatchString(ln) {
					return i + 1, ln
				}
			}
			return 0, ""
		}

		if rel == nsFile && reMSNetworkSecurity.MatchString(text) {
			for _, rule := range []struct {
				sev, kind, note string
				re              *regexp.Regexp
			}{
				{"中", "网络安全配置允许明文", "cleartextTrafficPermitted=true", reMSCleartextNS},
				{"中", "信任用户 CA", "src=user：用户证书可解密 HTTPS", reMSUserCA},
				{"中", "debug-overrides", "调试信任锚", reMSDebugOverrides},
				{"信息", "证书绑定配置", "pin-set：动态抓包需绕过", reMSPinSet},
			} {
				if ln, ev := matchLines(rule.re); ln > 0 {
					add(msHit(rule.sev, rule.kind, rel, ln, ev+" ("+rule.note+")"))
				}
			}
		}

		if strings.EqualFold(filepath.Ext(p), ".smali") {
			for _, rule := range mobileCodePatterns {
				if ln, ev := matchLines(rule.Re); ln > 0 {
					add(msHit(rule.Sev, rule.Kind, rel, ln, ev+" ("+rule.Note+")"))
				}
			}
		}
		for _, rule := range mobileSecretPatterns {
			if ln, ev := matchLines(rule.Re); ln > 0 {
				add(msHit(rule.Sev, rule.Kind, rel, ln, ev+" ("+rule.Note+")"))
			}
		}
		return nil
	})

	for kind, n := range overflow {
		if n > 0 {
			hits = append(hits, msHit("信息", kind+" 命中超限", "(汇总)", 0,
				fmt.Sprintf("另有 %d 条未列出，完整内容见全文落盘", n)))
		}
	}
	return hits, files, truncated
}

// runMobileScan 返回「一行一条命中」的完整文本，由 re_recipe 统一分页与落盘。
func runMobileScan(ctx context.Context, target string) (string, error) {
	dir, cleanup, err := unpackAPK(ctx, target)
	if err != nil {
		return "", err
	}
	defer cleanup()

	manifest, err := os.ReadFile(filepath.Join(dir, "AndroidManifest.xml"))
	if err != nil {
		return "", fmt.Errorf("解包后缺 AndroidManifest.xml（%v）：确认 target 是合法 APK", err)
	}
	xml := string(manifest)
	m := parseManifest(xml)
	hits, targetSDK, nsFile := scanMSManifest(xml, dir, m)
	more, files, truncated := scanMSPayload(dir, nsFile)
	hits = append(hits, more...)

	if targetSDK != "-" && nsFile == "" {
		// Android 9（targetSdk 28）之前默认允许明文；没配 NSC 就明确提示，不猜。
		var n int
		_, _ = fmt.Sscanf(targetSDK, "%d", &n)
		if n > 0 && n < 28 {
			hits = append(hits, msHit("中", "旧 targetSdk 默认允许明文", "apktool.yml", 1,
				fmt.Sprintf("targetSdk=%d 且未声明 networkSecurityConfig", n)))
		}
	}

	sort.SliceStable(hits, func(i, j int) bool {
		if mobileSevRank[hits[i].Sev] != mobileSevRank[hits[j].Sev] {
			return mobileSevRank[hits[i].Sev] < mobileSevRank[hits[j].Sev]
		}
		if hits[i].Kind != hits[j].Kind {
			return hits[i].Kind < hits[j].Kind
		}
		if hits[i].File != hits[j].File {
			return hits[i].File < hits[j].File
		}
		return hits[i].Line < hits[j].Line
	})

	var b strings.Builder
	fmt.Fprintf(&b, "[mobile_scan] package=%s targetSdk=%s nsconfig=%s hits=%d files=%d/%d truncated=%v\n",
		orDash(m.Package), targetSDK, orDash(nsFile), len(hits), files, mobileScanMaxFiles, truncated)
	if nsFile == "" {
		b.WriteString("[信息] 未声明 networkSecurityConfig | AndroidManifest.xml | 证书绑定/明文策略需从代码侧复核\n")
	}
	for _, h := range hits {
		fmt.Fprintf(&b, "[%s] %s | %s:%d | %s\n", h.Sev, h.Kind, h.File, h.Line, h.Why)
	}
	if len(hits) == 0 {
		b.WriteString("(未命中静态规则；不等于无漏洞，需人工复核)\n")
	}
	return b.String(), nil
}
