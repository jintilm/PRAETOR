package agent

// iOS IPA 静态解析（P2）。只做静态，不承诺 iOS 动态（需 macOS + 越狱真机）。
//
// 为什么沿用 mobile_scan 而不新增第 11 条配方：逆向域的配方上限是 10，
// 每多一条就多一份常驻提示词成本。按文件形态自动分流（APK → apktool，IPA → zip）
// 既保持 schema 与分页契约不变，也让模型只记一个入口。
//
// 纯 Go archive/zip，不依赖 unzip / plutil / macOS：
//   - IPA 本质是 zip，Info.plist 通常是 XML plist；二进制 plist 会明确报「需人工转换」；
//   - 不落盘解包：只读文本类条目 + 主二进制前 4 字节判 Mach-O，避免 zip slip 与磁盘膨胀。

import (
	"archive/zip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	ipaScanMaxEntries   = 400
	ipaScanMaxEntrySize = 2 << 20
	ipaScanMaxTotal     = 64 << 20
)

var (
	reIPAPlistKey   = regexp.MustCompile(`(?s)<key>\s*([^<]+?)\s*</key>`)
	reIPAPlistTrue  = regexp.MustCompile(`(?s)<true\s*/>`)
	reIPAPlistFalse = regexp.MustCompile(`(?s)<false\s*/>`)
	reIPAPlistStr   = regexp.MustCompile(`(?s)<string>\s*([^<]*?)\s*</string>`)
	reIPAHTTP       = regexp.MustCompile(`(?i)https?://[A-Za-z0-9_.\-]+`)
	reIPAScheme     = regexp.MustCompile(`(?s)<string>\s*([A-Za-z][A-Za-z0-9+.\-]{1,63})\s*</string>`)
)

// ipaPlistEntry 是扁平化后的 plist 键值（含原文行号，用于「文件:行」证据）。
type ipaPlistEntry struct {
	Value string
	Line  int
}

// parseIPAPlistFlat 把 XML plist 压成 key → value。
// 取值窗口严格限定在「本 key 结束 → 下一个 key 开始」之间：按固定行数取窗口会把
// 下一个 key 的 <true/> 错赋给当前 key（实测 MinimumOSVersion 会被读成 true）。
// 不追求完整还原嵌套结构：静态扫描要的是「某个危险开关键是否存在」。
func parseIPAPlistFlat(text string) map[string]ipaPlistEntry {
	out := map[string]ipaPlistEntry{}
	locs := reIPAPlistKey.FindAllStringSubmatchIndex(text, -1)
	for i, loc := range locs {
		key := strings.TrimSpace(text[loc[2]:loc[3]])
		end := len(text)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		window := text[loc[1]:end]
		val := ""
		switch {
		case reIPAPlistTrue.MatchString(window):
			val = "true"
		case reIPAPlistFalse.MatchString(window):
			val = "false"
		default:
			if s := reIPAPlistStr.FindStringSubmatch(window); len(s) == 2 {
				val = s[1]
			}
		}
		if val == "" {
			val = "(dict/array)"
		}
		out[key] = ipaPlistEntry{Value: val, Line: strings.Count(text[:loc[0]], "\n") + 1}
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func looksLikeIPA(target string) bool {
	if strings.EqualFold(path.Ext(strings.TrimSpace(target)), ".ipa") {
		return true
	}
	// 允许 .zip / 无扩展名的 IPA：看 zip 里有没有 Payload/*.app/Info.plist。
	f, err := os.Open(target)
	if err != nil {
		return false
	}
	defer f.Close()
	info, _ := f.Stat()
	if info == nil || info.Size() > 512<<20 {
		return false
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		return false
	}
	for _, e := range zr.File {
		if strings.Contains(e.Name, ".app/Info.plist") {
			return true
		}
	}
	return false
}

// runIPAScan 输出与 mobile_scan 同构的「一行一条」文本。
func runIPAScan(ctx context.Context, target string) (string, error) {
	f, err := os.Open(target)
	if err != nil {
		return "", fmt.Errorf("打开 IPA 失败：%w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		return "", fmt.Errorf("不是合法 IPA/zip：%w", err)
	}

	var hits []mobileHit
	plistName, plistText := "", ""
	macho := ""
	entries, total := 0, int64(0)
	truncated := false
	urlSchemes := map[string]bool{}

	for _, e := range zr.File {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		clean := path.Clean(strings.ReplaceAll(e.Name, "\\", "/"))
		if clean == "." || strings.HasPrefix(clean, "..") || strings.HasPrefix(clean, "/") {
			truncated = true // zip slip 条目：跳过并留痕，绝不落盘
			continue
		}
		if entries >= ipaScanMaxEntries || total >= ipaScanMaxTotal {
			truncated = true
			break
		}
		entries++
		total += int64(e.UncompressedSize64)
		if e.FileInfo().IsDir() {
			continue
		}

		// 主二进制：只读前 4 字节判 Mach-O 魔数，不把几十 MB 读进内存。
		base := path.Base(clean)
		if strings.Contains(clean, ".app/") && path.Ext(base) == "" {
			rc, err := e.Open()
			if err == nil {
				var magic [4]byte
				_, _ = io.ReadFull(rc, magic[:])
				_ = rc.Close()
				if isMachOMagic(magic) {
					macho = clean
				}
			}
			continue
		}

		ext := strings.ToLower(path.Ext(base))
		if ext == ".plist" && strings.Contains(clean, ".app/Info.plist") {
			plistName = clean
		}
		if !map[string]bool{
			".plist": true, ".strings": true, ".json": true, ".xml": true,
			".txt": true, ".js": true, ".html": true, ".entitlements": true,
			".mobileprovision": true, ".pbxproj": true,
		}[ext] {
			continue
		}
		if e.UncompressedSize64 > ipaScanMaxEntrySize {
			truncated = true
			continue
		}
		rc, err := e.Open()
		if err != nil {
			truncated = true
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(rc, ipaScanMaxEntrySize))
		_ = rc.Close()
		text := string(body)
		if ext == ".plist" && strings.Contains(clean, ".app/Info.plist") {
			plistText = text
		}
		scanIPAText(clean, text, &hits, urlSchemes)
	}

	if plistText == "" {
		return "", fmt.Errorf("IPA 里找不到 %s（可能加密/二进制 plist 或不是 App 包）："+
			"二进制 plist 需在 macOS 上用 plutil 转成 XML 后复核；本次不做猜测", "*.app/Info.plist")
	}
	if !strings.Contains(plistText, "<plist") {
		return "", fmt.Errorf("%s 不是 XML plist（疑似 binary plist）：需在 macOS 上 plutil -convert xml1 后复核", plistName)
	}

	flat := parseIPAPlistFlat(plistText)
	for _, rule := range []struct {
		sev, kind, key, want, note string
	}{
		{"中", "ATS 全局允许明文", "NSAllowsArbitraryLoads", "true", "NSAppTransportSecurity 关闭了 HTTPS 强制"},
		{"中", "ATS 允许任意 Web 内容", "NSAllowsArbitraryLoadsInWebContent", "true", "WebView 可加载 http://"},
		{"中", "ATS 本地网络例外", "NSAllowsLocalNetworking", "true", "本地网络明文例外"},
		{"中", "文件共享开启", "UIFileSharingEnabled", "true", "iTunes/Finder 可导出 App 沙盒文档"},
		{"中", "支持原地打开文档", "LSSupportsOpeningDocumentsInPlace", "true", "外部 App 可原地改写沙盒文件"},
		{"低", "允许 iTunes 文件共享", "CFBundleAllowMixedLocalizations", "true", "本地化混用（仅线索）"},
	} {
		if ent, ok := flat[rule.key]; ok && strings.EqualFold(ent.Value, rule.want) {
			hits = append(hits, msHit(rule.sev, rule.kind, plistName, ent.Line,
				"<key>"+rule.key+"</key> = "+ent.Value+" ("+rule.note+")"))
		}
	}
	if _, ok := flat["NSExceptionDomains"]; ok {
		hits = append(hits, msHit("信息", "ATS 域名例外", plistName, flat["NSExceptionDomains"].Line,
			"NSExceptionDomains 声明了逐域名例外，需人工核对是否允许明文"))
	}
	for _, key := range []string{"NSCameraUsageDescription", "NSMicrophoneUsageDescription", "NSLocationWhenInUseUsageDescription", "NSPhotoLibraryUsageDescription", "NSContactsUsageDescription"} {
		if ent, ok := flat[key]; ok {
			hits = append(hits, msHit("信息", "敏感权限用途", plistName, ent.Line, key+" = "+clipText(ent.Value, 80)))
			break // 权限面只提示一次，完整清单在全文里复核
		}
	}
	if ent, ok := flat["CFBundleURLTypes"]; ok {
		hits = append(hits, msHit("信息", "自定义 URL scheme", plistName, ent.Line,
			"CFBundleURLTypes 声明了 deeplink；"+
				strings.Join(sortedIPASchemes(urlSchemes), ", ")+
				"（需核对是否校验来源与参数）"))
	}
	if ent, ok := flat["MinimumOSVersion"]; ok {
		hits = append(hits, msHit("信息", "最低系统版本", plistName, ent.Line, "MinimumOSVersion = "+ent.Value))
	}

	// mobileprovision 里的 entitlements 是 DER，但明文片段仍可读到 key。
	for _, e := range zr.File {
		if !strings.HasSuffix(strings.ToLower(e.Name), ".mobileprovision") {
			continue
		}
		rc, err := e.Open()
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(rc, ipaScanMaxEntrySize))
		_ = rc.Close()
		text := string(body)
		if strings.Contains(text, "get-task-allow") {
			hits = append(hits, msHit("高", "调试 entitlement", e.Name, 1,
				"get-task-allow 出现在描述文件里：需核对是否为 Development 签名（可被附加调试器）"))
		}
		if strings.Contains(text, "com.apple.developer.default-data-protection") {
			hits = append(hits, msHit("信息", "数据保护 entitlement", e.Name, 1,
				"存在默认数据保护配置，需核对保护等级"))
		}
		break
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

	bundle := orDash(flat["CFBundleIdentifier"].Value)
	version := orDash(flat["CFBundleShortVersionString"].Value)
	var b strings.Builder
	fmt.Fprintf(&b, "[ipa_scan] bundle=%s version=%s macho=%s entries=%d/%d truncated=%v hits=%d\n",
		bundle, version, orDash(macho), entries, ipaScanMaxEntries, truncated, len(hits))
	b.WriteString("[信息] 仅静态解析 | " + plistName + " | iOS 动态需 macOS + 越狱真机，本平台不承诺自动化\n")
	if macho == "" {
		b.WriteString("[信息] 未定位 Mach-O 主二进制 | Payload/ | 签名/加密与 entitlement 需 codesign 复核\n")
	} else {
		b.WriteString("[信息] Mach-O 主二进制 | " + macho + ":1 | 魔数命中；签名、加密与 entitlement 需 codesign 复核\n")
	}
	for _, h := range hits {
		fmt.Fprintf(&b, "[%s] %s | %s:%d | %s\n", h.Sev, h.Kind, h.File, h.Line, h.Why)
	}
	if len(hits) == 0 {
		b.WriteString("(未命中静态规则；不等于无漏洞，需人工复核)\n")
	}
	return b.String(), nil
}

func isMachOMagic(m [4]byte) bool {
	le := binary.LittleEndian.Uint32(m[:])
	be := binary.BigEndian.Uint32(m[:])
	for _, v := range []uint32{0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe} {
		if le == v || be == v {
			return true
		}
	}
	return false
}

func scanIPAText(file, text string, hits *[]mobileHit, schemes map[string]bool) {
	lines := strings.Split(text, "\n")
	seenKind := map[string]bool{}
	for i, ln := range lines {
		for _, rule := range mobileSecretPatterns {
			if rule.Re.MatchString(ln) && !seenKind[rule.Kind] {
				seenKind[rule.Kind] = true
				*hits = append(*hits, msHit(rule.Sev, rule.Kind, file, i+1, ln+" ("+rule.Note+")"))
			}
		}
		if strings.Contains(ln, "NSAllowsArbitraryLoads") || strings.Contains(ln, "CFBundleURLSchemes") {
			for _, m := range reIPAScheme.FindAllStringSubmatch(strings.Join(lines[i:minInt(len(lines), i+3)], "\n"), -1) {
				if len(m) == 2 && !strings.HasPrefix(m[1], "http") {
					schemes[m[1]] = true
				}
			}
		}
		if !strings.Contains(ln, "http://") {
			continue
		}
		if m := reIPAHTTP.FindString(ln); m != "" && !seenKind["明文端点"] {
			seenKind["明文端点"] = true
			*hits = append(*hits, msHit("中", "明文端点", file, i+1, ln+" (plist/配置里出现 http:// 地址)"))
		}
	}
}

func sortedIPASchemes(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 8 {
		return append(out[:8], fmt.Sprintf("…(共 %d)", len(out)))
	}
	if len(out) == 0 {
		return []string{"未解析出 scheme 值"}
	}
	return out
}
