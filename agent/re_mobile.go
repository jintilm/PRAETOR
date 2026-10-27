package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jintilm/praetor/internal/samplestore"
)

// 这个文件是 P3-5 的两块：trace（动态，需授权）与 mobile（APK 静态解包），
// 以及样本库形态的 target 解析（sha256:…）。
//
// 为什么 trace 要授权开关：`trace` 会真的 `run` 样本 —— 它可能回连、写文件、
// 探测环境。静态配方最坏是读错文件，动态配方最坏是**执行了不该执行的东西**。
// 所以默认关，只有显式设 PRAETOR_RE_DYNAMIC=1 才放行；报错里写清怎么开。
const dynamicEnv = "PRAETOR_RE_DYNAMIC"

// sampleDirEnv 是样本库目录（加密文件 + index.json 所在处）。
const sampleDirEnv = "PRAETOR_SAMPLE_DIR"

// requireDynamic 是动态执行的总闸。
func requireDynamic() error {
	if strings.TrimSpace(os.Getenv(dynamicEnv)) == "1" {
		return nil
	}
	return fmt.Errorf("动态执行未授权：trace 会真的运行样本（可能回连、写文件、探测环境）。"+
		"确认在隔离环境里之后再设 %s=1 重试；静态方向请用 disasm / xrefs / strings", dynamicEnv)
}

// resolveSampleTarget 支持两种 target：
//   - 普通路径：原样返回；
//   - `sha256:<hex>`：从样本库解密到临时文件，返回清理函数。
//
// 为什么要这个形态：样本库是加密落盘的（internal/samplestore），工具不该知道密钥，
// 也不该把样本字节读进上下文。解密出来的临时文件用完即删，明文窗口只有一次分析那么长。
func resolveSampleTarget(target string) (string, func(), error) {
	noop := func() {}
	if !strings.HasPrefix(target, "sha256:") {
		return target, noop, nil
	}
	root := strings.TrimSpace(os.Getenv(sampleDirEnv))
	if root == "" {
		return "", nil, fmt.Errorf("样本库未配置：设 %s 指向样本库目录（用 `go run ./cmd/samplestore -put <样本>` 入库）", sampleDirEnv)
	}
	st, err := samplestore.Open(root)
	if err != nil {
		return "", nil, err
	}
	path, cleanup, err := st.Materialize(target)
	if err != nil {
		return "", nil, err
	}
	return path, cleanup, nil
}

// apkManifest 是 AndroidManifest 里值得进上下文的那几项。
//
// 为什么不整段返回：清单动辄几十 KB（几十个 activity/permission），全塞进去
// 每轮都要重发；模型真正需要的是「包名、入口、敏感权限、组件面」。
type apkManifest struct {
	Package string
	Launch  string
	Perms   []string
	Comps   []string
}

var (
	rePkgName = regexp.MustCompile(`package="([^"]+)"`)
	rePermUse = regexp.MustCompile(`<uses-permission[^>]*android:name="([^"]+)"`)
	reCompTag = regexp.MustCompile(`<(activity|activity-alias|service|receiver|provider)[^>]*android:name="([^"]+)"`)
	reActOpen = regexp.MustCompile(`<(?:activity|activity-alias)[^>]*android:name="([^"]+)"[^>]*>`)
)

// parseManifest 从 apktool 解出的明文 AndroidManifest.xml 里抽关键项。
//
// 入口 Activity 不能只用一条正则"匹配 MAIN 附近的 name"：自闭合的 `<activity .../>`
// 会让贪婪区间跨到下一个 activity 的 body 里，于是把无关的 Activity 认成入口。
// 这里逐个开标签判断：自闭合就跳过，否则取它到最近的 </activity 之间的 body。
func parseManifest(xml string) apkManifest {
	m := apkManifest{}
	if g := rePkgName.FindStringSubmatch(xml); len(g) == 2 {
		m.Package = g[1]
	}
	for _, g := range rePermUse.FindAllStringSubmatch(xml, -1) {
		m.Perms = append(m.Perms, g[1])
	}
	for _, g := range reCompTag.FindAllStringSubmatch(xml, -1) {
		m.Comps = append(m.Comps, g[2])
	}
	for _, loc := range reActOpen.FindAllStringSubmatchIndex(xml, -1) {
		name := xml[loc[2]:loc[3]]
		if strings.HasSuffix(xml[loc[0]:loc[1]], "/>") {
			continue // 自闭合标签没有 body
		}
		rest := xml[loc[1]:]
		i := strings.Index(rest, "</activity")
		if i < 0 {
			continue
		}
		body := rest[:i]
		if strings.Contains(body, "android.intent.action.MAIN") &&
			strings.Contains(body, "android.intent.category.LAUNCHER") {
			m.Launch = name
			break
		}
	}
	return m
}

// walkSmaliClasses 从 apktool 解出的 smali 目录反推类名（Lcom/a/B; → com.a.B）。
//
// 用 smali 而不是 dex 解析：apktool 已经把类铺成文件，遍历文件名比解析 dex 快且
// 不引入新依赖；类名清单的用途是"让模型知道该 decompile 哪个"，精度足够。
func walkSmaliClasses(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".smali") {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 2 || !strings.HasPrefix(parts[0], "smali") {
			return nil // 只看 smali 目录（含 smali_classes2 这类多 dex 目录）
		}
		cls := strings.TrimSuffix(strings.Join(parts[1:], "/"), ".smali")
		out = append(out, strings.ReplaceAll(cls, "/", "."))
		return nil
	})
	sort.Strings(out)
	return out
}

// renderMobile 把清单摘要 + 类名清单拼成"可分页"的文本。
//
// 类名一行一个：分页是按行切的，堆成一行会让"一次只取一页"失效。
func renderMobile(m apkManifest, classes []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "package: %s\n", orDash(m.Package))
	fmt.Fprintf(&b, "launch: %s\n", orDash(m.Launch))
	fmt.Fprintf(&b, "permissions (%d): %s\n", len(m.Perms), joinOrDash(m.Perms))
	fmt.Fprintf(&b, "components (%d): %s\n", len(m.Comps), joinOrDash(m.Comps))
	fmt.Fprintf(&b, "classes (%d):\n", len(classes))
	for _, c := range classes {
		b.WriteString(c)
		b.WriteByte('\n')
	}
	return b.String()
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func joinOrDash(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	if len(xs) > 12 {
		return strings.Join(xs[:12], ", ") + fmt.Sprintf(" …(共 %d)", len(xs))
	}
	return strings.Join(xs, ", ")
}

// runMobile 解包 APK 并返回清单摘要 / 类清单 / 单个类的源码。
//
// 依赖策略：apktool 是硬依赖（解包本身），jadx 可选 —— 装了就用 Java 源码，
// 没装就退回 smali（同一份逻辑，可读性差一点，但不阻塞分析）。
// 不为一个"可读性增强"要求所有人装 200MB 的 jadx。
func runMobile(ctx context.Context, target, sel string) (string, error) {
	dir, err := os.MkdirTemp("", "praetor-apk-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	if out, derr := reRecipeExec(ctx, []string{"apktool", "d", "-f", "-o", dir, target}, reRecipeMobile); derr != nil {
		return out, fmt.Errorf("apktool 解包失败：%v", derr)
	}
	manifest, _ := os.ReadFile(filepath.Join(dir, "AndroidManifest.xml"))

	if strings.TrimSpace(sel) == "" {
		return renderMobile(parseManifest(string(manifest)), walkSmaliClasses(dir)), nil
	}

	// 指定了类：先试 jadx（有的话），再退 smali。
	if _, lerr := reRecipeLookPath("jadx"); lerr == nil {
		if out, jerr := reRecipeExec(ctx, []string{"jadx", "-q", "--single-class", sel, "-d", dir, target}, reRecipeMobile); jerr != nil {
			return out, fmt.Errorf("jadx 反编译 %s 失败：%v", sel, jerr)
		}
		if src := findJavaSource(dir, sel); strings.TrimSpace(src) != "" {
			return src, nil
		}
	}
	if src, ok := readSmaliClass(dir, sel); ok {
		return src, nil
	}
	return "", fmt.Errorf("解包后找不到类 %s；先用不带 select 的 mobile 拿类名清单再指定", sel)
}

// findJavaSource 在 jadx 输出里找目标类的 .java（路径按包名铺开）。
func findJavaSource(root, class string) string {
	want := strings.ReplaceAll(class, ".", string(filepath.Separator)) + ".java"
	var found string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || found != "" {
			return nil
		}
		if strings.HasSuffix(filepath.ToSlash(p), "/"+filepath.ToSlash(want)) || strings.HasSuffix(p, want) {
			body, rerr := os.ReadFile(p)
			if rerr == nil {
				found = string(body)
			}
		}
		return nil
	})
	return found
}

// readSmaliClass 直接读 apktool 解出的 .smali 源码（jadx 缺席时的退路）。
func readSmaliClass(root, class string) (string, bool) {
	want := filepath.ToSlash(strings.ReplaceAll(class, ".", "/")) + ".smali"
	var found string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || found != "" {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasPrefix(rel, "smali") || !strings.HasSuffix(rel, want) {
			return nil
		}
		if body, rerr := os.ReadFile(p); rerr == nil {
			found = string(body)
		}
		return nil
	})
	return found, found != ""
}
