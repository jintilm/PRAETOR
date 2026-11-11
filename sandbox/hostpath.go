// Package sandbox — 宿主路径视角解析。
package sandbox

// 本文件回答一个「全 Docker 部署」特有、而宿主二进制部署完全不会遇到的问题：
//
//	同一棵任务目录树，应用进程和 Docker daemon 看到的是两个不同的名字。
//
// 应用跑在宿主机上时二者相同（都是 E:/repo/data/work/214），所以老代码把一个值
// 同时用在 os.MkdirAll 和 `docker run -v` 上一直没出事。应用一旦进了容器：
//
//	应用进程视角： /app/data/work/214   （compose 把宿主 data/ 挂到 /app/data）
//	daemon 视角：  E:/repo/data/work/214（`-v` 的源必须是这个）
//
// 老代码把 /app/data/work/214 原样交给 daemon，宿主上没有这个目录，Docker 就
// 自动建了个空目录挂进任务容器。于是宿主上预建好的 i622 和容器里 /work 下的
// 内容是两棵树，`docker exec --workdir /work/i622` 直接 chdir 失败：
//
//	OCI runtime exec failed: chdir to cwd ("/work/i622") ... no such file or directory
//
// 这里不要求用户填机器相关的绝对路径（那会破坏可移植性：仓库一挪、换台机器、
// 从别的目录执行 compose 就全错），而是在启动期问 Docker 一句：
// 「我这个容器的挂载，宿主侧源路径是什么？」——Compose 早已把相对路径解析成
// 绝对路径并写进了容器配置，docker inspect 读回来即可。任何 OS、任何 clone
// 位置、任何启动目录都自动成立，仓库移动后重启即自愈。
//
// 只有远程 daemon / 非常规布局才需要显式覆盖（PRAETOR_SANDBOX_WORK_HOST_ROOT），
// 那是逃生舱，不是常规配置。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const hostPathInspectTimeout = 5 * time.Second

// inspectMount 是 `docker inspect --format '{{json .Mounts}}'` 的最小子集。
type inspectMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
}

// HostPathTranslator 把「本进程看到的绝对路径」翻译成「daemon 可用作 -v 源的路径」。
//
// 依据是自身容器的 bind 挂载表：找 Destination 是待翻译路径最长前缀的那一条，
// 把前缀换成它的 Source。所以不只是工作区，/chal 这类额外挂载同样能被正确翻译。
type HostPathTranslator struct {
	mounts    []inspectMount // 按 Destination 长度降序
	container bool           // 是否运行在容器内
	via       string         // 依据说明，只用于日志/自查
}

// PathView 是一对路径视角 + 解析依据。
type PathView struct {
	Local   string              // 应用进程内：os.MkdirAll / 文件工具使用
	Daemon  string              // 交给 docker -v 的宿主绝对路径
	Via     string              // 解析依据（人读，不含秘密）
	Mapping *HostPathTranslator // 供额外挂载复用；永不为 nil
}

// ResolvePathView 决定工作区根的两个视角。
// local 是应用进程视角的根；override 是可选的显式 daemon 侧根（空 = 自动推导）。
func ResolvePathView(ctx context.Context, local, override string) (PathView, error) {
	v := PathView{Local: local}
	if abs, err := filepath.Abs(local); err == nil {
		v.Local = abs
	}
	m, err := NewHostPathTranslator(ctx)
	v.Mapping = m
	if err != nil {
		// 仍然返回一个 identity 映射：调用方即使降级也不会拿到 nil 方法值。
		v.Mapping = &HostPathTranslator{via: "推导失败"}
		return v, err
	}
	if o := strings.TrimSpace(override); o != "" {
		v.Daemon = normalizeDaemonPath(o)
		v.Via = "PRAETOR_SANDBOX_WORK_HOST_ROOT（显式覆盖）"
		return v, nil
	}
	d, err := m.Translate(v.Local)
	if err != nil {
		return v, err
	}
	v.Daemon = d
	v.Via = m.Via()
	return v, nil
}

// NewHostPathTranslator 构造翻译器。
//
// 三种情况：
//   - 宿主进程：零挂载的 identity 翻译器（本地路径 == daemon 路径）；
//   - 容器内且 docker 可用：读自身容器挂载表；
//   - 容器内但读不到：返回错误，由上层 fail-closed —— 静默回落正是本次事故的成因。
func NewHostPathTranslator(ctx context.Context) (*HostPathTranslator, error) {
	if !runningInContainer() {
		return &HostPathTranslator{via: "宿主进程（无需转换）"}, nil
	}
	m := &HostPathTranslator{container: true}
	cctx, cancel := context.WithTimeout(ctx, hostPathInspectTimeout)
	defer cancel()

	var lastErr error
	for _, id := range selfContainerIDs() {
		out, stderr, code, err := runDockerCLI(cctx, []string{
			"inspect", "--format", "{{json .Mounts}}", id,
		}, "")
		if err != nil || code != 0 {
			lastErr = fmt.Errorf("docker inspect %s: %v %s", id, err, strings.TrimSpace(stderr))
			continue
		}
		mounts, err := parseInspectMounts(out)
		if err != nil {
			lastErr = fmt.Errorf("解析 docker inspect %s 的挂载表: %w", id, err)
			continue
		}
		m.mounts = mounts
		m.via = "docker inspect " + id
		return m, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("无法识别自身容器 ID")
	}
	return nil, fmt.Errorf(
		"应用容器内无法推导宿主任务目录（%v）；请确认容器内可调用 docker CLI，"+
			"或显式设置 PRAETOR_SANDBOX_WORK_HOST_ROOT 为 daemon 可见的宿主绝对路径", lastErr)
}

// Via 返回解析依据，供启动日志与 -check-config 打印。
func (m *HostPathTranslator) Via() string {
	if m == nil {
		return "未初始化"
	}
	return m.via
}

// InContainer 报告本进程是否运行在容器内。
func (m *HostPathTranslator) InContainer() bool { return m != nil && m.container }

// Translate 把应用进程内的路径翻译成 daemon 侧路径。
//
// nil 接收器或宿主模式 = identity（Windows 反斜杠仍统一成正斜杠，docker -v 要求）。
// 容器内若没有命中 bind 挂载，返回错误而不是原样返回 —— 原样返回会重建出一个
// 宿主上不存在的空目录，正是要根治的那个 bug。
func (m *HostPathTranslator) Translate(local string) (string, error) {
	local = strings.TrimSpace(local)
	var p string
	if m != nil && m.container && strings.HasPrefix(local, "/") {
		// 容器内路径是 POSIX 绝对路径。这里不能用 filepath.Abs：源码要能
		// 在 Windows 上编译并用单测覆盖，而 Windows 的 filepath.Abs("/app/x")
		// 会变成 "E:/app/x"，从此匹配不上 daemon 侧记录的 /app 挂载点。
		p = path.Clean(filepath.ToSlash(local))
	} else {
		abs, err := filepath.Abs(local)
		if err != nil {
			return "", err
		}
		p = filepath.ToSlash(filepath.Clean(abs))
	}
	if m == nil || !m.container {
		return normalizeDaemonPath(p), nil
	}
	for _, bm := range m.mounts {
		if bm.Type != "bind" {
			continue
		}
		dest := strings.TrimSuffix(filepath.ToSlash(filepath.Clean(bm.Destination)), "/")
		if dest == "" || dest == "/" {
			continue
		}
		if p == dest {
			return normalizeDaemonPath(bm.Source), nil
		}
		if strings.HasPrefix(p, dest+"/") {
			rel := strings.TrimPrefix(p, dest+"/")
			if rel == ".." || strings.HasPrefix(rel, "../") {
				break
			}
			return normalizeDaemonPath(path.Join(filepath.ToSlash(bm.Source), rel)), nil
		}
	}
	// 落在命名卷里时没有「宿主路径」这个概念，明确说清该改哪里。
	for _, bm := range m.mounts {
		if bm.Type == "volume" && strings.HasPrefix(p, filepath.ToSlash(bm.Destination)+"/") {
			return "", fmt.Errorf(
				"应用容器内路径 %s 落在 Docker 命名卷 %s（%s）里，per-task 沙箱无法把它作为 -v 的宿主源；"+
					"请把 PRAETOR_DATA_DIR 改成宿主目录（bind mount），不要填卷名", p, bm.Source, bm.Destination)
		}
	}
	return "", fmt.Errorf(
		"应用容器内路径 %s 不在任何 bind 挂载之下，无法推导宿主路径；"+
			"请检查 compose 的 %s 挂载，或显式设置 PRAETOR_SANDBOX_WORK_HOST_ROOT", p, "/app/data")
}

// parseInspectMounts 解析并按挂载点长度降序排序（嵌套挂载时取最深的那条）。
func parseInspectMounts(raw string) ([]inspectMount, error) {
	var mounts []inspectMount
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &mounts); err != nil {
		return nil, err
	}
	out := make([]inspectMount, 0, len(mounts))
	for _, m := range mounts {
		if strings.TrimSpace(m.Source) == "" || strings.TrimSpace(m.Destination) == "" {
			continue
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return len(out[i].Destination) > len(out[j].Destination)
	})
	return out, nil
}

// normalizeDaemonPath 把 docker inspect 返回的宿主路径变成 -v 能用的写法。
//
// daemon 在 Windows 上返回 `E:\Code\...`，而 `-v` 只认正斜杠；即便翻译器跑在
// Linux 容器里，filepath.ToSlash 也不会转换反斜杠（Linux 上 \ 不是分隔符），
// 所以这里必须显式替换。UNC（\\server\share → //server/share）同样可用。
func normalizeDaemonPath(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	s = strings.ReplaceAll(strings.TrimSpace(s), `\`, "/")
	for len(s) > 1 && strings.HasSuffix(s, "/") {
		s = strings.TrimSuffix(s, "/")
	}
	if s == "" {
		return "/"
	}
	// 盘符根 "E:/" 的斜杠不能去掉，否则变成 "E:"（相对当前目录，语义完全不同）。
	if len(s) == 2 && s[1] == ':' && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) {
		return s + "/"
	}
	return s
}

// isDaemonAbs 判断 p 是否是「daemon 眼中的绝对路径」。
//
// 关键场景：应用跑在 Linux 容器里，而 daemon 在 Windows 宿主上，此时
// `E:/repo/data/work` 对 Go 的 filepath.IsAbs 来说是个**相对路径**，
// 再走 filepath.Abs 就会变成 `/app/E:/repo/data/work` —— 挂载源彻底错位。
// 所以这类路径必须先认出来，原样交给 -v，不做本机绝对路径展开。
func isDaemonAbs(p string) bool {
	p = strings.ReplaceAll(strings.TrimSpace(p), `\`, "/")
	if strings.HasPrefix(p, "/") { // POSIX 绝对路径，也覆盖 //server/share UNC
		return true
	}
	return len(p) >= 3 && p[1] == ':' && p[2] == '/' &&
		((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z'))
}

// normalizeWorkRoot 把配置里的 HostWorkRoot 规整成可直接拼进 -v 的形态。
//
//   - 本机绝对路径（Windows 的 C:\...、Linux 的 /opt/...）保持原样，不改写；
//   - daemon 侧路径（Linux 容器里的 E:/...）只统一斜杠，绝不展开；
//   - 真正的相对路径（./data/work）才按当前工作目录展开，避免被 docker 当卷名。
func normalizeWorkRoot(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if filepath.IsAbs(s) {
		return s
	}
	if isDaemonAbs(s) {
		return normalizeDaemonPath(s)
	}
	if abs, err := filepath.Abs(s); err == nil {
		return abs
	}
	return s
}

// runningInContainer 用两个约定文件判断，避免依赖某个特定的编排器环境变量。
func runningInContainer() bool {
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// selfContainerIDs 返回可用于 `docker inspect` 的候选 ID，按可靠性排序。
//
// 首选 hostname：Docker 默认把容器短 ID 设为主机名，实测在 Docker Desktop 与
// Linux 上都成立。若部署方用 compose `hostname:` 覆盖了它，就从 cgroup 里取
// 完整 ID 兜底。两条都失败时上层会 fail-closed，不会猜一个路径出来。
func selfContainerIDs() []string {
	var ids []string
	if h, err := os.Hostname(); err == nil {
		if h = strings.TrimSpace(h); h != "" {
			ids = append(ids, h)
		}
	}
	for _, f := range []string{"/proc/self/cgroup", "/proc/1/cpuset"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, tok := range strings.FieldsFunc(string(b), func(r rune) bool {
			return r == ':' || r == '/' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
		}) {
			if len(tok) >= 12 && isHexID(tok) {
				ids = append(ids, tok[:12])
				break
			}
		}
	}
	return ids
}

func isHexID(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
