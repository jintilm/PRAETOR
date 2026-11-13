package server

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jintilm/praetor/agent"
	"github.com/jintilm/praetor/config"
	"github.com/jintilm/praetor/sandbox"
)

// WireSandbox 在启动期选定沙箱后端并注入 agent。
//
// 两个维度：
//
//	PRAETOR_SANDBOX             required（默认）| optional | off
//	PRAETOR_SANDBOX_ISOLATION   per-task（默认）| shared
//
// per-task：一任务一容器（惰性创建 + 空闲回收），任务间文件/进程/后台任务天然隔离；
// shared  ：改造前的「常驻容器 + docker exec」，任务间共享文件系统。
//
// 探测失败不阻断服务启动——否则 Docker 没起时连 UI 都进不去；真正的拒绝发生在每次工具调用。
// WireSandboxWithImage 与 WireSandbox 相同，但允许用 settings 里记录的镜像（组件面板构建的 tag）。
//
// 为什么镜像来自 settings 而不是只有环境变量：面板构建出的镜像是 `praetor/sandbox:custom-<hash>`，
// 让用户改环境变量再重启既反直觉也容易忘。环境变量仍作为回落，保持"零配置能用"。
func WireSandboxWithImage(ctx context.Context, dataDir, image string) {
	wireSandbox(ctx, dataDir, image, SandboxRouting{})
}

// SandboxRouting 是按任务做的路由决策。
//
// 都是"只有上层知道"的知识，所以从外面注入：
//   - ImageFor：这个任务的领域要不要专用工具链（sandbox_image.go）；
//   - MountFor：这个任务的题面附件在宿主的哪儿、要挂到容器里的哪儿（sandbox_mounts.go）；
//   - TargetHosts：题面里出现了哪些主机名，用来推断任务容器该接入哪个 docker 网络
//     （sandbox/target_network.go）。
type SandboxRouting struct {
	ImageFor func(taskID string) string
	MountFor func(taskID string) []sandbox.Mount
	// Egress 返回该任务的全量出口上游；nil = 不启用（直连）。
	// 由 server 闭包提供：每次创建容器时求值，全局代理/出口池热改即生效。
	Egress func(taskID string) *sandbox.EgressUpstream
	// TargetHosts 返回题面里出现的主机名（描述/目标/资产）。
	// nil = 不做网络推断，行为与改造前一致。
	TargetHosts func(taskID string) []string
	// HostGatewayFor 报告该任务是否需要访问宿主服务（真机的 adb server / 录制代理）。
	// nil = 只有开了全量出口隐身时才加 host.docker.internal 映射（旧行为）。
	HostGatewayFor func(taskID string) bool
	// EnvFor 返回该任务额外的容器环境变量（设备序列号、adb 落点等）。
	EnvFor func(taskID string) []string
}

// WireSandboxWithImages 额外带上「按任务选镜像」的解析器（领域专用工具链，见 sandbox_image.go）。
//
// imageFor 返回空字符串 = 用默认镜像，所以传 nil 与 WireSandboxWithImage 等价。
func WireSandboxWithImages(ctx context.Context, dataDir, image string, imageFor func(taskID string) string) {
	wireSandbox(ctx, dataDir, image, SandboxRouting{ImageFor: imageFor})
}

// WireSandboxWithRouting 是完整形态：镜像与额外挂载都按任务路由。
func WireSandboxWithRouting(ctx context.Context, dataDir, image string, r SandboxRouting) {
	wireSandbox(ctx, dataDir, image, r)
}

func WireSandbox(ctx context.Context, dataDir string) {
	wireSandbox(ctx, dataDir, "", SandboxRouting{})
}

// sandboxPerTaskActive 记录「Bash 是否真的跑在一任务一容器里」。
//
// 存在理由：题面来源要据此决定是否把附件路径映射成容器内路径。这个结论不能靠
// "读环境变量重新猜一遍"——环境变量说 per-task，但镜像缺失时 Runner 会降级成
// 永远拒绝（不是容器），此时映射到 /chal 反而是错的方向。只有 wireSandbox
// 的最终分支才知道真相，所以由它写、别处只读。
var sandboxPerTaskActive atomic.Bool

// SandboxPerTaskActive 报告当前 Bash 是否跑在按任务创建的容器里。
func SandboxPerTaskActive() bool { return sandboxPerTaskActive.Load() }

// SandboxContainerRoot 是任务容器内的工作根（与 sandbox.PerTaskConfig.ContainerRoot 一致）。
//
// 提示词里要给模型的"工作目录"就是它：宿主 <data>/work/<taskID> 挂到这里，
// 模型看不到宿主路径（见 agent/worker.go 的 sandboxWorkRoot）。
const SandboxContainerRoot = "/work"

func wireSandbox(ctx context.Context, dataDir, imageOverride string, routing SandboxRouting) {
	sandboxPerTaskActive.Store(false)
	mode := sandbox.ModeFromEnv()
	if mode == sandbox.ModeOff {
		agent.SandboxExec = nil // 不包 Bash，行为与改造前一致
		agent.SetSandboxState(agent.SandboxOff)
		log.Printf("[sandbox] 已关闭（%s=off），Bash 在宿主执行", sandbox.EnvMode)
		return
	}

	isolation := sandbox.IsolationFromEnv()

	// 任务工作区根有两个视角，只有 per-task 才需要「daemon 侧」那一个：
	//   Local  = 应用进程内 os.MkdirAll / 文件工具看到的路径（/app/data/work）
	//   Daemon = 交给 `docker run -v` 的宿主路径（E:/repo/data/work）
	// 宿主二进制部署时二者相同；全 Docker 部署下不同，靠启动期 docker inspect
	// 自身容器自动推导，不需要填任何机器相关的绝对路径（见 sandbox/hostpath.go）。
	localWorkRoot := localSandboxWorkRoot(dataDir)

	var runner sandbox.Runner
	switch isolation {
	case sandbox.IsolationShared:
		runner = sandbox.NewDocker(sandbox.ContainerFromEnv(), SandboxContainerRoot)
	default:
		image := strings.TrimSpace(imageOverride)
		if image == "" {
			image = envOr("SANDBOX_IMAGE", "praetor/sandbox:latest")
		}
		view, viewErr := sandbox.ResolvePathView(ctx, localWorkRoot, config.Env("SANDBOX_WORK_HOST_ROOT"))
		if viewErr != nil {
			// 绝不把 Local 当 Daemon 兜底：那正是本次事故（宿主上不存在的
			// /app/data/work 被 Docker 建了个空目录）的成因。交给 Available()
			// 统一报出，由下面的 mode 分支 fail-closed 或降级。
			log.Printf("[sandbox] 工作区路径视角解析失败：%v", viewErr)
		} else {
			log.Printf("[sandbox] 工作区: 应用内=%s | docker -v 源=%s | 依据=%s",
				view.Local, view.Daemon, view.Via)
		}
		root := view.Daemon
		if viewErr != nil {
			root = ""
		}
		pt := sandbox.NewPerTask(sandbox.PerTaskConfig{
			Image:             image,
			ImageFor:          routing.ImageFor,
			MountFor:          routing.MountFor,
			HostWorkRoot:      root,
			InitErr:           viewErr,
			TranslateHostPath: view.Mapping.Translate,
			ContainerRoot:     SandboxContainerRoot,
			Network:           config.Env("SANDBOX_NETWORK"),
			Env:               sandboxContainerEnv(),
			IdleTTL:           durationOr("SANDBOX_IDLE_TTL", 30*time.Minute),
			Egress:            routing.Egress,
			HostGatewayFor:    routing.HostGatewayFor,
			EnvFor:            routing.EnvFor,
			// 题面主机名 → 目标网络：见 sandbox.TargetNetwork。这里只提供"名字从哪来"，
			// 具体要不要接、接哪个网络由沙箱层问 docker 决定。
			TargetHosts: routing.TargetHosts,
		})
		// 回收协程与探测结果无关：即使当前不可用，起来之后新容器也需要被回收。
		pt.StartReaper(ctx, 5*time.Minute)
		// 上一个进程留下的容器不在 boxes 里，回收协程永远看不见它们。
		// 启动时扫一次：这批容器占内存、占磁盘、还占着网络，症状只是"越跑越慢"。
		if n := pt.SweepOrphans(ctx); n > 0 {
			log.Printf("[sandbox] 清理了 %d 个上次运行遗留的任务容器", n)
		}
		runner = pt
	}

	if err := runner.Available(ctx); err != nil {
		log.Printf("[sandbox] 不可用（mode=%s, isolation=%s, runner=%s）：%v", mode, isolation, runner.Name(), err)
		if mode == sandbox.ModeOptional {
			log.Printf("[sandbox] %s=optional：降级为宿主执行（仅限本地调试）", sandbox.EnvMode)
			agent.SandboxExec = &sandbox.HostRunner{}
			agent.SetSandboxState(agent.SandboxHost)
			return
		}
		log.Printf("[sandbox] worker 的 Bash 将被拒绝；修好 Docker/镜像，或设 %s=optional 降级", sandbox.EnvMode)
		// 关键：注入「永远拒绝」的 Runner。置空会让 Bash 回落宿主执行 = fail-open。
		agent.SandboxExec = sandbox.Failing(err)
		agent.SetSandboxState(agent.SandboxUnavailable)
		return
	}

	agent.SandboxExec = runner
	agent.SetSandboxState(agent.SandboxContainer)
	// Bash 的 cwd：worker 的 run 落在 <root>/i<intentID>，与提示词（promptRunDir）同源。
	// 不宣告的话 Bash 会停在任务根，模型用相对路径写的产物落到共享目录里。
	agent.SetSandboxContainerRoot(SandboxContainerRoot)
	// 网络配错时容器起不来，而报错发生在每条 Bash 上——启动期说一次比重复几十遍便宜。
	// 这里只警告不降级：不跑靶机的任务不受影响，不该被别人的配置失误牵连。
	if err := sandbox.CheckNetwork(ctx, config.Env("SANDBOX_NETWORK")); err != nil {
		log.Printf("[sandbox] 警告：%v", err)
	}
	// 只有走到这里才是真的"Bash 跑在任务容器里"，附件才需要（也才可能）挂到 /chal。
	if isolation == sandbox.IsolationPerTask {
		sandboxPerTaskActive.Store(true)
	}
	log.Printf("[sandbox] 已启用：mode=%s isolation=%s runner=%s", mode, isolation, runner.Name())
}

// SandboxWorkRootDiagnostics 给 `-check-config` 用：一行说清工作区的两个视角。
//
// 换台机器、换 clone 位置、把仓库挪走之后，最容易怀疑的就是「路径是不是又错了」。
// 这行日志直接给出应用内路径、daemon 侧 -v 源和推导依据，不需要去翻容器挂载表。
// 只做只读 docker inspect（5s 超时），不连数据库、不改任何东西。
func SandboxWorkRootDiagnostics(ctx context.Context, dataDir string) string {
	local := localSandboxWorkRoot(dataDir)
	view, err := sandbox.ResolvePathView(ctx, local, config.Env("SANDBOX_WORK_HOST_ROOT"))
	if err != nil {
		return fmt.Sprintf("应用内=%s | docker -v 源=解析失败（%v）", local, err)
	}
	return fmt.Sprintf("应用内=%s | docker -v 源=%s | 依据=%s", view.Local, view.Daemon, view.Via)
}

// envOr 读 PRAETOR_<key>，空则用默认值。
func envOr(key, def string) string {
	if v := strings.TrimSpace(config.Env(key)); v != "" {
		return v
	}
	return def
}

// durationOr 解析 PRAETOR_<key> 为时长（如 "30m"），非法值回落默认。
func durationOr(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(config.Env(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Printf("[sandbox] %s=%q 不是合法时长，使用默认 %s", key, v, def)
		return def
	}
	return d
}

// sandboxContainerEnv 把宿主侧记录的 MITM 代理地址注入沙箱容器。
//
// 容器里访问宿主要用 host.docker.internal（Docker Desktop 支持），所以这里只做透传，
// 具体值由部署方给：PRAETOR_SANDBOX_PROXY=http://host.docker.internal:8899
func sandboxContainerEnv() []string {
	proxy := strings.TrimSpace(config.Env("SANDBOX_PROXY"))
	if proxy == "" {
		return nil
	}
	return []string{
		"HTTP_PROXY=" + proxy,
		"HTTPS_PROXY=" + proxy,
		"http_proxy=" + proxy,
		"https_proxy=" + proxy,
		"NO_PROXY=localhost,127.0.0.1",
	}
}

// sandboxEgress 把全局出口代理翻译成沙箱容器的透明重定向上游；未配置返回 nil。
//
// 每次创建容器时调用（不是 wiring 时快照）：全局代理支持热改，快照会让
// "改了代理"对之后的容器永远不生效。回环地址翻译成 host.docker.internal
// （容器创建时带 --add-host=host-gateway）；SANDBOX_PROXY 指向的 MITM 录制代理
// 加入直连绕过 —— 它的上游就是同一份全局代理，链路里不需要二跳。
func (s *Server) sandboxEgressFor(taskID string) *sandbox.EgressUpstream {
	if s == nil || s.m == nil {
		return nil
	}
	s.m.mu.RLock()
	pool := append([]string(nil), s.m.egressUpstreams...)
	s.m.mu.RUnlock()
	raw := s.m.EffectiveEgress()

	// 任务级出口池优先：按任务稳定分配（同一任务重建容器后仍同一出口，
	// 会话/登录态绑 IP 不能漂移）；池为空回落代理池/系统代理/直连的有效出口。
	if len(pool) > 0 {
		raw = pool[PickUpstreamIndex(taskID, len(pool))]
	}
	up, err := sandbox.ParseEgressUpstream(raw, "host.docker.internal")
	if err != nil {
		log.Printf("[sandbox] 任务 %s 的出口代理无法用于容器透明层（容器保持直连）：%v", taskID, err)
		return nil
	}
	if up == nil {
		// 没配全局出口时 ParseEgressUpstream 返回 (nil,nil)。旧代码在这里直接
		// 给 up.Exclude 赋值会 panic —— 只要部署方配了 SANDBOX_PROXY 却没配
		// 全局出口就会触发。没有透明层时也不存在「需要绕过」的链路，直接返回。
		return nil
	}
	excludes := sandbox.ParseEgressExclude(strings.TrimSpace(config.Env("SANDBOX_PROXY")))
	// 真机链路：到手机 IP、宿主 adb :5037、frida :27042 的流量不能被透明层
	// 劫到上游代理，否则 adb 连接直接断、设备看起来「掉线」。
	excludes = append(excludes, mobileEgressExcludes()...)
	if len(excludes) > 0 {
		up.Exclude = append(up.Exclude, excludes...)
	}
	return up
}

// mobileEgressExcludes 给出真机接入时必须直连绕过的 host:port。
// 设备模式没开时返回空 —— 不接手机的任务不该凭空多出白名单。
func mobileEgressExcludes() []string {
	if config.Env("MOBILE_DEVICE_MODE") != "1" {
		return nil
	}
	out := []string{"host.docker.internal:5037", "host.docker.internal:27042"}
	return append(out, sandbox.ParseEgressExclude(config.Env("MOBILE_DEVICE_EXCLUDE"))...)
}

// PickUpstreamIndex 是纯函数：hash(taskID) 对 N 取模。
// fnv32a 够用 —— 只需要"稳定 + 分布均匀"，不需要密码学强度。
func PickUpstreamIndex(taskID string, n int) int {
	if n <= 0 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(taskID))
	return int(h.Sum32() % uint32(n))
}

// targetHostsFromText 从若干段题面文本里提取主机名（去重、保序）。
//
// 复用 seed 的 parseTarget：站点播种与网络对齐必须看同一段文本、用同一套解析，
// 否则会出现"资产里有 delulu、沙箱却没接进 delulu 的网络"这种半对齐状态。
func targetHostsFromText(texts ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, text := range texts {
		if _, host, _, ok := parseTarget(text); ok && host != "" && !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return out
}

// taskTargetHosts 供沙箱推断「任务容器该接入哪个 docker 网络」。
// 任务不存在时返回 nil（沙箱退回默认网络，不报错）。
func (s *Server) taskTargetHosts(taskID string) []string {
	if s == nil || s.m == nil {
		return nil
	}
	t, ok := s.m.Task(taskID)
	if !ok || t == nil {
		return nil
	}
	return targetHostsFromText(t.Description, t.Goal)
}
