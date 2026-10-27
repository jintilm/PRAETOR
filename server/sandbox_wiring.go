package server

import (
	"context"
	"log"
	"path/filepath"
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

// SandboxRouting 是按任务做的两项路由决策。
//
// 两者都是"只有上层知道"的知识，所以从外面注入：
//   - ImageFor：这个任务的领域要不要专用工具链（sandbox_image.go）；
//   - MountFor：这个任务的题面附件在宿主的哪儿、要挂到容器里的哪儿（sandbox_mounts.go）。
type SandboxRouting struct {
	ImageFor func(taskID string) string
	MountFor func(taskID string) []sandbox.Mount
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

func WireSandbox(ctx context.Context, dataDir string) { wireSandbox(ctx, dataDir, "", SandboxRouting{}) }

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
		log.Printf("[sandbox] 已关闭（%s=off），Bash 在宿主执行", sandbox.EnvMode)
		return
	}

	isolation := sandbox.IsolationFromEnv()

	var runner sandbox.Runner
	switch isolation {
	case sandbox.IsolationShared:
		runner = sandbox.NewDocker(sandbox.ContainerFromEnv(), "/work")
	default:
		image := strings.TrimSpace(imageOverride)
		if image == "" {
			image = envOr("SANDBOX_IMAGE", "praetor/sandbox:latest")
		}
		pt := sandbox.NewPerTask(sandbox.PerTaskConfig{
			Image:         image,
			ImageFor:      routing.ImageFor,
			MountFor:      routing.MountFor,
			HostWorkRoot:  envOr("SANDBOX_WORK_ROOT", filepath.Join(dataDir, "work")),
			ContainerRoot: "/work",
			Network:       config.Env("SANDBOX_NETWORK"),
			Env:           sandboxContainerEnv(),
			IdleTTL:       durationOr("SANDBOX_IDLE_TTL", 30*time.Minute),
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
			return
		}
		log.Printf("[sandbox] worker 的 Bash 将被拒绝；修好 Docker/镜像，或设 %s=optional 降级", sandbox.EnvMode)
		// 关键：注入「永远拒绝」的 Runner。置空会让 Bash 回落宿主执行 = fail-open。
		agent.SandboxExec = sandbox.Failing(err)
		return
	}

	agent.SandboxExec = runner
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
