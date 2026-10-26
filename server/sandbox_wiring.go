package server

import (
	"context"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/praetor/agent"
	"github.com/Autumn-27/praetor/config"
	"github.com/Autumn-27/praetor/sandbox"
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
func WireSandbox(ctx context.Context, dataDir string) {
	mode := sandbox.ModeFromEnv()
	if mode == sandbox.ModeOff {
		agent.SandboxExec = nil // 不包 Bash，行为与改造前一致
		log.Printf("[sandbox] 已关闭（%s=off），Bash 在宿主执行", sandbox.EnvMode)
		return
	}

	isolation := strings.ToLower(strings.TrimSpace(config.Env("SANDBOX_ISOLATION")))
	if isolation == "" {
		isolation = "per-task"
	}

	var runner sandbox.Runner
	switch isolation {
	case "shared", "container", "single":
		runner = sandbox.NewDocker(sandbox.ContainerFromEnv(), "/work")
	default:
		pt := sandbox.NewPerTask(sandbox.PerTaskConfig{
			Image:         envOr("SANDBOX_IMAGE", "praetor/sandbox:latest"),
			HostWorkRoot:  envOr("SANDBOX_WORK_ROOT", filepath.Join(dataDir, "work")),
			ContainerRoot: "/work",
			Network:       config.Env("SANDBOX_NETWORK"),
			Env:           sandboxContainerEnv(),
			IdleTTL:       durationOr("SANDBOX_IDLE_TTL", 30*time.Minute),
		})
		// 回收协程与探测结果无关：即使当前不可用，起来之后新容器也需要被回收。
		pt.StartReaper(ctx, 5*time.Minute)
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
