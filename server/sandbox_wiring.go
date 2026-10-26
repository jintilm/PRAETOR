package server

import (
	"context"
	"log"

	"github.com/Autumn-27/praetor/agent"
	"github.com/Autumn-27/praetor/sandbox"
)

// WireSandbox 在启动期选定沙箱后端并注入 agent。
//
// 语义（见 sandbox 包注释）：
//   - PRAETOR_SANDBOX=required（默认） 容器不可用 → 整个沙箱视为不可用，worker 的 Bash
//     会在调用时明确报错（fail-closed），绝不静默跑回宿主。
//   - optional 容器不可用 → 告警一次后降级为宿主执行（本地调试用）。
//   - off 不使用沙箱，行为与改造前一致。
//
// 注意：这里只做「探测 + 注入」。探测失败不阻断服务启动——否则 Docker 没起时连 UI 都进不去；
// 真正的拒绝发生在每次工具调用，错误会回给模型与用户。
func WireSandbox(ctx context.Context) {
	mode := sandbox.ModeFromEnv()
	container := sandbox.ContainerFromEnv()

	runner, effective, err := sandbox.Select(ctx, sandbox.Options{
		Mode:      mode,
		Container: container,
		Warnf:     func(format string, args ...any) { log.Printf("[sandbox] "+format, args...) },
	})
	if err != nil {
		log.Printf("[sandbox] 不可用（mode=%s, container=%s）：%v", mode, container, err)
		log.Printf("[sandbox] worker 的 Bash 调用将被拒绝；启动 `docker compose up -d sandbox` 或设 PRAETOR_SANDBOX=optional 降级")
		// 关键：注入「永远拒绝」的 Runner。置空会让 Bash 回落宿主执行 = fail-open。
		agent.SandboxExec = sandbox.Failing(err)
		return
	}
	if effective == sandbox.ModeOff {
		agent.SandboxExec = nil // off：不包 Bash，行为与改造前一致
		log.Printf("[sandbox] 已关闭（%s=off），Bash 在宿主执行", sandbox.EnvMode)
		return
	}
	agent.SandboxExec = runner
	log.Printf("[sandbox] 已启用：mode=%s runner=%s", effective, runner.Name())
}
