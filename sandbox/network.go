package sandbox

import (
	"context"
	"fmt"
	"strings"
)

// networkInspect 是 CheckNetwork 用到的 docker 调用，抽成变量便于测试注入
// （测试不该真的去问 docker，否则 CI 没装 docker 就红）。
var networkInspect = runDockerCLI

// CheckNetwork 确认 docker 网络存在。
//
// 为什么值得单独探一次：`docker run --network <name>` 在网络不存在时直接失败，
// 于是**每一条 Bash** 都以 "network <name> not found" 收场。这个错误对模型毫无信息量
// —— 它不知道这是部署配置问题，会反复重试、换命令、最后自己编一道题。
// 启动期说一次，比在几十次工具调用里重复几十遍便宜得多。
//
// 空名字合法（= 用 docker 默认 bridge），不算错。
func CheckNetwork(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	stdout, stderr, code, err := networkInspect(ctx, []string{"network", "inspect", name}, "")
	if err != nil {
		// docker 本身不可用：交给 Available() 的既有报错，别在这里重复一遍。
		return nil
	}
	if code != 0 {
		detail := strings.TrimSpace(stderr)
		if detail == "" {
			detail = strings.TrimSpace(stdout)
		}
		return fmt.Errorf("docker 网络 %q 不存在（任务容器会全部创建失败）：先执行 `docker network create %s`，"+
			"或把 PRAETOR_SANDBOX_NETWORK 指向已有网络后重启。docker: %s", name, name, detail)
	}
	return nil
}
