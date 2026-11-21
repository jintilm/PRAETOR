# M2-3 HTTP OOB 最小实现

独立包 internal/oob 提供 New(origin)、Issue(taskID, ttl)、Handler()、Result(token)、Wait(ctx, token)。每次 Issue 生成独立随机 256-bit token，回连 GET/POST /oob/<token> 至多保留首次 hit。证据含 task ID、签发/过期时间、命中时间、方法、请求 headers 和远端地址；Cookie/Authorization 脱敏。没有命中且等待窗口耗尽的状态是 inconclusive，不是失败。

本机验证：

    go test -race ./internal/oob -count=1
    go run ./cmd/oobcatcher -task local-demo -ttl 30s -listen 127.0.0.1:8089
    # 等待窗口内复制程序输出的 URL，另开终端：curl -i -H "X-Trace: demo" "<URL>"

CLI 第一行 JSON 是探针 URL/token/task/到期时间，第二行 JSON 是最终证据；未收到 HTTP 回连时第二行显示 inconclusive。外部回连使用 -public-url https://<reachable-origin>，并代理外部入口至 -listen 地址；公网 TLS 与可达性由部署者配置。

缺口：DNS 回连尚未实现；内存存储不跨重启，尚无清理/容量上限；尚未挂接 agent/server/db、没有 UI 或持久化证据，终局判定需调用方依据 Status 且不得将 inconclusive 映射到 fail。需保留 CLI 输出或由调用方持久化事件以备审计。
