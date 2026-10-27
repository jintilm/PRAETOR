# 内联的上游代码：norma（agent 运行时 SDK）

本目录是 **`github.com/Autumn-27/norma` v0.4.3** 的源码副本，内联进本项目以消除构建期对
外部仓库的依赖。

## 来源与许可

| 项 | 值 |
| --- | --- |
| 上游仓库 | `github.com/Autumn-27/norma` |
| 版本 | `v0.4.3` |
| 模块校验 | `h1:DnmOhJPL6OZSMnCVYO5Ujh4yVINuDarEickVi9jx1hI=` |
| 许可 | **Apache-2.0**（全文见同目录 `LICENSE`） |
| 拉取日期 | 2026-10-27 |

> 说明：上游发布的模块 zip 里**没有携带 LICENSE 文件**（`go mod download` 的缓存目录中不存在），
> 本目录的 `LICENSE` 取自上游仓库根目录的 `LICENSE`（GitHub License API 识别为 Apache-2.0），
> 以满足 Apache-2.0 第 4 条「随分发保留许可副本」的要求。

## 我们对上游代码做的修改

1. **仅 import 路径前缀**：`github.com/Autumn-27/norma/...` → `github.com/jintilm/praetor/internal/norma/...`。
   没有任何逻辑改动。
2. **未拷贝**：`*_test.go`（98 个）、`cmd/`、`examples/`、`go.mod`、`go.sum`、上游 `README.md`。
   原因：上游测试依赖其自身模块路径与 fixture，放进本项目会污染 `go test ./...`；
   命令行与示例与本项目无关。

## 为什么内联（对应执行文档 R6 自包含优先）

- **构建期不依赖外部仓库**：干净机器/CI 上无需 `go mod download` 即可离线构建（上游删库或改 API 都不影响）。
- **可以按自身需要调整内部默认值**：例如上下文压缩预算、工具输出上限——这些此前只能从外部传参覆盖，
  现在可以直接改源码并留下注释说明原因。
- 保留独立升级能力：上游发布新版时，重新拷贝并用同样的替换即可（见下）。

## 升级步骤

```bash
# 1) 拿到新版源码（例：v0.5.0）
go mod download -json github.com/Autumn-27/norma@v0.5.0   # 看 "Dir" 字段

# 2) 覆盖本目录（排除测试/示例/模块文件），并改 import 前缀
#    PS: 参考 git 历史中本次内联的脚本思路，核心是:
#    s/github.com\/Autumn-27\/norma/github.com\/jintilm\/praetor\/internal\/norma/

# 3) 更新本文件里的版本/校验和，然后
go build ./... && go test ./... -count=1
```

## 边界

- 本目录是**第三方代码**，本项目自研逻辑不要写进这里（否则升级时会被覆盖）。
- 若上游代码与本项目约定冲突（例如日志格式），优先在调用侧适配，而不是改这里。
