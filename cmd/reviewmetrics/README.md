# 离线评测与成本对照（reviewmetrics）

对**已经保存的运行结果**出报告：逐条判出误报、漏报、证据不足，汇总 precision/recall，
并对照两次运行的 Token 成本与质量变化。**只读 JSON 文件**：不联网、不连库、不执行任何样本。

## 快速开始

```bash
# 单次运行报告
go run ./cmd/reviewmetrics -baseline before.json

# 两次运行对照（升级前后）
go run ./cmd/reviewmetrics -baseline before.json -candidate after.json

# 给 CI 用：有误报或有回归就退出码 1
go run ./cmd/reviewmetrics -baseline before.json -candidate after.json -gate
```

退出码：`0` 通过；`1` 门禁未通过；`2` 输入不合法。

## 输入格式

```json
{
  "name": "before",
  "results": [
    {
      "case": {
        "id": "injection_true", "class": "sqli", "kind": "positive",
        "fixture": "vulnerable", "url": "http://fixture.test/search?q=1",
        "payload": "q=1",
        "expected_oracle": "pass", "expected_conclusion": "confirmed"
      },
      "started_at": "2026-01-01T00:00:00Z",
      "executed": true,
      "input_tokens": 100, "output_tokens": 0,
      "findings": [
        {"id":"f1","oracle":"pass","conclusion":"confirmed","confirmed_at":"2026-01-01T00:02:00Z"}
      ]
    }
  ]
}
```

- `kind`：`positive` 真漏洞 / `negative` 已修好 / `trap` 像漏洞但不可利用 / `boundary` 边界样本。
- `executed`：该 case 是否真的跑过。**不写就按「证据不足」处理**，不会白拿分。
- `findings`：本次运行**上报的漏洞**。空数组表示没有上报。正确拒绝的样本不要放进 `findings`。
- `input_tokens`/`output_tokens`：该 case 整个任务的账本和，不按 finding 重复计。

## 评语口径

| 评语 | 含义 |
| --- | --- |
| `confirmed` | 正例被确定性判定确认为漏洞 |
| `correctly_neg` | 负例/陷阱没有上报（且标注已执行） |
| `false_positive` | 负例/陷阱被当成漏洞确认——**最贵的一类错误** |
| `missed` | 正例没被确认（漏报） |
| `inconclusive` | 未执行、采集不完整或判据不确定，不算对也不算错 |

关键规则：**误报 = 声称是漏洞而真值不是**。正确拒绝负例不算误报，否则越认真做拒绝判定的
运行分数反而越差（这条曾经是 bug，已修）。

## 指标

- `precision` = confirmed / (confirmed + fp)；分母为 0 时输出 `n/a`，不是 0%。
- `recall` = 被确认的正例 / 正例总数。
- `tokens` = 该类别全部 case 的输入+输出 token。
- `cost_per_confirmed` = tokens / confirmed；没有确认漏洞时为 `n/a`。

## 对照怎么看

Token 上升不等于变差。要看 `cost_per_confirmed`（每个确认漏洞的成本）和 `recall`：

- 成本 +50%、确认漏洞 +100% → 值得；
- 成本 +50%、确认漏洞不变 → 白花钱；
- 质量不变但 `Regressions` 非空 → 有样本从对变错，先查它。

## 注意

`bench/` 目录在 `.gitignore` 里（`/bench/*` 只放行 `xbow`、`ctf`），所以计分代码与样本
目前只存在于本机工作区。要纳入版本库需要调整忽略规则，这一步未做。
