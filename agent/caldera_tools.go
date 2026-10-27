package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jintilm/praetor/config"
	"github.com/jintilm/praetor/internal/caldera"
	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// 本文件是 P4-2：把 Caldera 接成**一个**工具（而不是一整套 MCP 工具面）。
//
// 红队真正需要的动作只有三件：看有哪些原子能力、下发一条、回收结果。
// 三件事走三个 REST 端点，模型看到的是一个 schema；Caldera 自带的 abilities/agents/
// objectives/planners 那几十个端点不进上下文 —— 那是别人家的内部结构，不是我们的决策面。
//
// Atomic Red Team 的接入路径也在这里：Caldera 的 atomic 插件把 ART 的 atomics 变成
// ability，所以我们只需要"按名字下发 ability"，不必再引一套 YAML 解析。

const (
	envCalderaURL = "CALDERA_URL"
	envCalderaKey = "CALDERA_KEY"
)

// calderaMaxField 是单条 link 里命令/输出保留的字符数。
//
// 一次 operation 可能回几十条链，每条输出几百 KB（谁还记得住上下文成本）；
// 这里只留"够判断成没成"的片段，全文由执行侧自己落盘。
const calderaMaxField = 400

// calderaClient 按环境变量构造客户端；未配置时返回带指引的错误。
func calderaClient() (*caldera.Client, error) {
	url := strings.TrimSpace(config.Env(envCalderaURL))
	if url == "" {
		return nil, fmt.Errorf("Caldera 未配置：设 PRAETOR_%s（如 http://127.0.0.1:8888）。"+
			"没有 Caldera 时红队只能做静态侦察与人工步骤，不要假装下发成功", envCalderaURL)
	}
	return caldera.New(url, config.Env(envCalderaKey))
}

// calderaTool 是红队域的编排执行器（P4-2）。
func calderaTool() actool.CoreTool {
	return readTool("caldera_operation",
		"通过 Caldera 下发/回收原子能力（Atomic Red Team 的 atomics 以 ability 形式存在）。\n"+
			"action=list 看有哪些 ability；action=start + ability 名字/id 下发一条；action=status + operation_id 回收结果。\n"+
			"结果只回「哪条链、什么状态、命令与输出片段」，完整输出请自己落盘。",
		obj(map[string]any{
			"action":       str("list | start | status"),
			"ability":      str("ability 名字或 id（start 必填；list 时可作为过滤词）"),
			"group":        str("目标 agent 组，默认 red"),
			"operation_id": str("operation id（status 必填，start 的返回值里有）"),
			"name":         str("operation 名称（可选，便于事后检索）"),
		}, "action"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Action      string `json:"action"`
				Ability     string `json:"ability"`
				Group       string `json:"group"`
				OperationID string `json:"operation_id"`
				Name        string `json:"name"`
			}
			_ = json.Unmarshal(in, &a)
			action := strings.ToLower(strings.TrimSpace(a.Action))
			if action == "" {
				return actool.Errorf("action 必填：list / start / status"), nil
			}
			cli, err := calderaClient()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}

			switch action {
			case "list":
				abs, err := cli.Abilities(ctx, a.Ability)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return actool.Text(renderAbilities(abs)), nil
			case "start":
				ab, err := cli.AbilityByName(ctx, a.Ability)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				op, err := cli.StartOperation(ctx, ab.AbilityID, a.Group, a.Name)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return actool.Text(fmt.Sprintf("operation %s 已下发：%s（%s，组=%s）。"+
					"用 action=status operation_id=%s 回收结果",
					op.ID, ab.Name, ab.AbilityID, orDefault(a.Group, "red"), op.ID)), nil
			case "status":
				op, err := cli.Status(ctx, a.OperationID)
				if err != nil {
					return actool.Errorf(err.Error()), nil
				}
				return actool.Text(renderOperation(op)), nil
			default:
				return actool.Errorf(fmt.Sprintf("未知 action %q：list / start / status", a.Action)), nil
			}
		})
}

// renderAbilities 输出能力清单（训练/演练时模型靠它挑一条，不看全量）。
func renderAbilities(abs []caldera.Ability) string {
	if len(abs) == 0 {
		return "（没有匹配的 ability；先不带过滤词 list 一次）"
	}
	const max = 30
	var b strings.Builder
	fmt.Fprintf(&b, "abilities %d：\n", len(abs))
	for i, a := range abs {
		if i >= max {
			fmt.Fprintf(&b, "…（还有 %d 条，用 ability 过滤）\n", len(abs)-max)
			break
		}
		fmt.Fprintf(&b, "- %s\t%s\t%s\n", a.Name, a.AbilityID, a.Tactic)
	}
	return b.String()
}

// renderOperation 把 operation 折成"哪条链、什么状态、输出片段"。
//
// 只回摘要：一次 operation 的输出可能几十 KB，全塞进上下文之后每轮都要重发。
func renderOperation(op *caldera.Operation) string {
	if op == nil {
		return "（空 operation）"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "operation %s state=%s links=%d\n", op.ID, orDefault(op.State, "?"), len(op.Links))
	done := 0
	for _, l := range op.Links {
		if l.Done() {
			done++
		}
		name := "?"
		if l.Ability != nil {
			name = l.Ability.Name
		}
		fmt.Fprintf(&b, "- %s\tstatus=%d\t%s\t%s\n", name, l.Status, clip(l.Paw), clip(l.Command))
		if out := clip(l.Output); out != "" {
			fmt.Fprintf(&b, "  out: %s\n", out)
		}
	}
	if len(op.Links) > 0 && done == 0 {
		b.WriteString("（还没有链完成：稍后再查一次）\n")
	}
	return b.String()
}

func clip(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " ⏎ "))
	if len(s) > calderaMaxField {
		return s[:calderaMaxField] + "…"
	}
	return s
}

func orDefault(s, def string) string {
	if v := strings.TrimSpace(s); v != "" {
		return v
	}
	return def
}
