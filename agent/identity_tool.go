package agent

import (
	"context"
	"encoding/json"

	"github.com/jintilm/praetor/db"
	actool "github.com/jintilm/praetor/internal/norma/tool"
)

// 双身份差分的前提是「A、B 是两个真的人」。让模型每次现拼 Cookie，它常把 B 又写成 A 的，
// 差分退化成"同一凭据"白跑一次。所以身份必须落库、可复用、可被后面的判定读到。

func identityGuidance() string {
	return "登记后用 http_probe 分别以两个身份请求**同一个对象**，把 A 独有标记（私有邮箱/订单号）作为 canary；" +
		"两边都拿到 200 且 B 读到 A 的 canary 才是越权。只是两人都能打开首页不算。"
}

func (t *ToolSet) registerIdentity() actool.CoreTool {
	schema := obj(map[string]any{
		"label": str("身份短名（a / b / admin），后续按它引用"),
		"headers": map[string]any{
			"type":        "object",
			"description": "该身份的请求头，如 {\"Cookie\":\"sid=...\"} 或 {\"Authorization\":\"Bearer ...\"}；至少一条",
		},
		"role":   str("可选：身份角色说明（owner / peer / admin）"),
		"canary": str("可选：该身份独有的资源标记（私有邮箱、订单号）。越权差分的主判据，强烈建议填"),
	}, "label", "headers")
	return t.writeExpTool("register_identity",
		"登记一个测试身份（Cookie/Authorization 等），供双身份越权差分复用。同名覆盖即更新凭据。"+
			"凭据只在服务端保存，返回的是打码结果。"+identityGuidance(),
		schema,
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			if t.ts == nil || t.taskID <= 0 {
				return actool.Errorf("register_identity 需要任务上下文"), nil
			}
			var a struct {
				Label   string            `json:"label"`
				Role    string            `json:"role"`
				Headers map[string]string `json:"headers"`
				Canary  string            `json:"canary"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			id, err := t.ts.UpsertTaskIdentity(ctx, t.taskID, a.Label, a.Role, a.Headers, a.Canary)
			if err != nil {
				return actool.Errorf("身份未登记：" + err.Error()), nil
			}
			out := map[string]any{
				"label": id.Label, "role": id.Role, "canary": id.Canary,
				"headers": id.MaskedHeaders(), "updated": true,
			}
			// 同一份凭据登记成两个身份是最常见的坑，当场提示而不是等判定失败。
			if others, err := t.ts.ListTaskIdentities(ctx, t.taskID); err == nil {
				for _, o := range others {
					if o.Label != id.Label && o.Fingerprint() == id.Fingerprint() {
						out["warning"] = "与身份 " + o.Label + " 的凭据完全相同，差分会被判成「同一凭据」"
						break
					}
				}
			}
			if id.Canary == "" {
				out["next"] = "还没填 canary：补一个该身份独有的资源标记，否则只能靠整页哈希对比，动态页面会判成不确定"
			}
			return jsonResult(out)
		})
}

func (t *ToolSet) listIdentities() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        "list_identities",
		Description: "列出本任务已登记的身份（打码），用于核对差分用的 A/B 是否真的是两个人。" + identityGuidance(),
		Prompt:      "越权判定前先看一眼：两个身份凭据相同、或某个身份没 canary，都先补再判。",
		Schema:      obj(map[string]any{}),
		ReadOnly:    func(json.RawMessage) bool { return true },
		Run: func(ctx context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if t.ts == nil || t.taskID <= 0 {
				return actool.Errorf("list_identities 需要任务上下文"), nil
			}
			list, err := t.ts.ListTaskIdentities(ctx, t.taskID)
			if err != nil {
				return actool.Errorf("读取身份失败：" + err.Error()), nil
			}
			items := make([]map[string]any, 0, len(list))
			seen := map[string]string{}
			for _, id := range list {
				item := map[string]any{"label": id.Label, "role": id.Role, "canary": id.Canary, "headers": id.MaskedHeaders()}
				if other, dup := seen[id.Fingerprint()]; dup {
					item["warning"] = "与 " + other + " 凭据相同"
				} else {
					seen[id.Fingerprint()] = id.Label
				}
				items = append(items, item)
			}
			return jsonResult(map[string]any{"count": len(items), "items": items})
		},
	})
}

// 供 wiring 处断言：两个工具都已登记进 worker 工具面。
var _ = db.TaskIdentity{}
