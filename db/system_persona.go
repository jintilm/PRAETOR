package db

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// settingSystemPersona 是系统级人设（身份/授权声明层）的存储键。
//
// 放在 settings 表而不是 agents 表：它是**全局单例**（所有 agent 共用一份），
// 与 per-agent 的职责提示词（agents/agent_prompts，带版本化）是两层不同的东西。
const settingSystemPersona = "system_persona"

// SystemPersona 的长度上限（字符）。取 8000 的依据：
// 人设是「一次性交代身份/授权/交付口径」，几百字足够；给到 8000 已经远超
// 正常需要（现有一份 agent 正文也就 4KB 量级），超过基本是误贴长文。
// 上限的作用不是限制表达，而是**挡住「把整份规范贴进每一轮上下文」**
// —— 它每轮重发，会直接抬高所有 agent 的成本。
const (
	MaxSystemPersonaChars = 8000
	// personaAuditNoteMax 是审计备注的长度上限（超长留档没意义）。
	personaAuditNoteMax = 500
)

// SystemPersona 读取系统级人设（未配置时 ok=false）。
func (d *DB) SystemPersona() (string, bool) {
	v, ok, err := d.GetSetting(settingSystemPersona)
	if err != nil || !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	return v, true
}

// PersonaSaveRequest 是一次系统人设保存请求（含门禁所需的确认信息）。
type PersonaSaveRequest struct {
	Text string `json:"text"`
	// Confirm 必须为 true —— 系统人设影响**所有** agent 的行为，
	// 属于高影响变更，保存侧要求显式确认（UI 上是勾选框）。
	Confirm bool `json:"confirm"`
	// Note 是变更说明，写入审计。强制非空：出了行为问题要能回溯「谁在什么时候、
	// 为什么改的」。这是门禁的一部分，不是可选字段。
	Note string `json:"note"`
	// Actor 记录操作者（单用户平台下为固定值，保留以便未来多用户）。
	Actor string `json:"actor"`
}

// PersonaAudit 是一次人设变更的审计记录。
type PersonaAudit struct {
	TS      time.Time `json:"ts"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"` // save | clear
	Note    string    `json:"note"`
	Chars   int       `json:"chars"`
	Version int64     `json:"version"` // 递增，便于对比历史快照
}

// ValidatePersonaSave 执行保存前的门禁校验（纯函数，便于单测）。
//
// 门禁规则与理由：
//  1. 必须显式确认 —— 高影响变更不能"顺手保存"。
//  2. 必须填写变更说明 —— 行为异常时要能回溯原因，这是审计的最低要求。
//  3. 长度上限 —— 见 MaxSystemPersonaChars 的说明（它每轮重发，直接影响成本）。
//  4. 不允许"保存空白"来达到清空目的 —— 清空要调 ClearSystemPersona，
//     让 UI/审计能明确区分「误删」与「有意清除」（一个静默变空的人设会
//     让所有 agent 的行为悄悄回到模型默认对齐，最难排查）。
func ValidatePersonaSave(req PersonaSaveRequest) error {
	if !req.Confirm {
		return fmt.Errorf("系统级人设影响所有 agent，保存前必须显式确认")
	}
	if strings.TrimSpace(req.Note) == "" {
		return fmt.Errorf("必须填写变更说明（用于审计回溯）")
	}
	if len([]rune(req.Note)) > personaAuditNoteMax {
		return fmt.Errorf("变更说明最多 %d 字", personaAuditNoteMax)
	}
	text := strings.TrimSpace(req.Text)
	if text == "" {
		return fmt.Errorf("人设内容不能为空；如需清除请使用「清空人设」")
	}
	if n := len([]rune(text)); n > MaxSystemPersonaChars {
		return fmt.Errorf("人设最多 %d 字（当前 %d）——它会在每一轮请求中随上下文重发，"+
			"过长会显著抬高所有 agent 的成本", MaxSystemPersonaChars, n)
	}
	return nil
}

// SaveSystemPersona 保存系统级人设并写审计。
func (d *DB) SaveSystemPersona(req PersonaSaveRequest) (*PersonaAudit, error) {
	if err := ValidatePersonaSave(req); err != nil {
		return nil, err
	}
	text := strings.TrimSpace(req.Text)
	if err := d.SetSetting(settingSystemPersona, text); err != nil {
		return nil, err
	}
	rec := PersonaAudit{
		TS: time.Now(), Actor: pickActor(req.Actor), Action: "save",
		Note: strings.TrimSpace(req.Note), Chars: len([]rune(text)),
	}
	return d.appendPersonaAudit(rec)
}

// ClearSystemPersona 清除人设（独立的显式动作，与"保存空白"区分开）。
func (d *DB) ClearSystemPersona(note, actor string) (*PersonaAudit, error) {
	if strings.TrimSpace(note) == "" {
		return nil, fmt.Errorf("必须填写清除原因（用于审计回溯）")
	}
	if err := d.SetSetting(settingSystemPersona, ""); err != nil {
		return nil, err
	}
	rec := PersonaAudit{TS: time.Now(), Actor: pickActor(actor), Action: "clear", Note: strings.TrimSpace(note)}
	return d.appendPersonaAudit(rec)
}

// PersonaAudits 返回最近的变更记录（新→旧，最多 limit 条）。
//
// 审计用 settings 表的独立键存 JSON 数组：规模极小（每次改动一条）、无需建表，
// 且与「当前值」同库同事务语义。
func (d *DB) PersonaAudits(limit int) ([]PersonaAudit, error) {
	if limit <= 0 {
		limit = 20
	}
	raw, ok, err := d.GetSetting(settingSystemPersonaAudit)
	if err != nil || !ok || strings.TrimSpace(raw) == "" {
		return nil, err
	}
	var all []PersonaAudit
	if err := json.Unmarshal([]byte(raw), &all); err != nil {
		return nil, err
	}
	// 新→旧
	out := make([]PersonaAudit, 0, limit)
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, all[i])
	}
	return out, nil
}

// settingSystemPersonaAudit 存审计数组（JSON）。
const settingSystemPersonaAudit = "system_persona_audits"

// appendPersonaAudit 追加一条审计并返回它（版本号 = 累计次数）。
func (d *DB) appendPersonaAudit(rec PersonaAudit) (*PersonaAudit, error) {
	var all []PersonaAudit
	if raw, ok, err := d.GetSetting(settingSystemPersonaAudit); err == nil && ok && strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &all)
	}
	rec.Version = int64(len(all)) + 1
	all = append(all, rec)
	// 审计只留最近 200 条：它是回溯用，不是归档系统；无界增长会拖慢每次读取。
	if len(all) > 200 {
		all = all[len(all)-200:]
	}
	blob, err := json.Marshal(all)
	if err != nil {
		return nil, err
	}
	if err := d.SetSetting(settingSystemPersonaAudit, string(blob)); err != nil {
		return nil, err
	}
	return &rec, nil
}

func pickActor(a string) string {
	a = strings.TrimSpace(a)
	if a == "" {
		return "operator"
	}
	return a
}
