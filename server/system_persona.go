package server

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/jintilm/praetor/db"
)

// 系统级人设（身份/授权声明层）的 API。
//
// 为什么单独一组路由、而不是塞进 PUT /api/settings 的字段里：
//   - 它是**最高优先级**的全局层（解除模型泛化拒绝），改动影响所有 agent；
//   - 它需要**门禁**（显式确认 + 变更说明 + 长度上限 + 独立清空动作）与**审计**，
//     这些语义塞不进扁平的设置键值对（那层是「改了就生效」的低影响开关）。
//
// 路径刻意与 per-agent 提示词分开（/api/agents/{key}/prompt），
// 避免运营混淆「改一个 agent」与「改全局人设」。

// registerPersonaRoutes 注册系统人设相关路由。
func (s *Server) registerPersonaRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/system-persona", s.getSystemPersona)
	mux.HandleFunc("PUT /api/system-persona", s.putSystemPersona)
	mux.HandleFunc("DELETE /api/system-persona", s.deleteSystemPersona)
	mux.HandleFunc("GET /api/system-persona/audits", s.getSystemPersonaAudits)
}

// getSystemPersona 返回当前人设、上限与最近审计（供 UI 一次拉全）。
func (s *Server) getSystemPersona(w http.ResponseWriter, r *http.Request) {
	text, on := s.m.pg.SystemPersona()
	audits, err := s.m.pg.PersonaAudits(20)
	if err != nil {
		// 审计读不出来不影响人设本身，回空数组即可（UI 上少一块历史而已）。
		audits = nil
	}
	writeJSON(w, 200, map[string]any{
		"text":       text,
		"configured": on,
		"max_chars":  db.MaxSystemPersonaChars,
		"audits":     audits,
	})
}

// putSystemPersona 保存人设（含门禁校验）。
func (s *Server) putSystemPersona(w http.ResponseWriter, r *http.Request) {
	var req db.PersonaSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if req.Actor == "" {
		req.Actor = "operator"
	}
	rec, err := s.m.pg.SaveSystemPersona(req)
	if err != nil {
		// 门禁拒绝是**预期行为**（未确认/无说明/超长），用 400 + 明确文案回给 UI，
		// 而不是 500 —— UI 要能把原因直接显示在表单上。
		writeErr(w, 400, err.Error())
		return
	}
	log.Printf("[persona] 系统人设已更新（%d 字，v%d）：%s", rec.Chars, rec.Version, rec.Note)
	writeJSON(w, 200, map[string]any{"ok": true, "audit": rec})
}

// deleteSystemPersona 清除人设（独立动作，需填原因）。
func (s *Server) deleteSystemPersona(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Note  string `json:"note"`
		Actor string `json:"actor"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	rec, err := s.m.pg.ClearSystemPersona(req.Note, req.Actor)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	log.Printf("[persona] 系统人设已清除：%s", rec.Note)
	writeJSON(w, 200, map[string]any{"ok": true, "audit": rec})
}

// getSystemPersonaAudits 只取审计历史。
func (s *Server) getSystemPersonaAudits(w http.ResponseWriter, r *http.Request) {
	audits, err := s.m.pg.PersonaAudits(50)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"audits": audits})
}
