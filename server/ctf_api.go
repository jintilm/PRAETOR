package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jintilm/praetor/agent/domain"
)

// CTF 任务配置与判分查询（P2-4 基准跑分要用）。
//
// 为什么不能复用 PUT /api/settings：那是**白名单类型的设置项**（traffic_capture 等固定键），
// 而 CTF 的期望 flag / 题面目录是**逐任务**的动态键。硬塞进去要么破坏类型安全，
// 要么让设置面板出现一堆 `ctf.expected_flag.17` 这种条目。所以单开一个任务级接口。

type ctfTaskConfigReq struct {
	ExpectedFlag string `json:"expected_flag"`
	ChallengeDir string `json:"challenge_dir"`
}

func (s *Server) registerCTFRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/tasks/{id}/ctf", s.putTaskCTFConfig)
	mux.HandleFunc("GET /api/tasks/{id}/ctf", s.getTaskCTFConfig)
	mux.HandleFunc("GET /api/ctf/submissions", s.listCTFSubmissions)
}

// putTaskCTFConfig 写入任务的 CTF 判分/题面配置。
//
// 校验三件事（都为了"别让基准因为配置写错而得出假结果"）：
//  1. 任务必须存在且领域是 ctf —— 给渗透任务配 CTF 判分只会让人困惑；
//  2. expected_flag 形状像 flag（离线判分靠它，写错就是全错）；
//  3. challenge_dir 必须是存在的目录（否则工具会在运行时才发现不可用）。
func (s *Server) putTaskCTFConfig(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "任务不存在")
		return
	}
	if t.Domain != string(domain.CTF) {
		writeErr(w, 400, fmt.Sprintf("任务 %s 的领域是 %q，只有 ctf 任务可配置 CTF 判分", t.ID, t.Domain))
		return
	}
	var req ctfTaskConfigReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "请求体不是合法 JSON")
		return
	}
	flag := strings.TrimSpace(req.ExpectedFlag)
	if flag != "" {
		if !strings.Contains(flag, "{") || !strings.HasSuffix(flag, "}") {
			writeErr(w, 400, "expected_flag 形状不对（应形如 flag{...}）")
			return
		}
		if err := s.m.pg.SetSetting("ctf.expected_flag."+t.ID, flag); err != nil {
			writeErr(w, 500, "保存 expected_flag 失败："+err.Error())
			return
		}
	}
	dir := strings.TrimSpace(req.ChallengeDir)
	if dir != "" {
		if !dirExists(dir) {
			writeErr(w, 400, "challenge_dir 不存在或不是目录："+dir)
			return
		}
		if err := s.m.pg.SetSetting("ctf.challenge_dir."+t.ID, dir); err != nil {
			writeErr(w, 500, "保存 challenge_dir 失败："+err.Error())
			return
		}
	}
	writeJSON(w, 200, s.taskCTFConfig(t))
}

func (s *Server) getTaskCTFConfig(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "任务不存在")
		return
	}
	writeJSON(w, 200, s.taskCTFConfig(t))
}

// taskCTFConfig 返回当前生效的配置（含来源：settings / env / 无）。
func (s *Server) taskCTFConfig(t *Task) map[string]any {
	out := map[string]any{"task_id": t.ID, "domain": t.Domain}
	out["expected_flag"] = settingOr(s.m.pg, "ctf.expected_flag."+t.ID, "")
	out["challenge_dir"] = settingOr(s.m.pg, "ctf.challenge_dir."+t.ID, "")
	// 工具是否真的可用：这才是运维关心的（配了但来源不成立时工具仍不可用）
	out["submitter_ready"] = s.ctfSubmitterFor(t) != nil
	out["challenge_ready"] = s.ctfChallengeSourceFor(t) != nil
	return out
}

// listCTFSubmissions 返回某任务的提交记录 + 是否已解出（基准判分口径）。
func (s *Server) listCTFSubmissions(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimSpace(r.URL.Query().Get("task_id"))
	taskID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || taskID <= 0 {
		writeErr(w, 400, "task_id 必填且必须是正整数")
		return
	}
	subs, err := s.m.pg.ListCTFSubmissions(taskID, 100)
	if err != nil {
		writeErr(w, 500, "读取提交记录失败："+err.Error())
		return
	}
	// solved 只用 AcceptedFlagForTask 这一个判定（不在这里再扫一遍列表）：
	// 跑分口径只能有一处定义，否则改了这边忘了那边就会算出两个分数。
	_, solved, err := s.m.pg.AcceptedFlagForTask(taskID)
	if err != nil {
		writeErr(w, 500, "判定是否解出失败："+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"task_id":     taskID,
		"solved":      solved,
		"submissions": subs,
	})
}
