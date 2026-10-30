package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jintilm/praetor/agent/domain"
	"github.com/jintilm/praetor/db"
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
	mux.HandleFunc("GET /api/tasks/{id}/ctf/board", s.getTaskCTFBoard)
	mux.HandleFunc("GET /api/ctf/submissions", s.listCTFSubmissions)
	mux.HandleFunc("POST /api/tasks/{id}/ctf/confirm", s.confirmTaskCTFFlag)
}

// getTaskCTFBoard 返回「先做哪题、什么时候放弃」的当前结论（P2-6）。
//
// 与工具 ctf_board 同一份计算：面板上看到的顺序就是模型看到的顺序，
// 否则"人以为它在做 A、其实它在磨 B"这种偏差根本没法解释。
func (s *Server) getTaskCTFBoard(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "任务不存在")
		return
	}
	if t.Domain != string(domain.CTF) {
		writeErr(w, 400, fmt.Sprintf("任务 %s 的领域是 %q，只有 ctf 任务有题目看板", t.ID, t.Domain))
		return
	}
	kit, ok := s.ctfKitFor(t)
	if !ok {
		writeErr(w, 400, "本任务没有配置题面来源（离线需设 ctf.challenge_dir 或 PRAETOR_CTF_CHALLENGE_DIR；在线需配 CTFd）")
		return
	}
	board, err := kit.Board(r.Context())
	if err != nil {
		writeErr(w, 500, "计算看板失败："+err.Error())
		return
	}
	writeJSON(w, 200, board)
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

// confirmTaskCTFFlag 人工确认一个 flag —— 真实比赛的判题通道。
//
// 为什么需要：多数比赛只让选手在网页上提交，**不开放 CTFd API token**。没有这条通道时：
//   - ctf_submit 建不起来 → 永远没有 accepted 记录；
//   - 按 prove_goal 的确定性验收（docs/batch-198-199 §缺陷二），没有 accepted 就不许标 met；
//   - 任务只能跑到 timeout，即使人已经眼看着它解出来了。
//
// 人工确认写一条 verdict=accepted 的记录，raw_response 里注明来源。这样 done 仍然可信：
// **有人签字**，不是模型自述。
//
// 幂等：同一任务同一 flag 重复确认只留一行（InsertCTFSubmission 的主键裁决），
// 重复调用返回 inserted=false 而不是报错。
func (s *Server) confirmTaskCTFFlag(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "任务不存在")
		return
	}
	if t.Domain != string(domain.CTF) {
		writeErr(w, 400, fmt.Sprintf("任务 %s 的领域是 %q，只有 ctf 任务需要 flag 判题", t.ID, t.Domain))
		return
	}
	var req struct {
		Flag        string `json:"flag"`
		ChallengeID string `json:"challenge_id"`
		Note        string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	flag := strings.TrimSpace(req.Flag)
	if flag == "" {
		writeErr(w, 400, "flag 必填")
		return
	}
	// 上限只为挡住"整段输出粘进来"这种误操作，不做格式校验：不同比赛的 flag 形状差别很大
	// （flag{...} / CTF{...} / 纯 hex），在入口硬套一个正则会把合法 flag 挡在外面。
	if len(flag) > 4096 {
		writeErr(w, 400, "flag 过长（>4096 字节），确认粘错了内容")
		return
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil || taskID <= 0 {
		writeErr(w, 500, "任务 id 非法")
		return
	}
	sha := sha256.Sum256([]byte(flag))
	note := strings.TrimSpace(req.Note)
	raw := "manual confirm via API"
	if note != "" {
		raw += ": " + note
	}
	inserted, err := s.m.pg.InsertCTFSubmission(&db.CTFSubmission{
		FlagSHA:     hex.EncodeToString(sha[:]),
		TaskID:      taskID,
		ChallengeID: strings.TrimSpace(req.ChallengeID),
		Flag:        flag,
		Verdict:     db.CTFVerdictAccepted,
		Raw:         raw,
	})
	if err != nil {
		writeErr(w, 500, "写入判题记录失败："+err.Error())
		return
	}
	// 叫醒 planner：它下一轮就能看到 accepted，prove_goal 会通过并正常收官。
	// 不叫醒的话，确认之后要等到下一次心跳（默认 5 分钟）才生效。
	if t != nil {
		t.Notify()
	}
	writeJSON(w, 200, map[string]any{
		"ok": true, "task_id": t.ID, "inserted": inserted, "verdict": db.CTFVerdictAccepted,
	})
}
