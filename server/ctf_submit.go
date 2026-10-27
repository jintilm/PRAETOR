package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jintilm/praetor/agent"
	"github.com/jintilm/praetor/config"
	"github.com/jintilm/praetor/db"
)

// CTF 提交后端（P2-2）：去重 → 判题 → 首解收敛。
//
// 三层职责刻意分开：
//   - ctfJudge 只管"这个 flag 平台认不认"，便于替换成离线比对或 CTFd；
//   - ctfSubmitter 管"同一 flag 只打一次平台"（DB 主键仲裁）；
//   - 收敛回调只关心"判对了要收束全任务"，不关心怎么判的。

const (
	settingCTFJudgeMode = "ctf.judge_mode" // offline（默认）| ctfd
	envCTFJudgeMode     = "CTF_JUDGE"
	envCTFExpectedFlag  = "CTF_EXPECTED_FLAG"
	envCTFCTFdURL       = "CTF_CTFD_URL"
	envCTFCTFdToken     = "CTF_CTFD_TOKEN"
)

// ctfJudge 判定一个 flag 是否被认可。
type ctfJudge interface {
	Ask(ctx context.Context, challengeID, flag string) (accepted bool, raw string, err error)
	Name() string
}

// offlineJudge 用期望 flag 精确比对（基准跑分走这条路，不需要联网）。
//
// 精确比对而不是"包含/忽略大小写"：flag 是唯一串，宽松匹配会把错答案判对，
// 那正是我们在渗透域花了很大力气避免的"假阳性"。
type offlineJudge struct{ expected string }

func (j offlineJudge) Name() string { return "offline" }

func (j offlineJudge) Ask(_ context.Context, _, flag string) (bool, string, error) {
	exp := strings.TrimSpace(j.expected)
	if exp == "" {
		return false, "", fmt.Errorf("离线判分没有配置期望 flag")
	}
	// 回执里不回显完整 flag（避免把答案写进日志/上下文），只给长度与是否一致
	return strings.TrimSpace(flag) == exp, "", nil
}

// ctfdJudge 走 CTFd 的判题 API。
//
// endpoint: POST {base}/api/v1/challenges/attempt  body {"challenge_id","submission"}
// 返回 data.status == "correct" 视为判对。
type ctfdJudge struct {
	base  string
	token string
	hc    *http.Client
}

func (j ctfdJudge) Name() string { return "ctfd" }

func (j ctfdJudge) Ask(ctx context.Context, challengeID, flag string) (bool, string, error) {
	if challengeID == "" {
		return false, "", fmt.Errorf("CTFd 判题需要 challenge_id")
	}
	body, _ := json.Marshal(map[string]string{
		"challenge_id": challengeID,
		"submission":   flag,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.base+"/api/v1/challenges/attempt", bytes.NewReader(body))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Token "+j.token)
	resp, err := j.hc.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return false, snippetBytes(raw), fmt.Errorf("CTFd 返回 HTTP %d", resp.StatusCode)
	}
	var out struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return false, snippetBytes(raw), fmt.Errorf("CTFd 响应解析失败")
	}
	return strings.EqualFold(out.Data.Status, "correct"), snippetBytes(raw), nil
}

func snippetBytes(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// ctfSubmitter 把去重、判题、收敛串起来。
type ctfSubmitter struct {
	pg     *db.DB
	judge  ctfJudge
	taskID string
	// converge 在判对后调用（向本任务所有在跑意图注入停止指令）。
	converge func(cause string)
	// onAccept 把"这题解出了"写进逐题进度（P2-6 看板据此把它移出待做）。
	// 与 converge 分开：一个记事实，一个停执行，任一为 nil 都不影响判题与落库。
	onAccept func(challengeID string)
}

// SubmitFlag 实现 agent.CTFSubmitter。
func (c *ctfSubmitter) SubmitFlag(ctx context.Context, challengeID, flag string) (*agent.CTFSubmitResult, error) {
	flag = strings.TrimSpace(flag)
	sum := sha256.Sum256([]byte(flag))
	sha := hex.EncodeToString(sum[:])

	// ① 已提交过 → 直接返回上次结论，**不再打平台**
	if prior, err := c.pg.GetCTFSubmission(sha); err == nil && prior != nil {
		detail := "该 flag 之前已提交（verdict=" + prior.Verdict + "），本次未再次提交"
		return &agent.CTFSubmitResult{Verdict: "duplicate", Detail: detail, Raw: prior.Raw}, nil
	}

	// ② 问平台
	accepted, raw, err := c.judge.Ask(ctx, challengeID, flag)
	if err != nil {
		return nil, fmt.Errorf("%s 判题失败：%w", c.judge.Name(), err)
	}
	verdict := "rejected"
	if accepted {
		verdict = "accepted"
	}

	// ③ 落库（主键仲裁并发：抢输的那一方按 duplicate 处理）
	taskID, _ := strconv.ParseInt(c.taskID, 10, 64)
	inserted, err := c.pg.InsertCTFSubmission(&db.CTFSubmission{
		TaskID: taskID, FlagSHA: sha, ChallengeID: challengeID, Flag: flag, Verdict: verdict, Raw: raw,
	})
	if err != nil {
		return nil, fmt.Errorf("记录提交结果失败：%w", err)
	}
	if !inserted {
		return &agent.CTFSubmitResult{Verdict: "duplicate", Detail: "并发提交：已由另一条请求先记录"}, nil
	}

	// ④ 判对 → 记进逐题进度 + 收敛全任务（只在这里做，调度器不猜"解出没解出"）
	if accepted {
		if c.onAccept != nil {
			c.onAccept(challengeID)
		}
		if c.converge != nil {
			c.converge("flag 已通过平台判题：" + flag)
		}
	}
	return &agent.CTFSubmitResult{Verdict: verdict, Detail: "判题后端：" + c.judge.Name(), Raw: raw}, nil
}

// ctfSubmitterFor 按任务构造提交后端；不是 CTF 域或未配置判题则返回 nil
// （工具会明确报"不可用"，而不是静默成功）。
// liveSubmitter 每次提交时重新解析判题后端。
//
// 与 ctfBoardProvider.source() 同一个理由：worker 的依赖在 bundle 构建时注入一次，
// 而 bundle 是进程内单例。若在那一刻把 submitter 定成 nil（"当时还没配 expected_flag"），
// 之后再配也永远用不上——现象是模型解出了 flag 却说 ctf_submit 不可用。
type liveSubmitter struct {
	s      *Server
	taskID string
}

func (l liveSubmitter) SubmitFlag(ctx context.Context, challengeID, flag string) (*agent.CTFSubmitResult, error) {
	t, ok := l.s.m.Task(l.taskID)
	if !ok || t == nil {
		return nil, fmt.Errorf("任务 %s 不存在", l.taskID)
	}
	sub := l.s.ctfSubmitterFor(t)
	if sub == nil {
		return nil, fmt.Errorf(
			"本任务没有可用的判题后端（offline 模式需设 settings ctf.expected_flag.%s 或 PRAETOR_CTF_EXPECTED_FLAG）", l.taskID)
	}
	return sub.SubmitFlag(ctx, challengeID, flag)
}

// liveCTFSubmitter 给 worker 注入"永远存在"的提交句柄；非 ctf 域返回 nil。
func (s *Server) liveCTFSubmitter(t *Task) agent.CTFSubmitter {
	if s == nil || t == nil || t.Domain != "ctf" {
		return nil
	}
	return liveSubmitter{s: s, taskID: t.ID}
}

func (s *Server) ctfSubmitterFor(t *Task) agent.CTFSubmitter {
	if t == nil || t.Domain != "ctf" {
		return nil
	}
	judge, err := s.buildCTFJudge(t)
	if err != nil {
		// 只记一条日志：任务照常跑（模型会看到工具不可用），但运维要知道为什么。
		log.Printf("[ctf] task %s 未启用 ctf_submit：%v", t.ID, err)
		return nil
	}
	taskID := t.ID
	var converge func(string)
	if s.engine != nil {
		converge = func(cause string) { s.engine.ConvergeTask(taskID, cause) }
	}
	// s.engine 为 nil 只出现在测试/装配早期；判题与去重照常工作，只是不收敛（不 panic）。
	onAccept := func(challengeID string) { s.markCTFSolvedOnAccept(t.ID, challengeID) }
	return &ctfSubmitter{pg: s.m.pg, judge: judge, taskID: taskID, converge: converge, onAccept: onAccept}
}

// buildCTFJudge 解析判题模式与参数。优先级：settings（任务级） > 环境变量 > 默认 offline。
func (s *Server) buildCTFJudge(t *Task) (ctfJudge, error) {
	mode := strings.ToLower(strings.TrimSpace(settingOr(s.m.pg, settingCTFJudgeMode, "")))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(config.Env(envCTFJudgeMode)))
	}
	if mode == "" {
		mode = "offline"
	}
	switch mode {
	case "offline":
		exp := settingOr(s.m.pg, "ctf.expected_flag."+t.ID, "")
		if exp == "" {
			exp = config.Env(envCTFExpectedFlag)
		}
		if strings.TrimSpace(exp) == "" {
			return nil, fmt.Errorf("offline 模式缺少期望 flag（设 settings ctf.expected_flag.%s 或环境变量 PRAETOR_%s）", t.ID, envCTFExpectedFlag)
		}
		return offlineJudge{expected: exp}, nil
	case "ctfd":
		base := settingOr(s.m.pg, "ctf.ctfd_url", "")
		if base == "" {
			base = config.Env(envCTFCTFdURL)
		}
		token := settingOr(s.m.pg, "ctf.ctfd_token", "")
		if token == "" {
			token = config.Env(envCTFCTFdToken)
		}
		if base == "" || token == "" {
			return nil, fmt.Errorf("ctfd 模式缺少 URL/Token（设 settings ctf.ctfd_url / ctf.ctfd_token 或对应环境变量）")
		}
		return ctfdJudge{
			base:  strings.TrimRight(base, "/"),
			token: token,
			hc:    &http.Client{Timeout: 20 * time.Second},
		}, nil
	default:
		return nil, fmt.Errorf("未知判题模式 %q（offline|ctfd）", mode)
	}
}
