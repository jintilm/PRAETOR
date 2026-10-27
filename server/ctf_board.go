package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jintilm/praetor/agent"
	"github.com/jintilm/praetor/agent/domain"
	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/internal/ctfplan"
)

// CTF 题目看板与放弃记录（P2-6）。
//
// 分工：
//   - `internal/ctfplan` 只有规则（排序、切片、放弃），纯函数；
//   - 这里负责**取数**（题目清单、逐题进度、任务用量）与**落库**；
//   - 工具层只负责把结论渲染给模型。
//
// 为什么"取数"必须在 server：题目来源、DB、任务预算三样东西只有这层同时握得住。

// ctfBoardProvider 同时实现 agent.CTFBoardProvider 与题面来源的包装（记录激活）。
//
// 注意它**不缓存**题面来源（早期版本缓存了 src，是个真 bug，见 source() 的注释）。
type ctfBoardProvider struct {
	s      *Server
	t      *Task
	taskID int64
}

// source 每次都重新解析题面来源，不缓存。
//
// 为什么：agentsForTask 造出来的 worker bundle 是**进程内单例、只建不换**
// （server/task_llm.go 的 taskAgents），而任务级题面配置（ctf.challenge_dir）是
// **运行时可改**的。若在 bundle 构建那一刻把 source 定下来，就会分裂成：
// 面板上 challenge_ready=true，模型调 ctf_challenge 却得到"本任务没有配置题面来源"。
// 实测后果不是报错就完了——模型转而去 ls 宿主路径（容器里必然 ENOENT），
// 然后判定"附件缺失"并开始自己编题，烧掉几十万 token。
//
// 副作用是每次 Fetch 多一次 settings 查询（单行 KV，可忽略），换来"配置改完立即生效"。
func (p *ctfBoardProvider) source() agent.CTFChallengeSource {
	if p == nil || p.s == nil || p.t == nil {
		return nil
	}
	return p.s.ctfChallengeSourceFor(p.t)
}

// ctfKitFor 构造 CTF 任务的工具依赖；不是 ctf 域或**当前**没有题面来源时返回 nil。
//
// 适合"要立刻回答能不能用"的场景（API 的 challenge_ready、看板请求）。
// 要让 worker 长期持有请用 ctfLiveKit——那个不依赖此刻是否已配置。
func (s *Server) ctfKitFor(t *Task) (*ctfBoardProvider, bool) {
	p := s.ctfLiveKit(t)
	if p == nil || p.source() == nil {
		return nil, false
	}
	return p, true
}

// ctfLiveKit 给 worker 注入一个**永远存在**的题面句柄：是不是 ctf 域由这里定，
// "有没有配题面来源"推迟到每次调用时判断。
//
// 这个区分是必要的：任务常常是"先建、跑起来、再配题目"（UI 上就是这个顺序），
// 若注入时要求已配置，后配的配置对已经在跑的 worker 永远不生效。
func (s *Server) ctfLiveKit(t *Task) *ctfBoardProvider {
	if s == nil || t == nil || t.Domain != string(domain.CTF) {
		return nil
	}
	id, _ := strconv.ParseInt(t.ID, 10, 64)
	return &ctfBoardProvider{s: s, t: t, taskID: id}
}

// ---- 题面来源的 List 实现 ----

// List 扫描离线题面根目录。
//
// 两种形态都支持：
//   - 根目录下每个子目录一道题（题库/基准常见）；
//   - 根目录本身就是一道题（单题任务）。
//
// 判定顺序是"先认根、再认子目录"，顺序错了会出真问题：单题目录里通常有个
// `files/` 附件容器目录，若先扫子目录，`files` 会被当成一道题，看板于是推荐
// id=files —— 模型照着 ctf_challenge(id="files") 拿到的是一堆附件，题面一个字都没有。
//
// 可选 `meta.json` 提供分值/解出人数/预估成本（题库作者填，缺省也能跑）。
func (s offlineChallengeSource) List(_ context.Context) ([]agent.CTFChallengeMeta, error) {
	if !dirExists(s.root) {
		return nil, fmt.Errorf("题面目录不存在：%s", s.root)
	}
	// 根目录自身带题目标识（name.txt / meta.json 等） = 这就是一道题。
	// 用强标识判定：题库根也常放 README 说明，不能据此把整库当单题。
	if rootHasChallengeMeta(s.root) {
		if meta, ok := offlineMeta(s.root, filepath.Base(s.root)); ok {
			return []agent.CTFChallengeMeta{meta}, nil
		}
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	var out []agent.CTFChallengeMeta
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		full := filepath.Join(s.root, e.Name())
		// 只认带题目标识的子目录：<chal>/files 这种附件容器不是题。
		if !hasChallengeMeta(full) {
			continue
		}
		if meta, ok := offlineMeta(full, e.Name()); ok {
			out = append(out, meta)
		}
	}
	if len(out) == 0 {
		// 兜底：一个裸目录（只有附件、没有任何标识）——按"单题"处理，
		// 这样手工放一个 zip 进去也能跑，不必先编 name.txt。
		if meta, ok := offlineMeta(s.root, filepath.Base(s.root)); ok {
			out = append(out, meta)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// challengeMetaFiles 是"这个目录是一道题"的标识文件（任一存在即可认定）。
//
// 与 offlineMetaFiles 的区别：那个是"列附件时该跳过哪些文件"，这个是
// "怎么判断一个目录是题目而不是附件容器"，用途不同不能合并。
var challengeMetaFiles = []string{
	chalNameFile, chalDescFiles, "description.md", "description.txt", "meta.json",
}

func hasChallengeMeta(dir string) bool {
	for _, f := range challengeMetaFiles {
		if readSmallFile(filepath.Join(dir, f)) != "" {
			return true
		}
	}
	return false
}

// rootChallengeMetaFiles 是"根目录**自身**就是一道题"的强标识，特意不含 README.md。
//
// 为什么这里要更严：题库根目录写一份 README 说明是常见做法（本项目的 corpus
// 就有一份）。若把 README 也算上，整个题库会被缩成"一道名叫目录名的题"，
// 看板只显示 1 题，其余题目连列都列不出来 —— 实测就是这么暴露的。
//
// 反过来，子目录判定可以宽松（含 README）：`pwn-2/{README.md,chall}` 是标准题形。
var rootChallengeMetaFiles = []string{
	chalNameFile, chalConnFile, "description.md", "description.txt", "meta.json",
}

func rootHasChallengeMeta(dir string) bool {
	for _, f := range rootChallengeMetaFiles {
		if readSmallFile(filepath.Join(dir, f)) != "" {
			return true
		}
	}
	return false
}

// offlineMeta 读一道题的元信息；目录里什么都没有就返回 false（不是题）。
func offlineMeta(dir, id string) (agent.CTFChallengeMeta, bool) {
	m := agent.CTFChallengeMeta{ID: id, Name: id, Solves: -1}
	if v := readSmallFile(filepath.Join(dir, chalNameFile)); v != "" {
		m.Name = v
	}
	hasContent := m.Name != id
	if b := readSmallFile(filepath.Join(dir, "meta.json")); b != "" {
		var raw struct {
			Name      string `json:"name"`
			Category  string `json:"category"`
			Points    int    `json:"points"`
			Solves    int    `json:"solves"`
			EstTokens int64  `json:"est_tokens"`
		}
		if err := json.Unmarshal([]byte(b), &raw); err == nil {
			if raw.Name != "" {
				m.Name = raw.Name
			}
			m.Category = raw.Category
			m.Points = raw.Points
			if raw.Solves > 0 {
				m.Solves = raw.Solves
			}
			m.EstTokens = raw.EstTokens
			hasContent = true
		}
	}
	if !hasContent {
		// 判定与 List 同源（hasChallengeMeta）：有题目标识（README/description…）
		// 或者有附件，都算一道题。
		//
		// 不能只看"除元信息外还有没有附件"：纯文本题（只有 README.md 的问答/情报题）
		// 会被判死，而它明明是一道题。两处判据不一致时，List 列出了题、
		// offlineMeta 却说不是题，看板就会出现"列了但点不进去"的鬼现象。
		if !hasChallengeMeta(dir) {
			if files, err := listChallengeFiles(dir, offlineMetaFiles()); err != nil || len(files) == 0 {
				return m, false
			}
		}
	}
	return m, true
}

// offlineMetaFiles 是"列附件时该跳过哪些文件"。
//
// 答案文件也在里面：附件列表会原样进模型的上下文，列出 `flag.txt` 等于告诉它
// "答案就在这个路径"。挂载侧另有一道闸门（ctf_hidden.go），两道都要有。
func offlineMetaFiles() map[string]bool {
	skip := map[string]bool{
		chalNameFile: true, chalDescFiles: true, chalConnFile: true,
		"description.md": true, "description.txt": true, "meta.json": true,
	}
	for name := range ctfAnswerFiles {
		skip[name] = true
	}
	return skip
}

// List 走 CTFd 的题目列表接口：GET /api/v1/challenges。
//
// value/solves 正好是决策要的两个信号（分值、难度），所以在线模式不用额外配置。
func (s ctfdChallengeSource) List(ctx context.Context) ([]agent.CTFChallengeMeta, error) {
	body, err := s.get(ctx, "/api/v1/challenges")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []struct {
			ID       json.RawMessage `json:"id"`
			Name     string          `json:"name"`
			Category string          `json:"category"`
			Value    int             `json:"value"`
			Solves   int             `json:"solves"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("CTFd 题目列表解析失败：%w", err)
	}
	out := make([]agent.CTFChallengeMeta, 0, len(resp.Data))
	for _, d := range resp.Data {
		id := strings.Trim(strings.TrimSpace(string(d.ID)), `"`)
		if id == "" {
			continue
		}
		solves := d.Solves
		if solves <= 0 {
			solves = -1 // 平台没给就是未知，别假装是 0（0 会被当成"极难"）
		}
		out = append(out, agent.CTFChallengeMeta{
			ID: id, Name: d.Name, Category: d.Category, Points: d.Value, Solves: solves,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ---- agent.CTFChallengeSource：Fetch 时记录激活 ----

func (p *ctfBoardProvider) Fetch(ctx context.Context, challengeID string) (*agent.CTFChallenge, error) {
	src := p.source()
	if src == nil {
		return nil, fmt.Errorf("本任务没有配置题面来源（离线需设 settings ctf.challenge_dir.%d 或 PRAETOR_CTF_CHALLENGE_DIR；在线需配 CTFd）", p.taskID)
	}
	ch, err := src.Fetch(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	// 激活记录失败不该让拉题面失败（题面才是模型当下要的东西），只记日志。
	if ch != nil && ch.ID != "" {
		if err := p.activate(ch.ID); err != nil {
			log.Printf("[ctf] task %d 记录题目激活失败: %v", p.taskID, err)
		}
	}
	return ch, nil
}

func (p *ctfBoardProvider) List(ctx context.Context) ([]agent.CTFChallengeMeta, error) {
	src := p.source()
	if src == nil {
		return nil, agent.ErrListUnsupported
	}
	return src.List(ctx)
}

// ---- agent.CTFBoardProvider ----

// Board 计算并返回当前看板。
func (p *ctfBoardProvider) Board(ctx context.Context) (*agent.CTFBoard, error) {
	plan, err := p.buildPlan(ctx)
	if err != nil {
		return nil, err
	}
	return plan, nil
}

// GiveUp 记录放弃并返回刷新后的看板。
//
// 记录里同时冻结"这题花了多少"：只写一句"放弃了"没法复盘，
// 而"花了 1.2M 还是没做出来"才是下一次排期真正需要的信号。
func (p *ctfBoardProvider) GiveUp(ctx context.Context, challengeID, reason string) (*agent.CTFBoard, error) {
	challengeID = strings.TrimSpace(challengeID)
	if challengeID == "" {
		return nil, fmt.Errorf("题目 id 不能为空")
	}
	metas, err := p.List(ctx)
	if err != nil {
		return nil, err
	}
	known := false
	for _, m := range metas {
		if m.ID == challengeID {
			known = true
			break
		}
	}
	if !known {
		return nil, fmt.Errorf("题目 %s 不在当前题库里（先调 ctf_board 看可用 id）", challengeID)
	}
	spent, err := p.spentFor(challengeID)
	if err != nil {
		return nil, err
	}
	if err := p.s.m.pg.MarkCTFProgress(p.taskID, challengeID, db.CTFProgressAbandoned, reason, spent); err != nil {
		return nil, fmt.Errorf("写入放弃记录失败：%w", err)
	}
	log.Printf("[ctf] task %d 放弃题目 %s（已花 %d tokens）：%s", p.taskID, challengeID, spent, reason)
	return p.Board(ctx)
}

// tokenTotal 读任务累计 token；读不到按 0 处理并记一条日志。
//
// 为什么要容忍：账本表（llm_usage）是首次调用 LLM 时才创建的，全新库/测试库里
// 可能还不存在。看板不该因为"还没花过钱"而报 500——那时正确的语义就是 0。
func (p *ctfBoardProvider) tokenTotal() int64 {
	n, err := p.s.m.pg.TaskTokenTotal(p.t.ID)
	if err != nil {
		log.Printf("[ctf] task %s 读取 token 用量失败（本次按 0 处理）：%v", p.t.ID, err)
		return 0
	}
	return n
}

// activate 把题目标为 active，基线=当前任务累计用量。
func (p *ctfBoardProvider) activate(challengeID string) error {
	return p.s.m.pg.ActivateCTFChallenge(p.taskID, challengeID, p.tokenTotal())
}

// spentFor 返回某题在本任务内的花费。
//
// active 的题 = 任务累计 - 激活时的基线；已结束的题用冻结值。
// 这是近似而不是精确账（账本只有任务级），但"某题花了 1M 还是 100K"这个量级足够决策。
func (p *ctfBoardProvider) spentFor(challengeID string) (int64, error) {
	pr, err := p.s.m.pg.GetCTFProgress(p.taskID, challengeID)
	if err != nil || pr == nil {
		return 0, err
	}
	if pr.State != db.CTFProgressActive || pr.BaseTokens <= 0 {
		// 非 active，或激活时没能取到基线（那时总用量未知）→ 用冻结值。
		// 基线为 0 时绝不能按"总量 - 0"算，否则会把整场花费都算到这一题头上。
		return pr.SpentTokens, nil
	}
	if spent := p.tokenTotal() - pr.BaseTokens; spent > 0 {
		return spent, nil
	}
	return 0, nil
}

// buildPlan 组装决策输入并调用 ctfplan。
func (p *ctfBoardProvider) buildPlan(ctx context.Context) (*agent.CTFBoard, error) {
	metas, err := p.List(ctx)
	if err != nil {
		return nil, err
	}
	if len(metas) == 0 {
		return nil, fmt.Errorf("题库里没有题目（离线目录为空或 CTFd 未返回数据）")
	}
	prog, err := p.s.m.pg.ListCTFProgress(p.taskID)
	if err != nil {
		return nil, fmt.Errorf("读取逐题进度失败：%w", err)
	}
	byID := make(map[string]db.CTFProgress, len(prog))
	for _, x := range prog {
		byID[x.ChallengeID] = x
	}
	// 分值/难度也要带进看板条目：模型是靠这两个数判断"值不值得做"的，
	// 只给预估成本等于让它自己在黑箱里排序。
	metaByID := make(map[string]agent.CTFChallengeMeta, len(metas))
	for _, m := range metas {
		metaByID[m.ID] = m
	}
	total := p.tokenTotal()

	chs := make([]ctfplan.Challenge, 0, len(metas))
	for _, m := range metas {
		c := ctfplan.Challenge{
			ID: m.ID, Name: m.Name, Category: m.Category,
			Points: m.Points, Solves: m.Solves, EstTokens: m.EstTokens,
			State: ctfplan.StateNew,
		}
		if pr, ok := byID[m.ID]; ok {
			c.State = ctfplan.State(pr.State)
			if pr.State == db.CTFProgressActive && pr.BaseTokens > 0 {
				if spent := total - pr.BaseTokens; spent > 0 {
					c.SpentTokens = spent
				}
			} else {
				c.SpentTokens = pr.SpentTokens
			}
		}
		chs = append(chs, c)
	}

	b := p.budget(total)
	plan := ctfplan.Build(chs, b)

	out := &agent.CTFBoard{
		Strategy:  plan.Strategy,
		Recommend: plan.Recommend,
		Note:      plan.Note,
		Slice:     plan.Slice,
		Exhausted: plan.Exhausted,
		Solved:    plan.Solved,
	}
	if !b.Unlimited {
		out.TokenLeft = b.TokenLeft
	}
	for _, v := range plan.Todo {
		out.Todo = append(out.Todo, boardEntry(v, byID, metaByID))
	}
	for _, v := range plan.GiveUp {
		out.GiveUp = append(out.GiveUp, boardEntry(v, byID, metaByID))
	}
	return out, nil
}

func boardEntry(v ctfplan.Verdict, prog map[string]db.CTFProgress,
	meta map[string]agent.CTFChallengeMeta) agent.CTFBoardEntry {
	e := agent.CTFBoardEntry{
		ID: v.ID, Name: v.Name, Action: string(v.Action),
		EstTokens: v.Est, SpentTokens: v.Spent, Score: v.Score, Reason: v.Reason,
	}
	if m, ok := meta[v.ID]; ok {
		e.Category = m.Category
		e.Points = m.Points
		e.Solves = m.Solves
		if e.Name == "" {
			e.Name = m.Name
		}
	}
	if pr, ok := prog[v.ID]; ok {
		e.State = pr.State
		if pr.Reason != "" && pr.State == db.CTFProgressAbandoned {
			e.Reason = pr.Reason // 已放弃的题用当时写下的原因，比"之前已放弃"信息量大
		}
	} else {
		e.State = db.CTFProgressNew
	}
	return e
}

// budget 把任务预算翻译成决策口径的"剩余"。
//
// token 上限取领域声明的 MaxTokens（与预算闸门同源：闸门在哪里砍，规划就该在哪里停），
// 时间上限取任务 deadline。两者都没有 → 不设限（本地刷题不该被误杀）。
func (p *ctfBoardProvider) budget(used int64) ctfplan.Budget {
	b := ctfplan.Budget{Unlimited: true}
	if pack, ok := domain.Get(domain.CTF); ok {
		if lim := int64(pack.Budget().MaxTokens); lim > 0 {
			left := lim - used
			if left < 0 {
				left = 0
			}
			b = ctfplan.Budget{TokenLeft: left}
			if p.t.DeadlineAt > 0 {
				b.TimeLeft = time.Until(time.Unix(p.t.DeadlineAt, 0))
			}
			return b
		}
	}
	if p.t.DeadlineAt > 0 {
		b = ctfplan.Budget{TimeLeft: time.Until(time.Unix(p.t.DeadlineAt, 0))}
	}
	return b
}

// markCTFSolvedOnAccept 在判对时把该题标为 solved（看板据此把它移出待做）。
//
// 放在提交侧而不是工具侧：只有"平台判对"这一个事实算数（与跑分口径同源）。
func (s *Server) markCTFSolvedOnAccept(taskID string, challengeID string) {
	if challengeID == "" {
		return
	}
	id, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || id <= 0 {
		return
	}
	spent := int64(0)
	if total, terr := s.m.pg.TaskTokenTotal(taskID); terr == nil {
		if pr, perr := s.m.pg.GetCTFProgress(id, challengeID); perr == nil && pr != nil {
			if d := total - pr.BaseTokens; d > 0 {
				spent = d
			}
		}
	}
	if err := s.m.pg.MarkCTFChallengeSolved(id, challengeID, spent); err != nil {
		log.Printf("[ctf] task %s 标记题目 %s 解出失败: %v", taskID, challengeID, err)
	}
}
