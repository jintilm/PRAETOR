package server

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/jintilm/praetor/config"
	"github.com/jintilm/praetor/sandbox"
)

// 本文件回答一个问题：**CTF 题面的附件，模型在沙箱里怎么拿到**。
//
// 病根：离线题面来源返回的 Dir / Files[].Path 是**宿主绝对路径**
// （E:\Code\pentest\corpus\ctf\xxx\files\release\x.zip）。一任务一容器只挂了
// <data>/work/<taskID> -> /work，所以这些路径在容器里根本不存在。
//
// 后果不是"读不到文件"这么轻。实测现象是：模型拿到一串宿主路径，Bash 里 ls 全部
// ENOENT，于是判断"题目附件缺失"，转而自己编一道题、写一堆和本题无关的笔记，
// 烧掉几十万 token 最后交不出 flag —— 而日志里看不到任何报错。
//
// 解法：把题面目录**只读**挂进容器 /chal，并让工具返回的所有路径都指向容器内位置。
// 两件事必须同时做：只挂载不映射，模型仍然会去 ls 宿主路径；只映射不挂载，
// /chal 是空的。所以两者共用同一个常量与同一个开关（见 SandboxPerTaskActive）。

// challengeMountTarget 是题面目录在容器内的挂载点。
const challengeMountTarget = "/chal"

// taskChallengeDir 返回该任务离线题面的宿主目录；没有则空串。
//
// 与 ctfChallengeSourceFor 共用同一套取值顺序（任务设置 → 环境变量），
// 但这里不做"目录存不存在"之外的判断——路径映射只需要知道根在哪。
func (s *Server) taskChallengeDir(t *Task) string {
	if s == nil || s.m == nil || t == nil || t.Domain != "ctf" {
		return ""
	}
	dir := settingOr(s.m.pg, "ctf.challenge_dir."+t.ID, "")
	if dir == "" {
		dir = config.Env(envCTFChallengeDir)
	}
	if dir == "" || !dirExists(dir) {
		return ""
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// taskMountsFor 是注入 sandbox.PerTaskRunner 的挂载解析器。
//
// 只挂离线题面目录：CTFd 来源下载到 <data>/chal/<taskID>，那条路走的是
// ctfdChallengeSource.workDir，同样需要挂载，但它按 challengeID 分目录，
// 根目录在任务创建后才确定，留待接入 CTFd 时再补——现在返回 nil 比挂错更安全。
func (s *Server) taskMountsFor(taskID string) []sandbox.Mount {
	if s == nil || s.m == nil {
		return nil
	}
	t, ok := s.m.Task(taskID)
	if !ok || t == nil {
		return nil
	}
	return s.mountsForTask(t)
}

// mountsForTask 与 taskMountsFor 同义，但直接吃已拿到的 *Task。
//
// 存在理由：路径映射器手上已经有 *Task，再按 id 回查一次库既慢又多一个"查不到就返回
// 空挂载"的失败点（测试里构造的 Task 不在库里，就会永远映射不到 /chal）。
func (s *Server) mountsForTask(t *Task) []sandbox.Mount {
	if s == nil || s.m == nil || t == nil {
		return nil
	}
	dir := s.taskChallengeDir(t)
	if dir == "" {
		return nil
	}
	// 挂载**脱敏视图**而不是源目录：题目录里通常有 flag.txt（标准答案），
	// 整体挂进去等于把答案发给模型（见 ctf_hidden.go）。
	src := s.challengeMountSource(t, dir)
	if src == "" {
		return nil
	}
	return []sandbox.Mount{{Source: src, Target: challengeMountTarget, ReadOnly: true}}
}

// guestChallengePath 把题面重排到容器内路径：宿主 <root>/a/b -> /chal/a/b。
//
// root 之外（理论上不会发生）原样返回：宁可给一个宿主路径让模型 ls 失败，
// 也不要凭空造一个 /chal/.. 出来——后者会静默指向错误文件。
func guestChallengePath(root, hostPath string) string {
	if root == "" || hostPath == "" {
		return hostPath
	}
	rel, err := filepath.Rel(root, hostPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return hostPath
	}
	if rel == "." {
		return challengeMountTarget
	}
	return path.Join(challengeMountTarget, filepath.ToSlash(rel))
}

// sandboxPathMapper 返回「容器内路径 → 宿主路径」的翻译器，供文件类工具使用。
//
// 为什么需要它：Bash 走容器，但 LS/Read/Glob/Grep/Write 在宿主进程里用 os 打开文件。
// 模型照着提示词说 `/chal/files/challenge`，宿主上并没有这条路径 —— Windows 上还会因为
// filepath.IsAbs("/chal/x") == false 把它当相对路径拼到工作目录下，错误信息里冒出
// `E:/.../data/tasks/29/i156/chal/...`，一眼看不出是"工具没进沙箱"。
//
// 翻译的是**挂载点**，不是"猜"：`/work` 来自 PerTaskConfig，`/chal` 来自 mountsFor，
// 两者都是真挂进容器的目录，所以翻出来的宿主路径看到的就是模型看到的那份内容。
// 未命中挂载点时返回 false，让工具按原逻辑处理（不臆造路径）。
func (s *Server) sandboxPathMapper(t *Task) func(string) (string, bool) {
	if s == nil || t == nil || t.ID == "" {
		return nil
	}
	// 与 NewPerTask 保持同一套解析：相对路径要展开，否则映射出来的宿主路径也是相对的。
	root := envOr("SANDBOX_WORK_ROOT", filepath.Join(s.m.DataDir(), "work"))
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	workHost := filepath.Join(root, t.ID)

	return func(p string) (string, bool) {
		p = filepath.ToSlash(strings.TrimSpace(p))
		if p == "" {
			return "", false
		}
		if host, ok := translateMount(p, SandboxContainerRoot, workHost); ok {
			return host, true
		}
		// 每次调用重新取，不能在构造时快照。
		//
		// 题面目录是**任务建好之后**才配的（POST /tasks/{id}/ctf），而 worker 在任务创建时
		// 就构造好了 —— 快照会让 /chal 的映射永远缺失，症状正是 LS /chal 报
		// "open /chal: cannot find the file"，看着像挂载没生效。
		// 这与题面来源改用惰性解析是同一个坑，同一个顺序：先建任务、后配题。
		for _, m := range s.mountsForTask(t) {
			if host, ok := translateMount(p, m.Target, m.Source); ok {
				return host, true
			}
		}
		return "", false
	}
}

// sandboxWriteDeny 返回「沙箱模式下这个路径能不能写」的判断器：
// 空串 = 可写，非空 = 拒绝理由（直接进 tool_result）。
//
// 为什么不是"只挡只读挂载"：`/tmp/x`、`/etc/x` 这类**没有挂载**的容器路径
// resolvePath 会原样返回，于是 Write 会落到宿主的 /tmp（Linux）或盘根的 E:\tmp
// （Windows）—— 那是绕开沙箱在宿主上写文件，比只读那个口子更严重。
// 所以规则反过来写：**只有映射过的可写挂载（/work）才允许写**，其余一律拒绝。
//
// 判据与 sandboxPathMapper 同源（同一份 mountsForTask），不另写一套路径规则 ——
// 两套规则对不上时，错法都是"只有真跑才发现"。
func (s *Server) sandboxWriteDeny(t *Task) func(string) string {
	if s == nil || t == nil || t.ID == "" {
		return nil
	}
	return func(p string) string {
		p = filepath.ToSlash(strings.TrimSpace(p))
		if p == "" {
			return ""
		}
		// 工作目录永远可写：它是模型的草稿纸。
		if hitsMount(p, SandboxContainerRoot) {
			return ""
		}
		// 每次重取，理由同 sandboxPathMapper：题面目录是任务建好之后才配的。
		for _, m := range s.mountsForTask(t) {
			if hitsMount(p, m.Target) || hitsMountFold(p, m.Source) {
				if m.ReadOnly {
					return fmt.Sprintf("%s 是只读挂载（题面附件），不能修改；把产物写到 %s/ 下",
						p, SandboxContainerRoot)
				}
				return ""
			}
		}
		if strings.HasPrefix(p, "/") {
			return fmt.Sprintf("沙箱里没有 %s 这条路径的挂载，写不到（宿主的 /tmp、/etc 不属于本任务）；"+
				"把产物写到 %s/ 下", p, SandboxContainerRoot)
		}
		return ""
	}
}

// hitsMountFold 与 hitsMount 同义，但大小写不敏感（Windows 语义）。
// 用于比对宿主路径：E:/Corpus 与 e:/corpus 是同一处。
func hitsMountFold(p, root string) bool {
	return hitsMount(strings.ToLower(filepath.ToSlash(p)), strings.ToLower(filepath.ToSlash(root)))
}

// hitsMount 判断 p 是否落在 container 之下（按路径段，不是字符串前缀）。
func hitsMount(p, container string) bool {
	container = strings.TrimSuffix(filepath.ToSlash(container), "/")
	if container == "" {
		return false
	}
	return p == container || strings.HasPrefix(p, container+"/")
}

// translateMount 把 container 前缀换成 host 前缀；不在 container 之下返回 false。
//
// `..` 必须挡住：模型传 `/work/../../../etc/passwd` 时 filepath.Join 会老老实实逃逸出去，
// 于是"沙箱内的路径"能读到宿主的任意文件 —— 这比不给映射更糟。
func translateMount(p, container, host string) (string, bool) {
	if !hitsMount(p, container) {
		return "", false
	}
	container = strings.TrimSuffix(filepath.ToSlash(container), "/")
	rest := strings.TrimPrefix(strings.TrimPrefix(p, container), "/")
	joined := host
	if rest != "" {
		joined = filepath.Join(host, filepath.FromSlash(rest))
	}
	rel, err := filepath.Rel(host, joined)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return joined, true
}
