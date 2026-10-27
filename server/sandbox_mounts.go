package server

import (
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
