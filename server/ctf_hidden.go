package server

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// 本文件回答一个问题：**怎么保证答案不跟着附件一起发给模型**。
//
// 病根：离线题面目录按"一题一目录"组织，同一层里往往既放附件、又放 flag.txt
// （导入器为每道题都写了一份）。把这个目录整体挂进容器 = 把标准答案发给模型：
// 一句 `cat /chal/flag.txt` 就结束了，模型根本不用解题。
// 实测就是这么暴露的 —— ctf_challenge 的 files 列表里直接出现了 /chal/flag.txt。
//
// 两道闸门，缺一不可：
//  1. 附件列表不列答案文件（listChallengeFiles）；
//  2. 挂载进容器前把答案文件从"视图目录"里剔掉（challengeMountSource）。
//
// 只挡列表会出现"列表说没有、容器里却有"的隐患，反过来会出现
// "列表里有 /chal/flag.txt、实际 ls 不到"的分裂 —— 两者都会让模型反复试探。

// ctfAnswerFiles 是要对模型隐藏的答案文件名（按 basename 匹配，大小写敏感）。
//
// 只列明确是"答案"的名字：`flag.txt` 是导入器的固定产物，其余是常见变体。
// 不按前缀模糊匹配 `flag*`：`flagchecker.py`、`flag.png` 这类**是附件**，
// 误挡会让题目缺文件，而缺文件比多给答案更难排查。
var ctfAnswerFiles = map[string]bool{
	"flag.txt":     true,
	"flag":         true,
	"FLAG":         true,
	"flag.md":      true,
	".flag":        true,
	"answer.txt":   true,
	"solution.txt": true,
}

func isCTFAnswerFile(name string) bool { return ctfAnswerFiles[name] }

// ctfViewCache 缓存"脱敏视图"的构建结果，避免每条 Bash 都重建目录。
//
// 键是 taskID，值是视图目录与构建时的指纹。指纹用源目录 mtime + 答案文件集合，
// 足以覆盖"换了题 / 补了文件"这两种真实变化。
//
// 必须显式初始化 byTask：对 nil map 赋值会 panic（"assignment to entry in nil map"），
// 而 panic 位置在 Bash 调用链里，模型只看到"工具 Bash 内部错误"——
// 这个坑真实踩过一次，且只有"题目录含答案文件"这条路径会触发。
var ctfViewCache = struct {
	mu     sync.Mutex
	byTask map[string]ctfViewEntry
}{byTask: map[string]ctfViewEntry{}}

type ctfViewEntry struct {
	dir string
	fp  string
}

// challengeMountSource 返回**应该挂进容器**的宿主目录。
func (s *Server) challengeMountSource(t *Task, dir string) string {
	if s == nil || s.m == nil || t == nil || dir == "" {
		return dir
	}
	view, err := ensureChallengeView(dir, filepath.Join(s.m.dir, "chal-view"), t.ID)
	if err != nil {
		// 视图构建失败时**不能**回落到原目录：那等于把答案发出去。
		// 返回空串，挂载会被 mountsFor 跳过 —— 模型看到"没有附件"，
		// 比悄悄拿到答案要好得多，而且日志里有明确原因。
		log.Printf("[ctf] task %s 构建脱敏视图失败，本次不挂载附件: %v", t.ID, err)
		return ""
	}
	return view
}

// ensureChallengeView 返回应该挂出去的目录：源目录不需要脱敏时就是它本身，
// 需要时是 viewRoot/<taskID> 下的一份剔除答案的副本。
//
// 这段逻辑独立于 *Server 存在，是为了能被直接测到：它曾经因为
// "缓存 map 未初始化"在真实任务里 panic，而当时的测试只覆盖了 copyTreeSkipping。
func ensureChallengeView(srcDir, viewRoot, taskID string) (string, error) {
	fp, hasAnswer := challengeFingerprint(srcDir)
	if !hasAnswer {
		// 没有答案文件：清掉可能残留的旧视图，避免"上一题的视图被复用"。
		dropCTFView(viewRoot, taskID)
		return srcDir, nil
	}

	ctfViewCache.mu.Lock()
	entry, ok := ctfViewCache.byTask[taskID]
	ctfViewCache.mu.Unlock()
	if ok && entry.fp == fp && dirExists(entry.dir) {
		return entry.dir, nil
	}

	view := filepath.Join(viewRoot, taskID)
	if err := os.RemoveAll(view); err != nil {
		log.Printf("[ctf] task %s 清理旧视图失败（继续重建）: %v", taskID, err)
	}
	if err := copyTreeSkipping(srcDir, view, isCTFAnswerFile); err != nil {
		return "", err
	}
	ctfViewCache.mu.Lock()
	ctfViewCache.byTask[taskID] = ctfViewEntry{dir: view, fp: fp}
	ctfViewCache.mu.Unlock()
	log.Printf("[ctf] task %s 题目录含答案文件，已生成脱敏视图：%s", taskID, view)
	return view, nil
}

// dropCTFView 丢弃某任务的视图缓存并删除其目录（源目录不再需要脱敏时）。
func dropCTFView(viewRoot, taskID string) {
	ctfViewCache.mu.Lock()
	entry, ok := ctfViewCache.byTask[taskID]
	delete(ctfViewCache.byTask, taskID)
	ctfViewCache.mu.Unlock()
	if ok && entry.dir != "" {
		_ = os.RemoveAll(entry.dir)
		return
	}
	// 缓存里没有记录也删一次：进程重启后缓存是空的，但磁盘上的旧视图还在，
	// 不删会一直被"看"成上一轮的题目（虽然不会被挂载，但占空间且误导排查）。
	if viewRoot != "" && taskID != "" {
		_ = os.RemoveAll(filepath.Join(viewRoot, taskID))
	}
}

// challengeFingerprint 用"目录 mtime + 答案文件相对路径"描述一次源目录的状态。
func challengeFingerprint(dir string) (string, bool) {
	fi, err := os.Stat(dir)
	if err != nil {
		return "", false
	}
	fp := fi.ModTime().UTC().Format(time.RFC3339Nano)
	hasAnswer := false
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if isCTFAnswerFile(d.Name()) {
			hasAnswer = true
			fp += "|" + p
		}
		return nil
	})
	return fp, hasAnswer
}

// copyTreeSkipping 递归复制目录，跳过 basename 命中的文件。
func copyTreeSkipping(src, dst string, skip func(string) bool) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if skip(d.Name()) {
			return nil
		}
		// 符号链接原样跳过：题库里偶尔有指向宿主绝对路径的链接，
		// 复制过去在容器里必然断链，留着只会让模型以为附件损坏。
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return copyFile(p, target, info.Mode().Perm())
	})
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer out.Close()
	// 用 CopyN + 大小上限之外还是一次普通 Copy：附件可能有几百 MB，
	// 分块缓冲由 io.Copy 内部处理，这里只需要保证 Close 前 flush。
	_, err = io.Copy(out, in)
	return err
}
