package server

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
)

// 本文件回答一个问题：**提示词说 cwd 是 /work/i<id>，这个目录谁建**。
//
// 病根：worker 只在宿主上建 <data>/tasks/<id>/i<id>（agent.ensureRunDir），而任务容器
// 挂的是 <data>/work/<id> -> /work。两棵树之间只有 sandboxPathMapper 的**翻译**，
// 没有任何创建动作 —— 提示词（promptRunDir）告诉模型"你在 /work/i7"，容器里却没有
// 这条路径，于是模型开局几乎每条命令都先撞一次 `cd: can't cd to /work/i7`，再花一次
// 工具调用自己 mkdir 补救。实测里这类失败占容器内 Bash 错误的主体，纯粹是平台欠账。
//
// 解法：在意图真正开跑前，把宿主那侧的 i<id> 建出来。宿主建 = 容器立刻可见（bind
// mount），不需要为了 mkdir 提前把容器拉起来，懒启动的收益原样保留。

// prepareIntentWorkDir 预建容器内工作目录 <workRoot>/<taskID>/i<intentID>。
func (e *Engine) prepareIntentWorkDir(t *Task, intentID int64) {
	if e == nil || e.m == nil || t == nil || intentID <= 0 {
		return
	}
	if !SandboxPerTaskActive() {
		return // Bash 在宿主执行：只有一棵树，且 ensureRunDir 已经建了它
	}
	dir := intentWorkDir(t, e.m.DataDir(), intentID)
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		// 建不出来不阻断执行：worker 照跑，模型第一次 cd 失败后自己补救。那正是本函数
		// 要消除的旧行为，但比"因为建目录失败整条意图不跑"轻得多。
		log.Printf("[sandbox] task %s 预建容器工作目录失败 %s: %v", t.ID, dir, err)
	}
}

// intentWorkDir 返回容器内 /work/i<intentID> 对应的宿主路径。必须与
// agent.promptRunDir 拼出的容器路径严格对应（/work + "/i" + id），否则模型 cd 的
// 是 A、我们建的是 B，症状和"根本没建"一模一样。
func intentWorkDir(t *Task, dataDir string, intentID int64) string {
	root := taskWorkHostFor(t, dataDir)
	if root == "" || intentID <= 0 {
		return ""
	}
	return filepath.Join(root, "i"+strconv.FormatInt(intentID, 10))
}
