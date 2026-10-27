package server

import (
	"context"
	"log"
	"strings"

	"github.com/jintilm/praetor/internal/components"
)

// 本文件回答一个问题：**这个任务该在哪个镜像里跑**。
//
// 沙箱镜像不是"全局一个"就够：CTF 域需要 pwntools / gdb / rizin / z3 这套工具链（约 700MB），
// 而渗透域一个都不需要。合成一个镜像的代价是所有任务都多背 700MB 的冷启动，
// 而拆开只需要在"创建容器"那一刻知道任务属于哪个领域 —— 这件事恰好只有 server 知道。
//
// 三条纪律：
//  1. 只在**领域明确需要**时换镜像，其余一律用用户当前选定的镜像（零意外）；
//  2. 镜像不存在时**不静默降级**（降级的表现是模型在 Bash 里逐个 `command -v` 试探，
//     然后得出"解不出"），而是回给模型一条能被人直接照做的错误；
//  3. 同一任务的容器复用时核对镜像（见 sandbox/per_task.go 的 sameImage），
//     否则"换了镜像却还在用旧容器"只会在重启后才神秘恢复。

// ctfImageTag 返回 CTF 域应使用的镜像 tag。
//
// 优先用**当前已选定的镜像**：如果它已包含 CTF 基础工具链（用户可能又叠了 angr），
// 那就直接用它——用户的选择优先于我们的预置。
// 否则回落到 ctf-base 预置算出的 tag（该预置构建过就直接命中）。
func (s *Server) ctfImageTag() string {
	base, err := components.PresetItems(presetCTFBase)
	if err != nil || len(base) == 0 {
		return ""
	}
	selected := map[string]bool{}
	for _, id := range s.selectedComponentIDs() {
		selected[id] = true
	}
	all := true
	for _, it := range base {
		if !selected[it.ID] {
			all = false
			break
		}
	}
	if all {
		if img := s.currentSandboxImage(); img != "" {
			return img
		}
	}
	tag, err := components.PresetImageTag(presetCTFBase)
	if err != nil {
		return ""
	}
	return tag
}

const presetCTFBase = "ctf-base"

// domainImageFor 是注入 sandbox.PerTaskRunner 的镜像解析器。
//
// 返回空 = 用默认镜像。只对**明确需要专用工具链**的领域返回专用镜像：
// 其余领域（pentest / redteam / reverse）目前共用基础镜像，多一条路由就是多一份要维护的映射。
func (s *Server) domainImageFor(taskID string) string {
	t, ok := s.m.Task(taskID)
	if !ok || t == nil {
		return ""
	}
	if strings.TrimSpace(t.Domain) != "ctf" {
		return ""
	}
	return s.ctfImageTag()
}

// logDomainImages 在启动期把"哪些领域有专用镜像、装没装"打进日志。
//
// 启动时就该知道，而不是等某个 CTF 任务第一次 Bash 才失败：那时已经烧了 planner 的钱。
func (s *Server) logDomainImages(ctx context.Context) {
	if s == nil {
		return
	}
	tag := s.ctfImageTag()
	if tag == "" {
		return
	}
	if s.imageExists(ctx, tag) {
		log.Printf("[sandbox] CTF 域镜像：%s（已就绪）", tag)
		return
	}
	log.Printf("[sandbox] CTF 域镜像 %s **未构建**：ctf 任务第一次 Bash 会被拒绝，先构建预置（POST /api/components/apply {\"preset\":\"%s\"}）",
		tag, presetCTFBase)
}
