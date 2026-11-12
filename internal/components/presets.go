package components

import (
	"fmt"
	"strings"
)

// Preset 是一组预置选装：把「某个领域需要哪些 CLI」从一张散落的勾选表变成一个可点选的集合。
//
// 为什么需要它：CTF 域在 `agent/domain/ctf.go` 里声明了自己的工具链（CTFToolchain），
// 但那张表是**给人和文档看的**，面板上的勾选框是另一份东西 —— 两份一起维护必然漂移，
// 表现是「文档说镜像里有 pwntools，实际构建出来的镜像没有」。预置把声明变成可执行的清单。
//
// 纪律：
//   - 预置只能引用 `All()` 里存在的 ID（`PresetItems` 会拒绝未知项），否则等于绕过白名单；
//   - 预置里不含重依赖（angr / sage / volatility3 单独成预置），基础镜像的体积直接决定冷启动；
//   - 顺序无关：构建 tag 由 ID 集合的哈希算出，同一组选择永远同一个 tag（构建缓存命中）。
type Preset struct {
	ID    string   // 稳定标识（API 用它，不要改）
	Title string   // 面板显示名
	Why   string   // 一句话说明这份预置解决什么
	IDs   []string // 组件 ID（引用 All()）
	// Base 指向要叠加的基础预置；空 = 独立完整集合。
	// 原先「凡不是 ctf-base 的预置都并上 ctf-base」是硬编码，一加第二个领域就错：
	// 移动端会为了一个 apktool 背上 12 项 CTF 工具（约 700MB）。增量改成显式声明。
	Base string
}

// Presets 返回全部预置。CTF 系以 ctf-base 为基础层，其余是它的**增量**（Base 字段声明）；
// 其它领域的预置是独立完整集合，不背 CTF 的体积。
//
// 增量而不是并列：crypto 预置 = 基础层 + angr，不是「只有 angr」。并列会让人勾了
// crypto 预置却发现自己没了 gdb，然后回去再勾一堆 —— 那还不如直接给张勾选表。
func Presets() []Preset {
	return []Preset{
		{
			ID:    "ctf-base",
			Title: "CTF 基础工具链（12 项）",
			Why:   "pwn/rev/crypto/forensics 的日常工具；约 700MB，冷启动可接受",
			IDs: []string{
				"gdb", "pwntools", "gef", "ropgadget", "seccomp-tools", // pwn
				"rizin", "binwalk", // rev
				"z3", "ciphey", // crypto
				"tshark", "exiftool", "zsteg", // forensics
			},
		},
		{
			ID:    "ctf-crypto",
			Title: "CTF + 符号执行（基础层 + angr）",
			Why:   "校验逻辑复杂到人读不动时用 angr 求输入；多约 1.2GB",
			IDs:   []string{"angr"},
			Base:  "ctf-base",
		},
		{
			ID:    "ctf-forensics",
			Title: "CTF + 内存取证（基础层 + volatility3）",
			Why:   "给了内存镜像（.raw/.vmem）的题；volatility3 按需装",
			IDs:   []string{"volatility3"},
			Base:  "ctf-base",
		},
		{
			ID:    "mobile-static",
			Title: "移动端静态分析（1 项）",
			Why:   "只装 apktool：解包 + 纯 Go 静态规则扫描，约 60MB；jadx 保持宿主侧可选增强",
			IDs:   []string{"apktool"},
		},
	}
}

// PresetByID 按 ID 取预置。
func PresetByID(id string) (Preset, bool) {
	id = strings.TrimSpace(id)
	for _, p := range Presets() {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

// PresetItems 把预置展开成组件列表。
//
// 带 Base 的预置是**增量**，展开时自动并上它声明的基础层 ——
// 调用方只需要说「我要 crypto 预置」，不用自己记「还得先勾基础层」。
// 不带 Base 的（ctf-base / mobile-static）就是完整集合，照原样校验。
// 这里刻意复用 Validate：白名单、去重、稳定排序都只实现一份。
func PresetItems(id string) ([]Item, error) {
	p, ok := PresetByID(id)
	if !ok {
		names := make([]string, 0, len(Presets()))
		for _, x := range Presets() {
			names = append(names, x.ID)
		}
		return nil, fmt.Errorf("未知预置：%s（可选：%s）", id, strings.Join(names, ", "))
	}
	ids := append([]string(nil), p.IDs...)
	if p.Base != "" {
		base, ok := PresetByID(p.Base)
		if !ok {
			return nil, fmt.Errorf("预置 %s 的基础层 %s 缺失：增量预置没有基础层可叠", p.ID, p.Base)
		}
		ids = append(ids, base.IDs...)
	}
	return Validate(ids)
}

// PresetImageTag 返回该预置对应的镜像 tag（与面板「应用」算出来的完全一致）。
//
// 存在的意义是让服务端能**预先算出**「CTF 任务该用哪个镜像」，
// 而不必让用户先手动应用一次再在别处填一遍 —— 那两处必然会不一致。
func PresetImageTag(id string) (string, error) {
	items, err := PresetItems(id)
	if err != nil {
		return "", err
	}
	return ImageTag(items), nil
}
