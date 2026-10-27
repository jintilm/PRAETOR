package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/internal/components"
)

// 可选组件管理（沙箱镜像层）。
//
// 设计要点（对应执行文档 R6）：
//   - 这些都是**可选加速器**，装不上不影响核心能力；
//   - 只装进沙箱镜像，不动宿主：零提权、可回滚（切回 :latest）、可复现（Dockerfile 由清单生成）；
//   - 清单在 `internal/components`，Dockerfile 与探测脚本都由它生成，不手写第二份。

const (
	settingSandboxExtras  = "sandbox.extras"       // 已构建的组件 ID（逗号分隔）
	settingSandboxImage   = "sandbox.image"        // 当前使用的镜像 tag
	settingSandboxBuiltAt = "sandbox.extras.built" // 最近一次构建成功时间（RFC3339）
)

// compJob 是唯一在跑的构建作业。
//
// 刻意只允许一个：构建会占用 Docker daemon 与磁盘，并发构建既容易 OOM，
// 也会让"当前用哪个镜像"变得含糊。
type compJob struct {
	mu       sync.Mutex
	running  bool
	ids      []string
	image    string
	lines    []string
	errMsg   string
	started  time.Time
	finished time.Time
}

const compJobMaxLines = 400

func (j *compJob) append(line string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	// 单行限长：docker build 的进度行可能带超长 URL
	if len(line) > 400 {
		line = line[:400] + "…"
	}
	j.lines = append(j.lines, line)
	if len(j.lines) > compJobMaxLines {
		j.lines = j.lines[len(j.lines)-compJobMaxLines:]
	}
}

func (j *compJob) snapshot() (running bool, ids []string, image, errMsg string, lines []string, started, finished time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	cp := make([]string, len(j.lines))
	copy(cp, j.lines)
	return j.running, append([]string(nil), j.ids...), j.image, j.errMsg, cp, j.started, j.finished
}

// componentsJob 挂在 Server 上（进程级单例）。
var componentsJob = &compJob{}

func (s *Server) registerComponentRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/components", s.getComponents)
	mux.HandleFunc("POST /api/components/apply", s.applyComponents)
	mux.HandleFunc("POST /api/components/probe", s.probeComponents)
	mux.HandleFunc("GET /api/components/stream", s.streamComponents)
}

// getComponents 返回清单 + 当前选择 + 构建状态（一次拉全，UI 不用多次请求）。
func (s *Server) getComponents(w http.ResponseWriter, r *http.Request) {
	selected := s.selectedComponentIDs()
	selSet := map[string]bool{}
	for _, id := range selected {
		selSet[id] = true
	}
	type itemDTO struct {
		ID       string   `json:"id"`
		Group    string   `json:"group"`
		Title    string   `json:"title"`
		Why      string   `json:"why"`
		License  string   `json:"license"`
		SizeMB   int      `json:"size_mb"`
		Needs    []string `json:"needs,omitempty"`
		Selected bool     `json:"selected"`
	}
	items := make([]itemDTO, 0, len(components.All()))
	for _, it := range components.All() {
		items = append(items, itemDTO{
			ID: it.ID, Group: it.Group, Title: it.Title, Why: it.Why,
			License: it.License, SizeMB: it.SizeMB, Needs: it.Needs,
			Selected: selSet[it.ID],
		})
	}
	// 预置：把「CTF 需要哪 12 项」变成一次点击。面板不必自己记清单，
	// 清单只在 internal/components 里存一份。
	type presetDTO struct {
		ID      string   `json:"id"`
		Title   string   `json:"title"`
		Why     string   `json:"why"`
		IDs     []string `json:"ids"`
		Image   string   `json:"image"`
		TotalMB int      `json:"total_mb"`
	}
	presets := make([]presetDTO, 0, len(components.Presets()))
	for _, p := range components.Presets() {
		items, err := components.PresetItems(p.ID)
		if err != nil {
			continue // 预置引用了不存在的组件：不展示，测试会把它卡住
		}
		mb := 0
		for _, it := range items {
			mb += it.SizeMB
		}
		presets = append(presets, presetDTO{
			ID: p.ID, Title: p.Title, Why: p.Why, IDs: p.IDs,
			Image: components.ImageTag(items), TotalMB: mb,
		})
	}

	running, ids, image, errMsg, lines, started, finished := componentsJob.snapshot()
	writeJSON(w, 200, map[string]any{
		"items":      items,
		"presets":    presets,
		"selected":   selected,
		"image":      s.currentSandboxImage(),
		"base_image": components.BaseImage,
		"job": map[string]any{
			"running":     running,
			"ids":         ids,
			"image":       image,
			"error":       errMsg,
			"lines":       lines,
			"started_at":  started,
			"finished_at": finished,
		},
	})
}

// applyComponents 校验选择并启动构建。
//
// 安全边界：只接受清单内的 ID（components.Validate 拒绝未知值），
// 服务端不会执行任何用户提供的命令 —— 命令只来自代码里的清单。
func (s *Server) applyComponents(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs    []string `json:"ids"`
		Preset string   `json:"preset"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, 400, "请求体不是合法 JSON")
		return
	}
	var (
		items []components.Item
		err   error
	)
	switch {
	case strings.TrimSpace(in.Preset) != "":
		// 预置展开后仍然过 Validate（白名单只有一处）
		items, err = components.PresetItems(in.Preset)
	default:
		items, err = components.Validate(in.IDs)
	}
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	tag := components.ImageTag(items)

	if running, _, _, _, _, _, _ := componentsJob.snapshot(); running {
		writeErr(w, 409, "已有构建在进行，等它结束再应用")
		return
	}

	// 已经构建过同一组选择：直接切换（不重复构建，省几分钟）
	if s.imageExists(r.Context(), tag) {
		if err := s.persistComponentSelection(items, tag); err != nil {
			writeErr(w, 500, "保存选择失败："+err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "image": tag, "skipped": true,
			"message": "该组合已构建过，已直接切换"})
		return
	}

	// 前置检查：基础镜像不在就直接说清楚，别让用户等半分钟看 docker 报 "pull access denied"
	if !s.imageExists(r.Context(), components.BaseImage) {
		writeErr(w, 409, fmt.Sprintf(
			"基础镜像 %s 不存在：先执行 `docker pull kalilinux/kali-rolling`，再 `docker build -t %s -f sandbox/Dockerfile sandbox/`，然后回来应用"+
				"（先 pull 是必须的：buildkit 拉基础镜像的 token 请求不走 Docker 代理，直连会报 Bad Gateway）",
			components.BaseImage, components.BaseImage))
		return
	}

	go s.buildComponents(items, tag)
	writeJSON(w, 202, map[string]any{"ok": true, "image": tag, "started": true})
}

// buildComponents 在后台构建镜像并把输出逐行喂给 SSE。
func (s *Server) buildComponents(items []components.Item, tag string) {
	ids := make([]string, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.ID)
	}
	componentsJob.mu.Lock()
	componentsJob.running = true
	componentsJob.ids = ids
	componentsJob.image = tag
	componentsJob.errMsg = ""
	componentsJob.lines = nil
	componentsJob.started = time.Now()
	componentsJob.finished = time.Time{}
	componentsJob.mu.Unlock()

	fail := func(msg string) {
		componentsJob.mu.Lock()
		componentsJob.running = false
		componentsJob.errMsg = msg
		componentsJob.finished = time.Now()
		componentsJob.mu.Unlock()
	}

	dir, err := os.MkdirTemp("", "praetor-extras-")
	if err != nil {
		fail("创建临时目录失败：" + err.Error())
		return
	}
	defer os.RemoveAll(dir)
	dfPath := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(dfPath, []byte(components.RenderDockerfile(items)), 0o644); err != nil {
		fail("写 Dockerfile 失败：" + err.Error())
		return
	}
	componentsJob.append("$ docker build -t " + tag + " (组件：" + strings.Join(ids, ", ") + ")")

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "build", "-t", tag, "-f", dfPath, dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fail("启动 docker 失败：" + err.Error())
		return
	}
	cmd.Stderr = cmd.Stdout // 同一个 pipe：构建失败原因常在 stderr，顺序也要保留
	if err := cmd.Start(); err != nil {
		fail("启动 docker 失败：" + err.Error())
		return
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		componentsJob.append(sc.Text())
	}
	if err := cmd.Wait(); err != nil {
		_, _, _, _, lines, _, _ := componentsJob.snapshot()
		tail := errorLines(lines, 3)
		hint := ""
		low := strings.ToLower(tail)
		switch {
		// 本机实测：Docker Desktop 把代理注入到构建容器的网络层，但那个代理网关自己
		// 解析不了 host.docker.internal，于是任何 apt 都失败（运行时容器却是正常的）。
		// 这不是镜像或代码问题，必须去改 Docker Desktop 设置，所以要把话说明白。
		case strings.Contains(low, "container settings http proxy") || strings.Contains(low, "no such host"):
			hint = "；构建期网络被 Docker Desktop 的容器代理挡住（代理网关解析不了 host.docker.internal）。" +
				"修法：Docker Desktop → Settings → Resources → Proxies → 关闭「Use proxy for containers」或改用手动代理，Apply & restart"
		case strings.Contains(low, "bad gateway") || strings.Contains(low, "anonymous token"):
			hint = "；这通常是 buildkit 取 token 的请求不走 Docker 代理：先 `docker pull kalilinux/kali-rolling` 预拉基础镜像，再重试"
		}
		fail("构建失败：" + err.Error() + "；最后输出：" + tail + hint)
		return
	}

	// 成功：先落 settings，再决定是否切换（写库失败就不切，避免"用着新镜像但库里没记"）
	if err := s.persistComponentSelection(items, tag); err != nil {
		fail("镜像已构建但保存选择失败：" + err.Error())
		return
	}
	componentsJob.mu.Lock()
	componentsJob.running = false
	componentsJob.errMsg = ""
	componentsJob.finished = time.Now()
	componentsJob.mu.Unlock()
	componentsJob.append("✅ 构建完成：" + tag + "（重启任务后新容器使用该镜像；常驻容器需重建）")
}

// persistComponentSelection 记录选择与镜像 tag。
func (s *Server) persistComponentSelection(items []components.Item, tag string) error {
	ids := make([]string, 0, len(items))
	for _, it := range items {
		ids = append(ids, it.ID)
	}
	if err := s.m.pg.SetSetting(settingSandboxExtras, strings.Join(ids, ",")); err != nil {
		return err
	}
	if err := s.m.pg.SetSetting(settingSandboxImage, tag); err != nil {
		return err
	}
	return s.m.pg.SetSetting(settingSandboxBuiltAt, time.Now().Format(time.RFC3339))
}

// selectedComponentIDs 读当前选择（非法/过期的 ID 会被过滤，不让旧配置卡死面板）。
func (s *Server) selectedComponentIDs() []string {
	raw, ok, err := s.m.pg.GetSetting(settingSandboxExtras)
	if err != nil || !ok || strings.TrimSpace(raw) == "" {
		return nil
	}
	items, err := components.Validate(strings.Split(raw, ","))
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.ID)
	}
	return out
}

// currentSandboxImage 返回当前应使用的沙箱镜像：settings 优先，回落环境变量/默认值。
func (s *Server) currentSandboxImage() string {
	if v, ok, err := s.m.pg.GetSetting(settingSandboxImage); err == nil && ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return ""
}

func (s *Server) imageExists(ctx context.Context, tag string) bool {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "docker", "image", "inspect", tag)
	return cmd.Run() == nil
}

// probeComponents 在当前镜像里跑一次探测，返回每个组件的安装状态。
//
// 为什么必须能探测：没有探测的面板会撒谎——用户勾了"已安装"，模型一跑就报缺。
// 一次 `sh -c` 跑完全部（而不是每项起一个容器）：16 项各起容器要十几秒，面板刷新不该让人等。
func (s *Server) probeComponents(w http.ResponseWriter, r *http.Request) {
	image := s.currentSandboxImage()
	if image == "" {
		image = components.BaseImage
	}
	if !s.imageExists(r.Context(), image) {
		writeErr(w, 409, fmt.Sprintf("镜像 %s 不存在：先构建沙箱镜像，或到面板应用一次选择", image))
		return
	}
	script := components.ProbeScript(components.All())
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--entrypoint", "sh", image, "-c", script)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		writeErr(w, 500, "探测失败："+err.Error())
		return
	}
	results := components.ParseProbe(string(out))
	writeJSON(w, 200, map[string]any{
		"image":   image,
		"probed":  len(results),
		"results": results,
	})
}

// streamComponents 用 SSE 推送构建日志。
//
// 实现用轮询而不是 channel 广播：构建是**串行单例**，轮询的延迟（400ms）对日志完全够用，
// 而 channel 方案要处理订阅/退订/丢事件，收益不成比例。
func (s *Server) streamComponents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	idx := 0
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	// 先推一次全量历史，让中途打开的页面也能看到之前发生了什么
	for {
		running, ids, image, errMsg, lines, _, finished := componentsJob.snapshot()
		for ; idx < len(lines); idx++ {
			b, _ := json.Marshal(map[string]any{"line": lines[idx]})
			fmt.Fprintf(w, "data: %s\n\n", b)
		}
		flusher.Flush()
		if !running {
			b, _ := json.Marshal(map[string]any{
				"done": true, "ids": ids, "image": image, "error": errMsg,
			})
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
			_ = finished
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
		}
	}
}

// settingOr 读一个 settings 值，缺失/空白时返回默认值（读失败也回落，不阻断启动）。
func settingOr(pg *db.DB, key, def string) string {
	if pg == nil {
		return def
	}
	v, ok, err := pg.GetSetting(key)
	if err != nil || !ok || strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

// errorLines 从构建日志里挑**信息量最大的**几行，而不是简单取最后 n 行。
//
// 为什么不能只取尾部：docker 失败时最后几行往往是它自己的包装信息
// （`process "/bin/sh -c apt-get install ..." did not complete successfully: exit code: 100`），
// 而真正的错误（apt 的 `E: ... 404` / `Temporary failure resolving`）在更上面。
// 只回传尾部会让用户对着"exit code 100"发懵 —— 这等于没说。
func errorLines(lines []string, n int) string {
	if len(lines) == 0 {
		return "（无输出）"
	}
	var hits []string
	for _, ln := range lines {
		l := strings.ToLower(ln)
		if strings.Contains(l, "e: ") || strings.Contains(l, "error") ||
			strings.Contains(l, "failed") || strings.Contains(l, "404") ||
			strings.Contains(l, "temporary failure") || strings.Contains(l, "could not resolve") ||
			strings.Contains(l, "no space left") || strings.Contains(l, "permission denied") {
			hits = append(hits, ln)
		}
	}
	if len(hits) == 0 {
		return tailLines(lines, n)
	}
	if len(hits) > n {
		hits = hits[len(hits)-n:]
	}
	return strings.Join(hits, " | ")
}

func tailLines(lines []string, n int) string {
	if len(lines) == 0 {
		return "（无输出）"
	}
	start := len(lines) - n
	if start < 0 {
		start = 0
	}
	return strings.Join(lines[start:], " | ")
}
