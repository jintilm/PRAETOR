package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// PerTaskRunner 是「一任务一容器」的隔离实现。
//
// 为什么需要它（对比常驻容器 DockerRunner）：
//   - 常驻容器在任务之间共享文件系统与进程表：A 任务的产物、后台进程、装的东西会串到 B 任务；
//   - 常驻容器的出网无法区分任务，流量留痕只能全量；
//   - 后台任务在常驻模型下没有归属，清理靠人。
//
// 一任务一容器把这三件事变成结构性的：容器名带 taskID、宿主工作目录按 taskID 隔离、
// 任务结束/空闲后整容器删除，后台进程随之消失。
//
// 生命周期：首次 Exec 时惰性创建（create+start），之后复用；空闲超过 IdleTTL 由
// StartReaper 回收；也可显式 Release(taskID)。
type PerTaskRunner struct {
	cfg   PerTaskConfig
	exec  execFn
	now   func() time.Time
	mu    sync.Mutex
	boxes map[string]*taskBox // taskID -> 容器与最近使用时间
}

// PerTaskConfig 是一任务一容器的参数。
type PerTaskConfig struct {
	Image         string        // 沙箱镜像，如 praetor/sandbox:latest
	HostWorkRoot  string        // 宿主任务目录根，如 <data>/work
	ContainerRoot string        // 容器内挂载点，默认 /work
	Network       string        // docker 网络；空 = 默认 bridge
	Env           []string      // 注入容器的环境变量（K=V），如 HTTP_PROXY=host.docker.internal:8080
	IdleTTL       time.Duration // 空闲回收阈值，默认 30m
	LabelPrefix   string        // 容器标签前缀，用于批量清理；默认 praetor.task
	Command       string        // 容器常驻命令，默认 sleep infinity
	// ImageFor 按任务选镜像；nil 或返回空 = 用 Image。
	//
	// 为什么镜像要按任务选：CTF 域需要 pwntools/gdb/rizin 这套工具链（约 700MB），
	// 而渗透域不需要 —— 让所有人都背上它，等于每次冷启动都多等一倍。镜像选择是**领域**
	// 的属性，领域又只有任务知道，所以决策由上层注入，这里只负责用。
	ImageFor func(taskID string) string
	// Egress 返回当前的全量出口上游；nil 或返回 nil = 不启用（容器直连，行为与从前一致）。
	//
	// 为什么是函数而不是值：全局出口代理支持运行时热改，创建容器时才求值；
	// 快照会让"改了代理"对已存在的箱子永远不生效（「先建任务、后配题」同款坑）。
	// 启用时容器追加 NET_ADMIN（打 iptables 规则）与 host-gateway 映射，
	// 并在创建后 exec 一次 praetor-egress 完成配置；失败只降级为直连并记日志
	// —— 隐身是增强，不该让任务起不来。
	Egress func() *EgressUpstream
	// MountFor 返回该任务额外的只读挂载（题面附件、题库目录等）；nil = 不挂。
	//
	// 为什么必须由上层注入：附件放在哪里是**题面来源**的知识（离线题库目录 vs CTFd
	// 下载目录），沙箱只该知道"挂哪个宿主目录到哪个容器路径"。
	// 不挂的后果不是"读不到文件"这么轻——模型会拿到一串宿主绝对路径，
	// 在容器里 `ls` 全部 ENOENT，然后得出"题目附件缺失"，转而自己编题。
	MountFor func(taskID string) []Mount
}

// Mount 是一个额外挂载。
//
// ReadOnly 默认该为 true：题面附件是**输入**，模型的任务不是改题库。
// 只有确实需要写回的场景（比如共享产物目录）才放开。
type Mount struct {
	Source   string // 宿主绝对路径
	Target   string // 容器内绝对路径
	ReadOnly bool
}

// spec 转成 docker -v 的写法。Windows 上源路径也必须是正斜杠（E:/x 可以，E:\x 不行）。
func (m Mount) spec() string {
	s := filepath.ToSlash(m.Source) + ":" + m.Target
	if m.ReadOnly {
		s += ":ro"
	}
	return s
}

// mountsFor 解析该任务的额外挂载并做三项兜底：
// 相对路径展开（否则 docker 会把 `./x` 当卷名，见 NewPerTask 的同类注释）、
// 宿主目录不存在就跳过（挂一个不存在的路径会直接让 create 失败，
// 而"题面来源没配"是常见状态，不该让整个沙箱不可用）、目标路径必须是绝对路径。
func (p *PerTaskRunner) mountsFor(taskID string) []Mount {
	if p.cfg.MountFor == nil {
		return nil
	}
	var out []Mount
	seen := map[string]bool{}
	for _, m := range p.cfg.MountFor(taskID) {
		src := strings.TrimSpace(m.Source)
		tgt := strings.TrimSpace(m.Target)
		if src == "" || tgt == "" || !strings.HasPrefix(tgt, "/") {
			continue
		}
		if abs, err := filepath.Abs(src); err == nil {
			src = abs
		}
		if !isDir(src) {
			continue
		}
		if seen[src+">"+tgt] {
			continue
		}
		seen[src+">"+tgt] = true
		out = append(out, Mount{Source: src, Target: tgt, ReadOnly: m.ReadOnly})
	}
	return out
}

// isDir 判断路径是不是一个存在的目录；不存在/不可读一律 false。
func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// mountKey 把挂载集合压成一个可比较的指纹。
//
// 与镜像同理：容器一旦建成，挂载集合就固定了。题面目录变了（换了题、或从"没配"
// 变成"配了"）却复用旧容器，表现是"明明配了题目，容器里 /chal 却是空的"。
func mountKey(ms []Mount) string {
	if len(ms) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, m.spec())
	}
	return strings.Join(parts, ",")
}

// imageFor 解析该任务该用哪个镜像。空返回 = 用默认镜像（上层没装镜像路由时）。
func (p *PerTaskRunner) imageFor(taskID string) string {
	if p.cfg.ImageFor != nil {
		if img := strings.TrimSpace(p.cfg.ImageFor(taskID)); img != "" {
			return img
		}
	}
	return p.cfg.Image
}

type taskBox struct {
	container string
	hostDir   string
	lastUsed  time.Time
	// mountKey 是创建该容器时实际使用的挂载指纹；空 = 当时没有任何额外挂载。
	// 复用时比对它，不同就重建容器（详见 mountKey 的注释）。
	mountKey string
	// mu 串行化「同一任务的创建」，避免两个并发 Exec 各建一个容器。
	mu sync.Mutex
}

// NewPerTask 构造一任务一容器 Runner。
func NewPerTask(cfg PerTaskConfig) *PerTaskRunner {
	if cfg.ContainerRoot == "" {
		cfg.ContainerRoot = "/work"
	}
	// 宿主工作目录必须是**绝对路径**：`docker -v 相对路径:/work` 会把相对路径当卷名，
	// 于是每一条 Bash 都以 "invalid volume specification" 失败，而错误发生在 create 阶段，
	// 表现为"沙箱完全不可用"——但真正的原因只是一个没展开的 `.`。
	// 配置里写 `./data/work` 是很自然的事（.env 里就是这么写的），所以在这里兜底。
	if cfg.HostWorkRoot != "" {
		if abs, err := filepath.Abs(cfg.HostWorkRoot); err == nil {
			cfg.HostWorkRoot = abs
		}
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 30 * time.Minute
	}
	if cfg.LabelPrefix == "" {
		cfg.LabelPrefix = "praetor.task"
	}
	if cfg.Command == "" {
		cfg.Command = "sleep infinity"
	}
	return &PerTaskRunner{
		cfg:   cfg,
		exec:  runDockerCLI,
		now:   time.Now,
		boxes: map[string]*taskBox{},
	}
}

func (p *PerTaskRunner) Name() string { return "per-task:" + p.cfg.Image }

// Available 探测：镜像存在 + docker 可调用。镜像不存在时给出可执行的修复命令。
func (p *PerTaskRunner) Available(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, stderr, code, err := p.exec(cctx, []string{"image", "inspect", p.cfg.Image}, "")
	if err != nil {
		return fmt.Errorf("docker 不可用: %w (%s)", err, strings.TrimSpace(stderr))
	}
	if code != 0 {
		return fmt.Errorf("沙箱镜像 %q 不存在：先 `docker compose build sandbox`（%s）", p.cfg.Image, strings.TrimSpace(stderr))
	}
	return nil
}

// Exec 在任务专属容器里执行命令（首次调用时惰性创建容器）。
func (p *PerTaskRunner) Exec(ctx context.Context, req Request) (Result, error) {
	if strings.TrimSpace(req.Cmd) == "" {
		return Result{}, fmt.Errorf("sandbox: empty command")
	}
	box, err := p.box(ctx, req.TaskID)
	if err != nil {
		return Result{}, err
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dir := req.WorkDir
	if dir == "" {
		dir = p.cfg.ContainerRoot
	}
	args := []string{"exec", "-i", "--workdir", dir}
	for _, k := range sortedKeys(req.Env) {
		args = append(args, "-e", k+"="+req.Env[k])
	}
	args = append(args, box.container, "sh", "-lc", req.Cmd)

	stdout, stderr, code, err := p.exec(cctx, args, "")
	res := Result{Stdout: stdout, Stderr: stderr, ExitCode: code, Runner: p.Name()}
	if err != nil {
		if cctx.Err() == context.DeadlineExceeded {
			return res, fmt.Errorf("sandbox: 命令超时（%s）: %w", timeout, cctx.Err())
		}
		return res, fmt.Errorf("sandbox: docker exec 失败: %w", err)
	}
	return res, nil
}

// ExecBackground 用 `docker exec -d` 起后台命令，输出重定向到任务目录里的日志，
// 立即返回日志路径（模型后续用 Read 读它，或再 grep 一次）。
//
// 与宿主后台任务的区别：进程活在容器里，任务容器被回收时一起消失，不会留在宿主。
func (p *PerTaskRunner) ExecBackground(ctx context.Context, req Request) (Result, error) {
	if strings.TrimSpace(req.Cmd) == "" {
		return Result{}, fmt.Errorf("sandbox: empty command")
	}
	box, err := p.box(ctx, req.TaskID)
	if err != nil {
		return Result{}, err
	}
	name := "bg-" + randomSuffix()
	relLog := path.Join(".praetor-bg", name+".log")
	wrapped := fmt.Sprintf("mkdir -p .praetor-bg && nohup sh -lc %s > %s 2>&1 &", shellQuote(req.Cmd), relLog)

	dir := req.WorkDir
	if dir == "" {
		dir = p.cfg.ContainerRoot
	}
	args := []string{"exec", "-d", "--workdir", dir, box.container, "sh", "-lc", wrapped}
	_, stderr, code, err := p.exec(ctx, args, "")
	if err != nil || code != 0 {
		return Result{}, fmt.Errorf("sandbox: 后台启动失败: %v (%s)", err, strings.TrimSpace(stderr))
	}

	res := Result{
		Stdout: fmt.Sprintf("已在任务容器内后台执行。\n日志（容器内）：%s\n日志（宿主）：%s",
			path.Join(dir, relLog), filepath.ToSlash(filepath.Join(box.hostDir, relLog))),
		Runner: p.Name(),
	}
	return res, nil
}

// Release 立即删除任务容器（工作目录保留，供取证/复盘）。幂等。
func (p *PerTaskRunner) Release(ctx context.Context, taskID string) error {
	p.mu.Lock()
	box, ok := p.boxes[taskID]
	delete(p.boxes, taskID)
	p.mu.Unlock()
	if !ok {
		return nil
	}
	_, stderr, code, err := p.exec(ctx, []string{"rm", "-f", box.container}, "")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("docker rm %s: %s", box.container, strings.TrimSpace(stderr))
	}
	return nil
}

// StartReaper 起一个后台协程，周期性回收空闲容器。ctx 结束即退出。
func (p *PerTaskRunner) StartReaper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.ReapIdle(ctx)
			}
		}
	}()
}

// ReapIdle 回收空闲超时的容器，返回回收数量。导出以便测试与运维手动触发。
func (p *PerTaskRunner) ReapIdle(ctx context.Context) int {
	now := p.now()
	var victims []*taskBox
	p.mu.Lock()
	for id, box := range p.boxes {
		if now.Sub(box.lastUsed) >= p.cfg.IdleTTL {
			victims = append(victims, box)
			delete(p.boxes, id)
		}
	}
	p.mu.Unlock()

	n := 0
	for _, box := range victims {
		if _, _, _, err := p.exec(ctx, []string{"rm", "-f", box.container}, ""); err == nil {
			n++
		}
	}
	return n
}

// box 返回任务容器，必要时创建。并发安全：同一任务只会创建一个容器。
func (p *PerTaskRunner) box(ctx context.Context, taskID string) (*taskBox, error) {
	key := normalizeTaskID(taskID)

	p.mu.Lock()
	box, ok := p.boxes[key]
	if !ok {
		box = &taskBox{
			container: "praetor-task-" + key,
			hostDir:   filepath.Join(p.cfg.HostWorkRoot, key),
		}
		p.boxes[key] = box
	}
	p.mu.Unlock()

	box.mu.Lock()
	defer box.mu.Unlock()
	box.lastUsed = p.now()

	image := p.imageFor(key)
	mounts := p.mountsFor(key)
	mk := mountKey(mounts)
	exists, current, err := p.containerState(ctx, box.container)
	if err != nil {
		return nil, err
	}
	if exists {
		// 镜像换了就换容器：否则"上一轮用基础镜像建的容器"会让新镜像永远用不上
		// （容器还在就直接 exec），现象是"装了工具却找不到"，且只在重启后才诡异地好了。
		// 挂载同理：题面目录从"没配"变成"配了"时，旧容器里没有 /chal，模型会看到空目录。
		if sameImage(current, image) && box.mountKey == mk {
			return box, nil
		}
		if err := p.removeContainer(ctx, box.container); err != nil {
			return nil, err
		}
	}

	// 领域专用镜像还没构建时，明确报出来（而不是让 docker 回一句 "Unable to find image"）：
	// 这类任务缺的是 pwntools/gdb 这类"没有就基本做不了"的工具，
	// 静默回落基础镜像会让模型在 Bash 里逐个试探，然后得出"解不出"。
	if image != p.cfg.Image {
		if _, _, code, ierr := p.exec(ctx, []string{"image", "inspect", image}, ""); ierr == nil && code != 0 {
			return nil, fmt.Errorf(
				"sandbox: 该任务所属领域需要镜像 %q，但它还没构建：先在组件面板应用对应预置，"+
					"或 `docker build` 出该 tag 后重试", image)
		}
	}

	// docker 的 -v 在 Windows 上也要求正斜杠源路径（E:/x 可以，E:\x 不行）。
	args := []string{
		"run", "-d",
		"--name", box.container,
		"--label", p.cfg.LabelPrefix + "=" + key,
		"--workdir", p.cfg.ContainerRoot,
		"-v", filepath.ToSlash(box.hostDir) + ":" + p.cfg.ContainerRoot,
		"--security-opt", "no-new-privileges:true",
	}
	// 全量出口隐身：egress 启用时容器需要 NET_ADMIN（iptables）与宿主网关映射
	//（上游是回环地址时 host.docker.internal 才能解析到宿主）。
	var egress *EgressUpstream
	if p.cfg.Egress != nil {
		egress = p.cfg.Egress()
	}
	if egress != nil {
		args = append(args,
			"--cap-add", "NET_ADMIN",
			"--add-host", "host.docker.internal:host-gateway",
		)
		for _, e := range egress.env() {
			args = append(args, "-e", e)
		}
	}
	// 额外挂载放在工作目录之后：工作目录是"模型的草稿纸"，附件是"只读输入"，
	// 顺序本身没有语义，但把只读的放后面读起来更清楚。
	for _, m := range mounts {
		args = append(args, "-v", m.spec())
	}
	if p.cfg.Network != "" {
		args = append(args, "--network", p.cfg.Network)
	}
	for _, e := range p.cfg.Env {
		args = append(args, "-e", e)
	}
	args = append(args, image, "sh", "-lc", p.cfg.Command)

	_, stderr, code, err := p.exec(ctx, args, "")
	if err != nil {
		return nil, fmt.Errorf("sandbox: 创建任务容器失败: %w (%s)", err, strings.TrimSpace(stderr))
	}
	if code != 0 {
		return nil, fmt.Errorf("sandbox: 创建任务容器失败: %s", strings.TrimSpace(stderr))
	}
	box.mountKey = mk

	// 出口隐身初始化：环境变量已在 run 时注入，这里只触发脚本。
	// exec -d 异步执行，失败降级为直连并记日志 —— 隐身失败不该让任务失败，
	// 但必须说清楚（安静地"以为在隐身"比明说没隐身危险得多）。
	if egress != nil {
		if _, stderr, code, ierr := p.exec(ctx, []string{
			"exec", "-d", box.container, "sh", "-lc", "praetor-egress",
		}, ""); ierr != nil || code != 0 {
			log.Printf("[sandbox] 出口隐身初始化失败，容器保持直连：%v %s", ierr, strings.TrimSpace(stderr))
		}
	}
	return box, nil
}

func (p *PerTaskRunner) containerExists(ctx context.Context, name string) (bool, error) {
	ok, _, err := p.containerState(ctx, name)
	return ok, err
}

// containerState 一次 inspect 同时回答「在不在」和「用的哪个镜像」。
//
// 合起来做是因为这两个问题永远一起问：只问在不在，就会把"镜像换了但容器还在"
// 当成可复用；分开再问一次又白白多起一个进程。
func (p *PerTaskRunner) containerState(ctx context.Context, name string) (bool, string, error) {
	out, _, code, err := p.exec(ctx, []string{"container", "inspect", "--format", "{{.Config.Image}}", name}, "")
	if err != nil {
		return false, "", fmt.Errorf("sandbox: inspect 失败: %w", err)
	}
	if code != 0 {
		return false, "", nil
	}
	return true, strings.TrimSpace(out), nil
}

// sameImage 容忍 tag 与 digest 两种写法：inspect 返回的是创建时给的字符串，
// 而落盘的 tag 可能带/不带 registry 前缀（docker 会补 index.docker.io/library/）。
func sameImage(have, want string) bool {
	if have == "" || want == "" {
		return have == want
	}
	return have == want || strings.HasSuffix(have, "/"+want) || strings.HasSuffix(want, "/"+have)
}

// SweepOrphans 删除「本部署的、但当前进程不认识」的任务容器，返回删除数量。
//
// 为什么需要它：箱子表（p.boxes）在内存里，ReapIdle 只遍历它 —— 上一个进程
// （重启、崩溃、实测中的测试运行）留下的容器对谁都是隐形的，于是永远 Up。
// 实测一次全量测试就留下 6 个运行中的容器，而症状是"机器越跑越慢"，
// 没人会联想到是三天前那批 praetor-task-*。
//
// 为什么可以只按名字前缀认领：容器名是 docker 全局的，`praetor-task-<key>`
// 意味着同一台 docker 上只能有一个本系统在跑 —— 这是命名方案本来就已经写死的假设。
// 即便如此仍先校验 /work 的宿主源落在我方 HostWorkRoot 之下才删，
// 免得误伤另一个 checkout 的容器（它可能有同名任务 id）。
func (p *PerTaskRunner) SweepOrphans(ctx context.Context) int {
	if p == nil {
		return 0
	}
	out, _, code, err := p.exec(ctx, []string{
		"ps", "-a",
		"--filter", "label=" + p.cfg.LabelPrefix,
		"--format", "{{.Names}}",
	}, "")
	if err != nil || code != 0 {
		// docker 不在/没权限：交给 Available() 去报，这里不抢答。
		return 0
	}

	root := p.cfg.HostWorkRoot
	n := 0
	for _, name := range strings.Split(out, "\n") {
		name = strings.TrimSpace(name)
		key, ok := strings.CutPrefix(name, "praetor-task-")
		if !ok || key == "" {
			continue
		}
		p.mu.Lock()
		_, known := p.boxes[key]
		p.mu.Unlock()
		if known {
			continue // 本进程在用
		}
		if src, owned := p.workMountSource(ctx, name); !owned || !underRoot(src, root) {
			continue // 不是这个部署的容器
		}
		if _, _, _, err := p.exec(ctx, []string{"rm", "-f", name}, ""); err == nil {
			n++
		}
	}
	return n
}

// workMountSource 返回容器 /work 挂载的宿主源；不是本系统建的容器返回 owned=false。
func (p *PerTaskRunner) workMountSource(ctx context.Context, name string) (string, bool) {
	format := `{{range .Mounts}}{{if eq .Destination "` + p.cfg.ContainerRoot + `"}}{{.Source}}{{end}}{{end}}`
	out, _, code, err := p.exec(ctx, []string{"inspect", "--format", format, name}, "")
	if err != nil || code != 0 {
		return "", false
	}
	src := strings.TrimSpace(out)
	return src, src != ""
}

// underRoot 判断 src 是否在 root 之下（按路径段，不是字符串前缀）。
// Windows 路径大小写不敏感，统一转小写再比 —— 只可能让"更宽"的匹配命中，
// 而命中的仍然是本部署根目录下的东西，不会越界。
func underRoot(src, root string) bool {
	s := strings.ToLower(filepath.ToSlash(strings.TrimSpace(src)))
	r := strings.ToLower(filepath.ToSlash(strings.TrimSpace(root)))
	if s == "" || r == "" {
		return false
	}
	if s == r {
		return true
	}
	return strings.HasPrefix(s, strings.TrimSuffix(r, "/")+"/")
}

// removeContainer 删除任务容器（镜像变更时用）。
func (p *PerTaskRunner) removeContainer(ctx context.Context, name string) error {
	_, stderr, code, err := p.exec(ctx, []string{"rm", "-f", name}, "")
	if err != nil {
		return fmt.Errorf("sandbox: 删除旧容器失败: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("sandbox: 删除旧容器失败: %s", strings.TrimSpace(stderr))
	}
	return nil
}

var unsafeNameChars = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

// normalizeTaskID 把任务 ID 变成合法容器名/目录名；空 ID 落到 "shared"，
// 这样「没有任务上下文」的调用也能跑（等价于单容器模式）。
func normalizeTaskID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "shared"
	}
	if len(id) > 40 {
		id = id[:40]
	}
	return unsafeNameChars.ReplaceAllString(id, "-")
}

func randomSuffix() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano()%1e6)
	}
	return hex.EncodeToString(b)
}

// shellQuote 单引号包裹，防注入（后台命令要穿过两层 shell）。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
