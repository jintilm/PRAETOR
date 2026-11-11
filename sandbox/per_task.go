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
	HostWorkRoot  string        // 宿主任务目录根（daemon 侧绝对路径，见 hostpath.go）
	ContainerRoot string        // 容器内挂载点，默认 /work
	Network       string        // docker 网络；空 = 默认 bridge
	Env           []string      // 注入容器的环境变量（K=V），如 HTTP_PROXY=host.docker.internal:8080
	IdleTTL       time.Duration // 空闲回收阈值，默认 30m
	LabelPrefix   string        // 容器标签前缀，用于批量清理；默认 praetor.task
	Command       string        // 容器常驻命令，默认 sleep infinity
	// InitErr 是装配期（路径视角解析等）留下的致命错误。
	//
	// 存在理由：wireSandbox 的统一流程是「构造 → Available() → 决定降级/拒绝」。
	// 把致命错误挂在这里由 Available 报出，就不必在调用方复制一遍 fail-closed
	// 分支，也不会出现「探测通过但每条 Bash 都挂错目录」的半可用状态。
	InitErr error
	// TranslateHostPath 把「应用进程视角的额外挂载源」翻译成 daemon 侧宿主路径。
	//
	// 题面附件（/chal）与工作区同源：应用跑在容器里时，配置里写的 /app/chal-view
	// 只有应用自己看得到，直接交给 `docker run -v` 会挂出一个空目录。nil = 不做
	// 转换（宿主二进制部署，两个视角本来就是同一个）。
	TranslateHostPath func(string) (string, error)
	// ImageFor 按任务选镜像；nil 或返回空 = 用 Image。
	//
	// 为什么镜像要按任务选：CTF 域需要 pwntools/gdb/rizin 这套工具链（约 700MB），
	// 而渗透域不需要 —— 让所有人都背上它，等于每次冷启动都多等一倍。镜像选择是**领域**
	// 的属性，领域又只有任务知道，所以决策由上层注入，这里只负责用。
	ImageFor func(taskID string) string
	// Egress 返回该任务的全量出口上游；nil 或返回 nil = 不启用（容器直连，行为与从前一致）。
	//
	// 为什么是函数而不是值：全局出口代理支持运行时热改，创建容器时才求值；
	// 快照会让"改了代理"对已存在的箱子永远不生效（「先建任务、后配题」同款坑）。
	// 带 taskID：任务级出口池（多上游）按任务稳定分配，同一任务的容器换镜像重建
	// 后仍落在同一出口 —— 会话与登录态绑 IP，漂移比不隐身更糟。
	// 启用时容器追加 NET_ADMIN（打 iptables 规则）与 host-gateway 映射，
	// 并在创建后 exec 一次 praetor-egress 完成配置；失败只降级为直连并记日志
	// —— 隐身是增强，不该让任务起不来。
	Egress func(taskID string) *EgressUpstream
	// MountFor 返回该任务额外的只读挂载（题面附件、题库目录等）；nil = 不挂。
	//
	// 为什么必须由上层注入：附件放在哪里是**题面来源**的知识（离线题库目录 vs CTFd
	// 下载目录），沙箱只该知道"挂哪个宿主目录到哪个容器路径"。
	// 不挂的后果不是"读不到文件"这么轻——模型会拿到一串宿主绝对路径，
	// 在容器里 `ls` 全部 ENOENT，然后得出"题目附件缺失"，转而自己编题。
	MountFor func(taskID string) []Mount
	// TargetHosts 返回该任务题面里出现的主机名（如 delulu / 10.0.0.5），供
	// TargetNetwork 推断「任务容器该接入哪个 docker 网络」。
	//
	// 为什么由上层注入：host 来自题面文本（描述/目标/资产），那是 server 侧的知识，
	// 沙箱只该知道"给了这些名字，去问 docker"。
	//
	// nil 或返回空 = 不做推断，行为与改造前一致（用 Network 或默认 bridge）。
	TargetHosts func(taskID string) []string
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
	s := normalizeDaemonPath(m.Source) + ":" + m.Target
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
		// 应用进程能打开的目录，不等于 daemon 能挂的目录。全 Docker 部署下
		// 二者是两条不同的路径（见 hostpath.go）；翻译失败宁可跳过挂载并留日志，
		// 也不要把 /app/... 原样交给 -v —— 那会挂出一个空目录，模型据此判定
		// 「题面附件缺失」然后开始编题。
		if p.cfg.TranslateHostPath != nil {
			daemonSrc, err := p.cfg.TranslateHostPath(src)
			if err != nil {
				log.Printf("[sandbox] task %s 跳过挂载 %s：%v", taskID, src, err)
				continue
			}
			src = daemonSrc
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
	// verified 标记「已确认过这个容器的 /work 挂在正确的宿主目录上」。
	// 进程重启后第一次见到遗留容器时查一次即可，不必每条 Bash 都 inspect。
	verified bool
	// dirs 记录已经确保存在过的容器内工作目录（/work/i<id>）。
	// docker exec --workdir 的 chdir 发生在 shell 启动之前，命令里写 mkdir 没用；
	// 每个意图目录只在首次使用时补一次，避免每条 Bash 多起一个进程。
	dirMu sync.Mutex
	dirs  map[string]bool
}

// NewPerTask 构造一任务一容器 Runner。
func NewPerTask(cfg PerTaskConfig) *PerTaskRunner {
	if cfg.ContainerRoot == "" {
		cfg.ContainerRoot = "/work"
	}
	// 宿主工作目录必须是**绝对路径**：`docker -v 相对路径:/work` 会把相对路径当卷名，
	// 于是每一条 Bash 都以 "invalid volume specification" 失败，而错误发生在 create 阶段，
	// 表现为"沙箱完全不可用"——但真正的原因只是一个没展开的 `.`。
	//
	// 但「绝对」要按 daemon 的视角判断：应用跑在 Linux 容器、daemon 在 Windows 宿主上时，
	// 推导出的 E:/repo/data/work 对 filepath.IsAbs 是相对路径，若在这里 filepath.Abs
	// 就会被拼成 /app/E:/repo/data/work，挂载源彻底错位。见 normalizeWorkRoot。
	cfg.HostWorkRoot = normalizeWorkRoot(cfg.HostWorkRoot)
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
	if p.cfg.InitErr != nil {
		return p.cfg.InitErr
	}
	if strings.TrimSpace(p.cfg.HostWorkRoot) == "" {
		return fmt.Errorf("sandbox: 任务工作区根为空，无法确定 docker -v 的宿主源")
	}
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
	if err := p.ensureWorkDir(ctx, box, dir); err != nil {
		return Result{}, err
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
	if err := p.ensureWorkDir(ctx, box, dir); err != nil {
		return Result{}, err
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

// ensureWorkDir 在正式 exec 前确保 --workdir 指向的目录在容器里真的存在。
//
// 正常路径下 server.prepareIntentWorkDir 已在宿主侧预建（bind mount 让容器立刻
// 可见），这里只是兜底：容器复用期间目录被删、宿主预建失败、或没走 Engine 的
// 调用路径时，`docker exec --workdir` 的 chdir 会在 shell 启动之前失败，
// 整条命令一行都跑不到，而报错（OCI runtime exec failed / exit 127）看起来
// 完全不像「目录不存在」。chdir 早于 shell，所以只能靠一条独立的 exec 补建。
//
// 这次 exec 刻意不带 --workdir：容器创建时的默认工作根（/work）一定存在。
// 每个 (容器, 目录) 只补一次，避免每条 Bash 都多起一个进程。
func (p *PerTaskRunner) ensureWorkDir(ctx context.Context, box *taskBox, dir string) error {
	if dir == "" || dir == p.cfg.ContainerRoot {
		return nil
	}
	box.dirMu.Lock()
	defer box.dirMu.Unlock()
	if box.dirs == nil {
		box.dirs = map[string]bool{}
	}
	if box.dirs[dir] {
		return nil
	}
	_, stderr, code, err := p.exec(ctx, []string{
		"exec", box.container, "sh", "-lc", "mkdir -p -- " + shellQuote(dir),
	}, "")
	if err != nil || code != 0 {
		return fmt.Errorf("sandbox: 预建容器工作目录 %s 失败: %v (%s)", dir, err, strings.TrimSpace(stderr))
	}
	box.dirs[dir] = true
	return nil
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
	if p.cfg.InitErr != nil {
		return nil, p.cfg.InitErr
	}
	key := normalizeTaskID(taskID)

	p.mu.Lock()
	box, ok := p.boxes[key]
	if !ok {
		box = &taskBox{
			container: "praetor-task-" + key,
			hostDir:   filepath.Join(p.cfg.HostWorkRoot, key),
			dirs:      map[string]bool{},
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
		// 老版本把应用容器内路径（/app/data/work/214）当成 -v 的宿主源，
		// 升级后正确的根是 E:/.../data/work。遗留容器会被 containerState 认成
		// 「已存在且镜像一致」而一直复用，空目录与 chdir 失败也就一直跟着。
		// 所以重启后第一次见到遗留容器时比一次挂载源，错了就重建。
		// 读不到挂载源时不动（docker 权限/版本差异不该导致每次都重建）。
		stale := false
		if !box.verified {
			stale = p.workMountStale(ctx, box)
			box.verified = true
			if stale {
				log.Printf("[sandbox] task %s 的遗留容器挂载源与当前工作根不符，重建容器", key)
			}
		}
		if !stale && sameImage(current, image) && box.mountKey == mk {
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
		"-v", normalizeDaemonPath(box.hostDir) + ":" + p.cfg.ContainerRoot,
		"--security-opt", "no-new-privileges:true",
	}
	// 全量出口隐身：egress 启用时容器需要 NET_ADMIN（iptables）与宿主网关映射
	//（上游是回环地址时 host.docker.internal 才能解析到宿主）。
	var egress *EgressUpstream
	if p.cfg.Egress != nil {
		egress = p.cfg.Egress(key)
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
	// 目标网络自动对齐（见 TargetNetwork 注释）：题面主机名（delulu 之类）只在与目标
	// 容器相同的自定义网络里才能被 Docker 内嵌 DNS 解析；任务容器默认在 bridge，
	// 解析不了时模型会自己猜 IP —— 实测浪费 10~17 分钟（task 187 / 194 各一次）。
	// declared 非空时以部署配置为准，TargetNetwork 会自动让路。
	netName := p.cfg.Network
	var targetHosts []string
	if p.cfg.TargetHosts != nil {
		targetHosts = p.cfg.TargetHosts(key)
	}
	if n, extra := TargetNetwork(ctx, netName, targetHosts); n != "" {
		netName = n
		// 两种网络靠的机制不同，日志必须说清是哪一种，否则排查时会往错的方向找：
		//   - 自定义网络：容器名由 Docker 内嵌 DNS 解析，接进同一网络即可；
		//   - 默认 bridge：**没有内嵌 DNS**，容器名只能靠 --add-host 写进 /etc/hosts
		//     （2026-10-30 用真实容器验证：不写 hosts 时 getent 直接失败）。
		why := "题面主机名只能在同一自定义网络内解析"
		if n == "bridge" {
			why = "默认 bridge 无内嵌 DNS，靠 --add-host 兜底"
		}
		log.Printf("[sandbox] task %s 接入目标网络 %q（%s）", key, n, why)
		if len(extra) > 0 {
			log.Printf("[sandbox] task %s 目标主机映射：%s", key, strings.Join(extra, ", "))
		}
		for _, h := range extra {
			args = append(args, "--add-host", h)
		}
	}
	if netName != "" {
		args = append(args, "--network", netName)
	}
	for _, e := range p.cfg.Env {
		args = append(args, "-e", e)
	}
	args = append(args, image, "sh", "-lc", p.cfg.Command)

	_, stderr, code, err := p.exec(ctx, args, "")
	if err != nil {
		return nil, fmt.Errorf("sandbox: 创建任务容器失败: %w (%s) [挂载=%q]", err, strings.TrimSpace(stderr), volumeArgs(args))
	}
	if code != 0 {
		return nil, fmt.Errorf("sandbox: 创建任务容器失败: %s [挂载=%q]", strings.TrimSpace(stderr), volumeArgs(args))
	}
	box.mountKey = mk
	box.verified = true

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

// volumeArgs 只挑出 -v 的参数用于报错。
//
// 容器创建失败最常见的两类原因是「宿主源路径不对」和「挂载目标写错」，把挂载
// 列进报错能一眼定位；但不能把整条 args 打进日志 —— 里面可能有 -e 注入的
// 代理凭据。只摘 -v 既够用又不会泄密。
func volumeArgs(args []string) []string {
	var out []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-v" || args[i] == "--volume" {
			out = append(out, args[i+1])
		}
	}
	return out
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
	if p == nil || p.cfg.InitErr != nil || strings.TrimSpace(p.cfg.HostWorkRoot) == "" {
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

// workMountStale 判断现存容器的 /work 是否挂在当前工作根之外。
//
// 只在能明确读到宿主源、且它确实不在根下时返回 true；读不到就当没问题，
// 免得 inspect 权限差异让每次执行都重建容器（重建会丢掉容器里已装的工具和后台进程）。
func (p *PerTaskRunner) workMountStale(ctx context.Context, box *taskBox) bool {
	if strings.TrimSpace(p.cfg.HostWorkRoot) == "" {
		return false
	}
	src, owned := p.workMountSource(ctx, box.container)
	if !owned {
		return false
	}
	return !underRoot(src, p.cfg.HostWorkRoot)
}

// workMountSource 返回容器 /work 挂载的宿主源；不是本系统建的容器返回 owned=false。
func (p *PerTaskRunner) workMountSource(ctx context.Context, name string) (string, bool) {
	format := `{{range .Mounts}}{{if eq .Destination "` + p.cfg.ContainerRoot + `"}}{{.Source}}{{end}}{{end}}`
	out, _, code, err := p.exec(ctx, []string{"inspect", "--format", format, name}, "")
	if err != nil || code != 0 {
		return "", false
	}
	src := normalizeDaemonPath(out)
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
