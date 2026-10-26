package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
}

type taskBox struct {
	container string
	hostDir   string
	lastUsed  time.Time
	// mu 串行化「同一任务的创建」，避免两个并发 Exec 各建一个容器。
	mu sync.Mutex
}

// NewPerTask 构造一任务一容器 Runner。
func NewPerTask(cfg PerTaskConfig) *PerTaskRunner {
	if cfg.ContainerRoot == "" {
		cfg.ContainerRoot = "/work"
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

	if exists, err := p.containerExists(ctx, box.container); err != nil {
		return nil, err
	} else if exists {
		return box, nil
	}

	args := []string{
		"run", "-d",
		"--name", box.container,
		"--label", p.cfg.LabelPrefix + "=" + key,
		"--workdir", p.cfg.ContainerRoot,
		// docker 的 -v 在 Windows 上也要求正斜杠源路径（E:/x 可以，E:\x 不行）。
		"-v", filepath.ToSlash(box.hostDir) + ":" + p.cfg.ContainerRoot,
		"--security-opt", "no-new-privileges:true",
	}
	if p.cfg.Network != "" {
		args = append(args, "--network", p.cfg.Network)
	}
	for _, e := range p.cfg.Env {
		args = append(args, "-e", e)
	}
	args = append(args, p.cfg.Image, "sh", "-lc", p.cfg.Command)

	_, stderr, code, err := p.exec(ctx, args, "")
	if err != nil {
		return nil, fmt.Errorf("sandbox: 创建任务容器失败: %w (%s)", err, strings.TrimSpace(stderr))
	}
	if code != 0 {
		return nil, fmt.Errorf("sandbox: 创建任务容器失败: %s", strings.TrimSpace(stderr))
	}
	return box, nil
}

func (p *PerTaskRunner) containerExists(ctx context.Context, name string) (bool, error) {
	_, _, code, err := p.exec(ctx, []string{"container", "inspect", name}, "")
	if err != nil {
		return false, fmt.Errorf("sandbox: inspect 失败: %w", err)
	}
	return code == 0, nil
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
