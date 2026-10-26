package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// defaultTimeout 与 Bash 工具的默认超时保持一致，避免两处语义漂移。
const defaultTimeout = 120 * time.Second

// execFn 是可注入的执行缝：测试用它断言命令组装，无需真的装 Docker。
type execFn func(ctx context.Context, args []string, stdin string) (stdout, stderr string, code int, err error)

// DockerRunner 通过 `docker exec` 在常驻容器里执行命令。
type DockerRunner struct {
	container string
	workDir   string
	exec      execFn
}

// NewDocker 构造 Docker 沙箱 Runner。
func NewDocker(container, workDir string) *DockerRunner {
	return &DockerRunner{container: container, workDir: workDir, exec: runDockerCLI}
}

func (d *DockerRunner) Name() string { return "docker:" + d.container }

// Available 用 `docker exec <c> true` 探测：容器在跑、且我们有权 exec。
// 同时覆盖「Docker 守护进程没起」和「容器不存在」两种情况。
func (d *DockerRunner) Available(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, stderr, code, err := d.exec(cctx, []string{"exec", d.container, "true"}, "")
	if err != nil {
		if stderr != "" {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr))
		}
		return err
	}
	// 关键：runDockerCLI 把「非零退出」归一成 code（err=nil），所以这里必须自己判码。
	// 否则容器不存在时（docker exec 退出码 1）会被误判为可用 —— 沙箱静默失效。
	if code != 0 {
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = "exit code " + itoa(code)
		}
		return fmt.Errorf("docker exec %s: %s", d.container, msg)
	}
	return nil
}

// Exec 组装 `docker exec -i --workdir W [-e K=V] <c> sh -lc <cmd>`。
//
// 用 sh -lc 而不是直接切词：命令里常有管道、重定向、heredoc，交给 shell 解释
// 才和宿主上的行为一致（模型的用法假设也是 shell）。
func (d *DockerRunner) Exec(ctx context.Context, req Request) (Result, error) {
	if strings.TrimSpace(req.Cmd) == "" {
		return Result{}, fmt.Errorf("sandbox: empty command")
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dir := req.WorkDir
	if dir == "" {
		dir = d.workDir
	}

	args := []string{"exec", "-i"}
	if dir != "" {
		args = append(args, "--workdir", dir)
	}
	for _, k := range sortedKeys(req.Env) {
		args = append(args, "-e", k+"="+req.Env[k])
	}
	args = append(args, d.container, "sh", "-lc", req.Cmd)

	stdout, stderr, code, err := d.exec(cctx, args, "")
	res := Result{Stdout: stdout, Stderr: stderr, ExitCode: code, Runner: d.Name()}
	if err != nil {
		if cctx.Err() == context.DeadlineExceeded {
			return res, fmt.Errorf("sandbox: 命令超时（%s）: %w", timeout, cctx.Err())
		}
		return res, fmt.Errorf("sandbox: docker exec 失败: %w", err)
	}
	return res, nil
}

// runDockerCLI 是默认实现：调本机 docker 命令。
func runDockerCLI(ctx context.Context, args []string, stdin string) (string, string, int, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); ok {
			code = ee.ExitCode()
			// 退出码非零不算「没能执行」——命令确实跑了，把码交给调用方。
			return out.String(), errb.String(), code, nil
		}
		return out.String(), errb.String(), -1, err
	}
	return out.String(), errb.String(), code, nil
}

// HostRunner 是降级实现：直接在宿主执行（仅 optional/off 模式）。
type HostRunner struct{ workDir string }

func (h *HostRunner) Name() string                    { return "host" }
func (h *HostRunner) Available(context.Context) error { return nil }

func (h *HostRunner) Exec(ctx context.Context, req Request) (Result, error) {
	if strings.TrimSpace(req.Cmd) == "" {
		return Result{}, fmt.Errorf("sandbox: empty command")
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, "sh", "-lc", req.Cmd)
	if h.workDir != "" {
		cmd.Dir = h.workDir
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	res := Result{Stdout: out.String(), Stderr: errb.String(), Runner: h.Name()}
	if err != nil {
		var ee *exec.ExitError
		if asExitError(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		return res, err
	}
	return res, nil
}
