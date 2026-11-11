// Command praetor runs the PRAETOR backend: the dual SQLite graph stores,
// the event-driven exploration engine, and the JSON HTTP API consumed by the
// shadcn/ui frontend.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jintilm/praetor/agent"
	"github.com/jintilm/praetor/config"
	actool "github.com/jintilm/praetor/internal/norma/tool"
	"github.com/jintilm/praetor/selfupdate"
	"github.com/jintilm/praetor/server"
)

// version is the build version, injected at release time via
// -ldflags "-X main.version=<tag>". Defaults to "dev" for local builds.
var version = "dev"

// banner 是 PRAETOR 的字形。改名自 ARTEX 时这一块曾被漏掉，终端里长期
// 显示旧品牌；它和二进制一起编译，光改源码不重编不会生效。
const banner = `
 ____    ____      _     _____   _____    ___    ____
|  _ \  |  _ \    / \   | ____| |_   _|  / _ \  |  _ \
| |_) | | |_) |  / _ \  |  _|     | |   | | | | | |_) |
|  __/  |  _ <  / ___ \ | |___    | |   | |_| | |  _ <
|_|     |_| \_\ /_/   \_\ |_____|   |_|    \___/  |_| \_\
`

// printBanner writes the startup banner + version/runtime info to stdout.
func printBanner(addr string) {
	fmt.Print(banner)
	fmt.Println("  PRAETOR · AI 自主渗透测试系统")
	fmt.Printf("  版本 %s  ·  %s/%s  ·  %s  ·  监听 %s\n\n",
		version, runtime.GOOS, runtime.GOARCH, runtime.Version(), addr)
}

// main only maps run's result onto the process exit code. The exit code is part
// of the update protocol — the supervising start script reads it to decide
// whether to relaunch us (see selfupdate.ExitRestart) — so the body has to live
// in a function that can *return* rather than os.Exit past its own defers.
func main() {
	os.Exit(run())
}

func run() int {
	var (
		addr        = flag.String("addr", ":8787", "HTTP listen address")
		dataDir     = flag.String("data", filepath.Join(config.BaseDir(), "data"), "data directory for SQLite stores (default: data/ next to the executable)")
		proxy       = flag.String("proxy", "127.0.0.1:8788", "traffic recording proxy address (empty to disable)")
		checkConfig = flag.Bool("check-config", false, "只打印配置来源后退出：不连数据库、不启动服务")
	)
	flag.Parse()

	// hand the build version to the server package so GET /api/health can report it
	// to the frontend top bar.
	server.BuildVersion = version

	printBanner(*addr)

	// capture backend logs into the in-memory sink (still to stderr) so the /logs
	// page can show a live log stream. Do this first, to catch startup logs too.
	server.StartLogCapture()

	// -check-config 是纯只读自查：放在 selfupdate / 开库 / 监听端口之前，
	// 用来回答「配置到底读到没有」，不会碰正在运行的数据库或服务。
	if *checkConfig {
		logConfigDiagnostics(*dataDir)
		return 0
	}

	// Self-update bootstrap: swap in a staged binary, or count a post-swap boot
	// attempt and roll back if the new build keeps dying. Must run before we open
	// the stores or bind a port — this may end with "exit and let the start script
	// relaunch me", and there is no point paying for either first.
	action, upState := selfupdate.Bootstrap()
	server.SetBootUpdateState(upState)
	if action == selfupdate.Restart {
		return selfupdate.ExitRestart
	}

	// 启动即把「配置到底从哪来」讲清楚，避免用户只能靠猜：路径、来源、
	// 识别到的变量名都打印，但绝不打印值（DSN 与 API key 都是秘密）。
	logConfigDiagnostics(*dataDir)

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, shutdown := shutdownContext(sigCtx)
	defer shutdown(agent.AbortShutdown)

	mgr, err := server.NewManager(*dataDir, *proxy)
	if err != nil {
		log.Fatalf("open stores: %v", err)
	}
	defer mgr.Close()

	// Surviving this long means a freshly swapped-in build actually works, so drop
	// the upgrade marker and stop counting attempts. Until it fires, every boot
	// increments the count and a build that keeps dying gets rolled back.
	settle := time.AfterFunc(selfupdate.SettleDelay, selfupdate.Settle)
	defer settle.Stop()

	skillDir := config.SkillDir()
	if abs, err := filepath.Abs(skillDir); err == nil {
		skillDir = abs
	}
	log.Printf("[config] skill 目录: %s", skillDir)
	// 宿主 shell 解析结果：Bash 的每一条命令都走它，而"为什么是 PowerShell"这类
	// 问题在别人的机器上没法靠猜。启动即打，纯只读探测（一次 LookPath + 若干 stat）。
	actool.LogHostShell()
	srv := server.New(ctx, mgr, skillDir, *dataDir, config.BaseDir())
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("PRAETOR %s backend listening on %s (data=%s, workers=%d)", version, *addr, *dataDir, mgr.Workers())
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	// Two ways out: a signal (normal stop → exit 0, the start script stops looping)
	// or a staged update / rollback (→ exit 75, the script relaunches us and the
	// bootstrap above installs the new build).
	code := 0
	select {
	case <-ctx.Done():
	case <-server.RestartRequested():
		code = selfupdate.ExitRestart
		shutdown(agent.AbortShutdown)
	}

	log.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return code
}

// logConfigDiagnostics answers "why can't the binary see my config?" from the
// startup log alone. It prints paths and SOURCES, never values: PRAETOR_PG_DSN
// and the LLM keys carry secrets. The binary deliberately does not read .env —
// that file belongs to docker compose — so an empty variable list is the normal
// case for a bare `./praetor.exe`; start.sh / start.bat bridge the gap.
func logConfigDiagnostics(dataDir string) {
	cfgPath := config.Path()
	if abs, e := filepath.Abs(cfgPath); e == nil {
		cfgPath = abs
	}
	if _, e := os.Stat(cfgPath); e == nil {
		log.Printf("[config] 配置文件: %s (已找到)", cfgPath)
	} else {
		log.Printf("[config] 配置文件: %s (不存在)", cfgPath)
	}

	var names []string
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if ok && strings.HasPrefix(name, "PRAETOR_") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		log.Printf("[config] 环境变量: 未检测到任何 PRAETOR_* 变量（二进制不读 .env；本地启动请用 ./start.sh / start.bat，或 set -a; . ./.env; set +a 后显式 export PRAETOR_PG_DSN）")
	} else {
		log.Printf("[config] 环境变量: 已识别 %d 个 PRAETOR_* 变量：%s（值不打印）", len(names), strings.Join(names, ", "))
	}

	// 全容器化部署最常见的坑：宿主目录与容器内 /work 是两棵树。把两个视角
	// 与推导依据打到日志里，别处的机器不需要猜（只读，不连库）。
	log.Printf("[config] 沙箱工作区: %s", server.SandboxWorkRootDiagnostics(context.Background(), dataDir))

	dsn, source, err := config.PostgresDSN()
	if err != nil {
		log.Printf("[config] 数据库配置: %v", err)
		return
	}
	// config.Redact only understands postgres:// URLs. A libpq "host=… password=…"
	// DSN would be echoed verbatim, so hide non-URL forms altogether.
	target := "(非 URL 格式 DSN，出于安全不显示)"
	t := strings.TrimSpace(dsn)
	if strings.HasPrefix(t, "postgres://") || strings.HasPrefix(t, "postgresql://") {
		target = config.Redact(dsn)
	}
	log.Printf("[config] 数据库配置: 来源=%s，目标=%s", source, target)
}

// shutdownContext deliberately does not derive from signalCtx. If it did, the
// parent's plain context.Canceled could win the race before AbortShutdown was
// attached to the child, losing the diagnostic cause in every running Agent.
func shutdownContext(signalCtx context.Context) (context.Context, context.CancelCauseFunc) {
	ctx, shutdown := context.WithCancelCause(context.Background())
	go func() {
		select {
		case <-signalCtx.Done():
			shutdown(agent.AbortShutdown)
		case <-ctx.Done():
		}
	}()
	return ctx, shutdown
}
