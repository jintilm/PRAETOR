// ctftarget 为「没带 Dockerfile 的 CTF pwn 题」生成可复现的靶机。
//
// 为什么需要它：Cybench（以及多数 CTF 题库）只给二进制和它自带的 glibc，
// 不给 Dockerfile —— 因为原题在比赛时是主办方起好的远程实例，附件里不需要。
// 于是本地跑这类题时，每题都要现写一遍 fork server + 记得把 glibc 一起放进去，
// 而这两件事都有静默失败的坑（见下）。把知识写成工具，就不用每次重踩。
//
// 用法：
//
//	go run ./cmd/ctftarget -challenge /path/to/very-easy-delulu -up
//
// 生成物落在 <challenge>/.praetor-target/（点开头，题库扫描会跳过），包括
// Dockerfile、tcp_srv.py、docker-compose.yml。默认只生成不启动，`-up` 才起。
//
// 两个已经踩过的坑，工具里固化：
//  1. PT_INTERP 是**相对路径**（Cybench 打包时 patchelf 过）：
//     缺了 interpreter 内核只报 "no such file or directory"，看起来像二进制损坏。
//     所以解析 PT_INTERP，把它指向的目录一并 COPY 进镜像，且 cwd 设为二进制所在目录。
//  2. 没有 socat：基础镜像未必装。用 python3 fork server，每个连接 execv 一个新进程
//     （同一进程反复交互会把上一轮的栈布局带进来，调试时行为不可复现）。
package main

import (
	"debug/elf"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"
)

func main() {
	var (
		challenge = flag.String("challenge", "", "题目录（含 files/ 附件与 connection.txt）")
		name      = flag.String("name", "", "靶机服务名/容器名（默认取题目录名的小写短横线形式）")
		port      = flag.Int("port", 0, "监听端口（默认从 connection.txt 解析，再退到 1337）")
		base      = flag.String("base", "", "基础镜像（默认取环境变量 PRAETOR_SANDBOX_IMAGE，再退到 praetor/sandbox:latest）")
		network   = flag.String("network", "", "docker 网络（默认取环境变量 PRAETOR_SANDBOX_NETWORK）")
		binary    = flag.String("bin", "", "指定二进制（默认在 files/ 下自动挑）")
		up        = flag.Bool("up", false, "生成后直接起靶机（含建网络、健康探测）")
		dryRun    = flag.Bool("dry-run", false, "只打印将要写出的文件，不落盘")
	)
	flag.Parse()

	if *challenge == "" {
		fatal("必须给 -challenge <题目录>")
	}
	dir, err := filepath.Abs(*challenge)
	if err != nil {
		fatal(err.Error())
	}
	if !isDir(dir) {
		fatal("题目录不存在：" + dir)
	}

	spec, err := plan(dir)
	if err != nil {
		fatal(err.Error())
	}
	if *name != "" {
		spec.Name = *name
	}
	if *port > 0 {
		spec.Port = *port
	}
	if *binary != "" {
		spec.Binary = *binary
	}
	if *base != "" {
		spec.BaseImage = *base
	}
	if *network != "" {
		spec.Network = *network
	}
	spec.fill()

	if *dryRun {
		for _, f := range spec.files() {
			fmt.Printf("===== %s =====\n%s\n", f.Name, f.Body)
		}
		return
	}

	out := filepath.Join(dir, targetDirName)
	if err := os.MkdirAll(out, 0o755); err != nil {
		fatal(err.Error())
	}
	for _, f := range spec.files() {
		p := filepath.Join(out, f.Name)
		if err := os.WriteFile(p, []byte(f.Body), f.Mode); err != nil {
			fatal(fmt.Sprintf("写 %s 失败: %v", p, err))
		}
	}

	fmt.Printf("已生成 %s\n", out)
	for _, f := range spec.files() {
		fmt.Printf("  %s\n", f.Name)
	}
	fmt.Printf("\n靶机：%s:%d  二进制：%s\n", spec.Name, spec.Port, spec.Binary)
	if spec.Interp != "" {
		fmt.Printf("interpreter：%s（%s）\n", spec.Interp, spec.InterpNote())
	}

	if !*up {
		fmt.Printf("\n下一步：\n")
		fmt.Printf("  docker network create %s   # 已存在可忽略\n", spec.Network)
		fmt.Printf("  docker compose -f %s up -d --build\n", filepath.Join(out, "docker-compose.yml"))
		printWiring(spec)
		return
	}

	if err := upTarget(spec, out); err != nil {
		fatal(err.Error())
	}
}

const targetDirName = ".praetor-target"

// defaultTargetNetwork 是靶机与任务容器共用的固定网络名。
// 固定值的好处：`PRAETOR_SANDBOX_NETWORK=praetor-ctf` 写一次就一直对。
const defaultTargetNetwork = "praetor-ctf"

// targetSpec 是一道 pwn 题的靶机描述。字段都来自题目录本身的客观信息，
// 不猜：端口从 connection.txt 读，interpreter 从 ELF 读。
type targetSpec struct {
	Dir       string // 题目录绝对路径
	Name      string // 服务名
	Port      int
	Binary    string // 相对题目录的路径（compose 的 build context 就是题目录）
	BaseImage string
	Network   string
	Interp    string // PT_INTERP，空 = 静态链接或没解析到
	WorkDir   string // 容器内 cwd（相对 interp 的解析基准）
}

func (s *targetSpec) fill() {
	if s.Name == "" {
		s.Name = serviceName(filepath.Base(s.Dir))
	}
	if s.Port == 0 {
		s.Port = 1337
	}
	if s.BaseImage == "" {
		s.BaseImage = envOr("PRAETOR_SANDBOX_IMAGE", "praetor/sandbox:latest")
	}
	if s.Network == "" {
		s.Network = strings.TrimSpace(os.Getenv("PRAETOR_SANDBOX_NETWORK"))
	}
	if s.Network == "" {
		// 固定名而不是让 compose 自己起名。compose 的默认网络是 `<项目名>_default`，
		// 项目名又取自目录名（`.praetor-target` → `praetor-target_default`）。
		// 让部署方去猜这个名字，等于把"实验和沙箱在不在同一网络"变成一个隐藏变量。
		s.Network = defaultTargetNetwork
	}
	if s.WorkDir == "" {
		s.WorkDir = "/app"
	}
}

// InterpNote 说明 interpreter 的处理方式，给人看的。
func (s *targetSpec) InterpNote() string {
	if s.Interp == "" {
		return "静态链接或未解析到，不额外复制"
	}
	if strings.HasPrefix(s.Interp, "/") {
		return "绝对路径，依赖基础镜像里同路径存在"
	}
	return "相对路径，必须按原目录结构复制进镜像"
}

// InterpRelDir 返回 PT_INTERP 相对路径的目录部分（去掉 "./"）。
// 例："./glibc/ld-linux-x86-64.so.2" → "glibc"；"libc.so.6" → ""（与二进制同目录）。
func (s *targetSpec) InterpRelDir() string {
	if s.Interp == "" || strings.HasPrefix(s.Interp, "/") {
		return ""
	}
	d := path.Dir(s.Interp)
	if d == "." {
		return ""
	}
	return strings.TrimPrefix(d, "./")
}

// InterpSource 返回 interp 目录在题目录下的相对路径（用于 COPY）。
// delulu 的布局是 files/challenge/glibc/ld-linux-x86-64.so.2 与
// files/challenge/delulu 同级，所以 interp 的目录就挨着二进制。
func (s *targetSpec) InterpSource() string {
	d := s.InterpRelDir()
	if d == "" {
		return ""
	}
	return path.Join(path.Dir(s.Binary), d)
}

type renderedFile struct {
	Name string
	Body string
	Mode os.FileMode
}

func (s *targetSpec) files() []renderedFile {
	must := func(t *template.Template, data any) string {
		var b strings.Builder
		if err := t.Execute(&b, data); err != nil {
			fatal("渲染模板失败: " + err.Error())
		}
		return b.String()
	}
	return []renderedFile{
		{"Dockerfile", must(dockerfileTmpl, s), 0o644},
		{"tcp_srv.py", must(tcpSrvTmpl, s), 0o644},
		{"docker-compose.yml", must(composeTmpl, s), 0o644},
	}
}

// plan 从题目录读出靶机参数。只读，不落盘。
func plan(dir string) (*targetSpec, error) {
	s := &targetSpec{Dir: dir}
	s.Name = serviceName(filepath.Base(dir))

	if p, ok := parseConnection(filepath.Join(dir, "connection.txt")); ok && p > 0 {
		s.Port = p
	}
	bin, err := pickBinary(dir)
	if err != nil {
		return nil, err
	}
	s.Binary = bin
	s.Interp = readInterp(filepath.Join(dir, filepath.FromSlash(bin)))
	s.fill()
	return s, nil
}

// connPortRe 抓 connection.txt 里的端口。文件里常见两种写法：
//
//	delulu:1337
//	nc delulu 1337
var connPortRe = regexp.MustCompile(`(?:^|[:\s])(\d{2,5})\s*$`)

func parseConnection(p string) (int, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := connPortRe.FindStringSubmatch(line); len(m) == 2 {
			if n, err := strconv.Atoi(m[1]); err == nil && n > 0 && n < 65536 {
				return n, true
			}
		}
	}
	return 0, false
}

// pickBinary 在题目录里挑「拿来跑的那一个」可执行文件。
//
// 只看 files/ 下（Cybench 的约定是 challenge/ 与 release/ 两个来源），
// 用 ELF magic 判定而不是扩展名：CTF 附件经常没有扩展名，也可能叫 `main`。
// 依赖库（.so）与源码、脚本一律排除 —— 靶机要跑的是程序，不是它的依赖。
func pickBinary(dir string) (string, error) {
	roots := []string{
		filepath.Join(dir, "files", "challenge"),
		filepath.Join(dir, "files", "release"),
		filepath.Join(dir, "files"),
		dir,
	}
	var found []string
	seen := map[string]bool{}
	for _, root := range roots {
		if !isDir(root) {
			continue
		}
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil
			}
			// .praetor-target 是我们自己生成的，别把它当附件。
			if info.IsDir() {
				if info.Name() == targetDirName {
					return filepath.SkipDir
				}
				return nil
			}
			if !info.Mode().IsRegular() || info.Size() < 1024 {
				return nil
			}
			if isLibOrSource(info.Name()) || !isELF(p) {
				return nil
			}
			rel, rerr := filepath.Rel(dir, p)
			if rerr != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)
			if !seen[rel] {
				seen[rel] = true
				found = append(found, rel)
			}
			return nil
		})
	}
	if len(found) == 0 {
		return "", fmt.Errorf("在 %s 下没找到 ELF 可执行文件（用 -bin 指定）", dir)
	}
	// 浅的优先：challenge/ 里的主程序通常比 release/ 里的更深层脚本更靠前；
	// 同层按名字排，保证同一道题每次生成结果一致。
	sort.Slice(found, func(i, j int) bool {
		di, dj := strings.Count(found[i], "/"), strings.Count(found[j], "/")
		if di != dj {
			return di < dj
		}
		return found[i] < found[j]
	})
	return found[0], nil
}

func isLibOrSource(name string) bool {
	l := strings.ToLower(name)
	switch {
	case strings.Contains(l, ".so"):
		return true
	case strings.HasSuffix(l, ".c"), strings.HasSuffix(l, ".h"),
		strings.HasSuffix(l, ".py"), strings.HasSuffix(l, ".sh"),
		strings.HasSuffix(l, ".txt"), strings.HasSuffix(l, ".md"),
		strings.HasSuffix(l, ".zip"), strings.HasSuffix(l, ".tar"),
		strings.HasSuffix(l, ".gz"), strings.HasSuffix(l, ".json"):
		return true
	}
	return false
}

func isELF(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.ReadAt(magic[:], 0); err != nil {
		return false
	}
	return magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F'
}

// readInterp 读 PT_INTERP。
//
// 这是整个工具里唯一"非猜"的部分：interpreter 是相对还是绝对，决定了镜像里
// 要不要原样复制一整个 glibc 目录。读不到（静态链接、非 ELF、架构不支持）就返回空，
// 让用户按 InterpNote 的说明自行判断，而不是编一个路径出来。
func readInterp(p string) string {
	f, err := elf.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_INTERP || prog.Filesz == 0 || prog.Filesz > 4096 {
			continue
		}
		buf := make([]byte, prog.Filesz)
		if _, err := prog.ReadAt(buf, 0); err != nil {
			continue
		}
		return strings.TrimRight(string(buf), "\x00")
	}
	return ""
}

// printWiring 给出"怎么让沙箱里的模型摸到这个靶机"。
//
// 这一步不写清楚，前面全白做：靶机起着、端口通着，而模型在另一个 docker 网络里
// 解析不到主机名，报的是 "Name or service not known" —— 看起来像题目有问题。
func printWiring(s *targetSpec) {
	fmt.Printf("\n把沙箱接到同一网络（否则模型在容器里解析不到 %s）：\n", s.Name)
	fmt.Printf("  PRAETOR_SANDBOX_NETWORK=%s   # 写进 .env 后重启服务\n", s.Network)
	fmt.Printf("  容器内地址：%s:%d\n", s.Name, s.Port)
}

// upTarget 建网络、起靶机、健康探测。任何一步失败都要说清是哪一步。
func upTarget(s *targetSpec, genDir string) error {
	// 先确认基础镜像在本地：不存在时 `docker compose up` 会去 pull，
	// 而国内网络下这一步的报错是 "pull access denied / i/o timeout"，
	// 看起来像"镜像名写错了"，实际是"没提前 pull"。错误信息误导成本很高。
	if out, err := exec.Command("docker", "image", "inspect", s.BaseImage).CombinedOutput(); err != nil {
		return fmt.Errorf("基础镜像 %s 不在本地：先 `docker pull %s`，或用 -base 指定已有镜像。\n  docker: %s",
			s.BaseImage, s.BaseImage, strings.TrimSpace(string(out)))
	}

	if s.Network != "" {
		// 网络已存在时 create 会返回非零，这不代表失败 —— 只有"不存在且建不出来"才是。
		out, err := exec.Command("docker", "network", "inspect", s.Network).CombinedOutput()
		if err != nil {
			fmt.Printf("网络 %s 不存在，创建中…\n", s.Network)
			if o, cerr := exec.Command("docker", "network", "create", s.Network).CombinedOutput(); cerr != nil {
				return fmt.Errorf("创建 docker 网络 %s 失败: %v (%s)", s.Network, cerr, strings.TrimSpace(string(o)))
			}
		}
		_ = out
	}

	compose := filepath.Join(genDir, "docker-compose.yml")
	cmd := exec.Command("docker", "compose", "-f", compose, "up", "-d", "--build")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker compose up 失败: %w", err)
	}

	// 健康探测放在这里而不是只靠 compose healthcheck：healthcheck 失败时
	// 容器依然是 Up，`docker ps` 看起来一切正常，而模型连不上会开始乱试。
	addr := fmt.Sprintf("127.0.0.1:%d", s.Port)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if dialOK(addr) {
			fmt.Printf("靶机就绪：%s（宿主）\n", addr)
			printWiring(s)
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("靶机起了但 %s 30 秒内连不上：看 docker logs %s", addr, s.Name)
}

// dialOK 探一次 TCP。超时要短：这是健康探测，不是压测。
func dialOK(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// serviceName 把目录名转成 compose 合法的服务名（小写、字母数字与短横线）。
func serviceName(dirName string) string {
	l := strings.ToLower(dirName)
	var b strings.Builder
	prevDash := false
	for _, r := range l {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	s := strings.Trim(b.String(), "-")
	// 去掉 "very-easy-" 这类前缀，容器名短一点更好念（delulu 比 very-easy-delulu 好用）。
	for _, p := range []string{"very-easy-", "easy-", "medium-", "hard-", "very-hard-"} {
		if strings.HasPrefix(s, p) && len(s) > len(p)+2 {
			s = strings.TrimPrefix(s, p)
			break
		}
	}
	if s == "" {
		return "target"
	}
	return s
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "ctftarget: "+msg)
	os.Exit(1)
}

// tmplFuncs 是模板里用到的小函数。path.Base 而不是 filepath.Base：
// Dockerfile 里的路径永远是正斜杠，filepath.Base 在 Windows 上会按反斜杠切分而失败。
var tmplFuncs = template.FuncMap{"base": path.Base}

var dockerfileTmpl = template.Must(template.New("dockerfile").Funcs(tmplFuncs).Parse(`# 由 ` + "`ctftarget`" + ` 生成 —— 改题目结构后重新生成，不要手工改这个文件。
#
# 基础镜像：{{.BaseImage}}
#   选它是因为仓库里一定已经有（沙箱镜像），省一次 docker pull。
#   若二进制需要的 glibc 比它新，换 -base 指向更新的发行版镜像。
FROM {{.BaseImage}}

WORKDIR {{.WorkDir}}

# 二进制本体。路径相对题目录（compose 的 build context）。
COPY {{.Binary}} {{.WorkDir}}/{{base .Binary}}
{{if .InterpRelDir}}
# PT_INTERP 是相对路径（{{.Interp}}）：必须按原目录结构复制，
# 否则内核只报 "no such file or directory"，看起来像二进制损坏。
COPY {{.InterpSource}} {{.WorkDir}}/{{.InterpRelDir}}
{{else if .Interp}}
# PT_INTERP 是绝对路径（{{.Interp}}）：依赖基础镜像里同路径存在，不额外复制。
{{end}}
# flag 只在靶机内部可读 —— 模型要走漏洞才拿得到。
COPY flag.txt /app/flag.txt

COPY .praetor-target/tcp_srv.py /app/tcp_srv.py
RUN chmod +x {{.WorkDir}}/{{base .Binary}}

EXPOSE {{.Port}}
CMD ["python3", "/app/tcp_srv.py"]
`))

// tcpSrvTmpl 用环境变量传二进制与端口，这样同一份脚本能给任何题目用。
var tcpSrvTmpl = template.Must(template.New("tcpsrv").Funcs(tmplFuncs).Parse(`"""最小 TCP fork server（由 ctftarget 生成）。

为什么不用 socat：基础镜像未必装（Kali 就没装），为一个靶机再跑 apt 既慢又依赖源可用。
python3 一定有。

为什么每个连接都 execv 一个新进程：pwn 题（尤其格式化字符串/堆题）在同一进程里
反复交互会带着上一轮的内存布局，模型调试时行为不可复现。
"""
import os
import socket

PORT = int(os.environ.get("PORT", "{{.Port}}"))
BIN = os.environ.get("BIN", "{{.WorkDir}}/{{base .Binary}}")


def main() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(16)
    print(f"listening on :{PORT} -> {BIN}", flush=True)
    while True:
        conn, _ = srv.accept()
        pid = os.fork()
        if pid == 0:
            srv.close()
            os.dup2(conn.fileno(), 0)
            os.dup2(conn.fileno(), 1)
            os.dup2(conn.fileno(), 2)
            conn.close()
            os.chdir(os.path.dirname(BIN))
            try:
                os.execv(BIN, [BIN])
            finally:
                os._exit(1)
        conn.close()
        os.waitpid(pid, os.WNOHANG)


if __name__ == "__main__":
    main()
`))

var composeTmpl = template.Must(template.New("compose").Funcs(tmplFuncs).Parse(`# 由 ` + "`ctftarget`" + ` 生成
services:
  {{.Name}}:
    container_name: {{.Name}}
    build:
      context: ..
      dockerfile: .praetor-target/Dockerfile
    ports:
      - "{{.Port}}:{{.Port}}"
{{if .Network}}    networks:
      - {{.Network}}
{{end}}    healthcheck:
      # 用 python3 而不是 nc：nc 的 -z 并非所有实现都有，缺了会让 healthcheck 永久 unhealthy，
      # 而容器照样 Up —— 看起来正常，实际没在监听。
      test: ["CMD-SHELL", "python3 -c \"import socket;socket.create_connection(('127.0.0.1',{{.Port}}),2).close()\""]
      interval: 10s
      timeout: 5s
      retries: 3
{{if .Network}}
networks:
  {{.Network}}:
    external: true
{{end}}`))
