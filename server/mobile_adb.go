package server

// adb 协议客户端的「执行侧」扩展。P1 的 adbRequest / adbShell 只做只读探测
// （4s 超时、64KB 上限），动态操作需要更长超时与 sync 通道，所以这里另起一组
// 带显式边界的函数，不改探测路径的行为。
//
// 为什么不用容器里的 adb 二进制：应用容器是 Go runtime 镜像，装不装 adb 取决于
// 组件预置；而 adb server 本来就跑在宿主、只暴露 TCP:5037。平台直接说这个协议，
// 换来「动态操作不依赖任何外部二进制、也不碰 USB」的可复刻性。
//
// 协议参考 AOSP adb/OVERVIEW.TXT 与 system/core/adb/SYNC.TXT。

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	mobileADBOpTimeout   = 90 * time.Second
	mobileADBMaxOutput   = 2 << 20  // 单次 shell 输出上限 2MB
	mobileADBMaxPull     = 8 << 20  // 单次取证拉取上限 8MB
	mobileADBSyncChunk   = 64 << 10 // adb sync 单块上限
	mobileADBRemoteTmp   = "/data/local/tmp/praetor-"
	mobileADBRemoteRegex = `^/data/local/tmp/[A-Za-z0-9_.-]+$`
)

var (
	reMobilePackage = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.]{1,128}$`)
	reMobileRemote  = regexp.MustCompile(mobileADBRemoteRegex)
	// shell 白名单：动态 shell 只提供确定性自省命令，不做通用命令执行。
	// 任意命令请走沙箱里的 Bash（同样受 guard 的 dynamicOpsForCall 授权校验），
	// 但工具面本身不该变成「绕过参数校验的 adb shell 直通车」。
	reMobileShellSafe = regexp.MustCompile(`^(id|ps -A|getprop(?: [A-Za-z0-9_.\-]+)?|pm (?:list|path) [A-Za-z0-9_.\- ]+|dumpsys package [A-Za-z0-9_.]+|settings get (?:global|secure|system) [A-Za-z0-9_.\-]+|ls(?: -[al])? /[A-Za-z0-9_./\-]*|stat /[A-Za-z0-9_./\-]+|cat /proc/version|date|uptime)$`)
	reMobileShellMeta = regexp.MustCompile("[;&|`$><\n\r\\\\]")
)

// adbConn 建立到 adb server 的连接并设置总超时。
func adbConn(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: mobileProbeTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

func adbWriteCmd(conn net.Conn, cmd string) error {
	_, err := io.WriteString(conn, fmt.Sprintf("%04x", len(cmd))+cmd)
	return err
}

// adbReadStatus 读 OKAY/FAIL 状态；FAIL 时把后面的错误正文带回来。
func adbReadStatus(conn net.Conn) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	switch string(head) {
	case "OKAY":
		return nil
	case "FAIL":
		lenBuf := make([]byte, 4)
		_, _ = io.ReadFull(conn, lenBuf)
		n, _ := strconv.ParseUint(string(lenBuf), 16, 32)
		msg := make([]byte, min(int(n), 512))
		_, _ = io.ReadFull(conn, msg)
		return fmt.Errorf("adb 返回 FAIL：%s", strings.TrimSpace(string(msg)))
	default:
		return fmt.Errorf("adb 返回非预期状态 %q", string(head))
	}
}

// adbTransport 把连接切到指定设备。
func adbTransport(conn net.Conn, serial string) error {
	if err := adbWriteCmd(conn, "host:transport:"+serial); err != nil {
		return err
	}
	return adbReadStatus(conn)
}

// adbShellEx 在设备上执行一条命令并回收输出（带可配超时与上限）。
func adbShellEx(ctx context.Context, addr, serial, cmd string, timeout time.Duration, maxBytes int64) (string, error) {
	if timeout <= 0 {
		timeout = mobileADBOpTimeout
	}
	if maxBytes <= 0 {
		maxBytes = mobileADBMaxOutput
	}
	conn, err := adbConn(ctx, addr, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := adbTransport(conn, serial); err != nil {
		return "", err
	}
	if err := adbWriteCmd(conn, "shell:"+cmd); err != nil {
		return "", err
	}
	if err := adbReadStatus(conn); err != nil {
		return "", err
	}
	out, err := io.ReadAll(io.LimitReader(conn, maxBytes))
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(string(out), "\r\n", "\n"), nil
}

// ---- adb sync 通道 ----

func writeSyncCmd(w io.Writer, id string, payload []byte) error {
	if len(id) != 4 {
		return fmt.Errorf("非法 sync 命令 %q", id)
	}
	var hdr [8]byte
	copy(hdr[:4], id)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

type syncResp struct {
	ID      string
	Payload []byte
}

func readSyncResp(r io.Reader) (syncResp, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return syncResp{}, err
	}
	n := binary.LittleEndian.Uint32(hdr[4:])
	if n > mobileADBMaxPull+mobileADBSyncChunk {
		return syncResp{}, fmt.Errorf("sync 响应块过大（%d 字节）", n)
	}
	buf := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, buf); err != nil {
			return syncResp{}, err
		}
	}
	return syncResp{ID: string(hdr[:4]), Payload: buf}, nil
}

// adbSyncPush 把本地文件推到设备 /data/local/tmp/ 下，返回字节数。
func adbSyncPush(ctx context.Context, addr, serial, localPath, remotePath string) (int64, error) {
	if !reMobileRemote.MatchString(remotePath) {
		return 0, fmt.Errorf("设备侧路径只允许 %s*：%q", mobileADBRemoteTmp, remotePath)
	}
	f, err := os.Open(localPath)
	if err != nil {
		return 0, fmt.Errorf("打开本地文件失败：%w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, errors.New("只允许推送普通文件")
	}
	if info.Size() > 512<<20 {
		return 0, fmt.Errorf("文件过大（%d 字节，上限 512MB）", info.Size())
	}
	conn, err := adbConn(ctx, addr, mobileADBOpTimeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if err := adbTransport(conn, serial); err != nil {
		return 0, err
	}
	if err := adbWriteCmd(conn, "sync:"); err != nil {
		return 0, err
	}
	if err := adbReadStatus(conn); err != nil {
		return 0, err
	}
	// SEND 的 payload 是 "<remote path>,<mode>"，mode 为十进制 Unix 权限位。
	if err := writeSyncCmd(conn, "SEND", []byte(remotePath+",33188")); err != nil { // 0100644
		return 0, err
	}
	buf := make([]byte, mobileADBSyncChunk)
	var total int64
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			if err := writeSyncCmd(conn, "DATA", buf[:n]); err != nil {
				return total, err
			}
			total += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return total, readErr
		}
	}
	// DONE 的 payload 是 4 字节 mtime（这里用 0，让设备侧保留推送时间）。
	// 长度写成 0 在部分 adb 版本会被当成畸形包，必须按协议补齐。
	var mtime [4]byte
	if err := writeSyncCmd(conn, "DONE", mtime[:]); err != nil {
		return total, err
	}
	resp, err := readSyncResp(conn)
	if err != nil {
		return total, err
	}
	if resp.ID == "FAIL" {
		return total, fmt.Errorf("adb sync 推送失败：%s", strings.TrimSpace(string(resp.Payload)))
	}
	if resp.ID != "OKAY" {
		return total, fmt.Errorf("adb sync 返回非预期状态 %q", resp.ID)
	}
	return total, nil
}

// adbSyncPull 从设备拉一个文件到内存（调用方负责落盘与脱敏）。
func adbSyncPull(ctx context.Context, addr, serial, remotePath string) ([]byte, error) {
	if !reMobileRemote.MatchString(remotePath) {
		return nil, fmt.Errorf("设备侧路径只允许 %s*：%q", mobileADBRemoteTmp, remotePath)
	}
	conn, err := adbConn(ctx, addr, mobileADBOpTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := adbTransport(conn, serial); err != nil {
		return nil, err
	}
	if err := adbWriteCmd(conn, "sync:"); err != nil {
		return nil, err
	}
	if err := adbReadStatus(conn); err != nil {
		return nil, err
	}
	if err := writeSyncCmd(conn, "RECV", []byte(remotePath)); err != nil {
		return nil, err
	}
	out := make([]byte, 0, mobileADBSyncChunk)
	for {
		resp, err := readSyncResp(conn)
		if err != nil {
			return nil, err
		}
		switch resp.ID {
		case "DATA":
			if int64(len(out))+int64(len(resp.Payload)) > mobileADBMaxPull {
				return nil, fmt.Errorf("拉取内容超过 %d 字节上限，已中止", mobileADBMaxPull)
			}
			out = append(out, resp.Payload...)
		case "DONE":
			return out, nil
		case "FAIL":
			return nil, fmt.Errorf("adb sync 拉取失败：%s", strings.TrimSpace(string(resp.Payload)))
		default:
			return nil, fmt.Errorf("adb sync 返回非预期状态 %q", resp.ID)
		}
	}
}

// mobileAPKLocalPath 把模型给的 APK 路径翻到应用进程能读的宿主路径。
// 模型在沙箱里看到的是 /work/...，宿主侧对应 <workRoot>/<taskID>/。
func (s *Server) mobileAPKLocalPath(taskID int64, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("apk_path 不能为空")
	}
	if strings.Contains(raw, "..") {
		return "", errors.New("apk_path 不允许包含 ..")
	}
	root := filepath.Join(localSandboxWorkRoot(s.m.DataDir()), strconv.FormatInt(taskID, 10))
	var local string
	switch {
	case strings.HasPrefix(raw, "/work/"):
		local = filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(raw, "/work/")))
	case filepath.IsAbs(raw):
		local = raw // 宿主二进制部署：模型看到的就是宿主路径
	default:
		local = filepath.Join(root, filepath.FromSlash(raw))
	}
	local = filepath.Clean(local)
	if !strings.HasPrefix(local, filepath.Clean(root)+string(os.PathSeparator)) && local != filepath.Clean(root) {
		return "", errors.New("apk_path 必须位于本任务工作区内")
	}
	info, err := os.Stat(local)
	if err != nil {
		return "", fmt.Errorf("APK 不可读（%s）：%w", raw, err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("apk_path 必须是普通文件")
	}
	return local, nil
}
