package server

// 真机任务的收尾清理：设备不是容器，没有「删掉即回滚」这回事。
// 任务结束或主动调用 mobile_cleanup 时，必须把设备恢复到下一个任务能接手的状态：
// 清目标 App 数据、复位全局代理、删推送到 /data/local/tmp 的临时 APK、释放设备独占锁。
//
// 与授权链的关系：收尾清理是**平台义务**，不受 ops 白名单约束 —— 若只有勾了
// cleanup 的任务才清理，没勾的任务会把脏环境留给下一台任务，反而更危险。
// 但每次清理都写 append-only 审计，且只作用于授权里签发的那台设备与目标包。

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	pgdb "github.com/jintilm/praetor/db"
	actool "github.com/jintilm/praetor/internal/norma/tool"
)

const mobileCleanupTimeout = 45 * time.Second

// performMobileCleanup 执行确定性收尾，返回一段人读日志。
// 单项失败不中断后续项：复位代理失败不该让设备锁永远不释放。
func (s *Server) performMobileCleanup(taskID int64, g *pgdb.DynamicGrant, pkg string) (string, error) {
	if s == nil || s.m == nil || s.m.pg == nil || g == nil {
		return "", fmt.Errorf("无效的收尾上下文")
	}
	ctx, cancel := context.WithTimeout(context.Background(), mobileCleanupTimeout)
	defer cancel()
	addr := mobileADBAddr()
	steps := []struct {
		name string
		cmd  string
	}{
		{"reset_proxy", "settings put global http_proxy :0"},
		{"delete_proxy_host", "settings delete global global_http_proxy_host"},
		{"delete_proxy_port", "settings delete global global_http_proxy_port"},
		{"remove_tmp_apk", "rm -f /data/local/tmp/praetor-*.apk"},
	}
	if pkg != "" {
		steps = append(steps, struct{ name, cmd string }{"clear_app_data", "pm clear " + pkg})
	}
	var b strings.Builder
	problems := 0
	for _, st := range steps {
		out, err := adbShellEx(ctx, addr, g.DeviceSerial, st.cmd, 15*time.Second, 64<<10)
		if err != nil {
			problems++
			b.WriteString(st.name + ": 失败（" + err.Error() + "）\n")
			continue
		}
		clean := strings.TrimSpace(sanitizeMobileEvidence(out))
		if clean == "" {
			clean = "ok"
		}
		b.WriteString(st.name + ": " + clean + "\n")
	}
	// frida-server 是签发人在设备上自行启动/管理的进程：平台不主动 kill，
	// 否则可能杀掉设备主人自己的服务。只做可见性检查并如实报告。
	if out, err := adbShellEx(ctx, addr, g.DeviceSerial, "ps -A", 15*time.Second, 64<<10); err == nil {
		if strings.Contains(strings.ToLower(out), "frida") {
			b.WriteString("frida_server: 仍可见，需签发人在设备上自行停止（平台不代管设备进程）\n")
		} else {
			b.WriteString("frida_server: 未检测到\n")
		}
	} else {
		b.WriteString("frida_server: 状态无法判定（" + err.Error() + "）\n")
	}
	if err := s.m.pg.ReleaseDeviceLease(ctx, g.DeviceSerial, taskID); err != nil {
		problems++
		b.WriteString("release_device_lease: 失败（" + err.Error() + "），租约将在 TTL 后自动过期\n")
	} else {
		b.WriteString("release_device_lease: ok\n")
	}
	_ = s.m.pg.AppendDynamicGrantAudit(ctx, pgdb.DynamicGrantAudit{
		TaskID: taskID, Action: "cleanup", Op: "cleanup", Tool: "server",
		DeviceSerial: g.DeviceSerial,
		Reason:       fmt.Sprintf("设备收尾：%d 项未完成；目标包=%s", problems, pkg),
	})
	return b.String(), nil
}

// mobileCleanupResult 是 mobile_cleanup 工具的返回封装。
func (s *Server) mobileCleanupResult(taskID int64, g *pgdb.DynamicGrant, pkg, trigger string) (actool.Result, error) {
	text, err := s.performMobileCleanup(taskID, g, pkg)
	if err != nil {
		return actool.Errorf(err.Error()), nil
	}
	_, view, eerr := s.saveMobileEvidence(taskID, "cleanup", "cleanup", "cleanup",
		"触发="+trigger+" 目标包="+pkg, text)
	if eerr != nil {
		return actool.Errorf("证据落盘失败：" + eerr.Error()), nil
	}
	return jsonResult(map[string]any{
		"ok": true, "trigger": trigger, "device": g.DeviceSerial,
		"package": pkg, "output_preview": view,
		"note": "已释放设备独占锁；frida-server 若由签发人手工启动，仍需自行停止。",
	})
}

// onTaskTerminal 由 Manager 在任务落到终态时回调（见 manager.SetTaskStatus*）。
// 异步执行：状态落库不能被 adb TCP 往返拖住；用独立 context 避免继承已取消的任务 ctx。
func (s *Server) onTaskTerminal(taskID int64, status string) {
	if taskID <= 0 {
		return
	}
	id := strconv.FormatInt(taskID, 10)
	if t, ok := s.m.Task(id); ok && t != nil && t.dynamicGate != nil {
		// 让内存令牌立即作废，杜绝「任务结束了但令牌还在 10 分钟窗口内」。
		t.dynamicGate.Invalidate()
	}
	go func() {
		// performMobileCleanup 内部自带独立超时 context；这里不继承已取消的任务 ctx。
		g, err := s.m.pg.GetTaskDynamicGrant(taskID)
		if err != nil {
			log.Printf("[dynamic-grant] 任务 %d 收尾读取授权失败（设备锁将靠租约过期）：%v", taskID, err)
			return
		}
		if g == nil {
			return // 普通任务：连授权都没有，不需要碰任何设备
		}
		pkg := ""
		// 目标包从证据索引里的 launch/install 记录里拿不到就直接留空：
		// 不猜包名，避免 pm clear 掉设备上的其它 App。
		text, err := s.performMobileCleanup(taskID, g, pkg)
		if err != nil {
			log.Printf("[dynamic-grant] 任务 %d（终态 %s）收尾失败：%v", taskID, status, err)
			return
		}
		log.Printf("[dynamic-grant] 任务 %d（终态 %s）设备收尾完成：\n%s", taskID, status, text)
	}()
}
