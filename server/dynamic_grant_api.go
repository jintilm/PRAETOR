package server

// 任务级动态授权的 HTTP 面：签发字段校验（随任务创建）、只读查询、审计、撤销、设备探测。
//
// 这里**没有**「创建授权」「修改授权」「续期授权」的独立接口 —— 授权只能随任务
// 在创建那一刻由人签发一次，之后只读或撤销。少了这条路，agent 就没有可以诱导
// 服务端扩大授权的入口（工具面里也不存在 grant 类工具）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jintilm/praetor/config"
	pgdb "github.com/jintilm/praetor/db"
)

// dynamicGrantReq 是新建任务抽屉里「Android 动态授权」折叠区的提交内容。
// Enabled=false（默认）= 不签发，任务的所有动态工具调用都会 fail-closed 降级静态。
type dynamicGrantReq struct {
	Enabled              bool     `json:"enabled"`
	WrittenAuthorization bool     `json:"written_authorization"`
	GrantRef             string   `json:"grant_ref"`
	Operator             string   `json:"operator"`
	DeviceSerial         string   `json:"device_serial"`
	APKSha256            string   `json:"apk_sha256"`
	Ops                  []string `json:"ops"`
	ValidHours           int      `json:"valid_hours"`
}

const (
	dynamicGrantMinHours = 1
	dynamicGrantMaxHours = 168 // 7 天；真机授权不该是长期凭据
)

// buildDynamicGrantInput 把前端提交校验成可落库的授权事实。
// 任何字段不合规都返回 400，不静默补默认值 —— 授权字段尤其不能「猜」。
func buildDynamicGrantInput(req *dynamicGrantReq) (*pgdb.DynamicGrantInput, error) {
	if req == nil || !req.Enabled {
		return nil, nil
	}
	if !req.WrittenAuthorization {
		return nil, errors.New("动态授权必须勾选「已取得书面授权」")
	}
	if strings.TrimSpace(req.GrantRef) == "" {
		return nil, errors.New("动态授权必须填写书面授权编号")
	}
	if strings.TrimSpace(req.Operator) == "" {
		return nil, errors.New("动态授权必须填写签发人")
	}
	serial := strings.TrimSpace(req.DeviceSerial)
	if !validDeviceSerial(serial) {
		return nil, errors.New("设备序列号为空或含非法字符（只允许字母数字与 . : - _）")
	}
	hash := strings.ToLower(strings.TrimSpace(req.APKSha256))
	if !validAPKSha256(hash) {
		return nil, errors.New("APK SHA256 必须是 64 位十六进制")
	}
	ops, err := pgdb.ValidDynamicOps(req.Ops)
	if err != nil {
		return nil, err
	}
	hours := req.ValidHours
	if hours == 0 {
		hours = 8
	}
	if hours < dynamicGrantMinHours || hours > dynamicGrantMaxHours {
		return nil, fmt.Errorf("授权有效期须在 %d~%d 小时之间", dynamicGrantMinHours, dynamicGrantMaxHours)
	}
	return &pgdb.DynamicGrantInput{
		GrantRef:             strings.TrimSpace(req.GrantRef),
		Operator:             strings.TrimSpace(req.Operator),
		WrittenAuthorization: true,
		DeviceSerial:         serial,
		APKSha256:            hash,
		Ops:                  ops,
		ValidHours:           hours,
	}, nil
}

func (s *Server) dynamicOpsCatalog(w http.ResponseWriter, _ *http.Request) {
	// device_mode / adb_addr 是只读的运行时前置，供 UI 明确告知「签发授权 ≠ 工具会注入」。
	// 没有这两个字段时用户签完授权只会看到任务静默降级，无从排查。
	serial, source := s.mobileTargetSerial()
	writeJSON(w, 200, map[string]any{
		"ops":           pgdb.DynamicOpNames(),
		"descriptions":  pgdb.DynamicOps,
		"min_hours":     dynamicGrantMinHours,
		"max_hours":     dynamicGrantMaxHours,
		"default_hours": 8,
		"device_mode":   config.Env("MOBILE_DEVICE_MODE") == "1",
		"adb_addr":      mobileADBAddr(),
		"traffic_addr":  config.Env("TRAFFIC_ADDR"),
		// 授权模式：assume（默认）下任务不签发授权记录也能拿到 mobile_* 工具，
		// UI 据此调整文案，避免显示「未签发 → 一律降级静态分析」这种过期说明。
		"auth_mode":    mobileAuthMode(),
		"auth_assumed": mobileAuthAssumed(),
		// 目标设备 + 命中来源（setting / env / none）：改了值却能看出是哪一层在生效。
		"device_serial": serial,
		"device_source": source,
	})
}

// mobileTargetDevice 读写目标设备，支持两个作用域：
//
//	不带 task_id → 全局默认（settings 的 mobile.target_device），影响所有未单独指定的任务
//	带  task_id → 该任务专属（settings 的 mobile.task_device.<id>），只影响这一个任务
//
// 为什么需要它：上游把设备序列号只存在任务级授权记录里，assume 模式没有那条记录，
// 若目标设备只放环境变量，换手机就得改 .env 再重建容器。放进 settings 表后运行期
// 即可切换；任务级那层则让多机并行时每个任务能各占一台设备。
//
// 三种写法，语义互不重叠（少了第三种，用户写一次空值就永久盖住下一层，没有出口退回）：
//
//	{"serial":"R58M1234567"}  指定设备（设备锁按它生效）
//	{"serial":""}             显式不锁设备（盖住下一层）
//	{"reset":true}            删掉本层，回落到下一层
func (s *Server) mobileTargetDevice(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.m == nil || s.m.pg == nil {
		writeErr(w, http.StatusServiceUnavailable, "数据库不可用，无法读写目标设备")
		return
	}
	// task_id 省略 → 全局作用域。解析失败按省略处理，不因为一个坏参数 500。
	taskID, _ := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("task_id")), 10, 64)
	key := settingMobileTargetDevice
	if taskID > 0 {
		key = mobileTaskDeviceKey(taskID)
	}

	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		var req struct {
			Serial string `json:"serial"`
			Reset  bool   `json:"reset"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "请求体不是合法 JSON")
			return
		}
		serial := strings.TrimSpace(req.Serial)
		switch {
		case req.Reset:
			// 回落下一层：删键而不是写空，否则又变成"盖住下一层"。
			if err := s.m.pg.DeleteSetting(key); err != nil {
				writeErr(w, http.StatusInternalServerError, "清除目标设备设置失败："+err.Error())
				return
			}
		default:
			if serial != "" && !validDeviceSerial(serial) {
				writeErr(w, http.StatusBadRequest, "设备序列号非法："+mobileDeviceSerialHint)
				return
			}
			if err := s.m.pg.SetSetting(key, serial); err != nil {
				writeErr(w, http.StatusInternalServerError, "写入目标设备失败："+err.Error())
				return
			}
		}
	}

	// 生效值：带 task_id 时走完整解析链，不带时就是全局那层。
	serial, source := s.mobileTargetSerial()
	if taskID > 0 {
		serial, source = mobileTargetSerialForTask(s.m.pg, taskID)
	}
	// 任务级覆盖单独回传，供 UI 显示「本任务覆盖 X / 跟随全局 Y」。
	taskSerial := ""
	if taskID > 0 {
		if v, ok, err := s.m.pg.GetSetting(mobileTaskDeviceKey(taskID)); err == nil && ok {
			taskSerial = strings.TrimSpace(v)
		}
	}
	globalSerial, globalSource := s.mobileTargetSerial()

	// 顺手列出当前 adb 在线设备：这是只读探测，不装包、不改设备、不抓数据。
	// adb 不通时不该让整个端点失败 —— 用户仍要能看到并改当前值。
	// 只给裸序列号：这个列表的每一项都可能被选中并回写成目标设备，
	// 混进带状态后缀的展示串会让提交必然 400（见 DeviceStatus.SerialList 的注释）。
	st := probeMobileDevice(r.Context(), "")
	devices := st.SerialList
	if devices == nil {
		devices = []string{}
	}
	for _, extra := range []string{serial, globalSerial, st.Serial} {
		if extra != "" && !containsString(devices, extra) {
			devices = append(devices, extra)
		}
	}
	writeJSON(w, 200, map[string]any{
		"serial":        serial,
		"source":        source,
		"scope":         map[bool]string{true: "task", false: "global"}[taskID > 0],
		"task_id":       taskID,
		"task_serial":   taskSerial,
		"global_serial": globalSerial,
		"global_source": globalSource,
		"env_serial":    strings.TrimSpace(config.Env("MOBILE_DEVICE_SERIAL")),
		"auth_mode":     mobileAuthMode(),
		"adb_addr":      mobileADBAddr(),
		"adb_reachable": st.Reachable,
		"devices":       devices,
		"locked":        serial != "",
		"hint":          mobileDeviceSerialHint,
	})
}

// containsString 小工具：设备列表去重判断。
func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// mobileDevices 是只读探测：不装包、不改设备、不抓数据。
// serial 省略时只列设备，Ready 恒为 false。
func (s *Server) mobileDevices(w http.ResponseWriter, r *http.Request) {
	st := probeMobileDevice(r.Context(), r.URL.Query().Get("serial"))
	writeJSON(w, 200, st)
}

func dynamicGrantTaskID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	return id, err == nil && id > 0
}

// taskDynamicGrant 返回授权事实 + 当前判定。已撤销/过期也返回，供审计与排障。
func (s *Server) taskDynamicGrant(w http.ResponseWriter, r *http.Request) {
	id, ok := dynamicGrantTaskID(r)
	if !ok {
		writeErr(w, 400, "bad task id")
		return
	}
	g, err := s.m.pg.GetTaskDynamicGrant(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	state := "none"
	if g != nil {
		state = "active"
		switch {
		case g.RevokedAt != nil:
			state = "revoked"
		case !g.Active(time.Now()):
			state = "expired"
		}
	}
	writeJSON(w, 200, map[string]any{"state": state, "grant": g})
}

func (s *Server) taskDynamicGrantAudits(w http.ResponseWriter, r *http.Request) {
	id, ok := dynamicGrantTaskID(r)
	if !ok {
		writeErr(w, 400, "bad task id")
		return
	}
	items, err := s.m.pg.ListDynamicGrantAudits(id, 100)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

// taskDynamicGrantRevoke 撤销授权：写撤销标记 → 让内存中的闸立刻失效 → 释放设备锁
// → 留一条 revoke 审计。顺序刻意如此：先让 DB 事实生效，再清缓存，
// 避免出现「缓存已清但库里还没撤销」的一瞬间被别的请求读到旧状态。
func (s *Server) taskDynamicGrantRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := dynamicGrantTaskID(r)
	if !ok {
		writeErr(w, 400, "bad task id")
		return
	}
	var req struct {
		Reason   string `json:"reason"`
		Operator string `json:"operator"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		writeErr(w, 400, "撤销原因不能为空")
		return
	}
	g, err := s.m.pg.GetTaskDynamicGrant(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if g == nil {
		writeErr(w, 404, "该任务未签发动态授权")
		return
	}
	changed, err := s.m.pg.RevokeTaskDynamicGrant(id, reason)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if t, ok := s.m.Task(strconv.FormatInt(id, 10)); ok && t != nil && t.dynamicGate != nil {
		t.dynamicGate.Invalidate()
	}
	ctx, cancel := context.WithTimeout(context.Background(), dynamicAuditTimeout)
	defer cancel()
	if err := s.m.pg.ReleaseDeviceLease(ctx, g.DeviceSerial, id); err != nil {
		// 释放失败不回滚撤销：租约会在 TTL 后自动过期，安全边界不依赖这一步。
		log.Printf("[dynamic-grant] 任务 %d 设备锁释放失败（租约将自动过期）：%v", id, err)
	}
	_ = s.m.pg.AppendDynamicGrantAudit(ctx, pgdb.DynamicGrantAudit{
		TaskID: id, Action: "revoke", DeviceSerial: g.DeviceSerial,
		Reason: reason, Operator: strings.TrimSpace(req.Operator),
	})
	if !changed {
		writeJSON(w, 200, map[string]any{"ok": true, "already_revoked": true})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
