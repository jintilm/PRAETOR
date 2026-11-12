package server

// 任务级动态授权的 HTTP 面：签发字段校验（随任务创建）、只读查询、审计、撤销、设备探测。
//
// 这里**没有**「创建授权」「修改授权」「续期授权」的独立接口 —— 授权只能随任务
// 在创建那一刻由人签发一次，之后只读或撤销。少了这条路，agent 就没有可以诱导
// 服务端扩大授权的入口（工具面里也不存在 grant 类工具）。

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	writeJSON(w, 200, map[string]any{
		"ops":           pgdb.DynamicOpNames(),
		"descriptions":  pgdb.DynamicOps,
		"min_hours":     dynamicGrantMinHours,
		"max_hours":     dynamicGrantMaxHours,
		"default_hours": 8,
	})
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
