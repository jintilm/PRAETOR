package server

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jintilm/praetor/config"
	pgdb "github.com/jintilm/praetor/db"
)

// Android 真机动态授权的模式开关。
//
//	required —— 必须由人在创建任务时签发任务级动态授权记录，否则 9 个 mobile_*
//	            工具不注入、动态命令被 guard 拦下。这是上游原本的行为。
//	assume   —— 视为「授权已获得」：不再要求任务级授权记录，op 范围取全量
//	            DynamicOps，目标设备走下面的解析链。
//	            其余约束一律照旧：设备独占锁、adb shell 白名单、取证边界、
//	            审计落库都还在，只是不再挡在入口。
//
// 做成开关而不是直接删掉门禁：授权门禁本身是这套栈的可移植资产，换机器或
// 交给别人部署时按需切回 required 即可，不必改代码重新编译。
const (
	mobileAuthAssume   = "assume"
	mobileAuthRequired = "required"
)

// settingMobileTargetDevice 是 settings 表里存「assume 模式目标设备」的键。
//
// 为什么不用环境变量：上游把设备序列号只存在任务级授权记录里（一任务一设备），
// assume 模式没有那条记录，若默认值只放 PRAETOR_MOBILE_DEVICE_SERIAL，换手机就得
// 改 .env + 重建容器。放进 settings 表后 UI 运行期就能改（见 mobileTargetDevice）。
const settingMobileTargetDevice = "mobile.target_device"

// mobileAuthMode 读授权模式，未配置时默认 assume（授权已获得）。
func mobileAuthMode() string {
	switch strings.ToLower(strings.TrimSpace(config.Env("MOBILE_AUTH_MODE"))) {
	case mobileAuthRequired, "require", "on", "1", "true", "yes":
		return mobileAuthRequired
	default:
		return mobileAuthAssume
	}
}

// mobileAuthAssumed 报告当前是否处于「视为已授权」模式。
func mobileAuthAssumed() bool { return mobileAuthMode() == mobileAuthAssume }

// mobileTargetSerial 解析 assume 模式下的目标设备序列号，按优先级回落：
//
//  1. settings 表的 mobile.target_device —— UI 运行期可改。**键存在即为权威**，
//     显式存空串表示「不锁设备」，不会被下面的环境变量顶回去。
//  2. PRAETOR_MOBILE_DEVICE_SERIAL —— 部署级默认，也作为首次使用的种子。
//  3. 都没有 → 空串，不锁设备。
//
// 第二个返回值是命中来源（setting / env / none），供 UI 与排障显示，
// 免得用户改了值却不知道到底哪一层在生效。
func mobileTargetSerial(pg *pgdb.DB) (serial, source string) {
	if pg != nil {
		if v, ok, err := pg.GetSetting(settingMobileTargetDevice); err == nil && ok {
			return strings.TrimSpace(v), "setting"
		}
	}
	if s := strings.TrimSpace(config.Env("MOBILE_DEVICE_SERIAL")); s != "" {
		return s, "env"
	}
	return "", "none"
}

// mobileTargetSerial 是 Server 侧的便捷包装，pg 不可用时退回环境变量。
func (s *Server) mobileTargetSerial() (string, string) {
	var pg *pgdb.DB
	if s != nil && s.m != nil {
		pg = s.m.pg
	}
	return mobileTargetSerial(pg)
}

// mobileTaskDeviceKey 是「单个任务的目标设备」在 settings 表里的键。
// 沿用 ctf.expected_flag.<taskID> 那种按任务后缀的既有约定，不新开表。
//
// 为什么需要单独一层：全局目标设备是「整机一台」的语义，多机并行时不够用。
// 任务级绑定让创建任务时就能挑设备，且只影响那一个任务 ——
// 于是 A 任务跑手机甲、B 任务跑手机乙，各自持有自己的设备独占锁。
func mobileTaskDeviceKey(taskID int64) string {
	return fmt.Sprintf("mobile.task_device.%d", taskID)
}

// mobileTargetSerialForTask 在全局解析链前面插一层任务级绑定。
//
// 完整优先级（仅 assume 模式使用；required 模式的设备号来自授权记录本身）：
//  1. settings 的 mobile.task_device.<taskID> —— 本任务专属，创建时或详情页设置
//  2. settings 的 mobile.target_device       —— 全局默认
//  3. PRAETOR_MOBILE_DEVICE_SERIAL           —— 部署默认
//  4. 都没有 → 不锁设备
//
// source 多一个 "task" 取值，UI 据此显示到底是哪一层在生效。
func mobileTargetSerialForTask(pg *pgdb.DB, taskID int64) (serial, source string) {
	if pg != nil && taskID > 0 {
		if v, ok, err := pg.GetSetting(mobileTaskDeviceKey(taskID)); err == nil && ok {
			return strings.TrimSpace(v), "task"
		}
	}
	return mobileTargetSerial(pg)
}

// assumedMobileGrant 合成一份「授权已获得」的授权事实。
//
// 它不落库，只在内存里用于解开注入层 / guard 层 / 工具层三处判定；
// 每一次被放行的调用仍会照常写进 dynamic_grant_audits，事后可查。
//
// serial 允许为空：真的没配目标设备时不锁设备（见 dynamicGrantGate.Check），
// 「没有具体设备」不该被独占，也就谈不上多任务互相打架。
func assumedMobileGrant(taskID int64, serial string) *pgdb.DynamicGrant {
	return &pgdb.DynamicGrant{
		TaskID:               taskID,
		GrantRef:             "assumed",
		Operator:             "assumed",
		WrittenAuthorization: true,
		DeviceSerial:         strings.TrimSpace(serial),
		Ops:                  pgdb.DynamicOpNames(),
		ValidFrom:            time.Unix(0, 0).UTC(),
		ValidUntil:           time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
	}
}

// errMobileGrantRevoked 表示该任务签过授权记录，但它已被撤销或已过期。
//
// assume 模式不要求签发授权，但**一旦签了就尊重它** —— 否则「撤销」会退化成
// 「解除限制」：操作人以为按下了停止，任务却拿着全量合成授权继续跑。
// 没签过的任务（g == nil）才走合成，签过的按记录自身的状态定生死。
var errMobileGrantRevoked = errors.New(
	"该任务的动态授权已被撤销或已过期，动态操作已停止；如需继续请新建任务（assume 模式下新任务无需再签发）")

// effectiveMobileGrant 是三个判定层共用的唯一取授权入口。
//
// 这是整套模式切换里最关键的一处，规则按优先级如下：
//
//  1. assume 模式 + 该任务签过且生效的授权 → 用记录本身。人明确写下的范围更具体
//     （可能只开部分 op，也可能指定另一台设备），它是有意的收窄，必须尊重。
//  2. assume 模式 + 该任务签过但已撤销/过期 → 拒绝。见 errMobileGrantRevoked。
//  3. assume 模式 + 从未签过 → 合成一份全量授权，设备取 mobileTargetSerialForTask
//     的解析结果（任务级绑定 > 全局默认 > 部署默认）。
//  4. required 模式 → 一律读库，保持上游语义。
//
// 于是「单任务指定另一台设备」有两条路：签一份带该序列号的授权，或在创建任务时
// 直接选设备（写入任务级绑定）。两种模式下都成立。
func (s *Server) effectiveMobileGrant(taskID int64) (*pgdb.DynamicGrant, error) {
	var pg *pgdb.DB
	if s != nil && s.m != nil {
		pg = s.m.pg
	}
	if mobileAuthAssumed() {
		if pg != nil {
			real, err := pg.GetTaskDynamicGrant(taskID)
			if err != nil {
				return nil, err
			}
			if real != nil {
				if real.Active(time.Now()) {
					return real, nil
				}
				return nil, errMobileGrantRevoked
			}
		}
		serial, _ := mobileTargetSerialForTask(pg, taskID)
		return assumedMobileGrant(taskID, serial), nil
	}
	if pg == nil {
		return nil, errors.New("数据库不可用")
	}
	return pg.GetTaskDynamicGrant(taskID)
}
