package server

// 报告模板的移动端目标信息，统一在这里取数与解析。
//
// 数据只来自两处：任务动态授权记录（设备序列号、APK SHA256，是事实，撤销后
// 也保留供溯源）与发现正文（包名 / 版本，正则提取，可能缺失）。渲染层不查库，
// 报告页与导出走同一个函数，避免「页面显示一份、导出写另一份」。
//
// 平台判定刻意保守：只认明确的移动端特征词，不因为文本里出现 "app" 就把
// Web 任务误判成移动端 —— 一旦误判，补天模板会把漏洞类别改推成 IOT。

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jintilm/praetor/db"
	"github.com/jintilm/praetor/report"
)

var (
	reReportMobileAndroid = regexp.MustCompile(`(?i)\b(android|apk|apktool|adb|androidmanifest)\b`)
	reReportMobileIOS     = regexp.MustCompile(`(?i)\b(ios|ipados|iphone|ipa)\b|info\.plist|cfbundle|mach-o`)
	// 解包产物里常见 package="com.x.y"；JSON 转义成 package=\"com.x.y\" 也要命中。
	reReportMobilePackage = regexp.MustCompile(`(?i)package\s*[=:：]\s*["'\\]{0,2}([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)`)
	reReportMobileVersion = regexp.MustCompile(`(?i)(?:versionName|应用版本|版本号|版本)\s*[=:：]\s*["'\\]{0,2}([0-9][A-Za-z0-9._-]*)`)
	reReportMobileBundle  = regexp.MustCompile(`(?is)CFBundleIdentifier.{0,160}?<string>([^<]+)</string>`)
)

// grantFor 读一条授权事实。查不到（无授权 / DB 不可用）返回 nil，不阻断报告。
func (s *Server) grantFor(taskID int64) *db.DynamicGrant {
	if s == nil || s.m == nil || s.m.pg == nil || taskID <= 0 {
		return nil
	}
	g, err := s.m.pg.GetTaskDynamicGrant(taskID)
	if err != nil {
		return nil
	}
	return g
}

// mobileMetaFor 是报告页 / 单条导出用的入口；批量路径请用 mobileMetaWithGrant
// 配一个 grant 缓存，避免每条 finding 打一次库。
func (s *Server) mobileMetaFor(taskID int64, texts ...string) report.MobileMeta {
	return s.mobileMetaWithGrant(s.grantFor(taskID), texts...)
}

func (s *Server) mobileMetaWithGrant(grant *db.DynamicGrant, texts ...string) report.MobileMeta {
	var m report.MobileMeta
	if grant != nil {
		m.DeviceSerial = grant.DeviceSerial
		m.APKSha256 = grant.APKSha256
	}
	blob := strings.Join(texts, "\n")
	switch {
	case reReportMobileIOS.MatchString(blob):
		m.Platform = "iOS"
	case grant != nil || reReportMobileAndroid.MatchString(blob):
		m.Platform = "Android"
	}
	if pm := reReportMobilePackage.FindStringSubmatch(blob); len(pm) == 2 {
		m.Package = pm[1]
	} else if bm := reReportMobileBundle.FindStringSubmatch(blob); len(bm) == 2 {
		m.Package = strings.TrimSpace(bm[1])
	}
	if vm := reReportMobileVersion.FindStringSubmatch(blob); len(vm) == 2 {
		m.Version = vm[1]
	}
	m.Present = grant != nil || m.Platform != "" || m.Package != ""
	if !m.Present {
		return report.MobileMeta{}
	}
	switch {
	case grant != nil && (m.Package != "" || m.Version != ""):
		m.Source = "任务动态授权记录 + 发现正文解析（包名 / 版本建议人工核对）"
	case grant != nil:
		m.Source = "任务动态授权记录；包名 / 版本未在正文中检出"
	default:
		m.Source = "发现正文解析（无授权记录，建议人工核对）"
	}
	return m
}

func viewTaskID(f *db.DBFinding, t *Task) int64 {
	if f != nil && f.TaskID != nil {
		return *f.TaskID
	}
	if t != nil {
		if id, err := strconv.ParseInt(t.ID, 10, 64); err == nil {
			return id
		}
	}
	return 0
}

func taskNumericID(t *Task) int64 {
	if t == nil {
		return 0
	}
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// mobileMetaTexts 取单份 View 里可能含包名 / 版本的自由文本。
func mobileMetaTexts(v report.View) []string {
	return []string{v.TaskDescription, v.Name, v.Summary, v.Evidence, v.Report}
}

// taskMobileMeta 给报告页展示同一份移动端目标信息。
// 探索图节点转成 View 只为复用字段解析，不做任何模板渲染。
func (s *Server) taskMobileMeta(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad task id")
		return
	}
	texts := []string{}
	if t := s.taskByID(&id); t != nil {
		texts = append(texts, t.Description, t.Goal)
		if t.Store != nil {
			nodes, _ := t.Store.ListByKind(db.KindFinding, 1000)
			for _, n := range nodes {
				if n == nil {
					continue
				}
				v := report.ViewFromNode(n, time.Now())
				texts = append(texts, v.Name, v.Summary, v.Evidence)
			}
		}
	}
	writeJSON(w, 200, s.mobileMetaFor(id, texts...))
}
