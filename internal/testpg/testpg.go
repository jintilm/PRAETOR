// Package testpg 是所有依赖 PostgreSQL 的集成测试的【唯一门】。
//
// 之前 db / agent / evidence / llmrec / server 五个包各写一套「有库就跑」的判断，
// 行为不一致：有的 skip、有的 t.Fatal、evidence 直接在 TestMain 里 panic，
// 于是没库时 `go test ./...` 一半红一半绿——红的并不代表代码坏，只代表环境缺。
//
// 统一成三条规则：
//
//  1. 没配置数据库      → skip（环境缺失，不是代码缺陷）
//  2. 目标库不是专门的测试库（名字必须以 _test 结尾） → skip
//  3. 服务连不上        → skip
//
// 规则 2 是数据安全红线：这些集成测试会建表 + DELETE 行。仓库默认的
// PRAETOR_PG_DSN 指向开发库 praetor（见 config），一旦拿它跑测试就会清掉开发数据。
// 逃生口仅用于一次性实例：PRAETOR_TEST_ALLOW_NON_TEST_DB=1。
//
// 本包只被 _test.go 引用，不会被任何生产代码 import，因此不会进二进制。
package testpg

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jintilm/praetor/config"
)

const pingTimeout = 3 * time.Second

// DSN 返回集成测试用的 DSN，并校验规则 1、2。返回 error 即表示应当 skip。
func DSN() (string, error) {
	dsn, src, err := config.PostgresDSN()
	if err != nil {
		return "", fmt.Errorf("no database config: %w", err)
	}
	if name := DBName(dsn); !strings.HasSuffix(name, "_test") && config.Env("TEST_ALLOW_NON_TEST_DB") != "1" {
		return "", fmt.Errorf("拒绝在非测试库 %q 上运行（来源：%s）：这些用例会建表并 DELETE 数据。"+
			"请把 PRAETOR_PG_DSN 指向独立的 *_test 库（如 .../praetor_test，db.Open 会自动建库），"+
			"或显式设 PRAETOR_TEST_ALLOW_NON_TEST_DB=1", name, src)
	}
	return dsn, nil
}

// Require 是测试侧的入口：库不可用时 skip 而不是 fail。
// 返回值保证可连，调用方直接 db.Open 即可。
func Require(tb testing.TB) string {
	tb.Helper()
	dsn, err := DSN()
	if err != nil {
		tb.Skip(err)
	}
	if err := Ping(dsn); err != nil {
		tb.Skipf("postgres unavailable (%v)", err)
	}
	return dsn
}

// Available 供 TestMain 使用（那个位置拿不到 testing.TB）。
func Available() bool {
	dsn, err := DSN()
	if err != nil {
		return false
	}
	return Ping(dsn) == nil
}

// Ping 在 pingTimeout 内验证连通性。
func Ping(dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	return db.PingContext(ctx)
}

// resetKeep 是【配置面】表白名单：跨用例共享的安装态数据（agent 定义、提示词、
// MCP 服务器、工具开关、分类/模板）。其余表一律视为测试产生的数据。
//
// llm_profiles / llm_profile_health / settings 刻意【不】在白名单里：
//   - llm_profiles：看着像配置，但 *_test 库里全是用例自己造的（conv-pick / t-lane-*），
//     保留会让「第一次跑通过、第二次撞 llm_profiles_name_key」—— -count=2 必红，
//     红的是用例自己的唯一键，不是被测代码；
//   - settings：它是**播种标记**（如 finding_retester_seed_v1）与运行开关的家。保留它
//     而清空 agents，就会出现「标记说已播种、目标行不存在」的不一致 —— 启动时
//     seedFindingRetester 看到 flag=true 直接返回，retester 永远缺失，四条
//     TestRetest* 报 409。清掉它让所有 seed 每次从零重跑（幂等，几十毫秒），
//     状态自然一致。
//
// 真实的运营配置在开发库 praetor 里，不会被这里碰到。
//
// 用白名单而不是黑名单：以后新增的表默认被清空。反过来漏清一张表，代价是套件
// 随跑次累积——2026-10-29 实测 praetor_test 攒到 2261 个任务（1686 个 created），
// Manager 启动时把它们全恢复成后台 goroutine，server 包整包 10 分钟超时，
// 而红灯只指向「expected goal nodes seeded, got 0」这种无关断言。
var resetKeep = map[string]bool{
	"schema_migrations":      true,
	"agents":                 true,
	"agent_prompts":          true,
	"agent_prompt_vars":      true,
	"agent_visibility":       true,
	"agent_skill_visibility": true,
	"agent_triggers":         true,
	"mcp_servers":            true,
	"mcp_tools_cache":        true,
	"tools":                  true,
	"task_categories":        true,
	"task_templates":         true,
}

// ResetData 清空测试库里的【数据面】表（保留 resetKeep 的配置面），返回清掉的表数。
//
// 调用点在各包的 TestMain 拿到 advisory lock（7337741002）之后：那把锁保证同一时刻
// 只有一个测试包在跑，所以清库不会打断别的包。
//
// 必须显式 Reset 而不是靠各用例自己收拾：用例只清自己建的行，一旦某个用例中途
// t.Fatalf/skip/被 -timeout 杀掉，残留就永久留下。累积到几百个非终态任务后，
// Manager 会把它们当"重启恢复"逐个拉起来，整个包变慢直到 10 分钟超时——此时
// 报错的是某个完全无关的断言，排查方向会被带偏。
func ResetData(dsn string) (int, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`)
	if err != nil {
		return 0, err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return 0, err
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	target := resetTargets(tables)
	if len(target) == 0 {
		return 0, nil
	}
	// 一条语句清全部：单事务，避免"清到一半失败"留下半干净状态。
	// CASCADE 处理外键顺序，RESTART IDENTITY 让 id 从 1 开始（用例里的固定 id 假设更稳）。
	if _, err := db.Exec(truncateStmt(target)); err != nil {
		return 0, err
	}
	return len(target), nil
}

// resetTargets 从库里实际存在的表里挑出要清空的那些：配置面白名单之外的全部。
// 抽成纯函数是为了能单测——这个判断错了会要么清掉安装态配置、要么留下数据面残留。
func resetTargets(tables []string) []string {
	out := make([]string, 0, len(tables))
	for _, name := range tables {
		if !resetKeep[name] {
			out = append(out, name)
		}
	}
	return out
}

// truncateStmt 拼出 TRUNCATE 语句。表名来自 pg_tables（不是用户输入），
// 仍按标识符规则加双引号：库里的表名大小写敏感，且这样拼不会产生语法歧义。
func truncateStmt(tables []string) string {
	quoted := make([]string, len(tables))
	for i, name := range tables {
		quoted[i] = `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
	}
	return "TRUNCATE TABLE " + strings.Join(quoted, ", ") + " RESTART IDENTITY CASCADE"
}

// DBName 从 DSN 里取库名；解析不出来时返回 ""，从而让 _test 后缀检查失败
// —— fail closed，绝不默认「安全」。
//
// 实现在 config 包里（server.NewManager 的生产侧联锁也要用它，而本包引了 testing，
// 生产代码不能依赖它）。这里保留一层转调，让既有调用方不必改名。
func DBName(dsn string) string { return config.DatabaseName(dsn) }
