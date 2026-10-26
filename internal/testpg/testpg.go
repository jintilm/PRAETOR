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
// ARTEX_PG_DSN 指向开发库 artex（见 config），一旦拿它跑测试就会清掉开发数据。
// 逃生口仅用于一次性实例：ARTEX_TEST_ALLOW_NON_TEST_DB=1。
//
// 本包只被 _test.go 引用，不会被任何生产代码 import，因此不会进二进制。
package testpg

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/config"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const pingTimeout = 3 * time.Second

// DSN 返回集成测试用的 DSN，并校验规则 1、2。返回 error 即表示应当 skip。
func DSN() (string, error) {
	dsn, src, err := config.PostgresDSN()
	if err != nil {
		return "", fmt.Errorf("no database config: %w", err)
	}
	if name := DBName(dsn); !strings.HasSuffix(name, "_test") && os.Getenv("ARTEX_TEST_ALLOW_NON_TEST_DB") != "1" {
		return "", fmt.Errorf("拒绝在非测试库 %q 上运行（来源：%s）：这些用例会建表并 DELETE 数据。"+
			"请把 ARTEX_PG_DSN 指向独立的 *_test 库（如 .../artex_test，db.Open 会自动建库），"+
			"或显式设 ARTEX_TEST_ALLOW_NON_TEST_DB=1", name, src)
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

// DBName 从两种 DSN 形态（postgres:// URL 或 host=… dbname=…）里取库名。
// 解析不出来时返回 ""，从而让 _test 后缀检查失败——fail closed，绝不默认「安全」。
func DBName(dsn string) string {
	dsn = strings.TrimSpace(dsn)
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return ""
		}
		return strings.TrimPrefix(u.Path, "/")
	}
	for _, kv := range strings.Fields(dsn) {
		if v, ok := strings.CutPrefix(kv, "dbname="); ok {
			return strings.Trim(v, `'"`)
		}
	}
	return ""
}
