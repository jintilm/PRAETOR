package config

import "os"

// 环境变量前缀。
//
// PRAETOR 是项目名（fork 自 ARTEX 后改名）。为了不让既有部署与开发机的 .env /
// shell 静默失效，读取顺序是「新前缀 → 旧前缀」：PRAETOR_X 优先，ARTEX_X 兜底。
// 旧前缀只作为兼容层保留，不再出现在任何脚本与文档的推荐用法里。
const (
	envPrefix       = "PRAETOR_"
	envLegacyPrefix = "ARTEX_"
)

// Env 读取配置项：先 PRAETOR_<key>，再 ARTEX_<key>，都没有返回空串。
// key 不带前缀，例如 Env("PG_DSN") 对应 PRAETOR_PG_DSN / ARTEX_PG_DSN。
func Env(key string) string {
	if v := os.Getenv(envPrefix + key); v != "" {
		return v
	}
	return os.Getenv(envLegacyPrefix + key)
}

// LookupEnv 是 Env 的布尔版，语义与 os.LookupEnv 一致（空值算未设置）。
func LookupEnv(key string) (string, bool) {
	if v, ok := os.LookupEnv(envPrefix + key); ok && v != "" {
		return v, true
	}
	if v, ok := os.LookupEnv(envLegacyPrefix + key); ok && v != "" {
		return v, true
	}
	return "", false
}
