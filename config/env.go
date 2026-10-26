package config

import "os"

// 环境变量前缀。PRAETOR 是独立项目，**只读 PRAETOR_***，不兼容 ARTEX_*。
//
// 这是一次有意的硬切：新旧两套栈各自部署、互不影响，配置也各管各的。
// 之前的「PRAETOR_ 优先 + ARTEX_ 兜底」已移除——那种兼容看似安全，实际会让
// 开发机 shell 里的旧变量悄悄污染新进程（同机两套栈并存时尤其危险）。
const envPrefix = "PRAETOR_"

// Env 读取配置项，key 不带前缀：Env("PG_DSN") 读 PRAETOR_PG_DSN。
func Env(key string) string {
	return os.Getenv(envPrefix + key)
}

// LookupEnv 是 Env 的布尔版，语义与 os.LookupEnv 一致（空值算未设置）。
func LookupEnv(key string) (string, bool) {
	v, ok := os.LookupEnv(envPrefix + key)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}
