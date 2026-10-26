package sandbox

import (
	"errors"
	"os/exec"
	"sort"
	"strconv"
)

// asExitError 把「命令跑了但非零退出」与「压根没跑起来」区分开：
// 前者要保留退出码回给模型，后者才是执行失败。
func asExitError(err error, target **exec.ExitError) bool {
	return errors.As(err, target)
}

// sortedKeys 保证 -e 参数顺序稳定（便于断言与日志复现）。
func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// itoa 只是让 docker.go 的报错少一次 strconv 引入。
func itoa(n int) string { return strconv.Itoa(n) }
