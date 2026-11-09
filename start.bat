@echo off
rem 控制台切 UTF-8，否则本文件里的中文在 GBK 终端下是乱码。
chcp 65001 >nul 2>&1
rem PRAETOR 守护启动脚本（Windows）
rem
rem 用法：
rem   start.bat                  前台运行（Ctrl-C 停止）
rem   start.bat -addr :9000      额外参数原样透传给 praetor
rem
rem 它只做一件事：把 praetor.exe 跑起来，进程退出后按退出码决定要不要再拉起。
rem
rem   0      用户正常停止     -> 退出循环
rem   75     程序请求重启     -> 立刻重跑（页面点了"一键更新"或"回滚"）
rem   其他   崩溃             -> 退避后重跑（1->2->4…最多 60 秒）
rem
rem 下载、SHA256 校验、换装都不在这里，全部由 praetor 自己在启动时完成
rem （selfupdate 包）。脚本保持傻瓜化，详见 start.sh 顶部的说明。

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "BIN=praetor.exe"
if not exist "%BIN%" (
	echo [praetor] 找不到可执行文件 %BIN% 1>&2
	exit /b 1
)

rem 二进制只读 config.json 和进程环境变量，**不读 .env**（.env 属于 docker compose）。
rem 这里把 .env 搬进环境并组装 PRAETOR_PG_DSN，否则启动日志会显示
rem 「未检测到任何 PRAETOR_* 变量」，而 config.json 常按容器内端口写、连不上库。
rem 只取白名单键，不 source 整个文件；已显式 set 的变量一律不覆盖。
rem 随机生成的数据库密码只含字母数字，不会与延迟展开的 ! 冲突。
if exist ".env" (
	for /f "usebackq tokens=1,* delims==" %%A in (`findstr /b /c:"PRAETOR_" ".env" 2^>nul`) do (
		if not defined %%A set "%%A=%%B"
	)
	for /f "usebackq tokens=1,* delims==" %%A in (`findstr /b /c:"POSTGRES_PASSWORD=" /c:"POSTGRES_USER=" /c:"POSTGRES_DB=" ".env" 2^>nul`) do (
		if "%%A"=="POSTGRES_PASSWORD" set "PGPASS=%%B"
		if "%%A"=="POSTGRES_USER" set "PGUSER=%%B"
		if "%%A"=="POSTGRES_DB" set "PGDB=%%B"
	)
)
if not defined PGUSER set "PGUSER=praetor"
if not defined PGDB set "PGDB=praetor"
if not defined PGPORT set "PGPORT=!PRAETOR_PG_PORT!"
if not defined PGPORT set "PGPORT=55433"
if not defined PRAETOR_PG_DSN (
	if defined PGPASS (
		if not "!PGPASS!"=="change-me-please" (
			set "PRAETOR_PG_DSN=postgres://!PGUSER!:!PGPASS!@127.0.0.1:!PGPORT!/!PGDB!?sslmode=disable"
			echo [praetor] 已从 .env 组装 PRAETOR_PG_DSN (127.0.0.1:!PGPORT!/!PGDB!)
		)
	)
)

set "RESTART_CODE=75"
set "MAX_DELAY=60"
set /a delay=1

:loop
"%BIN%" %*
set "code=!ERRORLEVEL!"

if "!code!"=="0" (
	echo [praetor] 正常退出
	exit /b 0
)

if "!code!"=="%RESTART_CODE%" (
	rem 更新/回滚已就绪：重跑后 praetor 会在启动时完成换装。
	echo [praetor] 请求重启（应用新版本）…
	set /a delay=1
	goto loop
)

echo [praetor] 异常退出 ^(code=!code!^)，!delay!s 后重启 1>&2
rem timeout 在被重定向的控制台里会失败，用 ping 兜底（延时 N 秒需要 N+1 次）。
set /a pings=!delay!+1
ping -n !pings! 127.0.0.1 >nul 2>&1
set /a delay=!delay!*2
if !delay! gtr %MAX_DELAY% set /a delay=%MAX_DELAY%
goto loop
