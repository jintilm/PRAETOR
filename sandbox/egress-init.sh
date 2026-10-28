#!/bin/sh
# praetor-egress —— 沙箱容器的全量出口隐身（IP 层透明重定向，v1）
#
# 由 runner 在容器创建后 exec 执行。读取注入的环境变量（密码走 env 不走 argv：
# argv 会进 docker inspect，容器内任何进程都读得到 /proc/*/cmdline）：
#   PRAETOR_EGRESS_TYPE    socks5 | http-connect（redsocks relay 类型）
#   PRAETOR_EGRESS_HOST    上游地址（已由 runner 翻译成容器可达形式）
#   PRAETOR_EGRESS_PORT    上游端口
#   PRAETOR_EGRESS_USER/PASS   可选认证
#   PRAETOR_EGRESS_EXCLUDE 额外直连绕过（逗号分隔 host[:port]，如 MITM 录制代理）
#
# 行为：写 redsocks 配置 → 起 redsocks → iptables 把全部出站 TCP（除保留网段、
# 上游自身、EXCLUDE 名单）REDIRECT 到本地 12345。
#
# 三个边界（文档同步说明，这里不过度设计）：
#   - 只代理 TCP：SYN 扫描（nmap -sS/masscan）承载不了，隐身语义下用 -sT；
#   - DNS：Docker 内嵌 resolver 从宿主发查询，目标侧权威 DNS 看到的是宿主 IP；
#     上游是 mihomo/Clash 时可把容器 --dns 指向其 DNS 监听顺带解决（部署选项）；
#   - 内网目标（RFC1918/链路本地/多播）直连 —— 本地靶场必须可达，不能发给外部代理。
set -eu

TYPE="${PRAETOR_EGRESS_TYPE:-}"
HOST="${PRAETOR_EGRESS_HOST:-}"
PORT="${PRAETOR_EGRESS_PORT:-}"
if [ -z "$TYPE" ] || [ -z "$HOST" ] || [ -z "$PORT" ]; then
    echo "[egress] 上游未配置，跳过（容器直连）"
    exit 0
fi

# redsocks 的 ip 字段要**纯 IP**：传主机名时它自己解析的结果与 iptables 规则里
# 固化的 IP 可能不一致（实测 host.docker.internal 被它解析到另一个接口 → 连接被拒）。
# 这里在容器内解析一次，写进配置与 iptables 规则的必然是同一个地址。
RESOLVED=$(getent ahostsv4 "$HOST" 2>/dev/null | awk '{print $1; exit}')
if [ -n "$RESOLVED" ]; then
    HOST="$RESOLVED"
fi

LOGIC_PORT=12345

# ---- redsocks 配置 ----
mkdir -p /etc/redsocks /var/log/redsocks 2>/dev/null || mkdir -p /etc/redsocks
{
    echo "base {"
    echo "    log_debug = off;"
    echo "    log_info = on;"
    echo "    log = \"file:/tmp/praetor-egress.log\";"
    echo "    daemon = on;"
    echo "    redirector = iptables;"
    echo "}"
    echo "redsocks {"
    echo "    local_ip = 127.0.0.1;"
    echo "    local_port = ${LOGIC_PORT};"
    echo "    ip = \"${HOST}\";"
    echo "    port = ${PORT};"
    echo "    type = ${TYPE};"
    [ -n "${PRAETOR_EGRESS_USER:-}" ] && echo "    login = \"${PRAETOR_EGRESS_USER}\";"
    [ -n "${PRAETOR_EGRESS_PASS:-}" ] && echo "    password = \"${PRAETOR_EGRESS_PASS}\";"
    echo "}"
} > /etc/redsocks.conf

redsocks -c /etc/redsocks.conf
# 等监听就绪再打规则，否则最初的几条连接会落空
# （/dev/tcp 是 bashism，容器的 sh 是 dash；nc 基础镜像已装）
i=0
while [ $i -lt 20 ]; do
    nc -z 127.0.0.1 "$LOGIC_PORT" >/dev/null 2>&1 && break
    i=$((i + 1))
    sleep 0.2
done

# ---- iptables：全部出站 TCP → redsocks，例外见下 ----
iptables -t nat -N PRAETOR_EGRESS 2>/dev/null || iptables -t nat -F PRAETOR_EGRESS
iptables -t nat -A PRAETOR_EGRESS -o lo -j RETURN

# 上游自身最先排除 —— 顺序是生死线：host.docker.internal 解析出来的正是
# 192.168.65.x（Docker Desktop）或 172.17.0.1（Linux host-gateway），若先走
# 下面的私网段 RETURN，发往代理的连接被"本地直连"放行，透明层静默失效。
iptables -t nat -A PRAETOR_EGRESS -d "$HOST" -p tcp --dport "$PORT" -j RETURN

# 部署方指定的额外绕过（host 或 host:port）
if [ -n "${PRAETOR_EGRESS_EXCLUDE:-}" ]; then
    echo "$PRAETOR_EGRESS_EXCLUDE" | tr ',' '\n' | while IFS= read -r item; do
        [ -n "$item" ] || continue
        case "$item" in
            *:*) iptables -t nat -A PRAETOR_EGRESS -d "${item%:*}" -p tcp --dport "${item##*:}" -j RETURN ;;
            *)   iptables -t nat -A PRAETOR_EGRESS -d "$item" -j RETURN ;;
        esac
    done
fi

# 保留/本地网段直连：本地靶场与内网目标必须可达（发往外部代理反而不可达）。
# 注意必须排在上游排除之后 —— 见上。
for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 \
           172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
    iptables -t nat -A PRAETOR_EGRESS -d "$net" -j RETURN
done

iptables -t nat -A PRAETOR_EGRESS -p tcp -j REDIRECT --to-ports "$LOGIC_PORT"
iptables -t nat -C OUTPUT -j PRAETOR_EGRESS 2>/dev/null || iptables -t nat -A OUTPUT -j PRAETOR_EGRESS

echo "[egress] 已启用：全部出站 TCP → ${TYPE}://${HOST}:${PORT}（本地网段直连）"
