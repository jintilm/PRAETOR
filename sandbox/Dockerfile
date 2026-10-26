# PRAETOR 工具沙箱（形态 A：常驻容器 + docker exec）
#
# 设计取舍：
#   - 用 Kali rolling 作底座：渗透工具生态最全，P1 接入 nmap/sqlmap/nuclei 等直接 apt/uv 装。
#   - 常驻 `sleep infinity`：agent 每次 Bash 是 `docker exec`，无冷启动。
#   - 只装「最小可用集」：真正按域加载的工具链（pwn/rev/AD）在 P1/P2 增量加，
#     避免镜像一开始就有几个 GB、构建十几分钟。
#   - 不加 privileged、不挂 docker.sock、不 mount 宿主根目录。
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    TERM=xterm

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git jq \
        python3 python3-pip python3-venv \
        nmap dnsutils whois netcat-traditional \
        iproute2 procps less vim-tiny \
    && rm -rf /var/lib/apt/lists/*

# 常用 Python 库：P1 再接 pwntools/requests 等（此处只放无编译依赖的）
RUN pip3 install --no-cache-dir --break-system-packages requests

WORKDIR /work

# 常驻等待 exec；不用 -d（容器本身就是长期运行的）
CMD ["sleep", "infinity"]
