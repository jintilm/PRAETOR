# PRAETOR 工具沙箱（形态 A：常驻容器 + docker exec）
#
# 设计取舍：
#   - 用 Kali rolling 作底座：渗透工具生态最全，P1 接入 nmap/sqlmap/nuclei 等直接 apt/uv 装。
#   - 常驻 `sleep infinity`：agent 每次 Bash 是 `docker exec`，无冷启动。
#   - 只装「最小可用集」：真正按域加载的工具链（pwn/rev/AD）在 P1/P2 增量加，
#     避免镜像一开始就有几个 GB、构建十几分钟。
#   - 不加 privileged、不挂 docker.sock、不 mount 宿主根目录。
#
# 构建前请先预拉基础镜像：`docker pull kalilinux/kali-rolling`
#   原因（本项目实测多次）：Docker Desktop 的代理只覆盖 docker pull，
#   buildkit 拉基础镜像时的 token 请求不走代理，直连 auth.docker.io 会 "Bad Gateway"。
#   本地已有镜像时 buildkit 直接复用，不再要 token。
# 可选组件（rizin/angr/sage…）不写在这里：由「系统设置 → 可选组件」勾选后
#   在此基础上生成 custom 镜像层（见 internal/components）。
#
# apt 源与重试：
#   - Kali 官方 http.kali.org 是重定向器，落到哪个镜像不可控；本项目实测本机被清华镜像
#     以 403 拒绝（同网络下阿里云 / 中科大 / kali.download 均 200）。所以默认钉到阿里云，
#     非中国大陆环境可 `--build-arg PRAETOR_KALI_MIRROR=http://http.kali.org/kali` 改回官方。
#   - Acquire::Retries：镜像偶发 5xx 时 apt 默认不重试，加 5 次能显著减少构建失败。
FROM kalilinux/kali-rolling

# 见上文：默认走可用的国内镜像，非 CN 环境用 --build-arg 改回官方
ARG PRAETOR_KALI_MIRROR=http://mirrors.aliyun.com/kali


ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    TERM=xterm

RUN set -eux; \
    sed -i "s|http://http.kali.org/kali|${PRAETOR_KALI_MIRROR}|g" /etc/apt/sources.list.d/kali.sources; \
    printf 'Acquire::Retries "5";\nAcquire::http::Pipeline-Depth "0";\n' > /etc/apt/apt.conf.d/99praetor-retry

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
