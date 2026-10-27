#!/usr/bin/env bash
# 在 CTF 沙箱镜像里做一次「真的能用」的验收。
#
# 为什么不是 `command -v`：装上了不等于能用。实测踩过的坑是
#   - pip 版 pwntools 装得上但 import 失败（系统 Python 3.14 编译原生依赖失败）；
#   - 依赖老版 setup.py 的包（ciphey 的 absl-py）直接拒绝新解释器。
# 这两类问题 `command -v` 全都看不见，只有**真跑一次任务**才能暴露。
#
# 用法：
#   scripts/ctf-toolchain-smoke.sh [镜像]
#   scripts/ctf-toolchain-smoke.sh praetor/sandbox:custom-eb685c80
set -uo pipefail

IMG="${1:-praetor/sandbox:latest}"

# 脚本经 stdin 喂给容器里的 sh：不挂载（Windows 下挂载路径要额外转换，且只读挂载
# 在某些 Docker Desktop 版本上对 /tmp 下的单文件不可靠）。
INNER=$(mktemp)
trap 'rm -f "$INNER"' EXIT

cat >"$INNER" <<'INNER_EOF'
set -u
fail=0
ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fail=$((fail+1)); }
chk() { # chk <名称> <命令...>
  local name="$1"; shift
  local out
  if out=$("$@" 2>&1); then ok "$name"; else bad "$name — $(printf '%s' "$out" | tail -n1)"; fi
}

cd /tmp && rm -rf smoke && mkdir smoke && cd smoke

# ---------- pwn：编译一个真有溢出的程序，用 pwntools 打通 ----------
# 用 read(0,...) 制造真实溢出：`gets` 在 C23 里已被移除，
# 基础镜像的 gcc 16 默认就是 gnu23，用它会让"编译失败"看起来像镜像坏了。
cat > vuln.c <<'C'
#include <stdio.h>
#include <unistd.h>
void win(void){ puts("PWN_WIN"); }
int main(void){
  char buf[32];
  puts("name?");
  fflush(stdout);
  ssize_t n = read(0, buf, 128);
  if (n > 0) { buf[n < 127 ? n : 127] = 0; }
  printf("hello %s\n", buf);
  return 0;
}
C
gcc -fno-stack-protector -no-pie -o vuln vuln.c 2>/dev/null || bad "gcc 编译测试程序"

chk "pwntools（import + ELF + process）" python3 - <<'PY'
from pwn import context, ELF, process
context.log_level = 'error'
e = ELF('./vuln', checksec=False)
p = process('./vuln')
p.sendline(b'hi')
out = p.recvall(timeout=5).decode(errors='replace')
assert 'hello hi' in out, out
assert e.symbols.get('win'), "ELF 符号解析失败"
print("ok")
PY

chk "gdb（batch 反查符号）" bash -c 'gdb -q -batch -ex "file ./vuln" -ex "info functions win" | grep -q win'
chk "gef（gdb 增强已就位）" test -x /usr/bin/gef
chk "ROPgadget" bash -c 'ROPgadget --binary ./vuln 2>/dev/null | grep -qi "gadget"'
chk "seccomp-tools" seccomp-tools --version

# ---------- rev ----------
chk "rizin（反汇编 main）" bash -c 'rizin -q -c "aa; pdf @ sym.main" ./vuln 2>/dev/null | grep -qi "main"'
chk "binwalk" bash -c 'binwalk ./vuln >/dev/null 2>&1'

# ---------- crypto ----------
chk "z3（真解一个约束）" python3 - <<'PY'
from z3 import BitVec, Solver, sat
x = BitVec('x', 32)
s = Solver()
s.add(x * 3 + 7 == 100)
assert s.check() == sat
assert s.model()[x].as_long() == 31
print("ok")
PY
chk "ciphey（可导入）" python3 -c 'import ciphey'

# ---------- forensics ----------
# 现场合成一个含明文的 pcap 再用 tshark 抽出来：
# 这是"能解析真实流量"的最小证明，比 --version 有用得多。
chk "tshark（解析 pcap 抽明文）" bash -c '
python3 - <<PY
import struct, socket

def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

payload = b"flag{smoke_test}"
eth = b"\x00"*12 + b"\x08\x00"
src, dst = socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2")
tcp = struct.pack("!HHIIBBHHH", 12345, 80, 1, 0, 5 << 4, 0x18, 8192, 0, 0) + payload
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst)
ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
frame = eth + ip + tcp
pcap = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
pcap += struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
open("t.pcap", "wb").write(pcap)
PY
tshark -r t.pcap -T fields -e tcp.payload 2>/dev/null | grep -qi 666c61677b
'
chk "exiftool（读元数据）" bash -c 'exiftool -ver >/dev/null && exiftool ./vuln >/dev/null 2>&1'
chk "zsteg" bash -c 'zsteg --version >/dev/null 2>&1 || zsteg -h >/dev/null 2>&1'

printf 'SMOKE_FAIL=%d\n' "$fail"
exit "$fail"
INNER_EOF

printf '== 镜像 %s\n' "$IMG"
docker run --rm -i --entrypoint sh "$IMG" -s <"$INNER"
rc=$?
if [ "$rc" -eq 0 ]; then
  printf '\n== 结果：全部通过\n'
else
  printf '\n== 结果：%d 项未通过（退出码 %d）\n' "$rc" "$rc"
fi
exit "$rc"
