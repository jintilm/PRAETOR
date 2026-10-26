#!/usr/bin/env bash
# PRAETOR cross-platform release builder.
#
# The default mode builds one target and embeds the already-exported frontend.
# `./build.sh --release` builds and packages all supported desktop/server targets.
#
# Environment variables:
#   PRAETOR_TARGET_OS=linux             One target OS in single-target mode.
#   PRAETOR_TARGET_ARCH=amd64           One target arch in single-target mode.
#   PRAETOR_TARGETS=linux/amd64,...     Comma-separated targets for multi-target mode.
#   PRAETOR_BUILD_VERSION=v0.3.3        Version embedded in the binary and archive name.
#   PRAETOR_OUTPUT=/path/to/praetor       Explicit binary path in single-target mode.
#   PRAETOR_OUTPUT_DIR=dist             Directory for default binary paths.
#   PRAETOR_PACKAGE=1                   Create a zip archive for each target.
#   PRAETOR_PACKAGE_DIR=dist            Directory for release archives.
#   PRAETOR_COMPRESS=off                UPX mode: off, auto, or required.
#   PRAETOR_UPX_ARGS="--best --lzma"    Arguments passed to UPX.
#   PRAETOR_SKIP_FRONTEND=1             Reuse server/webui/dist (for CI artifact builds).
#   PRAETOR_SKIP_NPM_CI=1               Skip npm ci while rebuilding the frontend.
#   PRAETOR_GOSUMDB=sum.golang.org      Go checksum database.
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)"

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok() { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法：
  ./build.sh                         编译当前系统当前架构
  ./build.sh --target linux/amd64   编译一个指定目标
  ./build.sh --release               编译并打包全部支持的目标

选项：
  --release              构建 Linux、macOS、Windows 的 amd64/arm64 目标并生成 zip
  --target OS/ARCH       设置单个目标，例如 windows/amd64
  --upx                  强制使用 UPX 压缩二进制（可能影响部分 Linux 环境兼容性）
  --no-compress          不使用 UPX，仅使用 Go linker 裁剪并压缩 zip
  --help                 显示帮助

多目标列表可通过 PRAETOR_TARGETS 覆盖，例如：
  PRAETOR_TARGETS=linux/amd64,windows/amd64 ./build.sh --release
EOF
}

RELEASE_TARGETS_DEFAULT="linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64"
PRAETOR_RELEASE="${PRAETOR_RELEASE:-0}"
PRAETOR_COMPRESS="${PRAETOR_COMPRESS:-off}"
PRAETOR_PACKAGE="${PRAETOR_PACKAGE:-0}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      PRAETOR_RELEASE=1
      PRAETOR_PACKAGE=1
      shift
      ;;
    --target)
      [ "$#" -ge 2 ] || die "--target 需要 OS/ARCH 参数"
      target_arg="$2"
      case "$target_arg" in
        */*)
          PRAETOR_TARGET_OS="${target_arg%%/*}"
          PRAETOR_TARGET_ARCH="${target_arg##*/}"
          PRAETOR_TARGETS="$target_arg"
          ;;
        *) die "目标必须是 OS/ARCH，例如 linux/amd64" ;;
      esac
      shift 2
      ;;
    --no-compress)
      PRAETOR_COMPRESS=0
      shift
      ;;
    --upx)
      PRAETOR_COMPRESS=required
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *) die "未知参数：$1（使用 --help 查看用法）" ;;
  esac
done

command -v go >/dev/null 2>&1 || die "未检测到 Go（项目需要 Go 1.26 或更高版本）"

PRAETOR_GOSUMDB="${PRAETOR_GOSUMDB:-sum.golang.org}"
if [ -z "${PRAETOR_BUILD_VERSION:-}" ]; then
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    PRAETOR_BUILD_VERSION="$(git describe --tags --always --dirty)"
  else
    PRAETOR_BUILD_VERSION="dev"
  fi
fi
# Release tags are commonly passed as v0.3.3; keep the binary version consistent.
PRAETOR_BUILD_VERSION="${PRAETOR_BUILD_VERSION#v}"
PRAETOR_OUTPUT_DIR="${PRAETOR_OUTPUT_DIR:-dist}"
PRAETOR_PACKAGE_DIR="${PRAETOR_PACKAGE_DIR:-$PRAETOR_OUTPUT_DIR}"
PRAETOR_UPX_ARGS="${PRAETOR_UPX_ARGS:---best --lzma}"

if [ "${PRAETOR_RELEASE}" = "1" ]; then
  PRAETOR_TARGETS="${PRAETOR_TARGETS:-$RELEASE_TARGETS_DEFAULT}"
else
  PRAETOR_TARGET_OS="${PRAETOR_TARGET_OS:-$(GOSUMDB="$PRAETOR_GOSUMDB" go env GOOS)}"
  PRAETOR_TARGET_ARCH="${PRAETOR_TARGET_ARCH:-$(GOSUMDB="$PRAETOR_GOSUMDB" go env GOARCH)}"
  PRAETOR_TARGETS="${PRAETOR_TARGETS:-${PRAETOR_TARGET_OS}/${PRAETOR_TARGET_ARCH}}"
fi

if [ "${PRAETOR_SKIP_FRONTEND:-0}" = "1" ]; then
  [ -d server/webui/dist ] || die "PRAETOR_SKIP_FRONTEND=1 但 server/webui/dist 不存在"
else
  command -v npm >/dev/null 2>&1 || die "未检测到 npm（前端静态构建需要 Node.js/npm）"
  command -v rsync >/dev/null 2>&1 || die "未检测到 rsync"
  info "构建前端静态资源"
  if [ "${PRAETOR_SKIP_NPM_CI:-0}" != "1" ]; then
    (cd web && npm ci)
  fi
  (cd web && npm run build:static)
  info "同步前端资源到 server/webui/dist"
  mkdir -p server/webui/dist
  rsync -a --delete web/out/ server/webui/dist/
fi

compress_binary() {
  binary="$1"
  goos="$2"
  case "$PRAETOR_COMPRESS" in
    0|off|false|none)
      info "跳过 UPX：$binary"
      return 0
      ;;
    auto|required|true|1) ;;
    *) die "PRAETOR_COMPRESS 必须是 off、auto 或 required" ;;
  esac

  if ! command -v upx >/dev/null 2>&1; then
    if [ "$PRAETOR_COMPRESS" = "required" ]; then
      die "PRAETOR_COMPRESS=required 但未检测到 upx"
    fi
    warn "未检测到 upx，保留 linker 压缩结果：$binary"
    return 0
  fi

  before=$(wc -c < "$binary" | tr -d ' ')
  upx_args="$PRAETOR_UPX_ARGS"
  [ "$goos" = "darwin" ] && upx_args="$upx_args --force-macos"
  # shellcheck disable=SC2086
  if ! upx $upx_args -- "$binary"; then
    if [ "$PRAETOR_COMPRESS" = "required" ]; then
      die "UPX 压缩失败：$binary"
    fi
    warn "UPX 不支持该目标格式，保留未压缩二进制：$binary"
    return 0
  fi
  after=$(wc -c < "$binary" | tr -d ' ')
  ok "UPX 压缩完成：$binary (${before} -> ${after} bytes)"
}

package_binary() {
  binary="$1"
  goos="$2"
  goarch="$3"
  package_name="praetor-${PRAETOR_BUILD_VERSION}-${goos}-${goarch}"
  package_root="${PRAETOR_PACKAGE_DIR}/${package_name}"
  archive="${PRAETOR_PACKAGE_DIR}/${package_name}.zip"

  command -v zip >/dev/null 2>&1 || die "打包需要 zip"
  rm -rf "$package_root" "$archive"
  mkdir -p "$package_root"
  cp "$binary" "$package_root/"
  # 守护启动脚本是正式入口：页面上的一键更新要靠它在进程退出后重新拉起，
  # 直接跑 praetor 本体的话更新完就再也起不来了。按目标系统只带对应的那一份。
  if [ "$goos" = "windows" ]; then
    cp start.bat "$package_root/"
  else
    cp start.sh "$package_root/"
    chmod +x "$package_root/start.sh"
  fi
  cp -R skills "$package_root/"
  cp config.example.json "$package_root/"
  if [ -f README.md ]; then cp README.md "$package_root/"; fi
  (cd "$PRAETOR_PACKAGE_DIR" && zip -q -r -9 "$(basename "$archive")" "$(basename "$package_root")")
  rm -rf "$package_root"
  ok "Release 压缩包：$archive"
}

build_target() {
  target="$1"
  case "$target" in
    */*) ;;
    *) die "无效目标：$target（必须是 OS/ARCH）" ;;
  esac
  goos="${target%%/*}"
  goarch="${target##*/}"
  case "$goos" in
    linux|darwin|windows) ;;
    *) die "不支持的系统：$goos（支持 linux、darwin、windows）" ;;
  esac

  binary_name="praetor"
  [ "$goos" = "windows" ] && binary_name="praetor.exe"
  if [ -n "${PRAETOR_OUTPUT:-}" ] && [ "$PRAETOR_RELEASE" != "1" ]; then
    output="$PRAETOR_OUTPUT"
  else
    output="${PRAETOR_OUTPUT_DIR}/praetor-${goos}-${goarch}/${binary_name}"
  fi
  mkdir -p "$(dirname "$output")"

  info "编译 ${goos}/${goarch}，版本 ${PRAETOR_BUILD_VERSION}"
  GOSUMDB="$PRAETOR_GOSUMDB" \
  CGO_ENABLED=0 \
  GOOS="$goos" \
  GOARCH="$goarch" \
  go build \
    -tags embedui \
    -trimpath \
    -ldflags "-s -w -buildid= -X main.version=${PRAETOR_BUILD_VERSION}" \
    -o "$output" \
    ./cmd/praetor

  compress_binary "$output" "$goos"
  if command -v file >/dev/null 2>&1; then file "$output"; fi
  if [ "$PRAETOR_PACKAGE" = "1" ]; then package_binary "$output" "$goos" "$goarch"; fi
  ok "编译完成：$output"
}

write_checksums() {
  [ "$PRAETOR_PACKAGE" = "1" ] || return 0
  checksum_file="$PRAETOR_PACKAGE_DIR/SHA256SUMS"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$PRAETOR_PACKAGE_DIR" && for archive in *.zip; do sha256sum "$archive"; done > "$(basename "$checksum_file")")
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$PRAETOR_PACKAGE_DIR" && for archive in *.zip; do shasum -a 256 "$archive"; done > "$(basename "$checksum_file")")
  else
    warn "未检测到 sha256sum 或 shasum，跳过 SHA256SUMS"
    return 0
  fi
  ok "校验文件：$checksum_file"
}

mkdir -p "$PRAETOR_OUTPUT_DIR"
if [ "$PRAETOR_PACKAGE" = "1" ]; then mkdir -p "$PRAETOR_PACKAGE_DIR"; fi

old_ifs="$IFS"
IFS=','
read -r -a targets <<< "$PRAETOR_TARGETS"
IFS="$old_ifs"
[ "${#targets[@]}" -gt 0 ] || die "PRAETOR_TARGETS 不能为空"
for target in "${targets[@]}"; do
  target="${target//[[:space:]]/}"
  [ -n "$target" ] || continue
  build_target "$target"
done

if [ "$PRAETOR_PACKAGE" = "1" ]; then
  write_checksums
  info "Release 包已生成于：$PRAETOR_PACKAGE_DIR"
fi
