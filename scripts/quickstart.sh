#!/bin/bash
#
# scripts/quickstart.sh - fwknop fork 一键启动 / 演示脚本。
#
# 在本机拉起一套完整自包含的 fwknop 系统并做端到端验证：构建项目、
# 生成配对密钥、启动 fwknopd（loopback pcap 抓包）+ 运维 WebUI，
# 从客户端发出真实 SPA 数据包，并验证 iptables「开门」规则生效
# （随后到期自动失效）。
#
# 子命令：
#   quickstart.sh              demo（默认）- 构建 + 启动 + 敲门 + 验证
#   quickstart.sh build        确保存在 pcap 模式的构建产物
#   quickstart.sh setup-sudo   配置窄范围 NOPASSWD sudo（fwknopd+iptables）
#   quickstart.sh demo         运行自包含演示
#   quickstart.sh knock [端口] 发送 SPA 包以开放 tcp/<端口>（默认 22）
#   quickstart.sh dashboard    仅（重）启动 WebUI
#   quickstart.sh status       查看 fwknopd + WebUI 状态
#   quickstart.sh stop         停止 fwknopd + WebUI
#   quickstart.sh clean        停止并删除演示工作目录
#
# 依赖：sudo（iptables/fwknopd 需要）、构建需要 autotools + libpcap-dev + gcc。
# 可选：Go（用于 WebUI）、qrencode/zbarimg（二维码功能）。
#
set -u

# ---- 路径 ----
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${FWKNOPQS_WORK:-/tmp/fwknop-quickstart}"
# 端口优先级：环境变量 > 现役工作目录 fwknopd.conf 的 PCAP_FILTER（保持与
# 运行中 fwknopd 一致，knock 无需每次显式带 FWKNOPQS_DPORT）> 默认 62201。
DPORT="${FWKNOPQS_DPORT:-$(sed -n 's/^PCAP_FILTER[[:space:]]*udp port \([0-9]\+\).*/\1/p' "$WORK/fwknopd.conf" 2>/dev/null)}"
DPORT="${DPORT:-62201}"
DASH_ADDR="${FWKNOPQS_DASH_ADDR:-127.0.0.1:8088}"
FWKNOP="$ROOT/client/fwknop"
FWKNOPD="$ROOT/server/fwknopd"
ADMIN="$ROOT/server/fwknopd-admin"
DASH_SRC="$ROOT/server/dashboard"
DASH_BIN="$DASH_SRC/fwknop-dashboard"

# ---- 辅助函数 ----
C_RESET="\033[0m"; C_CYAN="\033[1;36m"; C_GREEN="\033[32m"; C_RED="\033[31m"; C_YEL="\033[33m"; C_DIM="\033[2m"
say()  { printf "${C_CYAN}[*]${C_RESET} %s\n" "$*"; }
ok()   { printf "${C_GREEN}[+]${C_RESET} %s\n" "$*"; }
warn() { printf "${C_YEL}[!]${C_RESET} %s\n" "$*"; }
err()  { printf "${C_RED}[-]${C_RESET} %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

# 执行特权命令。走 sudo；若无免密 sudo，则提示输入一次密码（sudo 会缓存时间戳）。
have_sudo() { sudo -n true 2>/dev/null; }
priv() { if have_sudo; then sudo -n "$@"; else sudo "$@"; fi; }

# 确保 fwknopd + iptables 可免密执行（窄范围 sudoers 规则，仅限这两个二进制）。
# 没有它，后台运行的 fwknopd 无法被演示脚本可靠管理。需输入一次 sudo 密码。
setup_sudo() {
    # fwknopd 已经免密了吗？
    if sudo -n "$FWKNOPD" --version >/dev/null 2>&1; then return 0; fi
    say "正在为 fwknopd + iptables 配置窄范围 NOPASSWD sudo（需输入一次 sudo 密码）..."
    local ipt
    ipt="$(command -v iptables || echo /usr/sbin/iptables)"
    sudo bash -c "cat > /etc/sudoers.d/fwknop-quickstart <<EOF
fwknop ALL=(root) NOPASSWD: $FWKNOPD, $ipt, ${ipt}-save, ${ipt}-restore
EOF
chmod 0440 /etc/sudoers.d/fwknop-quickstart
visudo -cf /etc/sudoers.d/fwknop-quickstart >/dev/null" \
        || die "无法配置 sudoers（需要 sudo 权限）；请手动执行：sudo bash -c \"echo 'fwknop ALL=(root) NOPASSWD: $FWKNOPD, $ipt' > /etc/sudoers.d/fwknop-quickstart && chmod 0440 /etc/sudoers.d/fwknop-quickstart\""
    ok "已为 fwknopd + iptables 配置免密 sudo"
}

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "缺少必需命令：$1"; }

# ---- 构建 ----
ensure_built() {
    cd "$ROOT" || die "无法进入目录 $ROOT"
    need_cmd gcc; need_cmd make
    # 首次运行时重新生成 configure。
    if [ ! -x ./configure ]; then
        say "运行 autoreconf（首次）..."
        autoreconf -iv >/tmp/qs_autoreconf.log 2>&1 || die "autoreconf 失败（见 /tmp/qs_autoreconf.log）"
    fi
    # 演示需要 pcap（loopback 抓包）；NFQ/udp-server 模式会禁用它。
    # 当 Makefile/二进制缺失或当前构建不是 pcap 模式时，（重新）configure。
    local need_configure=0
    [ -f Makefile ] && [ -x "$FWKNOP" ] && [ -x "$FWKNOPD" ] || need_configure=1
    grep -q "define USE_LIBPCAP 1" "$ROOT/config.h" 2>/dev/null || need_configure=1
    if [ "$need_configure" = "1" ]; then
        say "配置中（pcap 模式）..."
        ./configure --enable-c-unit-tests --prefix=/usr/local >/tmp/qs_configure.log 2>&1 \
            || die "configure 失败（见 /tmp/qs_configure.log）；请安装 libpcap0.8-dev autoconf automake libtool pkg-config"
        say "编译中..."
        make -j"$(nproc)" >/tmp/qs_make.log 2>&1 || die "make 失败（见 /tmp/qs_make.log）"
    fi
    grep -q "define USE_LIBPCAP 1" "$ROOT/config.h" 2>/dev/null \
        || die "构建完成但 USE_LIBPCAP 仍未启用；请安装 libpcap0.8-dev 后重试"
    [ -x "$FWKNOP" ] && [ -x "$FWKNOPD" ] && [ -x "$ADMIN" ] \
        || die "构建后二进制缺失"
    ok "二进制就绪：fwknop、fwknopd、fwknopd-admin"
}

build_dashboard() {
    if command -v go >/dev/null 2>&1; then GO=go;
    elif [ -x /home/fwknop/.local/usr/lib/go-1.26/bin/go ]; then GO=/home/fwknop/.local/usr/lib/go-1.26/bin/go;
    else warn "未找到 Go —— WebUI 不可用（安装 golang-go 以启用）"; return 1; fi
    ( cd "$DASH_SRC" && "$GO" build -o fwknop-dashboard . >/tmp/qs_go.log 2>&1 ) \
        || { warn "面板构建失败（见 /tmp/qs_go.log）"; return 1; }
    ok "面板构建完成"
}

# ---- 配置生成 ----
gen_configs() {
    mkdir -p "$WORK/run"
    # 生成全新的配对密钥（客户端输出形如 "KEY_BASE64: <值>"）。
    # 锚定行首的 awk 避免把 HMAC_KEY_BASE64 误匹配为 KEY_BASE64 的子串。
    local key hmac
    key=$("$FWKNOP" --key-gen 2>/dev/null | awk -F': ' '/^KEY_BASE64:/{print $2}')
    hmac=$("$FWKNOP" --key-gen 2>/dev/null | awk -F': ' '/^HMAC_KEY_BASE64:/{print $2}')
    [ -n "$key" ] && [ -n "$hmac" ] || die "密钥生成失败"
    echo "$key"  >"$WORK/key.b64"
    echo "$hmac" >"$WORK/hmac.b64"
    chmod 0600 "$WORK/key.b64" "$WORK/hmac.b64"

    # 服务端 access.conf
    cat >"$WORK/access.conf" <<EOF
SOURCE              127.0.0.1
KEY_BASE64          $key
HMAC_KEY_BASE64     $hmac
OPEN_PORTS          tcp/22,tcp/443
FW_ACCESS_TIMEOUT   30
EOF
    chmod 0600 "$WORK/access.conf"

    # 服务端 fwknopd.conf —— loopback pcap 抓包，开启结构化审计。
    cat >"$WORK/fwknopd.conf" <<EOF
PCAP_INTF           lo
PCAP_FILTER         udp port $DPORT
FWKNOP_RUN_DIR      $WORK/run
ENABLE_AUDIT        Y
FLUSH_IPT_AT_INIT   Y
FLUSH_IPT_AT_EXIT   Y
EOF
    chmod 0600 "$WORK/fwknopd.conf"

    # 客户端 rc stanza（供 `quickstart.sh knock` 使用）
    cat >"$WORK/fwknoprc" <<EOF
[default]
SPA_SERVER             127.0.0.1
ACCESS                 tcp/22
KEY_BASE64             $key
HMAC_KEY_BASE64        $hmac
USE_HMAC               Y
EOF
    chmod 0600 "$WORK/fwknoprc"
    ok "演示配置已写入 $WORK"
}

# ---- 进程控制 ----
fwknopd_pid() { pgrep -f "fwknopd.*$WORK/fwknopd.conf" | head -1; }
dash_pid()    { pgrep -f "fwknop-dashboard.*$WORK/run" | head -1; }

start_fwknopd() {
    if [ -n "$(fwknopd_pid)" ]; then ok "fwknopd 已在运行（pid $(fwknopd_pid)）"; return; fi
    export LD_LIBRARY_PATH="$ROOT/lib/.libs:${LD_LIBRARY_PATH:-}"
    say "启动 fwknopd（pcap lo，udp 端口 $DPORT）..."
    priv "$FWKNOPD" -c "$WORK/fwknopd.conf" -a "$WORK/access.conf" -f --verbose \
        >"$WORK/fwknopd.log" 2>&1 &
    local i
    for i in $(seq 1 10); do
        sleep 1
        grep -q "main event loop\|Kicking off" "$WORK/fwknopd.log" 2>/dev/null && break
    done
    if grep -q "main event loop\|Kicking off" "$WORK/fwknopd.log" 2>/dev/null; then
        ok "fwknopd 运行中（pid $(fwknopd_pid)）"
    else
        err "fwknopd 启动失败；日志末尾："; tail -15 "$WORK/fwknopd.log" 2>/dev/null
        die "没有 fwknopd 无法继续"
    fi
}

start_dashboard() {
    [ -x "$DASH_BIN" ] || { build_dashboard || return 1; }
    if [ -n "$(dash_pid)" ]; then ok "面板已在运行（pid $(dash_pid)）"; return; fi
    say "启动面板 http://$DASH_ADDR ..."
    "$DASH_BIN" -run-dir "$WORK/run" -addr "$DASH_ADDR" >"$WORK/dashboard.log" 2>&1 &
    sleep 1
    if [ -n "$(dash_pid)" ]; then ok "面板运行中（pid $(dash_pid)）"; else warn "面板未能启动"; fi
}

send_knock() {
    local port="${1:-22}"
    local key hmac rc
    key=$(cat "$WORK/key.b64"); hmac=$(cat "$WORK/hmac.b64")
    export LD_LIBRARY_PATH="$ROOT/lib/.libs:${LD_LIBRARY_PATH:-}"
    say "发送 SPA 包到 127.0.0.1:$DPORT（开放 tcp/$port）..."
    # 客户端成功时默认静默；用 --verbose 取得 'bytes sent' 输出，
    # 并以退出码作为权威的成败信号。
    # -p 必须显式跟随 $DPORT：fwknop 客户端默认目的端口固定为 62201，
    # 仅在 DPORT 恰为 62201 时才与服务端一致（否则包发往旧端口，pcap 抓不到）。
    "$FWKNOP" -A "tcp/$port" -a 127.0.0.1 -D 127.0.0.1 -p "$DPORT" \
        --key-base64-rijndael "$key" --key-base64-hmac "$hmac" --no-save-args \
        --verbose >"$WORK/knock.log" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then
        ok "SPA 包已发送（$(grep -o 'bytes sent: [0-9]*' "$WORK/knock.log" | tail -1)）"
    else
        err "客户端失败（退出码 $rc）；末尾输出："; tail -10 "$WORK/knock.log"; return 1
    fi
}

verify_door() {
    local port="${1:-22}"
    sleep 1
    say "检查 iptables FWKNOP_INPUT 中的 tcp/$port 规则..."
    local n
    n=$(priv iptables -nL FWKNOP_INPUT 2>/dev/null | grep -c "dpt:$port")
    if [ "${n:-0}" -ge 1 ]; then
        ok "门已开：tcp/$port 的 iptables ACCEPT 规则已安装"
        priv iptables -nL FWKNOP_INPUT 2>/dev/null | grep "dpt:$port" | sed 's/^/      /'
    else
        warn "未看到 tcp/$port 规则（可能已到期失效，或查看 $WORK/fwknopd.log）"
    fi
}

stop_all() {
    local p
    p="$(dash_pid)"; [ -n "$p" ] && { say "停止面板（pid $p）"; kill "$p" 2>/dev/null; }
    # 用 fwknopd 自带的 --kill（-K）停止——它在 NOPASSWD 覆盖范围内
    # （fwknopd 二进制在 sudoers 列表中），并会自行读取 pid 文件。
    if [ -n "$(fwknopd_pid)" ]; then
        say "停止 fwknopd..."
        priv "$FWKNOPD" -c "$WORK/fwknopd.conf" -a "$WORK/access.conf" -K 2>/dev/null
        sleep 2
        # 兜底：SIGKILL 幸存者（若未配置 NOPASSWD 则需输入 sudo 密码）。
        if [ -n "$(fwknopd_pid)" ]; then
            priv pkill -KILL -f "fwknopd.*$WORK/fwknopd.conf" 2>/dev/null
            sleep 1
        fi
    fi
    [ -z "$(fwknopd_pid)" ] && [ -z "$(dash_pid)" ] && ok "已全部停止" || warn "部分进程可能仍在运行"
}

status_all() {
    local fp dp
    fp="$(fwknopd_pid)"; dp="$(dash_pid)"
    if [ -n "$fp" ]; then ok "fwknopd 运行中（pid $fp）"; else warn "fwknopd 未运行"; fi
    if [ -n "$dp" ]; then ok "面板运行中（pid $dp）-> http://$DASH_ADDR"; else warn "面板未运行"; fi
    if [ -d "$WORK" ]; then say "工作目录：$WORK"; fi
}

# ---- 子命令 ----
cmd_demo() {
    ensure_built
    setup_sudo
    stop_all >/dev/null 2>&1   # 清掉任何带着旧密钥的残留 fwknopd
    gen_configs
    start_fwknopd
    build_dashboard && start_dashboard
    send_knock 22
    verify_door 22
    echo
    say "=== 演示已上线 ==="
    echo "  WebUI：            http://$DASH_ADDR"
    echo "  fwknopd 日志：     tail -f $WORK/fwknopd.log"
    echo "  审计日志：         tail -f $WORK/run/fwknopd_audit.log"
    echo "  指标：             cat $WORK/run/fwknopd.metrics"
    echo "  再开一扇门：       $0 knock 443"
    echo "  停止：             $0 stop"
    echo
}

cmd_knock() { send_knock "${1:-22}"; verify_door "${1:-22}"; }
cmd_build() { ensure_built; build_dashboard; }
cmd_setup_sudo() { setup_sudo; }
cmd_dashboard() { [ -d "$WORK" ] || die "没有演示工作目录（$WORK）；请先运行 '$0 demo'"; start_dashboard; }
cmd_status() { status_all; }
cmd_stop() { stop_all; }
cmd_clean() { stop_all; rm -rf "$WORK"; ok "已删除 $WORK"; }

usage() {
    sed -n '3,22p' "$0"
}

case "${1:-demo}" in
    demo) cmd_demo ;;
    build) cmd_build ;;
    setup-sudo) cmd_setup_sudo ;;
    knock) shift; cmd_knock "$@" ;;
    dashboard) cmd_dashboard ;;
    status) cmd_status ;;
    stop) cmd_stop ;;
    clean) cmd_clean ;;
    -h|--help|help) usage ;;
    *) err "未知命令：$1"; usage; exit 1 ;;
esac
