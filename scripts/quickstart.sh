#!/bin/bash
#
# scripts/quickstart.sh - fwknop fork one-click startup / demo.
#
# Brings up a complete, self-contained fwknop system on the local host and
# proves it works end to end: builds the project, mints matching keys, starts
# fwknopd (pcap on loopback) + the operations WebUI, fires a real SPA packet
# from the client, and verifies the iptables door opens (then expires).
#
# Subcommands:
#   quickstart.sh              demo (default) - build + start + knock + verify
#   quickstart.sh build        ensure a pcap-enabled build exists
#   quickstart.sh setup-sudo   configure narrow NOPASSWD sudo (fwknopd+iptables)
#   quickstart.sh demo         run the self-contained demo
#   quickstart.sh knock [port] send an SPA packet to open tcp/<port> (def 22)
#   quickstart.sh dashboard    (re)start only the WebUI
#   quickstart.sh status       show fwknopd + dashboard status
#   quickstart.sh stop         stop fwknopd + dashboard
#   quickstart.sh clean        stop + remove the demo work dir
#
# Requires: sudo (for iptables/fwknopd), autotools + libpcap-dev + gcc to build.
# Optional: Go (for the WebUI), qrencode/zbarimg (QR features).
#
set -u

# ---- paths ----
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${FWKNOPQS_WORK:-/tmp/fwknop-quickstart}"
DPORT="${FWKNOPQS_DPORT:-62201}"
DASH_ADDR="${FWKNOPQS_DASH_ADDR:-127.0.0.1:8088}"
FWKNOP="$ROOT/client/fwknop"
FWKNOPD="$ROOT/server/fwknopd"
ADMIN="$ROOT/server/fwknopd-admin"
DASH_SRC="$ROOT/server/dashboard"
DASH_BIN="$DASH_SRC/fwknop-dashboard"

# ---- helpers ----
C_RESET="\033[0m"; C_CYAN="\033[1;36m"; C_GREEN="\033[32m"; C_RED="\033[31m"; C_YEL="\033[33m"; C_DIM="\033[2m"
say()  { printf "${C_CYAN}[*]${C_RESET} %s\n" "$*"; }
ok()   { printf "${C_GREEN}[+]${C_RESET} %s\n" "$*"; }
warn() { printf "${C_YEL}[!]${C_RESET} %s\n" "$*"; }
err()  { printf "${C_RED}[-]${C_RESET} %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

# Run a privileged command. Uses sudo; if passwordless sudo is not available,
# prompts once (sudo caches the timestamp).
have_sudo() { sudo -n true 2>/dev/null; }
priv() { if have_sudo; then sudo -n "$@"; else sudo "$@"; fi; }

# Ensure fwknopd + iptables can be run passwordless (narrow sudoers rule, only
# those two binaries). Without this, the backgrounded fwknopd cannot be managed
# reliably by the demo. Uses the user's sudo password once.
setup_sudo() {
    # Already passwordless for fwknopd?
    if sudo -n "$FWKNOPD" --version >/dev/null 2>&1; then return 0; fi
    say "setting up narrow NOPASSWD sudo for fwknopd + iptables (needs your sudo password once)..."
    local ipt
    ipt="$(command -v iptables || echo /usr/sbin/iptables)"
    sudo bash -c "cat > /etc/sudoers.d/fwknop-quickstart <<EOF
fwknop ALL=(root) NOPASSWD: $FWKNOPD, $ipt, ${ipt}-save, ${ipt}-restore
EOF
chmod 0440 /etc/sudoers.d/fwknop-quickstart
visudo -cf /etc/sudoers.d/fwknop-quickstart >/dev/null" \
        || die "could not configure sudoers (need sudo); run: sudo bash -c \"echo 'fwknop ALL=(root) NOPASSWD: $FWKNOPD, $ipt' > /etc/sudoers.d/fwknop-quickstart && chmod 0440 /etc/sudoers.d/fwknop-quickstart\""
    ok "passwordless sudo configured for fwknopd + iptables"
}

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }

# ---- build ----
ensure_built() {
    cd "$ROOT" || die "cannot cd $ROOT"
    need_cmd gcc; need_cmd make
    # Regenerate configure if missing.
    if [ ! -x ./configure ]; then
        say "running autoreconf (first time)..."
        autoreconf -iv >/tmp/qs_autoreconf.log 2>&1 || die "autoreconf failed (see /tmp/qs_autoreconf.log)"
    fi
    # The demo needs pcap (loopback capture); NFQ/udp-server modes disable it.
    # (Re)configure if Makefile/binaries missing OR the current build is not pcap.
    local need_configure=0
    [ -f Makefile ] && [ -x "$FWKNOP" ] && [ -x "$FWKNOPD" ] || need_configure=1
    grep -q "define USE_LIBPCAP 1" "$ROOT/config.h" 2>/dev/null || need_configure=1
    if [ "$need_configure" = "1" ]; then
        say "configuring (pcap mode)..."
        ./configure --enable-c-unit-tests --prefix=/usr/local >/tmp/qs_configure.log 2>&1 \
            || die "configure failed (see /tmp/qs_configure.log); install libpcap0.8-dev autoconf automake libtool pkg-config"
        say "building..."
        make -j"$(nproc)" >/tmp/qs_make.log 2>&1 || die "make failed (see /tmp/qs_make.log)"
    fi
    grep -q "define USE_LIBPCAP 1" "$ROOT/config.h" 2>/dev/null \
        || die "build completed but USE_LIBPCAP still not set; install libpcap0.8-dev and rerun"
    [ -x "$FWKNOP" ] && [ -x "$FWKNOPD" ] && [ -x "$ADMIN" ] \
        || die "binaries missing after build"
    ok "binaries ready: fwknop, fwknopd, fwknopd-admin"
}

build_dashboard() {
    if command -v go >/dev/null 2>&1; then GO=go;
    elif [ -x /home/fwknop/.local/usr/lib/go-1.26/bin/go ]; then GO=/home/fwknop/.local/usr/lib/go-1.26/bin/go;
    else warn "Go not found - WebUI disabled (install golang-go to enable)"; return 1; fi
    ( cd "$DASH_SRC" && "$GO" build -o fwknop-dashboard . >/tmp/qs_go.log 2>&1 ) \
        || { warn "dashboard build failed (see /tmp/qs_go.log)"; return 1; }
    ok "dashboard built"
}

# ---- config generation ----
gen_configs() {
    mkdir -p "$WORK/run"
    # Fresh, matching keys (client prints "KEY_BASE64: <val>"). The anchored
    # awk avoids matching HMAC_KEY_BASE64 as a substring of KEY_BASE64.
    local key hmac
    key=$("$FWKNOP" --key-gen 2>/dev/null | awk -F': ' '/^KEY_BASE64:/{print $2}')
    hmac=$("$FWKNOP" --key-gen 2>/dev/null | awk -F': ' '/^HMAC_KEY_BASE64:/{print $2}')
    [ -n "$key" ] && [ -n "$hmac" ] || die "key generation failed"
    echo "$key"  >"$WORK/key.b64"
    echo "$hmac" >"$WORK/hmac.b64"
    chmod 0600 "$WORK/key.b64" "$WORK/hmac.b64"

    # Server access.conf
    cat >"$WORK/access.conf" <<EOF
SOURCE              127.0.0.1
KEY_BASE64          $key
HMAC_KEY_BASE64     $hmac
OPEN_PORTS          tcp/22,tcp/443
FW_ACCESS_TIMEOUT   30
EOF
    chmod 0600 "$WORK/access.conf"

    # Server fwknopd.conf - pcap on loopback, structured audit on.
    cat >"$WORK/fwknopd.conf" <<EOF
PCAP_INTF           lo
PCAP_FILTER         udp port $DPORT
FWKNOP_RUN_DIR      $WORK/run
ENABLE_AUDIT        Y
FLUSH_IPT_AT_INIT   Y
FLUSH_IPT_AT_EXIT   Y
EOF
    chmod 0600 "$WORK/fwknopd.conf"

    # Client rc stanza (for `quickstart.sh knock`)
    cat >"$WORK/fwknoprc" <<EOF
[default]
SPA_SERVER             127.0.0.1
ACCESS                 tcp/22
KEY_BASE64             $key
HMAC_KEY_BASE64        $hmac
USE_HMAC               Y
EOF
    chmod 0600 "$WORK/fwknoprc"
    ok "demo configs written to $WORK"
}

# ---- process control ----
fwknopd_pid() { pgrep -f "fwknopd.*$WORK/fwknopd.conf" | head -1; }
dash_pid()    { pgrep -f "fwknop-dashboard.*$WORK/run" | head -1; }

start_fwknopd() {
    if [ -n "$(fwknopd_pid)" ]; then ok "fwknopd already running (pid $(fwknopd_pid))"; return; fi
    export LD_LIBRARY_PATH="$ROOT/lib/.libs:${LD_LIBRARY_PATH:-}"
    say "starting fwknopd (pcap lo, udp port $DPORT)..."
    priv "$FWKNOPD" -c "$WORK/fwknopd.conf" -a "$WORK/access.conf" -f --verbose \
        >"$WORK/fwknopd.log" 2>&1 &
    local i
    for i in $(seq 1 10); do
        sleep 1
        grep -q "main event loop\|Kicking off" "$WORK/fwknopd.log" 2>/dev/null && break
    done
    if grep -q "main event loop\|Kicking off" "$WORK/fwknopd.log" 2>/dev/null; then
        ok "fwknopd running (pid $(fwknopd_pid))"
    else
        err "fwknopd failed to start; tail of log:"; tail -15 "$WORK/fwknopd.log" 2>/dev/null
        die "cannot continue without fwknopd"
    fi
}

start_dashboard() {
    [ -x "$DASH_BIN" ] || { build_dashboard || return 1; }
    if [ -n "$(dash_pid)" ]; then ok "dashboard already running (pid $(dash_pid))"; return; fi
    say "starting dashboard on http://$DASH_ADDR ..."
    "$DASH_BIN" -run-dir "$WORK/run" -addr "$DASH_ADDR" >"$WORK/dashboard.log" 2>&1 &
    sleep 1
    if [ -n "$(dash_pid)" ]; then ok "dashboard running (pid $(dash_pid))"; else warn "dashboard did not start"; fi
}

send_knock() {
    local port="${1:-22}"
    local key hmac rc
    key=$(cat "$WORK/key.b64"); hmac=$(cat "$WORK/hmac.b64")
    export LD_LIBRARY_PATH="$ROOT/lib/.libs:${LD_LIBRARY_PATH:-}"
    say "sending SPA packet to 127.0.0.1:$DPORT (open tcp/$port)..."
    # The client is silent on success; use --verbose to get 'bytes sent' and
    # rely on the exit code as the authoritative success signal.
    "$FWKNOP" -A "tcp/$port" -a 127.0.0.1 -D 127.0.0.1 \
        --key-base64-rijndael "$key" --key-base64-hmac "$hmac" --no-save-args \
        --verbose >"$WORK/knock.log" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then
        ok "SPA packet sent ($(grep -o 'bytes sent: [0-9]*' "$WORK/knock.log" | tail -1))"
    else
        err "client failed (exit $rc); tail:"; tail -10 "$WORK/knock.log"; return 1
    fi
}

verify_door() {
    local port="${1:-22}"
    sleep 1
    say "checking iptables FWKNOP_INPUT for tcp/$port rule..."
    local n
    n=$(priv iptables -nL FWKNOP_INPUT 2>/dev/null | grep -c "dpt:$port")
    if [ "${n:-0}" -ge 1 ]; then
        ok "DOOR OPEN: iptables ACCEPT rule for tcp/$port is installed"
        priv iptables -nL FWKNOP_INPUT 2>/dev/null | grep "dpt:$port" | sed 's/^/      /'
    else
        warn "no tcp/$port rule visible (it may have already expired, or check $WORK/fwknopd.log)"
    fi
}

stop_all() {
    local p
    p="$(dash_pid)"; [ -n "$p" ] && { say "stopping dashboard (pid $p)"; kill "$p" 2>/dev/null; }
    # Stop fwknopd via its own --kill (-K), which is NOPASSWD-covered (the
    # fwknopd binary is in the sudoers list) and reads the pid file itself.
    if [ -n "$(fwknopd_pid)" ]; then
        say "stopping fwknopd..."
        priv "$FWKNOPD" -c "$WORK/fwknopd.conf" -a "$WORK/access.conf" -K 2>/dev/null
        sleep 2
        # Fallback: SIGKILL any survivor (needs password sudo if not NOPASSWD).
        if [ -n "$(fwknopd_pid)" ]; then
            priv pkill -KILL -f "fwknopd.*$WORK/fwknopd.conf" 2>/dev/null
            sleep 1
        fi
    fi
    [ -z "$(fwknopd_pid)" ] && [ -z "$(dash_pid)" ] && ok "stopped" || warn "some processes may still be running"
}

status_all() {
    local fp dp
    fp="$(fwknopd_pid)"; dp="$(dash_pid)"
    if [ -n "$fp" ]; then ok "fwknopd running (pid $fp)"; else warn "fwknopd not running"; fi
    if [ -n "$dp" ]; then ok "dashboard running (pid $dp) -> http://$DASH_ADDR"; else warn "dashboard not running"; fi
    if [ -d "$WORK" ]; then say "work dir: $WORK"; fi
}

# ---- subcommands ----
cmd_demo() {
    ensure_built
    setup_sudo
    stop_all >/dev/null 2>&1   # clear any stale fwknopd with old keys
    gen_configs
    start_fwknopd
    build_dashboard && start_dashboard
    send_knock 22
    verify_door 22
    echo
    say "=== demo is live ==="
    echo "  WebUI:              http://$DASH_ADDR"
    echo "  fwknopd log:        tail -f $WORK/fwknopd.log"
    echo "  audit log:          tail -f $WORK/run/fwknopd_audit.log"
    echo "  metrics:            cat $WORK/run/fwknopd.metrics"
    echo "  open another door:  $0 knock 443"
    echo "  stop:               $0 stop"
    echo
}

cmd_knock() { send_knock "${1:-22}"; verify_door "${1:-22}"; }
cmd_build() { ensure_built; build_dashboard; }
cmd_setup_sudo() { setup_sudo; }
cmd_dashboard() { [ -d "$WORK" ] || die "no demo work dir ($WORK); run '$0 demo' first"; start_dashboard; }
cmd_status() { status_all; }
cmd_stop() { stop_all; }
cmd_clean() { stop_all; rm -rf "$WORK"; ok "removed $WORK"; }

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
    *) err "unknown command: $1"; usage; exit 1 ;;
esac
