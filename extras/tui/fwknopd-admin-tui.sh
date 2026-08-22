#!/bin/bash
#
# extras/tui/fwknopd-admin-tui.sh — fwknopd-admin 的 TUI 管理外壳。
#
# 一个服务器本地的菜单驱动前端（方案 §7.6.1），通过 dialog/whiptail 包装
# fwknopd-admin CLI（阶段 4c）。适用于无法使用浏览器（WebUI）的控制台运维
# 场景。所有操作都转调 fwknopd-admin——它仍是密钥的唯一权威来源。
#
# 用法：  fwknopd-admin-tui.sh [--admin /path/to/fwknopd-admin] [--run-dir DIR]
# 依赖：  dialog 或 whiptail（在普通 tty 上退化为纯文本菜单）。
#
set -u
ADMIN="${FWKNOPD_ADMIN:-fwknopd-admin}"
RUN_DIR="${FWKNOP_RUN_DIR:-/var/run/fwknop}"
# 仅在存在可用终端时使用 dialog/whiptail；否则退化为 read 驱动的纯文本
# 菜单（在没有完整 tty 的串口/ssh 会话中也能工作）。
if [ -t 0 ] && [ -n "${TERM:-}" ] && [ "${TERM:-}" != dumb ]; then
    DIALOG="$(command -v dialog || command -v whiptail)"
else
    DIALOG=""
fi

# 若不在 PATH 中，则在本脚本附近查找 admin 二进制。
if ! command -v "$ADMIN" >/dev/null 2>&1; then
    HERE="$(cd "$(dirname "$0")" && pwd)"
    for cand in "$HERE/../../server/fwknopd-admin" "$HERE/../../server/.libs/fwknopd-admin"; do
        [ -x "$cand" ] && ADMIN="$cand" && break
    done
fi

# 解析参数。
while [ $# -gt 0 ]; do
    case "$1" in
        --admin) ADMIN="$2"; shift 2 ;;
        --run-dir) RUN_DIR="$2"; shift 2 ;;
        *) shift ;;
    esac
done

msg() { if [ -n "$DIALOG" ]; then $DIALOG --msgbox "$1" 12 60; else echo "$1"; fi }

show_status() {
    local out
    out=$("$ADMIN" status 2>&1)
    if [ -n "$DIALOG" ]; then
        $DIALOG --title "fwknopd-admin 状态" --msgbox "$out" 12 60
    else
        echo "$out"
    fi
}

show_audit() {
    local f="$RUN_DIR/fwknopd_audit.log"
    if [ ! -r "$f" ]; then msg "审计日志不存在：$f"; return; fi
    local tail
    tail=$(tail -n 30 "$f")
    if [ -n "$DIALOG" ]; then
        $DIALOG --title "最近审计事件（最近 30 条）" --scrolltext --msgbox "$tail" 22 76
    else
        echo "$tail"
    fi
}

show_metrics() {
    local f="$RUN_DIR/fwknopd.metrics"
    if [ ! -r "$f" ]; then msg "指标文件不存在：$f"; return; fi
    local m
    m=$(cat "$f")
    if [ -n "$DIALOG" ]; then
        $DIALOG --title "Prometheus 指标" --msgbox "$m" 20 70
    else
        echo "$m"
    fi
}

show_tofu() {
    local f="$RUN_DIR/fwknop_tofu.state"
    local out
    if [ -r "$f" ]; then out=$(cat "$f"); else out="（无 TOFU 状态文件）"; fi
    if [ -n "$DIALOG" ]; then
        $DIALOG --title "TOFU 设备绑定" --msgbox "$out" 18 70
    else
        echo "$out"
    fi
}

add_user() {
    local name server access user range
    if [ -z "$DIALOG" ]; then
        read -rp "名称: " name; read -rp "SPA 服务器: " server
        read -rp "访问权限 [tcp/22]: " access; read -rp "用户名: " user
        read -rp "端口范围 [30000-60000]: " range
    else
        name=$($DIALOG --inputbox "凭证名称" 8 50 --output-fd 1) || return
        server=$($DIALOG --inputbox "SPA 服务器" 8 50 --output-fd 1) || return
        access=$($DIALOG --inputbox "访问权限（如 tcp/22）" 8 50 tcp/22 --output-fd 1) || return
        user=$($DIALOG --inputbox "用户名" 8 50 --output-fd 1) || return
        range=$($DIALOG --inputbox "端口范围" 8 50 30000-60000 --output-fd 1) || return
    fi
    local args=(user add "$name" --no-qr)
    [ -n "$server" ] && args+=(--server "$server")
    [ -n "$access" ] && args+=(--access "$access")
    [ -n "$user" ] && args+=(--user "$user")
    [ -n "$range" ] && args+=(--port-range "$range")
    local out
    out=$("$ADMIN" "${args[@]}" 2>&1)
    if [ -n "$DIALOG" ]; then
        $DIALOG --title "fwknopd-admin user add" --scrolltext --msgbox "$out" 22 76
    else
        echo "$out"
    fi
}

# 主循环。
while true; do
    if [ -z "$DIALOG" ]; then
        # 纯 tty 兜底菜单。
        echo; echo "== fwknopd-admin TUI =="
        echo "  1) 状态   2) 最近审计   3) 指标   4) TOFU 绑定"
        echo "  5) 签发用户凭证   0) 退出"
        read -rp "请选择: " c
        case "$c" in
            1) show_status ;;
            2) show_audit ;;
            3) show_metrics ;;
            4) show_tofu ;;
            5) add_user ;;
            0|q|Q) break ;;
        esac
    else
        choice=$($DIALOG --title "fwknopd 管理" --menu \
            "fwknopd 管理（包装 fwknopd-admin）" 14 60 6 \
            1 "服务状态" \
            2 "最近审计事件" \
            3 "Prometheus 指标" \
            4 "TOFU 设备绑定" \
            5 "签发用户凭证" \
            0 "退出" --output-fd 1) || break
        case "$choice" in
            1) show_status ;;
            2) show_audit ;;
            3) show_metrics ;;
            4) show_tofu ;;
            5) add_user ;;
            0|"") break ;;
        esac
    fi
done

[ -n "$DIALOG" ] && clear
exit 0
