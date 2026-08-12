#!/bin/bash
#
# extras/tui/fwknopd-admin-tui.sh — TUI management shell for fwknopd-admin.
#
# A server-local, menu-driven front-end (plan §7.6.1) that wraps the
# fwknopd-admin CLI (Phase 4c) via dialog/whiptail. Intended for on-console
# administration where a browser (the WebUI) is not available. All actions shell
# out to fwknopd-admin, which remains the single source of truth for keys.
#
# Usage:  fwknopd-admin-tui.sh [--admin /path/to/fwknopd-admin] [--run-dir DIR]
# Requires: dialog or whiptail (falls back to a plain menu on a tty).
#
set -u
ADMIN="${FWKNOPD_ADMIN:-fwknopd-admin}"
RUN_DIR="${FWKNOP_RUN_DIR:-/var/run/fwknop}"
# Use dialog/whiptail only when a usable terminal is present; otherwise fall
# back to a plain read-driven menu (works over serial/ssh without a full tty).
if [ -t 0 ] && [ -n "${TERM:-}" ] && [ "${TERM:-}" != dumb ]; then
    DIALOG="$(command -v dialog || command -v whiptail)"
else
    DIALOG=""
fi

# Locate the admin binary next to this script if not on PATH.
if ! command -v "$ADMIN" >/dev/null 2>&1; then
    HERE="$(cd "$(dirname "$0")" && pwd)"
    for cand in "$HERE/../../server/fwknopd-admin" "$HERE/../../server/.libs/fwknopd-admin"; do
        [ -x "$cand" ] && ADMIN="$cand" && break
    done
fi

# Parse args.
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
        $DIALOG --title "fwknopd-admin status" --msgbox "$out" 12 60
    else
        echo "$out"
    fi
}

show_audit() {
    local f="$RUN_DIR/fwknopd_audit.log"
    if [ ! -r "$f" ]; then msg "No audit log at $f"; return; fi
    local tail
    tail=$(tail -n 30 "$f")
    if [ -n "$DIALOG" ]; then
        $DIALOG --title "Recent audit events (last 30)" --scrolltext --msgbox "$tail" 22 76
    else
        echo "$tail"
    fi
}

show_metrics() {
    local f="$RUN_DIR/fwknopd.metrics"
    if [ ! -r "$f" ]; then msg "No metrics file at $f"; return; fi
    local m
    m=$(cat "$f")
    if [ -n "$DIALOG" ]; then
        $DIALOG --title "Prometheus metrics" --msgbox "$m" 20 70
    else
        echo "$m"
    fi
}

show_tofu() {
    local f="$RUN_DIR/fwknop_tofu.state"
    local out
    if [ -r "$f" ]; then out=$(cat "$f"); else out="(no TOFU state file)"; fi
    if [ -n "$DIALOG" ]; then
        $DIALOG --title "TOFU device bindings" --msgbox "$out" 18 70
    else
        echo "$out"
    fi
}

add_user() {
    local name server access user range
    if [ -z "$DIALOG" ]; then
        read -rp "Name: " name; read -rp "SPA server: " server
        read -rp "Access [tcp/22]: " access; read -rp "User: " user
        read -rp "Port range [30000-60000]: " range
    else
        name=$($DIALOG --inputbox "Profile name" 8 50 --output-fd 1) || return
        server=$($DIALOG --inputbox "SPA server" 8 50 --output-fd 1) || return
        access=$($DIALOG --inputbox "Access (e.g. tcp/22)" 8 50 tcp/22 --output-fd 1) || return
        user=$($DIALOG --inputbox "Username" 8 50 --output-fd 1) || return
        range=$($DIALOG --inputbox "Port range" 8 50 30000-60000 --output-fd 1) || return
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

# Main loop.
while true; do
    if [ -z "$DIALOG" ]; then
        # Plain tty fallback.
        echo; echo "== fwknopd-admin TUI =="
        echo "  1) Status   2) Recent audit   3) Metrics   4) TOFU bindings"
        echo "  5) Add user (issue credential)   0) Quit"
        read -rp "Choice: " c
        case "$c" in
            1) show_status ;;
            2) show_audit ;;
            3) show_metrics ;;
            4) show_tofu ;;
            5) add_user ;;
            0|q|Q) break ;;
        esac
    else
        choice=$($DIALOG --title "fwknopd administration" --menu \
            "fwknopd management (wraps fwknopd-admin)" 14 60 6 \
            1 "Status" \
            2 "Recent audit events" \
            3 "Prometheus metrics" \
            4 "TOFU device bindings" \
            5 "Add user (issue credential)" \
            0 "Quit" --output-fd 1) || break
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
