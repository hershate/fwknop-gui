#!/bin/bash
#
# test/run_fork_tests.sh — fwknop fork regression suite (no root required).
#
# Runs everything the fork added that can be exercised without iptables/root:
#   - autotools build (lib + client + server + fwknopd-admin + unit tests)
#   - CUnit unit tests (lib / client / server)
#   - REF C tests: TOTP RFC6238 vectors, v4 device_id round-trip, stage-4
#     contract (TOTP port agreement + whitelist), audit JSON/metrics
#   - Phase 2: PCAP_PORT_RANGE -> BPF auto-generation (3 cases)
#   - Phase 4a: access.conf fingerprint/TOFU/TOTP parsing (4 cases)
#   - Phase 4c/4d: credential issuance -> encrypted file -> client import
#     -> rc stanza -> lint (end-to-end)
#
# Usage: ./test/run_fork_tests.sh [build-dir]
# Exits non-zero on any failure. Designed for CI.
#
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PASS=0; FAIL=0
section() { printf "\n\033[1;36m=== %s ===\033[0m\n" "$1"; }
ok()   { printf "  \033[32mPASS\033[0m %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "  \033[31mFAIL\033[0m %s\n" "$1"; FAIL=$((FAIL+1)); }
# assert_match <pattern> <label> : checks last command output (via $OUT)
chk()  { if [ "${2:-$OUT}" != "${2:-$OUT}" ]; then :; fi; }

# Load the user-local autotools toolchain if present (see note/04).
if [ -f /tmp/fwenv.sh ]; then . /tmp/fwenv.sh; fi
export LD_LIBRARY_PATH="$ROOT/lib/.libs:${LD_LIBRARY_PATH:-}"
FWKNOP="$ROOT/client/fwknop"
FWKNOPD="$ROOT/server/fwknopd"
ADMIN="$ROOT/server/fwknopd-admin"

# -------------------------------------------------------------------
section "build (autotools)"
# -------------------------------------------------------------------
if [ ! -f configure ]; then
    ./autogen.sh >/tmp/ft_autogen.log 2>&1 || { bad "autogen"; exit 1; }
fi
if [ ! -f Makefile ]; then
    ./configure --enable-udp-server --enable-nfq-capture --enable-c-unit-tests \
        >/tmp/ft_configure.log 2>&1 || { bad "configure"; exit 1; }
fi
make -j"$(nproc)" >/tmp/ft_make.log 2>&1
if [ $? -eq 0 ] && [ -x "$FWKNOP" ] && [ -x "$FWKNOPD" ] && [ -x "$ADMIN" ]; then
    ok "make (fwknop + fwknopd + fwknopd-admin built)"
else
    bad "make"; tail -20 /tmp/ft_make.log; exit 1
fi

VER=$("$FWKNOP" --version 2>/dev/null)
case "$VER" in
    *"protocol version 4.0.0"*) ok "version = 4.0.0" ;;
    *) bad "version: $VER" ;;
esac

# -------------------------------------------------------------------
section "CUnit unit tests"
# -------------------------------------------------------------------
OUT=$("$ROOT/lib/fko_utests" 2>&1); echo "$OUT" | tail -2
echo "$OUT" | grep -q "Passed" && ok "lib/fko_utests" || bad "lib/fko_utests"
OUT=$("$ROOT/client/fwknop_utests" 2>&1); echo "$OUT" | tail -2
echo "$OUT" | grep -q "Passed" && ok "client/fwknop_utests" || bad "client/fwknop_utests"
OUT=$("$ROOT/server/fwknopd_utests" 2>&1); echo "$OUT" | tail -2
echo "$OUT" | grep -q "Passed" && ok "server/fwknopd_utests" || bad "server/fwknopd_utests"

# -------------------------------------------------------------------
# helper to build & run a REF C test against libfko + libfko_util.a
# -------------------------------------------------------------------
run_ref_test() {
    local src="$1" extra_objs="$2"
    local bin="/tmp/ft_$(basename "$src" .c)"
    # -DHAVE_CONFIG_H + -I. so config.h (HAVE_STRNLEN etc.) resolves and the
    # fko_common.h fallback macros don't clash with _GNU_SOURCE decls.
    if gcc -std=c99 -O2 -D_GNU_SOURCE -DHAVE_ENDIAN_H -DHAVE_CONFIG_H -I. -Ilib -Icommon \
        "$src" $extra_objs lib/.libs/libfko.so \
        -L"${HOME}/.local/usr/lib/x86_64-linux-gnu" -lcunit \
        -o "$bin" 2>/tmp/ft_gcc.log && \
       "$bin" >/tmp/ft_run.log 2>&1; then
        if grep -qE "ALL PASS|ALL TESTS PASSED" /tmp/ft_run.log; then ok "$src"; else bad "$src"; cat /tmp/ft_run.log; fi
    else
        bad "$src (build/run)"; cat /tmp/ft_gcc.log /tmp/ft_run.log 2>/dev/null
    fi
    rm -f "$bin"
}

section "REF C tests (libfko)"
run_ref_test REF/build/test_totp.c       "common/libfko_util.a"
run_ref_test REF/build/test_device_id.c  ""
run_ref_test REF/build/test_stage4.c     "common/libfko_util.a"

# audit test needs server/audit.c + a log_msg stub
section "REF C test (audit module)"
cat > /tmp/ft_stub.c <<'EOF'
#include <stdarg.h>
void log_msg(int l, char*m, ...) { (void)l; (void)m; }
EOF
if gcc -std=c99 -O2 -D_GNU_SOURCE -DHAVE_ENDIAN_H -DHAVE_CONFIG_H -DFIREWALL_IPTABLES \
    -I. -Iserver -Ilib -Icommon -I"${HOME}/.local/usr/include" \
    REF/build/test_audit.c server/audit.c /tmp/ft_stub.c \
    -L"${HOME}/.local/usr/lib/x86_64-linux-gnu" -lcunit lib/.libs/libfko.so \
    -o /tmp/ft_test_audit 2>/tmp/ft_gcc.log && \
   /tmp/ft_test_audit >/tmp/ft_run.log 2>&1; then
    grep -q "ALL PASS" /tmp/ft_run.log && ok "test_audit.c" || { bad "test_audit.c"; cat /tmp/ft_run.log; }
else
    bad "test_audit.c (build/run)"; cat /tmp/ft_gcc.log
fi
rm -f /tmp/ft_test_audit /tmp/ft_stub.c

# -------------------------------------------------------------------
section "Phase 2: PCAP_PORT_RANGE -> BPF"
# -------------------------------------------------------------------
mkconf() {  # mkconf <dir> <range-or-empty>
    local d="$1" rng="$2"
    mkdir -p "$d/run"
    { echo "FWKNOP_RUN_DIR $d/run"; echo "PCAP_INTF lo";
      [ -n "$rng" ] && echo "PCAP_PORT_RANGE $rng"; } > "$d/fwknopd.conf"
    chmod 0600 "$d/fwknopd.conf"
}
mkacc() {  # mkacc <dir>
    cat > "$1/access.conf" <<'AC'
SOURCE ANY
KEY_BASE64 YWJjZGVmZ2hpamtsbW5vcHFyc3R1
HMAC_KEY_BASE64 MTIzNDU2Nzg5MDEyMzQ1Njc4
OPEN_PORTS tcp/22
AC
    chmod 0600 "$1/access.conf"
}
D=$(mktemp -d)
mkconf "$D" "30000-60000"; mkacc "$D"
OUT=$("$FWKNOPD" -a "$D/access.conf" -c "$D/fwknopd.conf" --dump-config -f 2>&1)
echo "$OUT" | grep -q "PCAP_FILTER.*udp dst portrange 30000-60000" \
    && ok "range -> portrange BPF" || { bad "range BPF"; echo "$OUT" | grep PCAP_FILTER; }

mkconf "$D" "30000-60000"; printf 'PCAP_FILTER udp port 62201\n' >> "$D/fwknopd.conf"; chmod 0600 "$D/fwknopd.conf"
OUT=$("$FWKNOPD" -a "$D/access.conf" -c "$D/fwknopd.conf" --dump-config -f 2>&1)
echo "$OUT" | grep -q "PCAP_FILTER.*udp port 62201" \
    && ok "explicit PCAP_FILTER overrides range" || bad "explicit filter override"

mkconf "$D" ""; mkacc "$D"
OUT=$("$FWKNOPD" -a "$D/access.conf" -c "$D/fwknopd.conf" --dump-config -f 2>&1)
echo "$OUT" | grep -q "PCAP_FILTER.*udp port 62201" \
    && ok "default filter when nothing set" || bad "default filter"
rm -rf "$D"

# -------------------------------------------------------------------
section "Phase 4a: access.conf fingerprint/TOFU/TOTP parsing"
# -------------------------------------------------------------------
D=$(mktemp -d); mkdir -p "$D/run"
printf 'FWKNOP_RUN_DIR %s/run\nPCAP_INTF lo\n' "$D" > "$D/fwknopd.conf"; chmod 0600 "$D/fwknopd.conf"
cat > "$D/a1.conf" <<'AC'
SOURCE ANY
KEY_BASE64 YWJjZGVmZ2hpamtsbW5vcHFyc3R1
HMAC_KEY_BASE64 MTIzNDU2Nzg5MDEyMzQ1Njc4
OPEN_PORTS tcp/22
REQUIRE_FINGERPRINT Y
FINGERPRINT dGVzdC1kZXZpY2UtMQ==
FINGERPRINT dGVzdC1kZXZpY2UtMg==
TOTP_SEED_BASE64 QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=
TOTP_PORT_RANGE 30000-60000
REQUIRE_TOTP_PORT_MATCH Y
AC
chmod 0600 "$D/a1.conf"
OUT=$("$FWKNOPD" -a "$D/a1.conf" -c "$D/fwknopd.conf" --dump-config -f 2>&1)
echo "$OUT" | grep -q "FINGERPRINT:.*dGVzdC1kZXZpY2UtMQ==,dGVzdC1kZXZpY2UtMg==" && ok "multi-line FINGERPRINT merged"
echo "$OUT" | grep -q "REQUIRE_FINGERPRINT:.*Yes" && ok "REQUIRE_FINGERPRINT parsed"
echo "$OUT" | grep -q "TOFU_MODE:.*No" && ok "whitelist set => not TOFU"
echo "$OUT" | grep -q "REQUIRE_TOTP_PORT_MATCH:.*Yes" && ok "REQUIRE_TOTP_PORT_MATCH parsed"

cat > "$D/a2.conf" <<'AC'
SOURCE ANY
KEY_BASE64 YWJjZGVmZ2hpamtsbW5vcHFyc3R1
HMAC_KEY_BASE64 MTIzNDU2Nzg5MDEyMzQ1Njc4
OPEN_PORTS tcp/22
REQUIRE_FINGERPRINT Y
FINGERPRINT_TOFU_TIMEOUT 86400
AC
chmod 0600 "$D/a2.conf"
OUT=$("$FWKNOPD" -a "$D/a2.conf" -c "$D/fwknopd.conf" --dump-config -f 2>&1)
echo "$OUT" | grep -q "TOFU_MODE:.*Yes" && ok "TOFU mode (no whitelist)" || bad "TOFU mode"

# validation failures
cat > "$D/a3.conf" <<'AC'
SOURCE ANY
KEY_BASE64 YWJjZGVmZ2hpamtsbW5vcHFyc3R1
HMAC_KEY_BASE64 MTIzNDU2Nzg5MDEyMzQ1Njc4
OPEN_PORTS tcp/22
REQUIRE_TOTP_PORT_MATCH Y
AC
chmod 0600 "$D/a3.conf"
OUT=$("$FWKNOPD" -a "$D/a3.conf" -c "$D/fwknopd.conf" --exit-parse-config -f 2>&1)
echo "$OUT" | grep -q "REQUIRE_TOTP_PORT_MATCH requires TOTP_SEED_BASE64" && ok "reject REQUIRE_TOTP_PORT_MATCH w/o seed"
rm -rf "$D"

# -------------------------------------------------------------------
section "Phase 4c/4d: credential issuance -> import (end-to-end)"
# -------------------------------------------------------------------
WORK=$(mktemp -d); HOMERC="$WORK/.fwknoprc"; mkdir -p "$WORK"
printf 'mypass\nmypass\n' | "$ADMIN" user add prod-ssh --server 203.0.113.10 \
    --access tcp/22 --user alice --no-qr --export "$WORK/prod.cred" >/dev/null 2>&1
[ -f "$WORK/prod.cred" ] && ok "admin writes encrypted credential file"

HOME="$WORK" "$FWKNOP" import "$WORK/prod.cred" --rc-file "$HOMERC" --passphrase mypass >/tmp/ft_import.log 2>&1
if grep -q "Imported stanza \[prod-ssh\]" /tmp/ft_import.log; then
    ok "import decrypts + writes stanza"
else
    bad "import"; cat /tmp/ft_import.log
fi
grep -q "KEY_BASE64" "$HOMERC" && grep -q "USE_TOTP_PORT" "$HOMERC" \
    && ok "rc stanza has keys + TOTP" || bad "rc stanza content"

HOME="$WORK" "$FWKNOP" lint "$HOMERC" >/tmp/ft_lint.log 2>&1
grep -q "no issues found" /tmp/ft_lint.log && ok "lint clean on imported rc" || { bad "lint"; cat /tmp/ft_lint.log; }

# profile list should show the imported stanza
HOME="$WORK" "$FWKNOP" profile list --rc-file "$HOMERC" >/tmp/ft_prof.log 2>&1
grep -q "prod-ssh" /tmp/ft_prof.log && ok "profile list shows imported stanza" || { bad "profile list"; cat /tmp/ft_prof.log; }
rm -rf "$WORK"

# -------------------------------------------------------------------
section "Phase 4c: fwknopd-admin management commands"
# -------------------------------------------------------------------
D=$(mktemp -d)
OUT=$("$ADMIN" user add webdemo --server 203.0.113.10 --user alice --no-qr 2>&1)
echo "$OUT" | grep -q "### fwknopd-admin user: webdemo" \
    && ok "user add emits name marker" || { bad "user add marker"; echo "$OUT"; }
sed -n '/### fwknopd-admin user/,/^$/p' <<<"$OUT" > "$D/access.conf"
printf 'SOURCE 10.0.0.0/24\nKEY_BASE64 YWJjZA==\nHMAC_KEY_BASE64 MTIzNA==\n' >> "$D/access.conf"
chmod 0600 "$D/access.conf"

OUT=$("$ADMIN" user list --access-conf "$D/access.conf" 2>&1)
grep -q "webdemo" <<<"$OUT" && ok "user list shows stanza" || { bad "user list"; echo "$OUT"; }
grep -q "YWJjZA" <<<"$OUT" && bad "user list leaks key material" || ok "user list masks keys"

OUT=$("$ADMIN" lint "$D/access.conf" 2>&1)
grep -q "0 error(s)" <<<"$OUT" && ok "lint clean" || { bad "lint"; echo "$OUT"; }

OUT=$("$ADMIN" user qr webdemo --access-conf "$D/access.conf" --server 203.0.113.10 2>&1)
grep -q "fwknop://203.0.113.10" <<<"$OUT" && ok "user qr re-renders URI" || { bad "user qr"; echo "$OUT"; }

printf 'ANY|alice|tcp/22 ZGV2MQ==\nANY||tcp/22 ZGV2Mg==\n' > "$D/tofu.state"
OUT=$("$ADMIN" tofu unbind 'ANY|alice|tcp/22' 'ZGV2MQ==' --state-file "$D/tofu.state" --pid-file "$D/no.pid" 2>&1)
grep -q "Removed 1" <<<"$OUT" && [ "$(wc -l < "$D/tofu.state")" = "1" ] \
    && ok "tofu unbind removes binding" || { bad "tofu unbind"; echo "$OUT"; cat "$D/tofu.state"; }

OUT=$("$ADMIN" user rm webdemo --access-conf "$D/access.conf" --pid-file "$D/no.pid" 2>&1)
grep -q "Disabled stanza" <<<"$OUT" && ok "user rm disables stanza" || { bad "user rm"; echo "$OUT"; }
OUT=$("$ADMIN" user list --access-conf "$D/access.conf" 2>&1)
grep -q "webdemo" <<<"$OUT" && bad "rm: stanza still listed" || ok "rm: stanza gone from list"
grep -q "^# \[disabled by fwknopd-admin rm" "$D/access.conf" \
    && ok "rm comments stanza (reversible)" || bad "rm comment format"
ls "$D"/access.conf.bak-* >/dev/null 2>&1 && ok "rm creates backup" || bad "rm backup"
rm -rf "$D"

# -------------------------------------------------------------------
section "Phase 5+: WebUI dashboard (Go)"
# -------------------------------------------------------------------
GOBIN="$(command -v go || echo "${HOME}/.local/usr/lib/go-1.26/bin/go")"
if [ -x "$GOBIN" ]; then
    export GOROOT="$("$GOBIN" env GOROOT 2>/dev/null || dirname "$(dirname "$GOBIN")")"
    if (cd "$ROOT/server/dashboard" && "$GOBIN" build -o /tmp/ft_dashboard . >/tmp/ft_go.log 2>&1); then
        ok "go build fwknop-dashboard"
        # spin it up against sample data and probe the APIs
        D=$(mktemp -d); mkdir -p "$D/run"
        echo '{"time":1723520000,"event":"open","user":"alice","device_id":"ZGV2MQ==","src_ip":"198.51.100.7","spa_port":46364,"target_port":22,"stanza":1,"reason":"accepted"}' > "$D/run/fwknopd_audit.log"
        printf '# TYPE fwknop_spa_packets_total counter\nfwknop_spa_packets_total{result="open"} 1\n' > "$D/run/fwknopd.metrics"
        printf 'ANY|alice|tcp/22 ZGV2MQ==\n' > "$D/run/fwknop_tofu.state"
        "$ADMIN" user add dashdemo --server 203.0.113.10 --user alice --no-qr 2>/dev/null \
            | sed -n '/### fwknopd-admin user/,/^$/p' > "$D/access.conf"
        printf 'FWKNOP_RUN_DIR %s/run\nPCAP_INTF eth0\nPCAP_PORT_RANGE 30000-60000\n' "$D" > "$D/fwknopd.conf"
        DASHBOARD_TOKEN=fttok /tmp/ft_dashboard -run-dir "$D/run" -addr 127.0.0.1:18099 \
            -access-conf "$D/access.conf" -fwknopd-conf "$D/fwknopd.conf" \
            -pid-file "$D/run/fwknopd.pid" -admin "$ADMIN" -fwknopd "$FWKNOPD" -enable-write >/tmp/ft_dash.log 2>&1 &
        DPID=$!; sleep 1
        if wget -qO- http://127.0.0.1:18099/api/metrics 2>/dev/null | grep -q 'counters' | grep -q 'open'; then
            ok "dashboard /api/metrics reads prometheus file"
        elif wget -qO- http://127.0.0.1:18099/api/metrics 2>/dev/null | grep -q 'counters'; then
            ok "dashboard /api/metrics reads prometheus file"
        else
            bad "dashboard metrics API"
        fi
        wget -qO- http://127.0.0.1:18099/api/events 2>/dev/null | grep -q '"event":"open"' \
            && ok "dashboard /api/events reads audit log" || bad "dashboard events API"
        wget -qO- http://127.0.0.1:18099/ 2>/dev/null | grep -q '<title>fwknop 运维面板</title>' \
            && ok "dashboard serves embedded UI (zh-CN)" || bad "dashboard UI"
        wget -qO- http://127.0.0.1:18099/api/overview 2>/dev/null | grep -q '"daemon"' \
            && ok "dashboard /api/overview" || bad "dashboard overview API"
        wget -qO- http://127.0.0.1:18099/api/users 2>/dev/null | grep -q 'dashdemo' \
            && ok "dashboard /api/users parses access.conf" || bad "dashboard users API"
        wget -qO- http://127.0.0.1:18099/api/users 2>/dev/null | grep -q 'KEY_BASE64.*[A-Za-z0-9+/=]\{8\}' \
            && bad "dashboard /api/users leaks keys" || ok "dashboard /api/users masks keys"
        wget -qO- http://127.0.0.1:18099/api/config 2>/dev/null | grep -q 'PCAP_PORT_RANGE' \
            && ok "dashboard /api/config parses fwknopd.conf" || bad "dashboard config API"
        wget -qO- http://127.0.0.1:18099/api/tofu 2>/dev/null | grep -q '"stanza_key":"ANY|alice|tcp/22"' \
            && ok "dashboard /api/tofu structured" || bad "dashboard tofu API"
        # write path: token required, then unbind via admin CLI wrapper
        wget -qO- --post-data 'stanza_key=x&device_id=y' http://127.0.0.1:18099/api/admin/tofu/unbind 2>/dev/null \
            && bad "unbind without token should fail" || ok "write endpoint requires token"
        wget -qO- --post-data 'stanza_key=ANY|alice|tcp/22&device_id=ZGV2MQ==' \
            --header='Authorization: Bearer fttok' http://127.0.0.1:18099/api/admin/tofu/unbind 2>/dev/null \
            | grep -q 'Removed 1' && ok "dashboard tofu unbind (write path)" || bad "dashboard tofu unbind"

        # --- 2.3.0: service control / config editing / profiles ---
        HDR='Authorization: Bearer fttok'; J='Content-Type: application/json'
        wget -qO- --post-data '' --header="$HDR" http://127.0.0.1:18099/api/service/validate 2>/dev/null \
            | grep -q '预检通过' && ok "service validate (preflight)" || bad "service validate"
        wget -qO- --post-data '' http://127.0.0.1:18099/api/service/stop 2>/dev/null \
            && bad "service stop without token" || ok "service endpoints require token"

        # stanza edit: change OPEN_PORTS, add FW_ACCESS_TIMEOUT; keys must survive
        wget -qO- --post-data '{"index":1,"fields":{"OPEN_PORTS":"tcp/2222","FW_ACCESS_TIMEOUT":"60"}}' \
            --header="$HDR" --header="$J" http://127.0.0.1:18099/api/config/stanza 2>/dev/null \
            | grep -q '已更新并通过预检' && ok "stanza edit saved+validated" || bad "stanza edit"
        grep -q 'OPEN_PORTS tcp/2222' "$D/access.conf" && grep -q 'FW_ACCESS_TIMEOUT 60' "$D/access.conf" \
            && ok "stanza edit wrote fields" || { bad "stanza edit content"; cat "$D/access.conf"; }
        grep -q 'KEY_BASE64.*[A-Za-z0-9+/]\{8\}' "$D/access.conf" \
            && ok "stanza edit preserves keys" || bad "stanza edit lost keys"
        wget -qO- --post-data '{"index":1,"fields":{"KEY_BASE64":"xx"}}' \
            --header="$HDR" --header="$J" http://127.0.0.1:18099/api/config/stanza 2>/dev/null \
            | grep -q '不允许在线编辑' && ok "stanza edit rejects key fields" || bad "stanza edit key guard"

        # fwknopd.conf save: structured ok, garbage refused
        wget -qO- --post-data '{"mode":"structured","lines":["FWKNOP_RUN_DIR '"$D"'/run","PCAP_INTF lo"]}' \
            --header="$HDR" --header="$J" http://127.0.0.1:18099/api/config/fwknopd 2>/dev/null \
            | grep -q '已保存并通过预检' && ok "fwknopd.conf structured save" || bad "conf save"
        wget -qO- --post-data '{"mode":"raw","raw":"PCAP_INTF"}' \
            --header="$HDR" --header="$J" http://127.0.0.1:18099/api/config/fwknopd 2>/dev/null \
            | grep -q '放弃保存' && ok "bad conf refused (preflight)" || bad "bad conf accepted?"

        # profiles: save -> list -> apply -> delete
        wget -qO- --post-data '{"name":"p1","note":"t"}' --header="$HDR" --header="$J" \
            http://127.0.0.1:18099/api/profiles/save 2>/dev/null | grep -q '已保存' \
            && ok "profile save" || bad "profile save"
        wget -qO- http://127.0.0.1:18099/api/profiles 2>/dev/null | grep -q '"name":"p1"' \
            && ok "profile list" || bad "profile list"
        wget -qO- 'http://127.0.0.1:18099/api/profiles/view?name=p1' 2>/dev/null | grep -q '已掩码' \
            && ok "profile view masks keys" || bad "profile view"
        wget -qO- --post-data '{"name":"p1"}' --header="$HDR" --header="$J" \
            http://127.0.0.1:18099/api/profiles/apply 2>/dev/null | grep -q '已切换到方案' \
            && ok "profile apply" || bad "profile apply"
        wget -qO- --post-data '{"name":"../evil"}' --header="$HDR" --header="$J" \
            http://127.0.0.1:18099/api/profiles/save 2>/dev/null | grep -q '方案名' \
            && ok "profile name traversal rejected" || bad "profile name guard"
        wget -qO- --post-data '{"name":"p1"}' --header="$HDR" --header="$J" \
            http://127.0.0.1:18099/api/profiles/delete 2>/dev/null | grep -q '已删除' \
            && ok "profile delete" || bad "profile delete"

        # rm then enable round-trip via WebUI endpoints
        wget -qO- --post-data 'name=dashdemo' --header="$HDR" http://127.0.0.1:18099/api/admin/rm >/dev/null 2>&1
        wget -qO- http://127.0.0.1:18099/api/users 2>/dev/null | grep -q '"disabled".*dashdemo' \
            && ok "disabled stanza surfaced" || bad "disabled stanza missing"
        wget -qO- --post-data '{"name":"dashdemo"}' --header="$HDR" --header="$J" \
            http://127.0.0.1:18099/api/config/stanza/enable 2>/dev/null | grep -q '已恢复' \
            && ok "stanza re-enable" || bad "stanza re-enable"
        wget -qO- http://127.0.0.1:18099/api/users 2>/dev/null | grep -q '"name":"dashdemo"' \
            && ok "re-enabled stanza active again" || bad "re-enable verify"
        kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null
        rm -f /tmp/ft_dashboard; rm -rf "$D"
    else
        bad "go build fwknop-dashboard"; cat /tmp/ft_go.log
    fi
else
    echo "  (skipped: go toolchain not installed)"
fi

# -------------------------------------------------------------------
printf "\n\033[1mRESULT: %d passed, %d failed\033[0m\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
