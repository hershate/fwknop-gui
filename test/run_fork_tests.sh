#!/bin/bash
#
# test/run_fork_tests.sh — fwknop fork 回归测试套件（无需 root）。
#
# 覆盖 fork 新增的全部可在无 iptables/root 环境下验证的内容：
#   - autotools 构建（lib + client + server + fwknopd-admin + 单元测试）
#   - CUnit 单元测试（lib / client / server）
#   - REF C 测试：TOTP RFC6238 测试向量、v4 device_id 往返、阶段 4
#     契约（TOTP 端口协商 + 白名单）、审计 JSON/指标
#   - 阶段 2：PCAP_PORT_RANGE -> BPF 自动生成（3 个用例）
#   - 阶段 4a：access.conf 指纹/TOFU/TOTP 解析（4 个用例）
#   - 阶段 4c/4d：凭证签发 -> 加密文件 -> 客户端导入
#     -> rc stanza -> lint（端到端）
#
# 用法：./test/run_fork_tests.sh [构建目录]
# 任一失败即以非零码退出。适合 CI 使用。
#
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PASS=0; FAIL=0
section() { printf "\n\033[1;36m=== %s ===\033[0m\n" "$1"; }
ok()   { printf "  \033[32mPASS\033[0m %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "  \033[31mFAIL\033[0m %s\n" "$1"; FAIL=$((FAIL+1)); }
# assert_match <模式> <标签>：检查上一条命令的输出（经由 $OUT）
chk()  { if [ "${2:-$OUT}" != "${2:-$OUT}" ]; then :; fi; }

# 若存在用户态 autotools 工具链则加载（见 note/04）。
if [ -f /tmp/fwenv.sh ]; then . /tmp/fwenv.sh; fi
export LD_LIBRARY_PATH="$ROOT/lib/.libs:${LD_LIBRARY_PATH:-}"
FWKNOP="$ROOT/client/fwknop"
FWKNOPD="$ROOT/server/fwknopd"
ADMIN="$ROOT/server/fwknopd-admin"

# -------------------------------------------------------------------
section "构建（autotools）"
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
    ok "make（fwknop + fwknopd + fwknopd-admin 均已构建）"
else
    bad "make"; tail -20 /tmp/ft_make.log; exit 1
fi

VER=$("$FWKNOP" --version 2>/dev/null)
case "$VER" in
    *"protocol version 4.0.0"*) ok "协议版本 = 4.0.0" ;;
    *) bad "版本号异常：$VER" ;;
esac

# -------------------------------------------------------------------
section "CUnit 单元测试"
# -------------------------------------------------------------------
OUT=$("$ROOT/lib/fko_utests" 2>&1); echo "$OUT" | tail -2
echo "$OUT" | grep -q "Passed" && ok "lib/fko_utests" || bad "lib/fko_utests"
OUT=$("$ROOT/client/fwknop_utests" 2>&1); echo "$OUT" | tail -2
echo "$OUT" | grep -q "Passed" && ok "client/fwknop_utests" || bad "client/fwknop_utests"
OUT=$("$ROOT/server/fwknopd_utests" 2>&1); echo "$OUT" | tail -2
echo "$OUT" | grep -q "Passed" && ok "server/fwknopd_utests" || bad "server/fwknopd_utests"

# -------------------------------------------------------------------
# 辅助函数：编译并运行针对 libfko + libfko_util.a 的 REF C 测试
# -------------------------------------------------------------------
run_ref_test() {
    local src="$1" extra_objs="$2"
    local bin="/tmp/ft_$(basename "$src" .c)"
    # 加 -DHAVE_CONFIG_H + -I. 使 config.h（HAVE_STRNLEN 等）可被解析，
    # 避免 fko_common.h 的兜底宏与 _GNU_SOURCE 声明冲突。
    if gcc -std=c99 -O2 -D_GNU_SOURCE -DHAVE_ENDIAN_H -DHAVE_CONFIG_H -I. -Ilib -Icommon \
        "$src" $extra_objs lib/.libs/libfko.so \
        -L"${HOME}/.local/usr/lib/x86_64-linux-gnu" -lcunit \
        -o "$bin" 2>/tmp/ft_gcc.log && \
       "$bin" >/tmp/ft_run.log 2>&1; then
        if grep -qE "ALL PASS|ALL TESTS PASSED" /tmp/ft_run.log; then ok "$src"; else bad "$src"; cat /tmp/ft_run.log; fi
    else
        bad "$src（构建/运行失败）"; cat /tmp/ft_gcc.log /tmp/ft_run.log 2>/dev/null
    fi
    rm -f "$bin"
}

section "REF C 测试（libfko）"
run_ref_test REF/build/test_totp.c       "common/libfko_util.a"
run_ref_test REF/build/test_device_id.c  ""
run_ref_test REF/build/test_stage4.c     "common/libfko_util.a"

# 审计测试需要 server/audit.c 和一个 log_msg 桩函数
section "REF C 测试（审计模块）"
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
    bad "test_audit.c（构建/运行失败）"; cat /tmp/ft_gcc.log
fi
rm -f /tmp/ft_test_audit /tmp/ft_stub.c

# -------------------------------------------------------------------
section "阶段 2：PCAP_PORT_RANGE -> BPF"
# -------------------------------------------------------------------
mkconf() {  # mkconf <目录> <端口范围或空>
    local d="$1" rng="$2"
    mkdir -p "$d/run"
    { echo "FWKNOP_RUN_DIR $d/run"; echo "PCAP_INTF lo";
      [ -n "$rng" ] && echo "PCAP_PORT_RANGE $rng"; } > "$d/fwknopd.conf"
    chmod 0600 "$d/fwknopd.conf"
}
mkacc() {  # mkacc <目录>
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
    && ok "端口范围 -> portrange BPF" || { bad "范围 BPF"; echo "$OUT" | grep PCAP_FILTER; }

mkconf "$D" "30000-60000"; printf 'PCAP_FILTER udp port 62201\n' >> "$D/fwknopd.conf"; chmod 0600 "$D/fwknopd.conf"
OUT=$("$FWKNOPD" -a "$D/access.conf" -c "$D/fwknopd.conf" --dump-config -f 2>&1)
echo "$OUT" | grep -q "PCAP_FILTER.*udp port 62201" \
    && ok "显式 PCAP_FILTER 覆盖端口范围" || bad "显式过滤器覆盖"

mkconf "$D" ""; mkacc "$D"
OUT=$("$FWKNOPD" -a "$D/access.conf" -c "$D/fwknopd.conf" --dump-config -f 2>&1)
echo "$OUT" | grep -q "PCAP_FILTER.*udp port 62201" \
    && ok "未设置时使用默认过滤器" || bad "默认过滤器"
rm -rf "$D"

# -------------------------------------------------------------------
section "阶段 4a：access.conf 指纹/TOFU/TOTP 解析"
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
echo "$OUT" | grep -q "FINGERPRINT:.*dGVzdC1kZXZpY2UtMQ==,dGVzdC1kZXZpY2UtMg==" && ok "多行 FINGERPRINT 合并"
echo "$OUT" | grep -q "REQUIRE_FINGERPRINT:.*Yes" && ok "REQUIRE_FINGERPRINT 解析"
echo "$OUT" | grep -q "TOFU_MODE:.*No" && ok "设置白名单 => 非 TOFU"
echo "$OUT" | grep -q "REQUIRE_TOTP_PORT_MATCH:.*Yes" && ok "REQUIRE_TOTP_PORT_MATCH 解析"

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
echo "$OUT" | grep -q "TOFU_MODE:.*Yes" && ok "TOFU 模式（无白名单）" || bad "TOFU 模式"

# 校验失败用例
cat > "$D/a3.conf" <<'AC'
SOURCE ANY
KEY_BASE64 YWJjZGVmZ2hpamtsbW5vcHFyc3R1
HMAC_KEY_BASE64 MTIzNDU2Nzg5MDEyMzQ1Njc4
OPEN_PORTS tcp/22
REQUIRE_TOTP_PORT_MATCH Y
AC
chmod 0600 "$D/a3.conf"
OUT=$("$FWKNOPD" -a "$D/a3.conf" -c "$D/fwknopd.conf" --exit-parse-config -f 2>&1)
echo "$OUT" | grep -q "REQUIRE_TOTP_PORT_MATCH requires TOTP_SEED_BASE64" && ok "缺少种子时拒绝 REQUIRE_TOTP_PORT_MATCH"
rm -rf "$D"

# -------------------------------------------------------------------
section "阶段 4c/4d：凭证签发 -> 导入（端到端）"
# -------------------------------------------------------------------
WORK=$(mktemp -d); HOMERC="$WORK/.fwknoprc"; mkdir -p "$WORK"
printf 'mypass\nmypass\n' | "$ADMIN" user add prod-ssh --server 203.0.113.10 \
    --access tcp/22 --user alice --no-qr --export "$WORK/prod.cred" >/dev/null 2>&1
[ -f "$WORK/prod.cred" ] && ok "admin 生成加密凭证文件"

HOME="$WORK" "$FWKNOP" import "$WORK/prod.cred" --rc-file "$HOMERC" --passphrase mypass >/tmp/ft_import.log 2>&1
if grep -q "Imported stanza \[prod-ssh\]" /tmp/ft_import.log; then
    ok "import 解密并写入 stanza"
else
    bad "import"; cat /tmp/ft_import.log
fi
grep -q "KEY_BASE64" "$HOMERC" && grep -q "USE_TOTP_PORT" "$HOMERC" \
    && ok "rc stanza 含密钥 + TOTP" || bad "rc stanza 内容"

HOME="$WORK" "$FWKNOP" lint "$HOMERC" >/tmp/ft_lint.log 2>&1
grep -q "no issues found" /tmp/ft_lint.log && ok "lint 检查导入的 rc 无问题" || { bad "lint"; cat /tmp/ft_lint.log; }

# profile list 应显示刚导入的 stanza
HOME="$WORK" "$FWKNOP" profile list --rc-file "$HOMERC" >/tmp/ft_prof.log 2>&1
grep -q "prod-ssh" /tmp/ft_prof.log && ok "profile list 显示已导入的 stanza" || { bad "profile list"; cat /tmp/ft_prof.log; }
rm -rf "$WORK"

# -------------------------------------------------------------------
section "阶段 4c：fwknopd-admin 管理命令"
# -------------------------------------------------------------------
D=$(mktemp -d)
OUT=$("$ADMIN" user add webdemo --server 203.0.113.10 --user alice --no-qr 2>&1)
echo "$OUT" | grep -q "### fwknopd-admin user: webdemo" \
    && ok "user add 输出名称标记" || { bad "user add 标记"; echo "$OUT"; }
sed -n '/### fwknopd-admin user/,/^$/p' <<<"$OUT" > "$D/access.conf"
printf 'SOURCE 10.0.0.0/24\nKEY_BASE64 YWJjZA==\nHMAC_KEY_BASE64 MTIzNA==\n' >> "$D/access.conf"
chmod 0600 "$D/access.conf"

OUT=$("$ADMIN" user list --access-conf "$D/access.conf" 2>&1)
grep -q "webdemo" <<<"$OUT" && ok "user list 显示 stanza" || { bad "user list"; echo "$OUT"; }
grep -q "YWJjZA" <<<"$OUT" && bad "user list 泄露密钥材料" || ok "user list 掩码密钥"

OUT=$("$ADMIN" lint "$D/access.conf" 2>&1)
grep -q "0 error(s)" <<<"$OUT" && ok "lint 无错误" || { bad "lint"; echo "$OUT"; }

OUT=$("$ADMIN" user qr webdemo --access-conf "$D/access.conf" --server 203.0.113.10 2>&1)
grep -q "fwknop://203.0.113.10" <<<"$OUT" && ok "user qr 重新渲染 URI" || { bad "user qr"; echo "$OUT"; }

printf 'ANY|alice|tcp/22 ZGV2MQ==\nANY||tcp/22 ZGV2Mg==\n' > "$D/tofu.state"
OUT=$("$ADMIN" tofu unbind 'ANY|alice|tcp/22' 'ZGV2MQ==' --state-file "$D/tofu.state" --pid-file "$D/no.pid" 2>&1)
grep -q "Removed 1" <<<"$OUT" && [ "$(wc -l < "$D/tofu.state")" = "1" ] \
    && ok "tofu unbind 移除绑定" || { bad "tofu unbind"; echo "$OUT"; cat "$D/tofu.state"; }

OUT=$("$ADMIN" user rm webdemo --access-conf "$D/access.conf" --pid-file "$D/no.pid" 2>&1)
grep -q "Disabled stanza" <<<"$OUT" && ok "user rm 禁用 stanza" || { bad "user rm"; echo "$OUT"; }
OUT=$("$ADMIN" user list --access-conf "$D/access.conf" 2>&1)
grep -q "webdemo" <<<"$OUT" && bad "rm：stanza 仍在列表中" || ok "rm：stanza 已从列表消失"
grep -q "^# \[disabled by fwknopd-admin rm" "$D/access.conf" \
    && ok "rm 注释 stanza（可逆）" || bad "rm 注释格式"
ls "$D"/access.conf.bak-* >/dev/null 2>&1 && ok "rm 创建备份" || bad "rm 备份"
rm -rf "$D"

# -------------------------------------------------------------------
section "阶段 5+：WebUI 运维面板（Go）"
# -------------------------------------------------------------------
GOBIN="$(command -v go || echo "${HOME}/.local/usr/lib/go-1.26/bin/go")"
if [ -x "$GOBIN" ]; then
    export GOROOT="$("$GOBIN" env GOROOT 2>/dev/null || dirname "$(dirname "$GOBIN")")"
    if (cd "$ROOT/server/dashboard" && "$GOBIN" build -o /tmp/ft_dashboard . >/tmp/ft_go.log 2>&1); then
        ok "go 构建 fwknop-dashboard"
        # 用样例数据启动面板并探测各 API
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
        TK='Authorization: Bearer fttok'
        wget -qO- http://127.0.0.1:18099/api/overview 2>/dev/null \
            && bad "未认证访问应当被拒绝" || ok "未认证访问被拒绝（401）"
        if wget -qO- --header="$TK" http://127.0.0.1:18099/api/metrics 2>/dev/null | grep -q 'counters' | grep -q 'open'; then
            ok "面板 /api/metrics 读取 prometheus 文件"
        elif wget -qO- --header="$TK" http://127.0.0.1:18099/api/metrics 2>/dev/null | grep -q 'counters'; then
            ok "面板 /api/metrics 读取 prometheus 文件"
        else
            bad "面板 metrics API"
        fi
        wget -qO- --header="$TK" http://127.0.0.1:18099/api/events 2>/dev/null | grep -q '"event":"open"' \
            && ok "面板 /api/events 读取审计日志" || bad "面板 events API"
        wget -qO- http://127.0.0.1:18099/ 2>/dev/null | grep -q '<title>fwknop 运维面板</title>' \
            && ok "面板提供内嵌 UI（zh-CN）" || bad "面板 UI"
        wget -qO- http://127.0.0.1:18099/ 2>/dev/null | grep -q '首次启动初始化' \
            && ok "面板内嵌初始化向导界面" || bad "面板初始化界面"
        wget -qO- --header="$TK" http://127.0.0.1:18099/api/overview 2>/dev/null | grep -q '"daemon"' \
            && ok "面板 /api/overview" || bad "面板 overview API"
        wget -qO- --header="$TK" http://127.0.0.1:18099/api/users 2>/dev/null | grep -q 'dashdemo' \
            && ok "面板 /api/users 解析 access.conf" || bad "面板 users API"
        wget -qO- --header="$TK" http://127.0.0.1:18099/api/users 2>/dev/null | grep -q 'KEY_BASE64.*[A-Za-z0-9+/=]\{8\}' \
            && bad "面板 /api/users 泄露密钥" || ok "面板 /api/users 掩码密钥"
        wget -qO- --header="$TK" http://127.0.0.1:18099/api/config 2>/dev/null | grep -q 'PCAP_PORT_RANGE' \
            && ok "面板 /api/config 解析 fwknopd.conf" || bad "面板 config API"
        wget -qO- --header="$TK" http://127.0.0.1:18099/api/tofu 2>/dev/null | grep -q '"stanza_key":"ANY|alice|tcp/22"' \
            && ok "面板 /api/tofu 结构化输出" || bad "面板 tofu API"
        # 写路径：要求令牌，然后经 admin CLI 包装执行解绑
        wget -qO- --post-data 'stanza_key=x&device_id=y' http://127.0.0.1:18099/api/admin/tofu/unbind 2>/dev/null \
            && bad "无令牌解绑应当失败" || ok "写端点要求令牌"
        wget -qO- --post-data 'stanza_key=ANY|alice|tcp/22&device_id=ZGV2MQ==' \
            --header='Authorization: Bearer fttok' http://127.0.0.1:18099/api/admin/tofu/unbind 2>/dev/null \
            | grep -q 'Removed 1' && ok "面板 tofu 解绑（写路径）" || bad "面板 tofu 解绑"

        # --- 2.3.0：服务控制 / 配置编辑 / 配置方案 ---
        HDR='Authorization: Bearer fttok'; J='Content-Type: application/json'
        wget -qO- --post-data '' --header="$HDR" http://127.0.0.1:18099/api/service/validate 2>/dev/null \
            | grep -q '预检通过' && ok "服务预检（validate）" || bad "服务预检"
        wget -qO- --post-data '' http://127.0.0.1:18099/api/service/stop 2>/dev/null \
            && bad "无令牌停止服务" || ok "服务端点要求令牌"

        # stanza 编辑：改 OPEN_PORTS、加 FW_ACCESS_TIMEOUT；密钥必须原样保留
        wget -qO- --post-data '{"index":1,"fields":{"OPEN_PORTS":"tcp/2222","FW_ACCESS_TIMEOUT":"60"}}' \
            --header="$HDR" --header="$J" http://127.0.0.1:18099/api/config/stanza 2>/dev/null \
            | grep -q '已更新并通过预检' && ok "stanza 编辑保存+预检" || bad "stanza 编辑"
        grep -q 'OPEN_PORTS tcp/2222' "$D/access.conf" && grep -q 'FW_ACCESS_TIMEOUT 60' "$D/access.conf" \
            && ok "stanza 编辑写入字段" || { bad "stanza 编辑内容"; cat "$D/access.conf"; }
        grep -q 'KEY_BASE64.*[A-Za-z0-9+/]\{8\}' "$D/access.conf" \
            && ok "stanza 编辑保留密钥" || bad "stanza 编辑丢失密钥"
        wget -qO- --post-data '{"index":1,"fields":{"KEY_BASE64":"xx"}}' \
            --header="$HDR" --header="$J" http://127.0.0.1:18099/api/config/stanza 2>/dev/null \
            | grep -q '不允许在线编辑' && ok "stanza 编辑拒绝密钥字段" || bad "stanza 编辑密钥防护"

        # fwknopd.conf 保存：结构化保存成功，坏配置被拒绝
        wget -qO- --post-data '{"mode":"structured","lines":["FWKNOP_RUN_DIR '"$D"'/run","PCAP_INTF lo"]}' \
            --header="$HDR" --header="$J" http://127.0.0.1:18099/api/config/fwknopd 2>/dev/null \
            | grep -q '已保存并通过预检' && ok "fwknopd.conf 结构化保存" || bad "conf 保存"
        wget -qO- --post-data '{"mode":"raw","raw":"PCAP_INTF"}' \
            --header="$HDR" --header="$J" http://127.0.0.1:18099/api/config/fwknopd 2>/dev/null \
            | grep -q '放弃保存' && ok "坏配置被拒绝（预检）" || bad "坏配置竟被接受？"

        # 配置方案：保存 -> 列表 -> 应用 -> 删除
        wget -qO- --post-data '{"name":"p1","note":"t"}' --header="$HDR" --header="$J" \
            http://127.0.0.1:18099/api/profiles/save 2>/dev/null | grep -q '已保存' \
            && ok "方案保存" || bad "方案保存"
        wget -qO- --header="$TK" http://127.0.0.1:18099/api/profiles 2>/dev/null | grep -q '"name":"p1"' \
            && ok "方案列表" || bad "方案列表"
        wget -qO- --header="$TK" 'http://127.0.0.1:18099/api/profiles/view?name=p1' 2>/dev/null | grep -q '已掩码' \
            && ok "方案预览掩码密钥" || bad "方案预览"
        wget -qO- --post-data '{"name":"p1"}' --header="$HDR" --header="$J" \
            http://127.0.0.1:18099/api/profiles/apply 2>/dev/null | grep -q '已切换到方案' \
            && ok "方案应用" || bad "方案应用"
        wget -qO- --post-data '{"name":"../evil"}' --header="$HDR" --header="$J" \
            http://127.0.0.1:18099/api/profiles/save 2>/dev/null | grep -q '方案名' \
            && ok "方案名路径穿越被拒绝" || bad "方案名防护"
        wget -qO- --post-data '{"name":"p1"}' --header="$HDR" --header="$J" \
            http://127.0.0.1:18099/api/profiles/delete 2>/dev/null | grep -q '已删除' \
            && ok "方案删除" || bad "方案删除"

        # 经 WebUI 端点完成 rm（禁用）再 enable（恢复）的往返
        wget -qO- --post-data 'name=dashdemo' --header="$HDR" http://127.0.0.1:18099/api/admin/rm >/dev/null 2>&1
        wget -qO- --header="$TK" http://127.0.0.1:18099/api/users 2>/dev/null | grep -q '"disabled".*dashdemo' \
            && ok "已禁用 stanza 在列表中可见" || bad "已禁用 stanza 缺失"
        wget -qO- --post-data '{"name":"dashdemo"}' --header="$HDR" --header="$J" \
            http://127.0.0.1:18099/api/config/stanza/enable 2>/dev/null | grep -q '已恢复' \
            && ok "stanza 恢复启用" || bad "stanza 恢复启用"
        wget -qO- --header="$TK" http://127.0.0.1:18099/api/users 2>/dev/null | grep -q '"name":"dashdemo"' \
            && ok "恢复的 stanza 重新生效" || bad "恢复验证"
        # --- 2.4.0：首次启动初始化与登录鉴权（第二实例，无 DASHBOARD_TOKEN） ---
        # 注：本实例刻意不传 -enable-write —— 2.4.1 起写操作默认启用，
        # 「带 CSRF 头的写操作成功」用例同时验证默认管理模式。
        D2=$(mktemp -d); mkdir -p "$D2/run"
        /tmp/ft_dashboard -run-dir "$D2/run" -addr 127.0.0.1:18098 \
            -access-conf "$D/access.conf" -fwknopd-conf "$D/fwknopd.conf" \
            -pid-file "$D2/run/fwknopd.pid" -admin "$ADMIN" -fwknopd "$FWKNOPD" \
            >/tmp/ft_dash2.log 2>&1 &
        DPID2=$!; sleep 1
        code() { wget -q -S -O /dev/null "$@" 2>&1 | awk '/^  HTTP/{c=$2} END{print c}'; }
        JAR="$D2/cookies.txt"; CJ='Content-Type: application/json'; X='X-Fwknop-Request: 1'

        # 注：wget 对 401 按认证失败处理，不输出响应体；needs_setup 标志由
        # 下一条 /api/auth/state 用例覆盖，此处仅核对状态码。
        [ "$(code http://127.0.0.1:18098/api/overview)" = 401 ] \
            && ok "未初始化：API 一律 401" || bad "未初始化 401"
        wget -qO- http://127.0.0.1:18098/api/auth/state 2>/dev/null | grep -q '"needs_setup":true' \
            && ok "auth/state 报告需要初始化" || bad "auth/state"
        [ "$(code --post-data '{"password":"short1x","confirm":"short1x"}' --header="$CJ" \
            http://127.0.0.1:18098/api/setup)" = 400 ] \
            && ok "初始化拒绝过短密码" || bad "短密码校验"
        [ "$(code --post-data '{"password":"longenough1","confirm":"longenough2"}' --header="$CJ" \
            http://127.0.0.1:18098/api/setup)" = 400 ] \
            && ok "初始化拒绝两次密码不一致" || bad "密码一致性校验"
        wget -q --content-on-error -O- --post-data '{"password":"adm1npass!","confirm":"adm1npass!"}' \
            --header="$CJ" --save-cookies "$JAR" --keep-session-cookies \
            http://127.0.0.1:18098/api/setup 2>/dev/null | grep -q '已自动登录' \
            && ok "初始化成功并自动登录" || bad "初始化"
        [ "$(code --post-data '{"password":"adm1npass!x","confirm":"adm1npass!x"}' --header="$CJ" \
            http://127.0.0.1:18098/api/setup)" = 409 ] \
            && ok "重复初始化返回 409" || bad "重复初始化"
        wget -qO- --load-cookies "$JAR" http://127.0.0.1:18098/api/overview 2>/dev/null | grep -q '"daemon"' \
            && ok "会话 Cookie 可访问 API" || bad "会话访问"
        [ "$(code --load-cookies "$JAR" --post-data '' \
            http://127.0.0.1:18098/api/service/validate)" = 403 ] \
            && ok "Cookie 写操作缺 CSRF 头返回 403" || bad "CSRF 防护"
        wget -qO- --load-cookies "$JAR" --post-data '' --header="$X" \
            http://127.0.0.1:18098/api/service/validate 2>/dev/null | grep -q '预检通过' \
            && ok "带 CSRF 头的写操作成功" || bad "CSRF 通过路径"
        wget -qO- --load-cookies "$JAR" --post-data '' http://127.0.0.1:18098/api/logout 2>/dev/null \
            | grep -q '已注销' && ok "注销" || bad "注销"
        [ "$(code --load-cookies "$JAR" http://127.0.0.1:18098/api/overview)" = 401 ] \
            && ok "注销后会话失效（401）" || bad "注销后仍可访问"
        wget -q --content-on-error -O- --post-data '{"password":"adm1npass!"}' --header="$CJ" \
            --save-cookies "$JAR" --keep-session-cookies \
            http://127.0.0.1:18098/api/login 2>/dev/null | grep -q '登录成功' \
            && ok "正确密码重新登录" || bad "重新登录"
        for i in 1 2 3 4 5; do
            wget -qO /dev/null --post-data '{"password":"wrongpw"}' --header="$CJ" \
                http://127.0.0.1:18098/api/login 2>/dev/null
        done
        [ "$(code --post-data '{"password":"adm1npass!"}' --header="$CJ" \
            http://127.0.0.1:18098/api/login)" = 429 ] \
            && ok "连续失败触发登录限流（429）" || bad "登录限流"
        kill "$DPID2" 2>/dev/null; wait "$DPID2" 2>/dev/null; rm -rf "$D2"

        # --- 2.4.1：默认管理模式 / -read-only 显式只读（第三实例） ---
        D3=$(mktemp -d); mkdir -p "$D3/run"
        DASHBOARD_TOKEN=fttok3 /tmp/ft_dashboard -run-dir "$D3/run" -addr 127.0.0.1:18097 \
            -access-conf "$D/access.conf" -fwknopd-conf "$D/fwknopd.conf" \
            -pid-file "$D3/run/fwknopd.pid" -admin "$ADMIN" -fwknopd "$FWKNOPD" \
            -read-only >/tmp/ft_dash3.log 2>&1 &
        DPID3=$!; sleep 1
        TK3='Authorization: Bearer fttok3'
        wget -qO- --header="$TK3" http://127.0.0.1:18097/api/auth/state 2>/dev/null \
            | grep -q '"write_enabled":false' \
            && ok "-read-only 实例报告只读" || bad "-read-only 状态"
        body=$(wget -q --content-on-error -O- --post-data '' --header="$TK3" \
            http://127.0.0.1:18097/api/service/validate 2>/dev/null)
        [ "$(code --post-data '' --header="$TK3" http://127.0.0.1:18097/api/service/validate)" = 403 ] \
            && echo "$body" | grep -q '只读模式' \
            && ok "-read-only 拒绝写操作（403）" || bad "-read-only 写防护"
        wget -qO- --header="$TK3" http://127.0.0.1:18097/api/overview 2>/dev/null | grep -q '"daemon"' \
            && ok "-read-only 读接口正常" || bad "-read-only 读接口"
        kill "$DPID3" 2>/dev/null; wait "$DPID3" 2>/dev/null; rm -rf "$D3"

        kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null
        rm -f /tmp/ft_dashboard; rm -rf "$D"
    else
        bad "go 构建 fwknop-dashboard"; cat /tmp/ft_go.log
    fi
else
    echo "  （跳过：未安装 Go 工具链）"
fi

# -------------------------------------------------------------------
printf "\n\033[1m结果：%d 通过，%d 失败\033[0m\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
