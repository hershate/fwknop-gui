#!/bin/bash
# run_bench.sh — 性能基准统一入口
#
# 用法:
#   ./run_bench.sh c  <label> [runs]   # C/libfko 基准（默认 runs=5，取中位数）
#   ./run_bench.sh go <label> [runs]   # dashboard 解析层基准
#   ./run_bench.sh all <label>         # 两者都跑
#
# 输出: benchmark/results/<label>-{c,go}.json（中位数聚合）+ 终端明细。
# 报告生成由 note/report/perf/ 下各轮报告引用这些 JSON。

set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$(pwd)"
RES="$ROOT/benchmark/results"
mkdir -p "$RES"

BUILD_C() {
    # 用当前工作树构建基准程序（优化前后各跑一次即得对比）
    if [ ! -f lib/.libs/libfko.a ]; then
        echo "[!] libfko 未构建（先 make）" >&2; return 1
    fi
    gcc -O2 -I lib -I common benchmark/c_bench.c \
        -Wl,--start-group lib/.libs/libfko.a \
        common/fko_util.o common/strlcat.o common/strlcpy.o \
        -Wl,--end-group -o benchmark/c_bench || return 1
}

RUN_C() {
    local label="$1" runs="${2:-5}"
    BUILD_C || exit 1
    echo "== C 基准（$label，$runs 轮取中位数） =="
    local tmp="$RES/.c-samples.$$"; rm -f "$tmp"
    for i in $(seq 1 "$runs"); do
        ./benchmark/c_bench 3000 200000 2>/dev/null | grep '"' >> "$tmp"
    done
    python3 - "$tmp" "$RES/$label-c.json" "$label" <<'EOF'
import json, re, sys
samples_file, out_file, label = sys.argv[1:4]
# 样本行形如 "name": {"ns_per_op": X, "ops_per_sec": Y, "iters": N}，每轮 7 行
per_run = []
cur = {}
for line in open(samples_file):
    m = re.match(r'\s*"([^"]+)":\s*\{"ns_per_op": ([\d.]+), "ops_per_sec": ([\d.]+)', line)
    if m:
        cur[m.group(1)] = float(m.group(2))
        if len(cur) == 7:
            per_run.append(cur); cur = {}
names = list(per_run[0].keys())
median = {n: sorted(r[n] for r in per_run)[len(per_run)//2] for n in names}
json.dump({"label": label, "runs": len(per_run), "median_ns_per_op": median},
          open(out_file, "w"), indent=1)
print(json.dumps(median, indent=1))
EOF
    rm -f "$tmp"
}

RUN_GO() {
    local label="$1" runs="${2:-5}"
    echo "== Go 基准（$label，$runs 轮取中位数） =="
    cp benchmark/go_bench_test.go server/dashboard/zz_perf_bench_test.go
    ( cd server/dashboard && go test -run='^$' -bench='BenchmarkPerf' \
        -benchtime=200x -count="$runs" -benchmem 2>&1 ) | tee "$RES/.go-raw.$$" | tail -n +1
    python3 - "$RES/.go-raw.$$" "$RES/$label-go.json" "$label" <<'EOF'
import json, re, sys
raw, out_file, label = sys.argv[1:4]
# 行形如: BenchmarkPerfX-4   200   123456 ns/op   1234 B/op   12 allocs/op
data = {}
for line in open(raw):
    m = re.match(r'(BenchmarkPerf\S*?)(?:-\d+)?\s+\d+\s+([\d.]+) ns/op(?:\s+(\d+) B/op\s+(\d+) allocs/op)?', line)
    if m:
        data.setdefault(m.group(1), []).append(
            (float(m.group(2)), int(m.group(3) or 0), int(m.group(4) or 0)))
med = {}
for name, rows in data.items():
    rows.sort()
    r = rows[len(rows)//2]
    med[name] = {"ns_per_op": r[0], "b_per_op": r[1], "allocs_per_op": r[2]}
json.dump({"label": label, "median": med}, open(out_file, "w"), indent=1)
print(json.dumps(med, indent=1))
EOF
    rm -f server/dashboard/zz_perf_bench_test.go "$RES/.go-raw.$$"
}

case "${1:-}" in
    c)  RUN_C "${2:-base}" "${3:-5}" ;;
    go) RUN_GO "${2:-base}" "${3:-5}" ;;
    all) RUN_C "${2:-base}" "${3:-5}"; RUN_GO "${2:-base}" "${3:-5}" ;;
    *) echo "用法: $0 {c|go|all} <label> [runs]"; exit 1 ;;
esac
