# benchmark/ — 性能基准测试

量化优化前后性能的统一入口。每轮优化「不同方面」，对比报告落
`note/report/perf/`，原始中位数数据落 `benchmark/results/`。

## 组成

| 文件 | 说明 |
| --- | --- |
| `c_bench.c` | libfko 基准：客户端产包全路径 / 服务端验包全路径 + base64、SHA-256、HMAC-SHA256、AES-CBC 微基准。内建正确性自检（解密回读校验），测的不是错的东西 |
| `go_bench_test.go` | dashboard 解析层基准：审计日志尾部读取（1 万行夹具）、指标解析、access.conf 多 stanza 解析。运行时由脚本拷入 `server/dashboard/` |
| `run_bench.sh` | 统一入口：编译→多轮运行→**取中位数**（VM 噪声 ±20%，均值不可信）→JSON 落 `results/` |

## 用法

```bash
./benchmark/run_bench.sh c   R1-b64digest   # C 侧，第 R1 轮，默认 5 轮取中位
./benchmark/run_bench.sh go  R1-b64digest   # Go 侧
./benchmark/run_bench.sh all R1-b64digest   # 两侧
```

## 基线与红线

- 基线数据：`results/R0-baseline-{c,go}.json`（2026-09-04，Ubuntu 26.04 VM，
  gcc -O2，go 1.24+）。对比报告一律引用同一轮机器状态下的基线。
- **红线**：只许改实现，不许改线上行为/协议格式/安全语义（const-time
  比较、密钥清零、HMAC 先于解密等），每轮优化后必须：
  1. `c_bench` 内建自检通过（exit 0）；
  2. 项目自带测试（`make check` 的 c-unit 部分）通过；
  3. 端到端冒烟：systemd fwknopd 存活 + 真实敲门开门（quickstart knock）。

## 结果目录

`results/` 下 `<label>-c.json` / `<label>-go.json`，字段
`median_ns_per_op` / `median`（含 B/op、allocs/op）。报告引用文件名，
不复述全部数字。
