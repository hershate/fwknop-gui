# R3 — dashboard 轮询热路径优化：mtime 缓存层（2026-09-04）

> 对比链：`R0-baseline` → 本轮 `R3-cache`。JSON：
> `benchmark/results/R3-cache-go.json`（5 轮中位数，稳态 = 面板轮询真实体感）。

## 背景

面板前端以 5s 轮询 `/api/overview` / `/api/metrics` / `/api/users`，
后端每次都全量读盘+解析同一批文件（metrics、access.conf、TOFU）。
`readAuditTail` 此前已有作者实现的增量缓存（本轮未动），其余三处无缓存。

## 改动（server/dashboard/parse.go）

- 通用 `mtimeCache`：键 = `(size, mtime_ns)`，一次 `os.Stat` 判定；
- `parseMetrics` / `parseAccessConf` / `readTOFU` 三处接入：命中 →
  stat + 副本返回；未命中 → 落盘读并按 (size, mtime_ns) 存档；
- 原读盘逻辑原样保留为 `readMetricsFile` / `readAccessConf` /
  `readTofuFile`（单一职责，错误语义不变）；
- **返回一律副本**：调用方修改返回值不污染缓存（防御红线，现无此用法）；
- 失效保证：fwknopd 重写文件、confedit tmp+rename 写回都会改变
  size/mtime_ns 之一；测试用 `Chtimes` 显式验证（含同 size 不同内容）。

## 红线验证

1. `TestR3CacheInvalidation`：冷读/暖读一致 → 内容变化即时可见（值变 +
   同 size 值变）→ 文件删除回退空结果；
2. `TestR3AccessCacheStaleness`：stanza 增删即时可见；文件缺失错误语义
   与原实现一致（err 非 nil）；
3. 既有 `TestQREncodeMatchesReference` 回归通过；
4. `go vet` 干净。

## 结果（中位 ns/op，稳态）

| 基准项 | R0 基线* | R3 | 加速比 | allocs/op |
| --- | ---: | ---: | ---: | --- |
| ParseMetrics | 151 467 | 6 572 | **23×** | 14 → 5 |
| ParseAccessConf（20 stanza） | 194 262 | 10 820 | **18×** | 129 → 3 |
| ReadAuditTail50 | 183 430（冷） | 54 678 | —（本轮未改，见注） | 6 |

\* 注：R0 的 ReadAuditTail 数字为**冷启动**（首读全量），该函数在 R0
之前就有增量缓存，稳态本就远低于冷读；本轮未触碰它，表中数字仅作口径
参考，不计入本轮收益。

## 用户体感换算

单标签页 5s 轮询的 three-parse 组合成本从 ~0.35ms/轮降到 ~0.02ms/轮；
多标签页/多人同时看面板时按倍数放大（每请求都省）；对 fwknopd 端
无影响（读的是面板进程的 CPU）。

## 遗留

- 审计日志 >200MB 时事件页冷启动仍会慢（增量缓存只加速后续轮询）——
  属既有行为，轮转/清理由面板「清理审计日志」覆盖，暂不动；
- Go 侧 HTTP 层（617KB 内嵌页面无 gzip/etag）是页面首载的下一个可优化
  点，留作 R4 候选。
