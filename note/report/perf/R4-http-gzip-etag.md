# R4 — dashboard HTTP 层：页面预压缩 + 强 ETag（2026-09-04）

> 对比链：`R0-baseline` → R1 → R2 → R3 → 本轮 `R4-http-gzip-etag`。
> 本轮收益在**传输体量与重复访问延迟**（非 ns/op 微基准），以实测报文验证。

## 背景

UI 是单页嵌入 HTML（`web/index.html` ≈ 617KB），原先由
`http.FileServer` 原样输出：每次首载/强刷全量传输，二次访问也要重新
下载。这是浏览器侧「打开面板」体感延迟的最大构成。

## 改动（server/dashboard/main.go）

- 新增 `uiHandler`：启动时对嵌入页面做一次性 gzip 预压缩
  （BestCompression）+ 内容 SHA-256 强 ETag；
- `Accept-Encoding: gzip` → 传输 gzip 体；否则原样传输（行为兼容）；
- `If-None-Match` 命中 → **304 Not Modified**（重复访问零下载）；
- 服务统一走 `http.ServeContent`（Content-Type / HEAD / Range / 条件
  请求语义由标准库保证）；非 `/`、`/index.html` 路径保持 404。

## 红线验证

- 浏览器语义不变：无头 Firefox 实测进入「首次初始化向导」
  （`auth-loading: none`），与 R1 修复后的行为一致；
- `go vet` 干净；`go build` 通过；
- ETag 为嵌入内容哈希 —— 内容变（重建二进制）即变，不会跨版本误命中。

## 实测（127.0.0.1:8090 临时实例）

| 项 | 改动前 | 改动后 |
| --- | --- | --- |
| 首次传输体量 | 618 208 B | **208 452 B（gzip，≈1/3）** |
| 二次访问（ETag 命中） | 全量重传 | **304，0 B** |
| 强 ETag | 无 | `"59d3d4fc…"` |

## 用户体感

LAN/隧道下首载体量降约 2/3；日常刷新（轮询间隙回页面、F5）从
「重新下载 600KB」变为 304 秒回 —— 面板打开/回切明显变快。

## 遗留

- API JSON 体量小（<10KB），不值得加压缩，明确不做；
- gzip 流式压缩中转 API 响应的复杂度收益比差，明确不做。
