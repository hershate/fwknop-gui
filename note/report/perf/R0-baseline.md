# R0 — 性能基线（2026-09-04）

> 环境：Ubuntu 26.04 / VMware VM / gcc -O2 / Go 1.24+。
> 方法：`benchmark/run_bench.sh`，5 轮取中位数；原始 JSON 见
> `benchmark/results/R0-baseline-{c,go}.json`。本报告只记录数字与判读，
> 优化动作见后续各轮报告。

## C 侧（libfko，SPA 数据面）

| 基准项 | 中位 ns/op | 判读 |
| --- | ---: | --- |
| client_full_packet | 288 626 | 客户端一次完整产包（含 ctx 构造、随机数、编码、加密、HMAC） |
| server_verify_full | 32 743 | fwknopd 每收一个包的验包 CPU（HMAC→解密→解码→摘要比对） |
| b64_encode_256B | 916 | 微基准：逐字符查表实现 |
| b64_decode_256B | 1 009 | 微基准：256 表逐字节分支 |
| sha256_256B | 3 549 | ≈72 MB/s，明显低于标量实现应有水平 |
| hmac_sha256_256B | 4 000 | 内部两遍 SHA（key pad×2），与 sha256 一致 |
| aes_cbc_enc_256B | 89 439 | **异常大头**：含每次调用 /dev/urandom 取 IV 的系统调用；纯密码核占比待 R2 拆分 |

### 判读

1. `client_full_packet` 是 `server_verify_full` 的 ~9 倍，主因是客户端侧
   一次性开销（ctx 构造 + urandom 取随机值/IV）叠加；
2. SHA-256 吞吐 ~72 MB/s 是 libfko 内最值得优化的常量级热点（验包路径
   HMAC 校验必须先行，摘要成本无法绕过，只能做快）；
3. base64 均为逐字节实现，1µs 级，有 2~4 倍常量级空间；
4. AES 一项需先拆分「urandom IV」与「密码核」再定优化策略。

## Go 侧（dashboard 解析层，面板轮询热路径）

| 基准项 | 中位 ns/op | B/op | allocs/op | 判读 |
| --- | ---: | ---: | ---: | --- |
| ReadAuditTail50（1 万行夹具） | 183 430 | 4 504 | 6 | 每次 /api/events 全量重读文件尾部 |
| ParseMetrics | 151 467 | 4 888 | 14 | 每次轮询全文件重读+重解析 |
| ParseAccessConf（20 stanza） | 194 262 | 15 128 | 129 | 每次请求全量重解析 |

### 判读

面板以 5s 轮询消费这三个函数；单次 0.15~0.2ms 虽不高，但**全部结果
可缓存**（文件 mtime 未变时直接复用），是零风险消除重复工作的方向；
R3 处理。

## 轮次规划

| 轮 | 方面 | 目标 |
| --- | --- | --- |
| R1 | 基础算子 | base64 位打包重写 + SHA-256 滚动展开（红线：输出与现实现逐字节一致） |
| R2 | SPA 编解码路径 | AES IV 拆分测量、解码路径内存分配削减、全路径收益聚合 |
| R3 | dashboard | mtime 缓存层（mtime+size 双校验），消除轮询重复解析 |
