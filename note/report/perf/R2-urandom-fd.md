# R2 — SPA 产包路径优化：urandom fd 进程级缓存（2026-09-04）

> 对比链：`R0-baseline` → `R1-b64-sha` → 本轮 `R2-urandom-fd`。
> JSON：`benchmark/results/R2-urandom-fd-c.json`（5 轮中位数）。

## R1 遗留问题的定位

R1 后 `aes_cbc_enc_256B` 仍为 48.7µs，与纯 AES 计算量（272B ≈ 1~2µs）
严重不符。拆分 `rij_encrypt` 路径发现成本在 `rijndael_init` →
`get_random_data`：**每次调用都 fopen/fread/fclose `/dev/urandom`**，
一次完整 open+close 往返约数十微秒。SPA 产包每包至少两处调用
（随机值 + Rijndael salt），这正是 R0 判读中 `client_full_packet` 是
`server_verify_full` 约 9 倍的主因。

## 改动

`lib/cipher_funcs.c` `get_random_data()`（非 WIN32 分支）：

- fd 进程级缓存（static，`-2` 未初始化 / `-1` 不可用 / `>=0` 已缓存），
  首次 `open(RAND_FILE, O_RDONLY|O_CLOEXEC)`，此后直接 `read`；
- `read` 循环读满（原 `fread` 等价语义）；
- 失败回退时间种子的逻辑原样保留（熵源失败语义不变）。

## 红线论证（安全优先）

| 维度 | 论证 |
| --- | --- |
| 安全 | 熵源不变（仍是内核 urandom，每次都读新字节，非缓存**数据**只缓存**描述符**）；O_CLOEXEC 防 exec 泄漏；从不 close ⇒ 不存在 fd 复用竞态 |
| 并发 | fwknopd/fwknop 单线程；假想多线程最坏情形为重复 open（幂等、无 UAF），已注释说明 |
| 兼容 | 失败回退路径逐字保留；协议格式零变化 |

## 结果（中位 ns/op）

| 基准项 | R1 | R2 | 加速比 |
| --- | ---: | ---: | ---: |
| **aes_cbc_enc_256B**（含取随机 salt） | 48 714 | 12 105 | **4.0×** |
| **client_full_packet** | 97 784 | 84 248 | **1.16×** |
| server_verify_full | 11 655 | 13 331 | (解密路径不取熵，R1↔R2 差异为 VM 噪声带 ±15%) |
| b64 / sha / hmac 微基准 | — | 持平 | 符合预期（本轮未触碰） |

累计（对 R0 基线）：**client_full_packet 3.4×、server_verify_full ~2.5×**。

## 红线验证

全树零警告重链（日志中 "error" 命中均为 `fwknopd-errors.o` 文件名）、
`c_bench` 自检 exit 0、源码树端到端敲门开门（隔离端口 52943）。

## 遗留

- `rijndael.c` 密码核本身（~1-2µs 量级）未动：收益占比已小，T-table
  重写风险收益比不佳，明确放弃；
- 客户端 `fko_new` 剩余开销为 context 分配树，属 R2 原计划的分配削减，
  预期收益 <10µs，合并进 R3 之后视情况再做。
