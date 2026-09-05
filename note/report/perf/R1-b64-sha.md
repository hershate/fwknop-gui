# R1 — 基础算子优化：base64 位打包 + SHA-256 未滚动变换（2026-09-04）

> 对比基线：`R0-baseline`（见 [R0-baseline.md](R0-baseline.md)）。
> 方法：`benchmark/run_bench.sh c R1-b64-sha 5`，5 轮取中位数，
> JSON：`benchmark/results/R1-b64-sha-c.json`。

## 改动

| 文件 | 改动 |
| --- | --- |
| `lib/base64.c` | `b64_decode`：256 项常量值表 + 位累加器重写（原为 map2 偏移表逐字节分支）；`b64_encode`：3B→4C 位打包（原为 VLC 风格逐字符移位循环）；删除失效的 `map2` |
| `lib/sha2.c` | 定义 `SHA2_UNROLL_TRANSFORM`（作者预留的编译期开关，64 轮展开；仅指令调度差异） |

## 红线验证（安全/稳定/兼容）

1. **逐字节等价**：`benchmark/verify_r1.c` 内嵌旧实现副本（git 基线版），
   对长度 0..600 的确定性 LCG 缓冲 + 全部 256 字节值模式逐字节对比
   新旧编码/解码输出；`=` 截断位置语义、非法字符（含 `~`、空白、高位
   字节）必须同样拒绝 —— **ALL PASS**；
2. **SHA-256 NIST 向量**（空串 / "abc" / 448bit 消息）全部命中；
3. `c_bench` 内建端到端自检（client 产包 → server HMAC+解密+解码 →
   消息回读一致）exit 0；
4. 全树 `make` 零警告重链通过；
5. **端到端冒烟**：源码树 fwknopd + fwknop 真实敲门，iptables 门开
   （隔离端口 52942，与 systemd 生产服务互不干扰）。

## 结果（中位 ns/op，基线 → R1）

| 基准项 | R0 | R1 | 加速比 |
| --- | ---: | ---: | ---: |
| b64_encode_256B | 916 | 141 | **6.5×** |
| b64_decode_256B | 1 009 | 332 | **3.0×** |
| sha256_256B | 3 549 | 1 176 | **3.0×** |
| hmac_sha256_256B | 4 000 | 1 901 | **2.1×** |
| **server_verify_full**（fwknopd 每包 CPU） | 32 743 | 11 655 | **2.8×** |
| **client_full_packet**（客户端每包开销） | 288 626 | 97 784 | **3.0×** |
| aes_cbc_enc_256B | 89 439 | 48 714 | (1.8×，含 urandom 噪声，R2 拆分) |

## 判读

- 服务端验包是 HMAC 先行的安全关键路径，其成本主体（b64 解码 + HMAC +
  摘要）全部命中本轮优化，fwknopd 单核验包吞吐 28k→86k 包/秒；
- 客户端路径的大头（urandom 取随机值/IV）未动，留给 R2 拆分测量后决策；
- 本轮改动不触碰密钥处理、时序安全比较与协议格式，等价性由机器验证。
