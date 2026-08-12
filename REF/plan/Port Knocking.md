# 基于 fwknop SPA 扩展的动态端口隐身与零信任增强方案

> 版本：v2.1　·　基线代码：fwknop `2.6.11`（`VERSION`、`configure.ac`）　·　最后更新：2026-08
>
> 本文档取代旧版「概念设计」，把方案**落地到 fwknop 实际代码库**（`lib/` libfko + `client/` fwknop + `server/` fwknopd），给出完整技术架构、分阶段升级路线、文件级改动清单与全维度 UX 设计。
>
> v2.1 变更（2026-08-13，用户决策确认）：新增 §7.6「服务端管理界面与凭证发放」——`fwknopd-admin` CLI 先行、授权 QR（`fwknop://`）、凭证文件（默认 scrypt+AES-GCM 加密）、TOFU 首次使用设备绑定（默认启用）；同步更新 §3.4/§5/§6/§12/附录 D/E。

---

## 0. 文档定位与核心决策

### 0.1 与原方案的关系
旧版文档描述的是「TOTP + 多端口敲门 + SPA + 零信任」的**概念组合**，但其中的「多端口敲门序列」「敲门包内嵌加密指纹/时间戳」与本项目（fwknop 单包 SPA）模型并不直接对应，且部分能力 fwknop **早已具备**。本文做三件事：

1. **澄清复用边界**：明确 fwknop 已满足哪些需求（防重放、HMAC 认证加密、时效、最小权限、审计入口），避免重复造轮子。
2. **定义净新增**：TOTP 引擎、动态端口跳变（port-hopping SPA）、设备身份绑定、零信任策略增强、UX 层。
3. **给出可执行升级路线**：分阶段、文件级、可验收。

### 0.2 关键架构决策（已确认）
- **扩展现有单包 SPA**，而非新建「多端口敲门子系统」。理由：
  - 单包 SPA 在安全性上**严格优于**多包敲门（旧文档自己也承认 SPA 解决了 PK 的重放/伪造/DoS 短板）。把方案做成「多包敲门」是安全退化。
  - 本仓库就是 fwknop；复用 `libfko` 密码学栈、`incoming_spa` 验证管线、防火墙后端，改动可控、可向后兼容。
- **动态性体现为「目标端口跳变」**：单包 SPA 内容不变，仅目的端口由 TOTP 派生并随时间跳变，实现「无固定监听端口」的隐身。服务端用端口范围监听（首选 NFQ）。
- **UX 全维度覆盖**：CLI/配置易用、透明自动敲门、GUI、运维可视化，并补充威胁模型、兼容性、测试、迁移、路线图。

### 0.3 原方案需求 ↔ fwknop 现状对照表

| 原方案诉求 | fwknop 现状 | 处置 |
| --- | --- | --- |
| 加密载荷 + HMAC 认证 | `lib/fko_encryption.c` + `lib/fko_hmac.c`，encrypt-then-MAC | **已具备**，直接复用 |
| 时间戳防重放 | SPA `timestamp` 字段 + `check_pkt_age`（`max_spa_packet_age`）+ `replay_cache` 外层摘要 | **已具备**，仅需收紧配置 |
| 最小权限/时效端口 | `OPEN_PORTS` + `FW_ACCESS_TIMEOUT` + iptables `_exp_<ts>` 注释自动过期 | **已具备**，仅需配置纪律 |
| 一次一密的动态端口 | 固定 62201 端口 | **净新增**：TOTP→端口跳变 |
| 用户/设备身份绑定 | 仅有 `username` 字段 | **净新增**：`device_id` 字段 + 指纹白名单 |
| 多因素（TOTP） | 无 | **净新增**：TOTP 引擎（共享模块） |
| 零信任细粒度策略 | SOURCE/OPEN_PORTS/REQUIRE_USERNAME/CMD_CYCLE 等原语 | **增强**：身份绑定 + 动态策略 + 审计 |
| 透明代理（对应用无感知） | 仅手动 CLI | **净新增**：客户端透明敲门代理 |
| GUI / 运维面板 | 无（仓库无 GUI 代码） | **净新增**：桌面 GUI + 服务端面板 |

---

## 1. 背景与目标

### 1.1 公网服务暴露的现实风险
大规模自动化扫描（Nmap/Masscan/ZMap 可数分钟扫完全 IPv4）、漏洞利用自动化、低攻击成本、持续威胁——任何暴露端口都构成攻击面。传统防御（防火墙黑名单、IDS、VPN、端口随机化）各有局限。

### 1.2 传统 Port Knocking 的固有缺陷
静态序列易嗅探、无加密、无身份、易重放、密钥分发难、无时效。fwknop 的 SPA 已解决大部分；本方案在此基础上补齐「动态性」与「强身份」。

### 1.3 本方案目标
1. **无固定监听端口**：TOTP 驱动目的端口跳变，扫描器看不到稳定端口。
2. **强身份绑定**：每包绑定设备指纹 + TOTP，敲门即身份认证。
3. **零信任最小权限**：身份→策略→时效端口，全程可审计。
4. **用户无感**：透明自动敲门，CLI/GUI 双形态，运维可视化。
5. **向后兼容**：与现有 fwknop v3 客户端/服务端共存，可分阶段灰度。

---

## 2. 现有 fwknop 架构基线（升级前的「项目实际情况」）

升级必须建立在对现有架构的准确理解之上。以下是关键基线（均可在仓库中定位）。

### 2.1 三大组件
| 组件 | 目录 | 产物 | 职责 |
| --- | --- | --- | --- |
| libfko | `lib/` | `libfko.la` / `libfko.lib` | SPA 编码/加密/解码/HMAC/重放摘要等全部密码学 |
| fwknop 客户端 | `client/` | `fwknop` / `fwknop.exe` | 解析配置→构造→发送单包 SPA |
| fwknopd 服务端 | `server/` | `fwknopd`（仅 Unix） | 抓包→验证→操纵防火墙 |

### 2.2 SPA 数据格式与加密流水线
编码明文（冒号分隔，`lib/fko_encode.c` `fko_encode_spa_data`）：
```
<rand_val 16位>:<b64(username)>:<timestamp>:<version>:<message_type>:<b64(message)>[:b64(nat_access)][:b64(server_auth)][:client_timeout]
```
- `message` 格式（`lib/fko_message.c`）：访问型 `<IP>,<proto>/<port>`、命令型 `<IP>,<cmd>`、NAT 型 `<host>,<port>`。
- 加密流水线（`lib/fko_funcs.c` `fko_spa_data_final`）：拼装→追加摘要(SHA-256)→Rijndael/AES-CBC 加密（密钥经 OpenSSL 兼容 salt+IV+MD5 派生，`lib/cipher_funcs.c`）或 GnuPG→base64 去 `Salted__` 前缀→**encrypt-then-MAC** 追加 HMAC。
- 协议版本：`FKO_PROTOCOL_VERSION "3.0.0"`（`lib/fko.h`）。**本方案升级到 `4.0.0`。**
- 解码字段解析器：`FIELD_PARSERS = 9`、`SPA_FIELD_SEPARATOR = ":"`（`lib/fko_decode.c`）。

### 2.3 服务端验证管线（`server/incoming_spa.c` `incoming_spa`）
关键顺序（任何扩展都必须插入到正确阶段）：
1. `preprocess_spa_data`：base64 合法性（可选 SPA-over-HTTP 解包）。
2. `src_check`：源 IP 是否被某 stanza 的 `SOURCE` 覆盖；命中则计算**外层 raw digest**（无密钥）做 `is_replay` 重放检查（**在解密之前**）。
3. 遍历 `acc_stanzas`：`fko_new_with_data` 一次性完成 **HMAC 验证 + 解密**；成功后 `add_replay_cache`。
4. `check_pkt_age`（`ENABLE_SPA_PACKET_AGING` + `max_spa_packet_age`）校验新鲜度。
5. 拆 `spa_message`、校验嵌入 IP / `REQUIRE_USERNAME` / NAT 权限 / 端口策略（`acc_check_port_access`）。
6. 动作派发：`CMD_CYCLE_OPEN` / `process_cmd_msg` / `process_spa_request`（开端口）。

### 2.4 抓包后端（编译期选择，优先级 NFQ > UDP > pcap）
- `server/pcap_capture.c`：libpcap，BPF 默认 `udp port 62201`。
- `server/udp_server.c`：UDP socket 绑定 `INADDR_ANY:62201`，无 libpcap 依赖。
- `server/nfq_capture.c`：Netfilter Queue，匹配端口 `NFQUEUE` 规则投递，**投递后 DROP**。**端口范围监听的最佳载体。**
- `server/tcp_server.c`：伪 TCP 服务，仅为握手，仍由 pcap 抓字节。

### 2.5 防火墙后端（编译期选一）
iptables（参考实现，`server/fw_util_iptables.c`）：自定义链 `FWKNOP_INPUT` 等，从 `INPUT` 跳入；规则形如 `-A FWKNOP_INPUT -p tcp -s <ip> --dport 22 -m comment --comment _exp_<过期时间戳> -j ACCEPT`；`check_firewall_rules` 周期扫描注释里的 `_exp_` 并 `-D` 过期规则。另有 firewalld / pf(anchor) / ipfw / ipf。

### 2.6 访问控制 stanza（`server/access.c`，`acc_stanza_t` 于 `server/fwknopd_common.h`）
每用户一条链表节点：`SOURCE` / `KEY`/`KEY_BASE64` / `HMAC_KEY`/`HMAC_KEY_BASE64` / `OPEN_PORTS` / `RESTRICT_PORTS` / `REQUIRE_USERNAME` / `REQUIRE_SOURCE_ADDRESS` / `FW_ACCESS_TIMEOUT` / `MAX_FW_TIMEOUT` / `CMD_CYCLE_OPEN/CLOSE` / `FORCE_NAT` / GPG 相关等。**本方案在此结构上增加 TOTP 与指纹字段。**

### 2.7 客户端配置（`client/config_init.c`）
两趟解析：CLI（`getopt_long`，`client/cmd_opts.h`）+ `~/.fwknoprc` 的 `[stanza]`，命令行优先级最高；`--key-gen`（`lib/fko_funcs.c` `fko_key_gen`）生成 Rijndael+HMAC 密钥；`--rand-port`（`client/fwknop.c` `get_rand_port`，范围 `[10000,65535]`）已有随机端口能力（可复用为 TOTP 端口的基础）。

---

## 3. 增强后的总体技术架构

### 3.1 设计原则
1. **单包优先**：保留 fwknop 单包 SPA 的安全优势，动态性只作用于「目的端口」这一路由维度。
2. **向后兼容**：协议版本升级到 `4.0.0`，v3 报文继续可用；新特性按 stanza 开关启用。
3. **最小侵入**：尽量复用 `libfko`、`incoming_spa`、防火墙后端；新功能以「模块 + 配置开关」加入，关闭即退化为经典 fwknop。
4. **可降级**：TOTP/端口跳变/身份绑定均可独立开关；任一环节故障有安全回退（不是静默放行，而是保守拒绝 + 告警）。

### 3.2 逻辑分层
```
┌─────────────────────────────────────────────────────────────────┐
│  UX 层：CLI 向导 / 透明自动敲门代理 / 桌面 GUI / 服务端运维面板      │
├─────────────────────────────────────────────────────────────────┤
│  策略层（零信任）：身份→TOTP 种子→端口范围→开放端口/命令→时效→审计   │
├─────────────────────────────────────────────────────────────────┤
│  SPA 协议层（v4）：rand|user|ts|ver|type|message[|nat][|auth]      │
│                   [|timeout][|device_id]  +  digest + HMAC        │
├─────────────────────────────────────────────────────────────────┤
│  密码学层（libfko）：AES-CBC / GnuPG / HMAC-SHA256 / base64 / 重放  │
├─────────────────────────────────────────────────────────────────┤
│  动态性引擎（新增）：TOTP(RFC6238) → 端口映射 → 端口范围监听(NFQ)    │
├─────────────────────────────────────────────────────────────────┤
│  传输/抓取层：客户端 UDP/TCP/HTTP/raw/ICMP ｜ 服务端 NFQ/UDP/pcap   │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 端到端数据流（增强后）
```
应用发起连接
   │  （UX：透明代理拦截，或 CLI `fwknop knock`）
   ▼
客户端：TOTP(种子, 当前窗口) ──► port = map(totp, 端口范围)
        构造 SPA v4：message=访问请求, device_id=设备指纹, timestamp=now
        encrypt+HMAC ──► 单包发往 server:port
   ▼
网络：目的端口随 TOTP 跳变，扫描器看不到固定端口
   ▼
服务端：NFQ 监听整个端口范围 ──► 收包
        incoming_spa：base64 → src_check → raw_digest 重放检查
        → HMAC 验证 + 解密 → (可选)校验「到达端口 == map(totp, 报文时间戳窗口)」
        → 解析 device_id → 指纹白名单 → check_pkt_age → 端口策略
        → process_spa_request：开端口（_exp_ 自动过期）/ CMD_CYCLE
        → 结构化审计 + 指标
   ▼
客户端：透明代理探测到端口开放 ──► 转发真实连接 ──► 超时前自动续敲门
```

### 3.4 新增/修改组件清单
| 组件 | 状态 | 位置 | 作用 |
| --- | --- | --- | --- |
| TOTP 引擎 | 新增 | `lib/fko_totp.c` + `lib/fko_totp.h` | RFC6238，复用 `lib/hmac.c`；客户端/服务端共享 |
| 端口映射 | 新增 | `common/fko_util.c` | `totp → port` 确定性映射 + 窗口枚举 |
| SPA v4 `device_id` 字段 | 修改 | `lib/fko_encode.c`/`fko_decode.c`/`fko_message.c`/`fko_context.h`/`fko.h` | 身份绑定，版本 `4.0.0` |
| 客户端 TOTP 端口 | 修改 | `client/fwknop.c`/`spa_comm.c`/`config_init.c`/`cmd_opts.h`/`fwknop_common.h` | 目的端口由 TOTP 派生 |
| 服务端范围监听 | 修改 | `server/nfq_capture.c`/`pcap_capture.c`/`udp_server.c`/`fwknopd.conf` | 监听端口范围 + 滑动窗口 |
| 服务端身份/端口校验 | 修改 | `server/incoming_spa.c`/`access.c`/`fwknopd_common.h` | 指纹白名单 + 可选 TOTP 端口匹配 |
| 透明敲门代理 | 新增 | `client/proxy/`（新目录） | 自动拦截/敲门/转发 |
| 交互式向导 | 新增 | `client/wizard.c` | 一键配置与密钥/TOTP 分发 |
| 桌面 GUI | 新增 | `gui/`（新目录，Qt） | 配置/一键敲门/状态可视化 |
| 运维面板 | 新增 | `server/dashboard/`（新目录） | 审计/指标/告警/轮换 |
| 服务端管理工具 | 新增 | `server/fwknopd-admin.c` + `server/credential.c` | stanza 增删改、密钥/种子生成、授权 QR、凭证导出、TOFU 绑定管理、lint/status（§7.6） |
| 客户端凭证导入 | 新增 | `client/import.c` | `fwknop import`：QR/URI/JSON 凭证 → 生成 rc stanza（§7.6） |

---

## 4. 核心技术设计

### 4.1 TOTP 引擎（共享模块 `lib/fko_totp.c`）
- **标准**：RFC 6238，HMAC-SHA256（复用 `lib/hmac.c` 的 `hmac_sha256`），动态截断生成数值。
- **参数**（ stanza 可配，默认值给出）：
  - 时间步长 `TOTP_STEP`（默认 30s）
  - 口令位数 `TOTP_DIGITS`（默认 8）
  - 起始时间 `T0`（默认 0，Unix 纪元）
  - 容忍窗口 `TOTP_SKEW`（默认 ±1 步，即 ±30s）
- **API 草案**：
  ```c
  int fko_totp_generate(const char *seed_b64, size_t seed_len,
                        uint64_t unix_time, uint8_t digits,
                        char *out_code /* digits+1 */);
  int fko_totp_verify(const char *seed_b64, size_t seed_len,
                      const char *code, uint64_t unix_time, int skew);
  /* 端口映射：把 TOTP 数值映射到 [start,end] 内 */
  uint16_t fko_totp_to_port(const char *code, uint16_t start, uint16_t end);
  /* 枚举某时刻 ±skew 窗口内的合法端口集合（服务端监听/校验用） */
  int fko_totp_port_window(const char *seed_b64, uint64_t now, int skew,
                           uint16_t start, uint16_t end,
                           uint16_t *ports_out, int max_ports);
  ```
- **密钥分发**：TOTP 种子与 Rijndael/HMAC 密钥一同由 `--key-gen` 扩展生成，base64 后写入 `fwknoprc` 与 `access.conf`；向导可输出标准 `otpauth://` URI 与二维码（见 §7）。

### 4.2 动态端口跳变（port-hopping SPA）
- **端口映射函数**（确定性、双端一致）：
  ```
  range_size = end - start + 1            # 例 10000..65535 → 55536
  code_int   = totp(seed, window)          # 8 位整数
  port       = start + (code_int mod range_size)
  ```
- **客户端**（`client/fwknop.c`，在 `send_spa_packet` 之前）：
  - 新增模式 `--totp-port`（或 rc 变量 `USE_TOTP_PORT Y`）。
  - 计算 `port = fko_totp_to_port(...)`，赋给 `options.spa_dst_port`（复用现有字段，零侵入）。
  - 复用现有 UDP/TCP/HTTP 发送路径（`client/spa_comm.c`）。
- **服务端**（关键差异点）：
  - **首选 NFQ**：在 `server/nfq_capture.c` + iptables 规则上，把单端口 `--dport 62201 -j NFQUEUE` 改为 **端口范围** `--dport START:END -j NFQUEUE`；NFQ 把范围内所有 UDP 包交给 fwknopd，投递后照旧 DROP。内核负责按范围过滤，用户态零额外开销。
  - **pcap 回退**：BPF 改为 `udp dst portrange START-END`（噪声较多，仅低流量主机推荐）。
  - **UDP 回退**：单 socket 绑定范围不现实；UDP 模式仅用于固定端口的传统部署，端口跳变建议走 NFQ。
  - **滑动窗口**：服务端无需精确预测单个端口，只要监听整个范围即可；`TOTP_SKEW` 在此退化为「报文时间戳新鲜度」由 `check_pkt_age` 兜底。
- **可选增强（强身份因子）**：`REQUIRE_TOTP_PORT_MATCH Y` —— 服务端解密后用报文自带 `timestamp` 反推该时刻应使用的端口，校验「实际到达端口 ∈ 该窗口端口集合」。这样**端口本身就是一次性口令**，攻击者即便拿到加密包重放到别的端口也会被拒。这是本方案相对原「多包敲门」的核心增益。
- **与「多端口敲门序列」的关系**：默认单包即可；若需更强迷惑，可在单包前追加 1–2 个无载荷「诱饵敲门」（纯 SYN 到 TOTP 派生的端口），但**认证与授权仍由单包 SPA 承担**，诱饵仅为流量混淆，非安全边界。

### 4.3 设备身份绑定（SPA v4 `device_id`）
- **协议升级**：`FKO_PROTOCOL_VERSION` → `"4.0.0"`。v4 在 `client_timeout` 之后新增可选字段 `device_id`（base64）。解码器按版本分支（v3 走旧布局，v4 多一个可选尾字段），保证向后兼容。
- **新 SPA v4 编码**：
  ```
  rand:b64(user):ts:4.0.0:type:b64(message)[:b64(nat)][:b64(auth)][:timeout][:b64(device_id)]
  ```
- **`device_id` 生成（设备指纹）规范**（见附录 C）：
  - 采集稳定的设备属性（主机名、机器 ID、主板/磁盘序列号哈希、OS/内核版本等），SHA-256 后取前 16 字节，base64。
  - 由向导一次性生成并写入 `fwknoprc`（`DEVICE_ID <b64>`），客户端每次 SPA 携带。
  - 设计为「稳定但不可链接到真实身份」的伪标识；敏感属性仅本地哈希，不上链明文。
- **服务端校验**（`server/access.c` + `incoming_spa.c`）：
  - `acc_stanza_t` 新增 `fingerprint_list`（`acc_str_list`）与 `require_fingerprint` 标志；对应 `access.conf` 指令 `FINGERPRINT <b64>`（可多行）、`REQUIRE_FINGERPRINT Y`。
  - 解密后若 v4 含 `device_id` 且 stanza 要求指纹，做白名单匹配（常量时间比较，复用 `common/fko_util.c` `constant_runtime_cmp`）。
  - 不匹配 → 与「HMAC 不对应」同样静默丢弃 + DEBUG 审计（不向攻击者泄露差异）。

### 4.4 防重放与时效（复用为主）
- fwknop 已有：`timestamp` + `max_spa_packet_age`（`ENABLE_SPA_PACKET_AGING`）+ `replay_cache`（外层 raw digest，`server/replay_cache.c`）。**本方案不另起炉灶**，仅：
  - 收紧默认 `max_spa_packet_age`（建议 ≤ 60s）。
  - TOTP 步长（30s）与 SPA 时效对齐，形成「窗口 + 时效」双保险。
  - 审计增强：重放命中、未知指纹、端口不匹配均结构化记录（见 §7.4）。

### 4.5 零信任策略层（增强）
- **现有原语**（直接采用）：`SOURCE`（源白名单）、`OPEN_PORTS`/`RESTRICT_PORTS`（最小权限端口）、`REQUIRE_USERNAME`、`REQUIRE_SOURCE_ADDRESS`、`FW_ACCESS_TIMEOUT`（时效）、`CMD_CYCLE_OPEN/CLOSE`（命令级开关）。
- **增量**：
  - **身份→策略绑定**：每个 stanza 绑定唯一 TOTP 种子 + 指纹集合，实现「敲门序列唯一对应身份」。
  - **动态策略**（可选）：`CMD_CYCLE_OPEN` 可在开门时回调身份系统（如查询 CMDB/SSO 当前角色），实现上下文感知授权。
  - **持续验证**：长连接场景下，`FW_ACCESS_TIMEOUT` 到期即关；透明代理在到期前自动续敲门 = 持续再认证。
  - **审计闭环**：每次开门/关门/拒绝都带身份、端口、TOTP 窗口、源 IP，写入结构化审计。

### 4.6 通信时序（含异常）
```
Client                            Network                      Server(NFQ@range)
  │ TOTP(now)→port                                                 │ 监听 [START:END]
  │── SPA v4 encrypt+HMAC ─────────► :port ──────────────────────► │
  │                                                                 │ base64→src→replay→HMAC→decrypt
  │                                                                 │ device_id 校验 / (可选)port∈window
  │                                                                 │ age / username / port-policy
  │                                                                 │ process_spa_request → _exp_ rule
  │◄────────────── （端口已开，应用连接正常建立） ──────────────────── │
  │                                                                 │
异常：序列错/指纹不符/端口不匹配/过期 → 服务端静默丢弃 + 审计；客户端超时重试
```

---

## 5. 升级项目：分阶段实施路线

> 每阶段独立可验收、可回退；关闭新开关即退化为经典 fwknop。T 恤工作量估算：S≈1–2 人日，M≈3–5，L≈1–2 周。

### 阶段 0 —— 基线与约定（S）
- 建立 v3 回归测试基线（复用 `test/tests/*.pl`）。
- 约定协议版本 `4.0.0`、字段编号、TOTP 参数默认值、端口范围默认 `[30000,60000]`（避开临时端口段）。
- 产物：本设计文档定稿 + ADR（架构决策记录）。

### 阶段 1 —— TOTP 引擎 + 客户端端口跳变（M）
- 新增 `lib/fko_totp.c/.h`（RFC6238，复用 `lib/hmac.c`）+ 单元测试（扩展 `lib/fko_utests.c`）。
- `common/fko_util.c` 增 `fko_totp_to_port` / `fko_totp_port_window`。
- 客户端：`client/cmd_opts.h` 加 `--totp-port`/`--totp-seed`/`--port-range`；`client/config_init.c` 加 rc 变量；`client/fwknop.c` 在发送前用 TOTP 端口覆盖 `spa_dst_port`。
- **验收**：客户端能按 TOTP 把单包发到跳变端口（`--test` + 抓包可见）；v3 行为不受影响。
- **回退**：不开 `--totp-port` 即经典行为。

### 阶段 2 —— 服务端范围监听（M，依赖阶段 1）
- NFQ：iptables 规则改端口范围；`server/nfq_capture.c` 适配（验证范围投递 + DROP 策略）。
- pcap：BPF `udp dst portrange`；UDP：文档标注「端口跳变请用 NFQ」。
- `server/fwknopd.conf` 增 `NFQ_PORT_RANGE`/`PCAP_PORT_RANGE`。
- **验收**：服务端在范围内任一端口收到 v3 SPA 仍能正常开门；范围外不响应。

### 阶段 3 —— SPA v4 身份绑定（L）
- `lib/fko.h`/`fko_context.h` 增 `device_id` 字段与 get/set；`lib/fko_encode.c`/`fko_decode.c`/`fko_message.c` 按 `4.0.0` 分支编解码；`FKO_PROTOCOL_VERSION` 升级。
- 客户端：`--device-id`/rc `DEVICE_ID`；向导生成指纹。
- 服务端：`acc_stanza_t` 增 `fingerprint_list`/`require_fingerprint`；`access.c` 解析 `FINGERPRINT`/`REQUIRE_FINGERPRINT`；`incoming_spa.c` 解密后校验。
- **验收**：v4 包带 `device_id` 通过；白名单外被静默拒；v3 包仍兼容。

### 阶段 4 —— 零信任硬化 + 审计 + 服务端管理工具（L，由 M 升级）
- 可选 `REQUIRE_TOTP_PORT_MATCH`：`incoming_spa.c` 用报文 `timestamp` 反推端口集合并校验到达端口。
- 结构化审计（JSON 行）+ Prometheus 指标 + 异常告警钩子（见 §7.4）。
- **服务端管理工具**（§7.6，2026-08-13 决策）：`fwknopd-admin` CLI（stanza 管理 / 授权 QR / 凭证导出 / TOFU 绑定管理）+ 客户端 `fwknop import`；凭证默认 scrypt+AES-GCM 加密；TOFU 默认启用。
- **验收**：重放/未知指纹/端口不匹配/过期均有结构化日志与指标；「QR/凭证发放 → 客户端导入 → TOFU 绑定 → 敲门开门」全链路可跑通。

### 阶段 5 —— UX 层（L，可拆分并行）
- CLI 向导 `fwknop setup`（S）、一键 `fwknop knock`/`connect`（S）、透明敲门代理（L）、桌面 GUI（L）、运维面板（M）、服务端 TUI/WebUI 管理壳（包装 `fwknopd-admin`，M）。详见 §7。

### 阶段 6 —— 测试、打包、部署、迁移（M）
- 扩展 `test/tests/`（端口跳变、v4、指纹、时钟偏移、兼容）；`test/afl/` 新 fuzz 目标；打包 systemd/MSVC；迁移文档与灰度策略。详见 §10–§12。

---

## 6. 详细文件级改动清单（怎么升级项目）

| 文件 | 现状 | 改动 | 阶段 |
| --- | --- | --- | --- |
| `lib/fko.h` | 协议 `3.0.0`，公开 API | 升 `4.0.0`；声明 `fko_set/get_device_id`；声明 TOTP API | 1,3 |
| `lib/fko_context.h` | `struct fko_context` | 增 `char *device_id`（与对应 free/zero） | 3 |
| `lib/fko_encode.c` | 9 字段编码 | v4 追加可选 `b64(device_id)` | 3 |
| `lib/fko_decode.c` | `FIELD_PARSERS=9` | 按版本解析第 10 字段 | 3 |
| `lib/fko_message.c` | message 校验 | （device_id 不在 message 内，无需大改）备注 | 3 |
| `lib/fko_funcs.c` | `fko_new/destroy/final` | destroy 释放 `device_id`；`fko_new` 默认置空 | 3 |
| `lib/fko_totp.c/.h` | 不存在 | **新建** RFC6238 + 端口映射 | 1 |
| `lib/hmac.c` | HMAC-SHA256 等 | 复用，供 TOTP 与（可选）端口因子 | 1 |
| `common/fko_util.c/.h` | 工具函数 | 增 `fko_totp_to_port`/`port_window`/指纹哈希 | 1,3 |
| `client/cmd_opts.h` | getopt 表 | 增 `--totp-port` `--totp-seed` `--port-range` `--device-id` | 1,3 |
| `client/config_init.c` | rc 变量表 | 增 `USE_TOTP_PORT` `TOTP_SEED` `PORT_RANGE` `DEVICE_ID` | 1,3 |
| `client/fwknop_common.h` | `fko_cli_options_t` | 增对应字段 | 1,3 |
| `client/fwknop.c` | `get_rand_port` 等 | 发送前 TOTP 端口覆盖；调用 `device_id` set | 1,3 |
| `client/spa_comm.c` | 协议派发 | 无需改（端口已是 `spa_dst_port`） | — |
| `client/wizard.c` | 不存在 | **新建** 交互式向导（§7.1） | 5 |
| `client/proxy/*` | 不存在 | **新建** 透明敲门代理（§7.2） | 5 |
| `server/fwknopd_common.h` | `acc_stanza_t` | 增 `fingerprint_list`/`require_fingerprint`/`totp_*`/`require_totp_port_match` | 2,3,4 |
| `server/access.c` | stanza 解析 | 解析 `FINGERPRINT`/`REQUIRE_FINGERPRINT`/`TOTP_*` | 3,4 |
| `server/access.conf(.inst)` | 配置模板 | 增新指令示例与注释 | 3,4 |
| `server/incoming_spa.c` | 验证管线 | 解密后指纹校验 + 可选端口匹配插入第 4–5 步之间 | 3,4 |
| `server/nfq_capture.c` | 单端口 NFQ | 端口范围 NFQUEUE；DROP 策略保持 | 2 |
| `server/pcap_capture.c` | BPF 单端口 | `udp dst portrange`（回退） | 2 |
| `server/fwknopd.conf(.inst)` | 链/端口配置 | 增 `NFQ_PORT_RANGE`/`PCAP_PORT_RANGE` | 2 |
| `server/log_msg.c` + 新 `audit.c` | 文本日志 | 增结构化 JSON 审计 + 指标 | 4 |
| `server/fwknopd-admin.c` | 不存在 | **新建** 服务端管理 CLI（stanza 管理/授权 QR/凭证导出/TOFU 管理/lint/status） | 4 |
| `server/credential.c/.h` | 不存在 | **新建** 凭证文件 JSON 组装/解析 + scrypt+AES-GCM 加解密 | 4 |
| `client/import.c` | 不存在 | **新建** `fwknop import`（QR/URI/JSON → rc stanza） | 4 |
| `server/dashboard/*` | 不存在 | **新建** 运维面板（§7.4） | 5 |
| `gui/*` | 不存在 | **新建** 桌面 GUI（§7.3） | 5 |
| `test/tests/*.pl` | 集成脚本 | 增端口跳变/v4/指纹/偏移用例 | 6 |
| `win32/*.vcxproj` | VS2026 客户端 | 把新 `lib/fko_totp.c`/`wizard.c` 纳入编译 | 1,5 |

> 原则：每个改动都受 stanza/命令行开关控制；未启用时行为与 v3 完全一致，保证可灰度、可回退。

---

## 7. UX 设计（用户使用体验）

> 目标：把 fwknop 从「专家级 CLI 工具」升级为「安装即用、对应用无感、可视可运维」的隐身访问系统。覆盖 CLI 易用、透明自动敲门、GUI、运维可视化四大面，并补充部署与文档。

### 7.1 CLI 与配置易用性
**痛点**：现需手写 `fwknoprc`/`access.conf`、手填密钥、错误码晦涩（`FKO_ERROR_INVALID_DATA_*`）、多套配置切换靠 `-n`。

**改进**：
1. **交互式向导 `fwknop setup`**（新 `client/wizard.c`）：
   - 问答式收集：服务端地址、用户名、开放端口、是否 NAT、是否 TOTP 端口跳变、端口范围。
   - 自动 `--key-gen` 生成 Rijndael + HMAC + TOTP 种子。
   - 生成客户端 `fwknoprc` stanza **与** 对应服务端 `access.conf` stanza（终端打印 + 可选写文件）。
   - 生成 `otpauth://` URI + 终端二维码（纯文本/ASCII，或调用 `qrencode`），方便扫码录入 Authenticator（仅作可视对照，真正校验用种子）。
2. **一键命令**：
   - `fwknop knock [profile]`：解析外网 IP + TOTP 端口 + 发包，打印「端口已开，剩余 N 秒」。
   - `fwknop connect [profile]`：knock 后自动 `ssh`/`nc` 到目标（可配连接命令模板）。
   - `fwknop status`：本地配置体检 + 到服务端的可达性/时钟偏移探测。
3. **profile 管理**：`fwknop profile {add|list|use|remove}` 管理多套身份/服务器，替代裸 `-n`。
4. **错误信息优化**：把 `FKO_ERROR_*` 翻译为人话（「HMAC 不匹配：检查 HMAC_KEY 是否与服务端一致」），并给出排查清单链接。
5. **配置模板与校验**：`fwknop lint` 校验 `fwknoprc`/`access.conf` 语法、密钥长度、端口范围合法性、客户端与服务端 stanza 是否对齐。

### 7.2 透明自动敲门（对应用无感知）
**目标**：应用照常 `ssh user@host`，代理自动完成 TOTP+敲门+转发，应用零改动。

**架构**（新 `client/proxy/`）：
- **触发**：监听对本机受保护目标的出站连接。
- **流程**：拦截 → 查 profile → TOTP 端口 → 发 SPA → 探测目标端口开放 → 转发真实流量 → 维护会话 → 到期前自动续敲门。
- **平台实现**：
  - **Linux**：`iptables/nftables REDIRECT` 把目标流量导入用户态代理（类 redsocks），或 `LD_PRELOAD` 劫持 `connect()`；代理内部完成敲门后转发。
  - **Windows**：本地 SOCKS5 代理（应用配置 SOCKS）或 WFP 重定向 callout；考虑到本仓库已有 win32 原生客户端（`win32/*.vcxproj`），代理可与 `fwknop.exe` 同栈发布。
- **健壮性**：时钟偏移自动 ±窗口重试；敲门失败有可配重试次数与退避；失败保守阻断（不静默放行）并弹错。
- **降级**：可一键关闭代理，回退到手动 `fwknop knock`。

### 7.3 图形界面 GUI
> 仓库现无 GUI 代码（「fwknop-gui」仅是上游 Jonathan Bennett 的独立 Qt 项目，本仓库为 C 核心）。本方案 GUI 为 **greenfield**。

**桌面客户端（Qt6，跨平台）**：
- **配置管理**：多 profile 可视化增删改，密钥/TOTP 种子安全存储（系统钥匙串：macOS Keychain / Windows DPAPI / Linux Secret Service）。
- **一键敲门**：大按钮 + 倒计时（TOTP 窗口剩余秒数 + 当前跳变端口可视化）。
- **状态**：当前活动规则、剩余时效、最近敲门历史。
- **向导**：图形化 `fwknop setup`，扫码录入、导出 `access.conf` 片段。
- **集成**：可调用本机 `fwknop.exe`/`fwknop` 或内嵌 libfko；优先复用 libfko 以保证密码学一致。

**服务端 Web 面板（轻量，可选）**：
- 见 §7.4，作为运维可视化的一部分，浏览器访问。

**技术选型建议**：Qt6（桌面）+ 内嵌 libfko；Web 面板用 Go/Python 读 fwknopd 的 JSON 审计 + 指标，避免把 Web 栈引入 C 守护进程。

### 7.4 运维与可视化
**结构化审计**（`server/audit.c` + `log_msg.c`）：每条事件一行 JSON，字段含 `time, event(open/close/reject/replay/unknown_fp/port_mismatch/aged), user, device_id, src_ip, spa_port, target_port, totp_window, stanza, reason`。

**指标**（Prometheus `/metrics`，文本暴露便于 fwknopd 内置）：
- `fwknop_spa_packets_total{result=...}`
- `fwknop_active_rules`
- `fwknop_replay_rejects_total`、`fwknop_unknown_fingerprint_total`、`fwknop_port_mismatch_total`
- `fwknop_totp_skew_seconds` 直方图

**异常告警**：可配阈值（如单位时间重放/未知指纹突增 → 疑似扫描或泄露），触发脚本（邮件/webhook/IM）。

**密钥轮换工具** `fwknop rotate`：
- 生成新 TOTP 种子 + SPA 密钥，写入「下一个生效」stanza；
- 服务端在**宽限期**内同时接受新旧（双 stanza / 双窗口），客户端灰度切换后下线旧密钥；
- 全程审计，支持回滚。

### 7.5 其他必要部分
- **部署**：提供 systemd unit（`extras/systemd/` 已有基础）、MSVC 客户端打包、配置管理示例（Ansible/Terraform 片段）。
- **文档**：快速上手（5 分钟）、运维手册、威胁模型（§8）、迁移指南（§11），中英双语。
- **无障碍/国际化**：GUI 与 CLI 错误信息支持 i18n；CLI 输出可选 JSON（`--json`）便于脚本与面板消费。
- **安全默认**：开箱即启用 HMAC + TOTP 端口跳变 + 指纹要求 + 短时效（≤300s），弱配置 `fwknop lint` 告警。

### 7.6 服务端管理界面与凭证发放（v2.1 新增）

> 决策（2026-08-13 用户确认）：
> 1. **CLI 先行**：`fwknopd-admin` CLI 承载全部管理逻辑，WebUI/TUI 后置为壳；
> 2. **凭证文件支持明文+加密，默认加密**（scrypt + AES-256-GCM）；
> 3. **默认启用 TOFU 首次使用设备绑定**。

**动机**：服务端现状只能手改 `access.conf` + SIGHUP 重载；密钥/TOTP 种子分发靠人工拷贝。上游 `extras/console-qr/console-qr.sh` 已有「access.conf → QR」雏形，但仅明文配置、无 HMAC/TOTP 密钥、无安全模型。本节把服务端管理升级为「安装即用的凭证发放闭环」。

#### 7.6.1 界面分层

| 层 | 形态 | 状态 |
| --- | --- | --- |
| 核心 | `fwknopd-admin` CLI（C，`server/`，复用 libfko 的 `fko_key_gen`） | 阶段 4 实现 |
| TUI 壳 | dialog/whiptail 包装 CLI（服务器本机菜单） | 阶段 5+ 可选 |
| WebUI 壳 | Go/Python 面板，写操作复用 `fwknopd-admin`；默认只读 + localhost 绑定 + 写操作额外认证 | 阶段 5+ |
| GUI | 属客户端侧（§7.3），服务端管理不做桌面 GUI | — |

#### 7.6.2 `fwknopd-admin` 子命令草案

```
fwknopd-admin user add <name>   # 生成 Rijndael/HMAC/TOTP 种子、写 stanza；
                                # --totp-port --port-range --require-fingerprint
                                # --fingerprint <b64> --expire <days>
                                # --qr | --export <file> [--plain]
fwknopd-admin user list|show|rm
fwknopd-admin user qr <name>    # 一次性重渲染授权 QR
fwknopd-admin rotate <name>     # 宽限期密钥轮换（服务端侧执行，见 §7.4）
fwknopd-admin to-fingerprint list|unbind <name> <fp>   # TOFU 绑定管理
fwknopd-admin lint|status
```

#### 7.6.3 授权 QR（客户端扫码自动配置）

- **URI**：`fwknop://<server>?user=<u>&key=<b64>&hmac=<b64>&totp=<b64>&range=<s>-<e>&access=<proto/port>&name=<stanza>&v=1`（规范见附录 E）。
- **渲染**：终端 ANSI 块状 QR（运行时可选依赖 `qrencode -t ANSIUTF8`；缺失时降级打印 URI 文本）；WebUI 阶段输出 PNG。
- **客户端**：`fwknop import <qr.png|uri|cred.json>` —— zbar 解码（可选编译依赖）；GUI 阶段摄像头扫码。导入即生成 rc stanza + 本机 `DEVICE_ID`。
- **与 otpauth:// 严格区分**：otpauth 供 Authenticator 验证器对照 TOTP；`fwknop://` 是给 fwknop 客户端的完整授权凭证。

#### 7.6.4 凭证文件（导入即获权）

- JSON schema 见附录 E；默认 **passphrase 加密**（scrypt + AES-256-GCM），`--plain` 显式输出明文。
- 密文凭证可靠任意不安全渠道分发；凭证 = 邀请函，撤销 = `user rm`（reload 立即生效）。
- 客户端 `fwknop import file.json` 写入 `~/.fwknoprc` stanza。

#### 7.6.5 TOFU 首次使用设备绑定（默认启用）

- access.conf 新增：`FINGERPRINT <b64>`（可多行，显式白名单）、`REQUIRE_FINGERPRINT Y`、`FINGERPRINT_TOFU_TIMEOUT <sec>`（默认 86400）。
- 语义：
  - 白名单非空 → 常量时间匹配（§4.3）；
  - 白名单空 + `REQUIRE_FINGERPRINT Y` → **TOFU 模式**：首个通过密钥+HMAC+新鲜度校验的 v4 包，其 `device_id` 自动锁定进白名单（原子落盘 + 审计「新设备绑定」事件）。
- **凭证泄露缓解**：偷到凭证的攻击者须在宽限期内抢先绑定才有用；绑定事件审计 + 可配告警兜底。
- **诚实局限**：TOFU 不能阻止「首用抢占」（凭证被盗者先敲门），需结合短宽限窗口与 `fwknopd-admin to-fingerprint` 人工复核。

#### 7.6.6 安全纪律

- QR/凭证 = **持票凭证（bearer credential）**：一次性展示、不落日志/历史、导出即标记、可撤销。
- WebUI 是攻击面：默认只读 + localhost 绑定；写操作需额外认证；面板不落凭证明文。

---

## 8. 安全分析与威胁模型

| 威胁 | 对策 | 残余风险 |
| --- | --- | --- |
| 全网端口扫描发现服务 | 默认 DROP + 端口跳变（无固定监听口） | 范围内 SYN 噪声需监控 |
| SPA 包嗅探/重放 | HMAC + timestamp + raw_digest 重放缓存 + 可选端口因子 | 时钟不同步 → 配 NTP + ±skew |
| 加密包重放到别的端口 | `REQUIRE_TOTP_PORT_MATCH`：端口须 ∈ 报文时间窗口集合 | 需服务端与客户端时钟同步 |
| 伪造身份/设备 | `device_id` 指纹白名单 + TOTP 种子绑定 | 设备克隆 → 结合 CMDB/堡垒机 |
| 密钥泄露 | `fwknop rotate` 带宽限期轮换 + 审计 | 旧密钥宽限期内仍可用（可配） |
| TOTP 种子泄露 | 与 SPA 加密密钥分离存储；系统钥匙串；轮换 | 单点泄露 → 多因素补强 |
| DoS（范围内端口被刷） | NFQ DROP + 速率限制 + 噪声指标告警 | 高带宽泛洪仍可耗资源 |
| 客户端时间漂移 | 向导 `fwknop status` 测偏移；±skew 容忍 | 超窗失败有清晰错误 |
| 供应链/实现缺陷 | 复用经审计的 libfko；AFL/ASAN 模糊（§10） | 新代码（TOTP/指纹）需重点 fuzz |

**端口跳变的局限（诚实声明）**：跳变增加「发现成本」但不等于不可发现；范围内的端口仍可被穷举 SYN 探测。真正阻止访问的是 DROP 策略 + SPA 认证，跳变主要提升扫描成本与迷惑性，不能替代认证。

---

## 9. 配置参考（完整示例）

### 9.1 客户端 `~/.fwknoprc`（v4 增强 stanza）
```ini
[prod-ssh]
SPA_SERVER             203.0.113.10
ACCESS                 tcp/22
ALLOW_IP               resolve
KEY_BASE64             <Rijndael b64>
HMAC_KEY_BASE64        <HMAC b64>
USE_HMAC               Y
# —— 本方案新增 ——
USE_TOTP_PORT          Y
TOTP_SEED_BASE64       <TOTP seed b64>
PORT_RANGE             30000-60000
DEVICE_ID              <device fingerprint b64>
```

### 9.2 服务端 `/etc/fwknopd/access.conf`（v4 增强 stanza）
```conf
SOURCE                  ANY
KEY_BASE64              <Rijndael b64>
HMAC_KEY_BASE64         <HMAC b64>
OPEN_PORTS              tcp/22
FW_ACCESS_TIMEOUT       60
MAX_SPA_PACKET_AGE      60
REQUIRE_USERNAME        alice
# —— 本方案新增 ——
TOTP_SEED_BASE64        <TOTP seed b64>
REQUIRE_TOTP_PORT_MATCH Y
REQUIRE_FINGERPRINT     Y
FINGERPRINT             <allowed device_id b64>
```

### 9.3 服务端 `/etc/fwknopd/fwknopd.conf`（端口范围）
```conf
ENABLE_NFQ_CAPTURE      Y
NFQ_PORT_RANGE          30000-60000
NFQ_QUEUE_NUMBER        1
# （回退）PCAP_FILTER "udp dst portrange 30000-60000"
```

### 9.4 透明代理配置示例（`~/.fwknop/proxy.conf`）
```ini
[default]
target                  203.0.113.10:22
profile                 prod-ssh
mode                    redirect            # linux=redirect/nft, windows=socks
reknock_before          45s                 # 到期前续敲门
retry                   3
on_fail                 block               # block|allow|prompt
```

---

## 10. 测试策略

| 层级 | 位置 | 内容 |
| --- | --- | --- |
| 单元 | `lib/fko_utests.c`、`test/c-unit-tests/` | TOTP 生成/验证、端口映射确定性、指纹哈希、v4 编解码、窗口枚举边界 |
| 集成 | `test/tests/*.pl` | 端口跳变往返、v4 身份通过/拒绝、`REQUIRE_TOTP_PORT_MATCH`、时钟偏移 ±skew、v3↔v4 兼容 |
| 模糊 | `test/afl/`、`test/fuzzing/` | 新 fuzz 目标：TOTP 解析、device_id 字段、端口范围投递异常包 |
| 内存安全 | ASAN/UBSAN/MSAN/Valgrind | 新模块（TOTP、指纹、代理）必跑 |
| 性能 | — | NFQ 范围内大流量下的 DROP/处理延迟 |
| 兼容 | `test/tests/os_compatibility.pl` | v3 客户端 ↔ v4 服务端、v4 客户端 ↔ v3 服务端（降级） |

关键用例：RFC 6238 官方测试向量校验 TOTP；`port(now) == port(now±step)` 窗口语义；重放到错误端口被 `REQUIRE_TOTP_PORT_MATCH` 拒。

---

## 11. 迁移与兼容

- **协议协商**：版本在加密载荷内；服务端解密后按版本解析，v3/v4 共存于同一 `access.conf`（不同 stanza）。
- **灰度**：先在服务端开启端口范围监听（仍兼容固定 62201），客户端逐步切 TOTP 端口；再开 v4 身份；最后启用 `REQUIRE_*` 强制。
- **降级**：任一开关关闭即回退；`fwknop lint` 校验双端配置一致。
- **从经典 fwknop 迁移**：`fwknop setup` 读取旧 `fwknoprc`，提示补齐 TOTP 种子与 `DEVICE_ID`，生成新 stanza 而不破坏旧配置。

---

## 12. 路线图与里程碑

| 阶段 | 交付物 | 依赖 | 估算 | 里程碑 |
| --- | --- | --- | --- | --- |
| 0 | 设计定稿 + ADR + 测试基线 | — | S | M0 文档签发 |
| 1 | TOTP 引擎 + 客户端端口跳变 | 0 | M | M1 单包到跳变端口 |
| 2 | 服务端 NFQ 范围监听 | 1 | M | M2 范围内可开门 |
| 3 | SPA v4 身份绑定 | 1 | L | M3 device_id 白名单生效 |
| 4 | 零信任硬化 + 审计/指标 + 服务端管理工具（`fwknopd-admin`/QR/凭证/TOFU） | 2,3 | L | M4 端口因子 + 可观测 + 凭证发放闭环 |
| 5 | UX：透明代理/GUI/TUI+WebUI 管理壳/面板 | 3,4 | L | M5 用户无感可用 |
| 6 | 测试/打包/部署/迁移 | 1–5 | M | M6 生产灰度 |

---

## 附录

### A. SPA v4 字段定义
| # | 字段 | 编码 | 必填 | 说明 |
| --- | --- | --- | --- | --- |
| 1 | rand_val | 明文 16 位数字 | 是 | 随机 nonce |
| 2 | username | base64 | 是 | 用户名 |
| 3 | timestamp | 十进制 | 是 | Unix 秒 |
| 4 | version | 明文 | 是 | `4.0.0`（v3 为 `3.0.0`） |
| 5 | message_type | 十进制 | 是 | 见 `fko_message_type_t` |
| 6 | message | base64 | 是 | 访问/命令/NAT |
| 7 | nat_access | base64 | 否 | NAT 目标 |
| 8 | server_auth | base64 | 否 | 服务端认证（少用） |
| 9 | client_timeout | 十进制 | 否 | 服务端规则时效 |
| **10** | **device_id** | **base64** | **否（v4 新增）** | **设备指纹** |

之后追加 `digest`，整体加密后追加 `HMAC`（与 v3 一致）。

### B. TOTP 端口映射算法（伪代码）
```
function totp_to_port(seed, window, start, end):
    code = TOTP_HMAC_SHA256(seed, window)        # RFC6238, 截断 8 位
    range_size = end - start + 1
    return start + (code mod range_size)

function server_expected_ports(seed, now, skew, start, end):
    step = TOTP_STEP                              # 默认 30
    base = floor(now / step)
    ports = {}
    for w in [base-skew .. base+skew]:
        ports.add( totp_to_port(seed, w, start, end) )
    return ports                                  # 服务端监听范围即可；此集合用于可选端口因子校验
```

### C. 设备指纹生成规范
- 采集属性（跨平台，取存在项）：主机名、`/etc/machine-id` 或 Windows `MachineGuid`、根卷/系统盘序列号、主板/产品 UUID、OS 名称与版本。
- 拼接为规范字符串（固定顺序、去平台敏感分隔符），`SHA-256`，取前 16 字节，base64（22 字符）。
- 仅本地计算与哈希传输；不上链任何明文硬件信息。
- 稳定性优先：属性变化（如重装系统）会改变指纹 → 需 `fwknop rotate`/重新登记；向导检测指纹漂移并提示。

### D. 术语表
| 术语 | 含义 |
| --- | --- |
| SPA | Single Packet Authorization，单包授权 |
| TOTP | Time-based One-Time Password（RFC 6238） |
| Port-hopping | 目的端口随 TOTP 跳变 |
| device_id | 设备指纹，v4 新增 SPA 字段 |
| stanza | fwknoprc/access.conf 中的一段配置（一个用户/目标） |
| NFQ | Netfilter Queue，Linux 内核包排队机制 |
| 宽限期 | 密钥轮换时新旧并存的过渡期 |
| TOFU | Trust On First Use：首次到达的 `device_id` 自动锁定进白名单（§7.6.5） |
| bearer credential | 持票凭证：持有即拥有访问权（授权 QR / 凭证文件） |
| fwknop:// | 授权 URI scheme，供 fwknop 客户端导入的完整凭证（附录 E） |

### E. 凭证文件与授权 URI 规范（v2.1 新增）

**凭证文件（JSON, fmt v1，未加密形态）**：

```json
{
  "fmt": "fwknop-credential",
  "version": 1,
  "issued_at": 1753520000,
  "expires_at": null,
  "stanza": "prod-ssh",
  "spa_server": "203.0.113.10",
  "access": "tcp/22",
  "key_base64": "<Rijndael b64>",
  "hmac_key_base64": "<HMAC b64>",
  "totp_seed_base64": "<TOTP seed b64>",
  "port_range": "30000-60000"
}
```

- 加密形态（默认）：passphrase → scrypt → AES-256-GCM 加密整个 JSON，输出 base64，magic 前缀 `fwknop-cred v1 enc`；`fwknop import` 按前缀自动识别。

**授权 URI**：

```
fwknop://<server>?user=<u>&key=<b64>&hmac=<b64>&totp=<b64>&range=<s>-<e>&access=<proto/port>&name=<stanza>&v=1
```

- 值均为 URL 安全 base64（`+`→`-`、`/`→`_`、去 `=`）；QR 直接编码该 URI。
- 客户端导入时按字段映射生成 rc stanza；`access` 缺省 `tcp/22`；`range` 仅在启用 TOTP 端口跳变时必需。

---

> 本文档为活文档，随阶段 0 的 ADR 与实现反馈持续修订。所有改动遵循「开关可控、向后兼容、可灰度回退」三原则。
