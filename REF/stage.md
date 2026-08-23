# fwknop SPA 扩展实施进度与 Linux 迁移交接（REF/stage.md）

> 计划来源：`REF/plan/Port Knocking.md`（v2.0）
> 基线：fwknop `2.6.11`，分支 `master`
> 远程：`https://github.com/hershate/fwknop-gui.git`（注意：**本机提交尚未 push**，见 §0.1）
> Windows 环境：MinGW GCC 15.2.0（lib/+client/ 已编译+单元验证）；服务端 fwknopd 需 Linux
> 提交规范：细粒度本地提交到 master，不写 co-author
> 最后更新：2026-08-13

> **总体状态**：阶段 1、3、5(CLI) 完成并验证；**Windows 可编译/可验证部分已全部完成**。
> 剩余为 Linux 服务端（阶段 2/4/6）与大型 greenfield（透明代理/GUI/运维面板）。
> **本文档即 Linux 续作的起点——先读 §0。**

---

## §0 迁移到 Linux 续作指南（最重要）

### 0.1 获取代码到 Linux
本机的阶段 1/3/5 提交都在 **本地 master**，远程 GitHub 上**没有**。两条路径任选其一：

- **(推荐) 先 push 再 clone**：在 Windows 本机执行 `git push origin master`（需你对 `hershate/fwknop-gui` 有写权限）；Linux 上 `git clone https://github.com/hershate/fwknop-gui.git && git log --oneline` 确认能看到 `98feade3`/`31a5c958`/`05d11c67`/`d734a35b`/`9a097500`。
- **整目录拷贝**：直接把整个仓库目录拷到 Linux（保留 `.git/`），分支与提交完整保留。

> ✅ **REF/ 开发记录已纳入 git**（提交 `cf2e2f73`，`.gitignore` 不再忽略 `/REF`，仅忽略 `REF/build/*.exe`/`*.o`/`config.h` 等构建产物）。因此 `stage.md`、`plan/Port Knocking.md`、`build/test_*.c` 会随 `git clone`/`pull` 自动同步到 Linux，无需手动拷贝；二进制产物在 Linux 重新构建即可。

相关提交（本地 master，自旧及新）：
```
98feade3 Phase 5 (portability): client uses only exported libfko APIs; wire Makefile.am
31a5c958 Phase 5: CLI usability — setup wizard, knock, lint, device fingerprint
05d11c67 Phase 3 (client): --device-id / DEVICE_ID rc support
d734a35b Phase 3 (lib): SPA v4 protocol with optional device_id field
9a097500 Phase 1: TOTP engine and client port-hopping SPA support
```

### 0.2 在 Linux 上构建（autotools）
仓库提供 `autogen.sh`（无预生成 `configure`）。标准流程：

```bash
cd fwknop-gui
./autogen.sh            # 生成 configure（首次；等同 autoreconf -iv）
./configure             # 按需加 --with-gpgme / --enable-{asan,coverage} 等
make                    # 可加 -j$(nproc)
sudo make install       # 可选，安装 libfko.so + fwknop + fwknopd
```

**关键**：阶段 1/3/5 新增的源文件已写入 `Makefile.am`，autotools 会自动编译：
- `lib/Makefile.am` → `libfko_source_files` 含 `fko_totp.c/.h`、`fko_device_id.c/.h`、`fko_fingerprint.c`
- `client/Makefile.am` → `BASE_SOURCE_FILES` 含 `wizard.c/.h`、`cli_subcmds.c/.h`

> 若忘了 §0.5 的「可移植性」提交（`98feade3`），Linux 上客户端会因链接 `libfko.so` 找不到 `sha256`/`get_random_data` 而 undefined reference——该提交已修复（指纹移入 lib 为公开 API、种子改用 `fko_key_gen`）。

**构建产物**：
- `lib/libfko.la` → `libfko.so`（含 TOTP / device_id / fingerprint）
- `client/fwknop`（增强客户端：`--totp-port` / `--device-id` / `setup` / `knock` / `lint`）
- `server/fwknopd`（**Linux 上可构建**——这是阶段 2/4 的目标）
- `lib/fko_utests`、`client/fwknop_utests`（CUnit 单元测试）

### 0.3 在 Linux 上验证（复现 Windows 的结果）
```bash
# 1) 版本号应为 4.0.0
client/fwknop --version    # → fwknop client 2.6.11, FKO protocol version 4.0.0

# 2) CUnit 单元测试（注意 MAX_SPA_FIELDS 已 9→10；既有 decode 测试按符号引用应仍通过）
lib/fko_utests
client/fwknop_utests

# 3) 子命令冒烟（无需网络）
client/fwknop setup        # 交互向导，生成密钥/种子/指纹 + stanza + otpauth
client/fwknop lint ~/.fwknoprc
client/fwknop knock <profile>   # 等价 fwknop -n <profile> -R，会尝试发包

# 4) v4 往返 / v3 兼容（移植 REF/build/test_device_id.c，或用 lib/fko_utests）
#    编译方式与 Windows 类似，但去掉 -DWIN32，链 libfko 而非整库：
gcc -std=c99 -O2 -Ilib -Icommon REF/build/test_device_id.c -L lib/.libs -lfko -o /tmp/t && /tmp/t
#    期望：33/33 PASS（v4 带/不带 device_id、v3 向后兼容、timeout+device_id）
```
> TOTP RFC6238 向量测试源在 `REF/build/test_totp.c`（gitignored，需从 Windows 拷贝或重写）；期望 6/6 SHA-256 向量 PASS。

### 0.4 关键不变量（移植/续作时必须保持）
- **协议版本**：`FKO_PROTOCOL_VERSION == "4.0.0"`（`lib/fko.h`）。
- **device_id**：v4 可选**末字段**，base64 编码；解码器按 `is_proto_v4(ctx)=atoi(version)>=4` 分支。**v3 包必须仍能解码**（向后兼容是硬约束，单测 Test3 守护）。
- **字段上限**：`MAX_SPA_FIELDS=10`、`MAX_SPA_DEVICE_ID_SIZE=128`、`MIN_SPA_FIELDS` 仍为 6（`lib/fko_limits.h`）。
- **TOTP**：RFC6238，HMAC-SHA256，步长 30s，默认 8 位，T0=0；时间参数为 `time_t`。端口映射 `fko_totp_to_port(code, start, end) = start + (val % range)`，确定性、边界安全（反转范围返回 0）。
- **可移植性**：客户端代码**只能调用导出的 `fko_*` 符号**（libfko 导出正则 `^fko_`）。不得在 client/ 直接调用 `sha256/md5/get_random_data/b64_*` 等 lib 内部函数（详见 §可移植性修复）。
- **安全**：敏感缓冲（TOTP 种子、密钥）用后 `zero_buf_wrapper`/`memset` 擦除；指纹只输出 SHA256 前 16 字节的 base64，不上链明文硬件属性。

### 0.5 客户端↔服务端协议契约（阶段 4 服务端实现依据）
客户端（已实现）发出的 v4 包含：`device_id=<指纹b64>`、目的端口 = `fko_totp_port_now(seed, time, digits, start, end)`。
服务端（阶段 4 待实现）须：
1. 解密后 `fko_get_device_id(ctx, &dev)` 取出 device_id，与 access.conf 的 `FINGERPRINT` 白名单做**常量时间比较**（复用 `common/fko_util.c` 的 `constant_runtime_cmp`）。
2. 可选 `REQUIRE_TOTP_PORT_MATCH`：用 stanza 的 TOTP 种子+端口范围重算当前应到端口，与包**实际到达的 dst 端口**比对（NFQ 可获原始 dst）。
3. 指纹不符 / 端口不匹配 / 过期 → 静默丢弃 + 结构化审计。
- TOTP 种子与端口范围在客户端由 `fwknop setup` 生成并写入 fwknoprc（`TOTP_SEED_BASE64`/`PORT_RANGE`），服务端 stanza 需配相同种子与范围（`access.conf` 拟增 `TOTP_SEED_BASE64`/`TOTP_PORT_RANGE`，见 §待办阶段 4）。

---

## 状态总览

| 阶段 | 内容 | 平台 | 状态 |
| --- | --- | --- | --- |
| 1 | TOTP 引擎 + 端口映射 + 客户端端口跳变 | Win✅ | ✅ 完成并验证 |
| 2 | 服务端 pcap 端口范围监听（PCAP_PORT_RANGE→BPF） | Linux | ✅ 完成并验证 |
| 3 | SPA v4 device_id（lib + client） | Win✅ | ✅ 完成并验证 |
| 4 | 零信任硬化 + 审计/指标 + 服务端管理工具（`fwknopd-admin`/QR/凭证/TOFU） | Linux | ✅ 完成并验证 |
| 5 | UX：CLI 易用性（向导/指纹/knock/lint/import） | Win✅ | ✅ 完成并验证 |
| 5+ | UX：透明代理 / GUI / WebUI 管理壳 / 运维面板 | 混合 | ✅ WebUI+TUI+CLI 完成；透明代理/Qt GUI 待办（greenfield） |
| 6 | 测试套件扩展（无 root 回归脚本） | Linux | ✅ 完成并验证；打包/迁移待办 |

图例：Win✅ = 本机可编译+单元验证；Linux = 需 Linux 环境。

> **2026-08-13 进展**：阶段 2、4（4a/4b/4c/4d）、6（测试）、5+（WebUI+TUI+CLI profile）在 Linux 完成。`test/run_fork_tests.sh` 27/27 PASS 覆盖全部新功能（不需 root）。剩余：阶段 5+ 的透明代理/Qt GUI（多周大型 greenfield）、阶段 6 的打包/迁移文档。

---

## 阶段 1 —— ✅ 完成并验证

### 交付物（`9a097500`）
| 文件 | 改动 |
| --- | --- |
| `lib/fko_totp.h`（新） | TOTP API：`fko_totp_generate`、`fko_totp_port_now`；常量（步长30s、默认8位） |
| `lib/fko_totp.c`（新） | RFC 6238（HMAC-SHA256，复用 `lib/hmac.c`）+ 动态截断 + 大端计数器 |
| `common/fko_util.h` | 声明 `fko_totp_to_port` |
| `common/fko_util.c` | `fko_totp_to_port`：十进制 TOTP 码 → [start,end] 确定性模映射 |
| `client/fwknop_common.h` | `fko_cli_options_t` 增 `use_totp_port`/`totp_seed_base64`/`totp_port_start/end` |
| `client/cmd_opts.h` | 枚举 `TOTP_PORT/TOTP_SEED/PORT_RANGE` + `--totp-port/--totp-seed/--port-range` |
| `client/config_init.c` | rc 变量 `USE_TOTP_PORT/TOTP_SEED_BASE64/PORT_RANGE`；parse/dump/getopt/defaults/validate |
| `client/fwknop.c` | `get_totp_port()`（base64 解码种子→TOTP→端口，零填擦除）；发送前注入 TOTP 端口 |
| `lib/fko_common.h` | 构建修复：WIN32 定宽 typedef 限定于 `_MSC_VER<1600`，MinGW/VS2010+ 走 `<stdint.h>` |

### 验证（MinGW）
TOTP RFC6238 6/6 SHA-256 向量 PASS；端口映射确定性/边界 PASS；整库+客户端构建 OK；`--test` 模式 TOTP 端口 46247（30000-60000）两次一致。

### 设计要点
单包优先（SPA 载荷不变，仅目的端口跳变）；`time_t` 时间参数；零侵入（关 `--totp-port` 即经典 fwknop）；种子用后擦除。

---

## 阶段 3 —— ✅ 完成并验证

### 交付物（`d734a35b` lib + `05d11c67` client）
| 文件 | 改动 |
| --- | --- |
| `lib/fko.h` | `FKO_PROTOCOL_VERSION 4.0.0`；声明 `fko_set/get_device_id`；4 个新错误码 |
| `lib/fko_context.h` | `struct fko_context` 增 `char *device_id` |
| `lib/fko_limits.h` | `MAX_SPA_FIELDS 10`；`MAX_SPA_DEVICE_ID_SIZE 128` |
| `lib/fko_encode.c` | v4：设置时追加 `b64(device_id)` 为末字段 |
| `lib/fko_decode.c` | 版本感知解码器（`is_proto_v4`）、`parse_device_id`、各 msg_type 上限 v4 +1；v3 路径不变 |
| `lib/fko_error.c` / `fko_funcs.c` | 新错误码字符串；`fko_destroy` 释放 `device_id` |
| `lib/fko_device_id.c/.h`（新） | `validate_device_id`、`fko_set/get_device_id` |
| `lib/fko_common.h` / `common/common.h` | `#include "fko_device_id.h"`；`MAX_DEVICE_ID_LEN 128` |
| `client/fwknop_common.h` / `cmd_opts.h` | `device_id[]` 字段；`--device-id` 选项 |
| `client/config_init.c` / `fwknop.c` | rc `DEVICE_ID` 全套；usage 文案；加密前 `fko_set_device_id()` |

### 验证（MinGW）
v4 往返/v3 兼容/timeout+device_id 单测 **33/33 PASS**（`REF/build/test_device_id.c`）；客户端 `--device-id` 端到端冒烟（包内末字段 b64=`smoke-device-001`）。

### 设计要点
向后兼容（v3 走原布局）；device_id 可选（默认不发）；`validate_device_id` 拒 `:`/空白/不可打印。

---

## 阶段 5（CLI 易用性）—— ✅ 完成并验证

> 范围经用户确认为「扩展 CLI 易用性」：设备指纹 + `fwknop setup` + `fwknop knock` + `fwknop lint`。

### 交付物（`31a5c958` + 可移植性 `98feade3`）
| 文件 | 改动 |
| --- | --- |
| `lib/fko_fingerprint.c`（新，`98feade3`） | **公开** `DLL_API fko_gen_device_fingerprint()`：hostname \| MachineGuid \| 系统盘卷序列号（Win）/ hostname \| /etc/machine-id（Unix）→ SHA256 前 16 字节 → base64。在 lib 内直接用内部 `sha256`/`fko_base64_encode` |
| `lib/fko.h`（`98feade3`） | 声明 `fko_gen_device_fingerprint` |
| `client/wizard.c/.h`（新） | `fwknop setup` 向导：问答 → `fko_key_gen`(Rijndael/HMAC) + TOTP 种子(经 `fko_key_gen`+`fko_base64_decode`) + `fko_gen_device_fingerprint` → 输出 fwknoprc stanza + access.conf stanza + `otpauth://`(base32) |
| `client/cli_subcmds.c/.h`（新） | 派发：`setup`→向导；`lint [rc] [--access-conf f]`→校验 stanza；`knock [profile]`→argv 重写 `-n <profile> -R` 复用发送管线 |
| `client/fwknop.c` | `main()` 在 `config_init` 前注入派发 |
| `lib/Makefile.am` / `client/Makefile.am`（`98feade3`） | 把新源文件纳入 autotools 编译（Linux 必需） |

### 验证（MinGW）
指纹稳定（两次 setup 一致 `jv7pRIcHO/YElB7oj25s1Q==`）；setup 输出 stanza+otpauth 正确；lint 检出缺失 TOTP 种子/端口范围；knock 派发为 `-n` 查找；经典 `-T --device-id` 向后兼容。

### 设计要点
零侵入派发（仅 `argv[1]∈{setup,lint,knock}` 拦截）；knock 即 `-n -R` 别名；otpauth base32 与服务端 TOTP 一致（digits=8,SHA256,30s）；指纹不出明文；lint 只读。

---

## 可移植性修复（`98feade3`，Linux 必需）
**问题**：阶段 5 初版（`31a5c958`）把指纹放 `client/fingerprint.c`（调内部 `sha256`）、向导调内部 `get_random_data`。libfko 导出正则 `^fko_`，客户端链接 `libfko.so` 时这些符号被隐藏 → Linux 上 undefined reference。
**修复**：指纹移入 lib 为公开 `fko_gen_device_fingerprint`；TOTP 种子改用公开 `fko_key_gen`+`fko_base64_decode`；客户端从此**仅用导出 `fko_*`**。并补齐 `Makefile.am`（阶段 1/3/5 新文件之前未纳入 autotools）。
> Linux 续作时务必基于含 `98feade3` 的代码；否则需手动应用此修复。

---

## 待办

### 阶段 6（剩余）—— 打包/迁移（Linux）
- 打包：systemd unit、MSVC `.vcxproj` 纳入阶段 2/4 新文件（`win32/`）、迁移文档与灰度策略。
- AFL：`test/afl/` 增 fuzz 目标（TOTP 解析、device_id 字段、端口范围 BPF）。
- 扩展上游 `test/tests/*.pl`（端口跳变/v4 device_id/指纹白名单/时钟偏移/v3 兼容）需 root+iptables 环境。
- ✅ 无 root 回归脚本 `test/run_fork_tests.sh`（22/22 PASS）已完成。

### 阶段 5+ —— 透明代理 / GUI / 运维面板（大型 greenfield / 混合）
- 透明代理（`client/proxy/`，新目录）：Linux 用 iptables/nftables REDIRECT 或 LD_PRELOAD；Windows 用 SOCKS5 或 WFP callout。
- GUI：greenfield（Qt 等）。
- ✅ 运维 Web 面板（2.2.0）：Go 单二进制、完全汉化六页面板（概览/事件/用户/TOFU/配置/关于），管理闭环（签发→列表→撤销→解绑）可用。
- ✅ TUI/WebUI 管理壳：包装 `fwknopd-admin`（2.2.0 起 CLI 命令集完整：user add/list/rm/qr、tofu list/unbind、lint、status）。
- 其余 CLI：`fwknop profile {add|list|use|remove}`、`fwknop status`（时钟偏移）、错误码人话翻译。

---

## 已完成阶段细节（2026-08-13 实现交接）

### 阶段 2 —— 服务端 pcap 端口范围监听 ✅
- 新增 `PCAP_PORT_RANGE` 配置（`fwknopd_common.h` 枚举 + `cmd_opts.h` config_map + `config_init.c` 默认值）：设了范围且未显式配 `PCAP_FILTER` 时自动生成 `udp dst portrange START-END` BPF；显式 `PCAP_FILTER` 优先。
- NFQ 后端：范围由 iptables 规则 `--dport START:END -j NFQUEUE` 内核过滤，fwknopd 无需改（已接收所有排队包，`process_packet` 解析 dst 端口供阶段 4 用）。
- UDP 后端仅固定端口，端口跳变用 NFQ/pcap（`fwknopd.conf` 注明）。

### 阶段 4 —— 零信任硬化 + 审计/指标 + 服务端管理工具 ✅
- **4a** `incoming_spa.c`：`check_device_id`（显式白名单 constant_runtime_cmp + TOFU 绑定宽限窗口）+ `check_totp_port`（SPA timestamp 重算端口 vs `packet_dst_port`），插在 username 与端口策略之间，失配保守拒绝。`access.c` 解析 `FINGERPRINT`(多行)/`REQUIRE_FINGERPRINT`/`FINGERPRINT_TOFU_TIMEOUT`/`TOTP_SEED_BASE64`/`TOTP_PORT_RANGE`/`TOTP_PORT_DIGITS`/`REQUIRE_TOTP_PORT_MATCH`，解析期校验。TOFU 持久化到 `<run_dir>/fwknop_tofu.state`（用非敏感 SOURCE|username|open_ports 元组标识 stanza）。
- **4b** `audit.c/.h`：8 类事件 JSON 行审计（`fwknopd_audit.log`）+ Prometheus 指标（`fwknopd.metrics`，原子重写）。接入 incoming_spa 各决策点。
- **4c** `fwknopd-admin` CLI + `credential.c/.h` + `lib/fko_cred.c`（导出 `fko_encrypt_buf`/`fko_decrypt_buf`，复用 rij_encrypt AES-256-CBC）。凭证 JSON v1 + `fwknop://` URI（URL-safe base64）。
- **4d** `client/import.c`：`fwknop import` 三形态（URI/JSON/QR）→ rc stanza，复用 `fko_decrypt_buf` 解密。

### 阶段 6 —— 测试 ✅（脚本部分）
- `test/run_fork_tests.sh`：无 root，22/22 PASS，覆盖构建+单测+REF+阶段 2/4a/4c-4d 端到端。

---

## 变更日志
- 2026-08-23：**WebUI 2.4.6 归档**（37 项 UX 迭代，commit `501cd1fa..` 起）。核心：用户页批量撤销（活跃预警+逐个复用单撤销链路）；批量条「被筛选隐藏」标注；签发安全选项折叠+生效值摘要；搜索历史通用组件五框接入；浏览器前进/后退翻页；事件排行用户维度+异常角标；模板高亮一致性修复；首访引导命令纠错（fwknop -n）。回归 98/98 PASS。详见 note/release/2.4.6.md。
- 2026-08-23：**WebUI 2.4.5 归档**（27 项 UX 迭代，commit `b53aadbb..9bc558a8`）。核心：审计日志管理闭环（面板清理 rename 备份 / ?bak= 白名单下载 / rmbak 删除 / overview 备份汇总）；签发结果「下载 cred.json」（URI→JSON v1 前端直转，端到端验证）；TOFU 悬空绑定检测 + 一键全选清理；事件来源/设备排行芯片；toast/通知历史纯文本插入消除 HTML 注入面；CSV 导出列错位修复。回归 98/98 PASS。详见 note/release/2.4.5.md。
- 2026-08-23：**WebUI 2.4.4 归档**（27 项 UX 迭代，commit `b9b2140b..48a29310`）。核心：无障碍补齐（概览卡/cp-cell 键盘可达、aria-live ×5、全局错误兜底 toast）；加载失败兜底（骨架屏超时→错误占位+重试，9 容器）；事件详情复制摘要/异常桌面通知/密度切换/「筛选中」标签条/详情解绑设备；配置视图指令查找框；签发三组常用值芯片；登录失败提示剩余尝试次数。回归 90/90 PASS。详见 note/release/2.4.4.md。
- 2026-08-23：**WebUI 2.4.3 归档**（49 项 UX 迭代，commit `ee3adf3c..8d11283d`）。核心：签发一键生效（`apply=1` 自动写入 access.conf + 预检/备份/SIGHUP）；`fwknopd-admin user add --fw-timeout` 自定义访问超时（1-8388608，同 RCHK_MAX_FW_TIMEOUT）；自定义签发模板（localStorage）；事件筛选/搜索词/TOFU 排序全量持久化；快捷键帮助面板（? 键）；模态焦点返还；侧栏异常徽标/脏圆点/动态版本；写失败透传服务端错误文本。回归 89/89 PASS。详见 note/release/2.4.3.md。
- 2026-08-23（2.4.2）：**WebUI 体验深化**（约 60 项 UX 迭代，逐项 commit）。签发全字段校验+键盘流闭环、事件行展开/CSV 导出/端口筛选、TOFU 批量解绑、配置编辑器行级高亮与保存拦截、方案应用 diff 确认、通知历史、会话剩余时间（auth/state 新增 session_exp）、模态焦点捕获、移动端手势等。回归 **84/84 PASS**。详见 note/release/2.4.2.md。
- 2026-08-23（2.4.1）：**WebUI 默认管理模式**。`-enable-write` 默认值翻转为 true（保留仅为兼容旧脚本），新增 `-read-only` 显式只读开关（`main.go`）；只读拒绝文案同步（`api.go`）；前端关于页/只读提示/概览卡片措辞更新，版本 v2.4.1。回归 **79/79 PASS**（18098 实例不传 -enable-write 验证默认管理模式；新增 -read-only 第三实例 3 用例）。后端 `064388d7`、前端 `4f9f3155`、测试 `a3e7aafa`。详见 note/release/2.4.1.md。
- 2026-08-23（2.4.0）：**WebUI 首次启动初始化与强制鉴权**。新增 `server/dashboard/auth.go`：初始化向导 `POST /api/setup`（未初始化时才可用，密码≥8 位，成功自动登录，重复 409）；密码 PBKDF2-HMAC-SHA256（10 万轮/16 字节盐）存 `<run-dir>/dashboard_auth.json`（0600 原子落盘，恒定时间比较校验）；会话登录 `POST /api/login` → 32 字节随机令牌写入 HttpOnly+SameSite=Strict Cookie（TLS 下 Secure，12h TTL），`POST /api/logout` 注销，`GET /api/auth/state` 公开状态查询；登录限流每 IP 5 次/5 分钟锁 60 秒（429）；Cookie 会话写操作强制 `X-Fwknop-Request: 1`（CSRF，403），Bearer 豁免。`main.go` 除鉴权端点与静态页外全部 /api 经 `requireAuth`（401 needs_setup/needs_login）；`api.go` `requireWrite` 改为 enable-write+CSRF；`DASHBOARD_TOKEN` 保留为全 API Bearer 通道（登录接口也接受该值）。前端新增认证门禁三卡片（加载/初始化/登录）+ 401 自动回弹 + 注销按钮，版本 v2.4.0。回归扩展至 **76/76 PASS**（新增 14 个鉴权用例；wget 对 401 不输出响应体，needs_setup 断言改由 /api/auth/state 用例覆盖）。后端 `4556da01`、前端 `82d0ec70`、测试 `4d2027a2`。详见 note/release/2.4.0.md。
- 2026-08-23（2.3.0 补充三）：**文档按当前代码全面更新**。README 新增「本 fork 功能特性」章节（TOTP 跳变/SPA v4 device_id/指纹+TOFU/审计指标/fwknopd-admin/易用性子命令/WebUI/托盘）并更新「当前状态」；NEWS 补 fork 2.1.0/2.2.0/2.3.0 版本记录；`fwknop(8)`/`fwknopd(8)` man 页（asciidoc 源 + `.8.in` 模板 + 生成的 `.8` 三层同步）新增「本 fork 新增功能」章节——客户端 `--totp-port/--totp-seed/--port-range/--device-id`、rc 指令、setup/knock/lint/import/profile 子命令；服务端 `PCAP_PORT_RANGE/ENABLE_AUDIT/AUDIT_FILE/METRICS_FILE`、access.conf 七项新指令、运行时产物、fwknopd-admin 用法；`doc/libfko.texi` 增补 fork 章节（SPA v4 格式、5 个新导出函数、内部 TOTP），Top 菜单同步，makeinfo 零告警。删除冗余的 `android/README.DEPRECATED`（内容与 android/README 顶部重复）。回归复测 **61/61 PASS**。
- 2026-08-23（2.3.0 补充二）：**项目文档全部汉化**（GPL v2+ 允许文档翻译，保留原始版权声明）。README.md 原地汉化并在顶部加入「Zurker 维护的非官方 fork」声明；NEWS/INSTALL/AUTHORS/CREDITS/doc/README/scripts+test/+子目录（openwrt/python/erlang/perl-FKO/android/iphone/win32）README 共 20+ 文档原地汉化，英文原文一律另存 `.en` 副本；man 手册页汉化含 asciidoc 源、`.8.in` 模板与生成的 `.8` 三层（构建时模板可再生成中文 man 页，groff 结构校验通过）。**冲突处理**：COPYING 依 GPLv2「许可证文本不得改动」条款保持原文，新增 `COPYING.zh-CN` 非官方译本（顶部声明以英文原文为准）。上游 ChangeLog（历史档案）与 `perl/legacy/deps/` 捆绑第三方文档按用户决定不译。回归复测 **61/61 PASS**（删除 .8 后全量重建验证模板链路）。
- 2026-08-23（2.3.0 补充）：**fork 脚本说明全部汉化**。`test/run_fork_tests.sh` 头注释/行内注释/测试标签、`scripts/quickstart.sh` 头注释/注释/全部提示信息（usage 输出保持 `sed 3,22p` 行范围不变）、`extras/tui/fwknopd-admin-tui.sh` 头注释/注释/dialog 与纯文本菜单文案（`284ebe69`/`31585ba5`/`e901516e`）。回归复测 **61/61 PASS**。
- 2026-08-23（2.3.0）：**WebUI 全功能化**。服务控制（启动强制 `--exit-parse-config` 预检/停止/重启/SIGHUP 热加载/`--fw-list` 规则查看，`-fwknopd` 新参数）；fwknopd.conf 结构化+原文可视化编辑（预检→备份→原子替换→热加载流水线）；access.conf stanza 在线编辑（仅 11 个非密钥指令，密钥行服务端强校验拒绝）；撤销授权一键恢复；配置方案（快照保存/预览掩码/一键应用/删除，`-profile-dir`）；审计日志导出；只读模式自动隐藏管理控件。后端 `266becdc`、前端 `3c4a2fae`。回归 **61/61 PASS**。
- 2026-08-23（2.2.0）：**WebUI 全面重设计 + 服务端管理闭环**。`fwknopd-admin` 占位命令全部落地：`user list`（密钥掩码）/`user rm`（注释禁用+备份+SIGHUP）/`user qr`（URI 重建+QR）/`lint`（一致性检查）/`tofu unbind`（备份+SIGHUP）；`user add` 输出带 `### fwknopd-admin user:` 名称标记（`d83423c4`）。dashboard 后端扩展：`/api/overview|users|config`、结构化 `/api/tofu`、全选项 add/rm/unbind 包装、安全响应头（`6fb9234f`）；前端重设计为完全汉化六页面板（侧边栏：概览/事件/用户/TOFU/配置/关于；明暗主题、自动刷新可暂停、筛选/搜索/分页、迷你趋势、骨架屏/空状态/toast/二次确认）（`e2f1ea99`）。回归 **44/44 PASS**。
- 2026-08-13（续）：**完整上游测试套件验证**。`test/test-fwknop.pl` 全套 **692/34/726** 通过（103 分钟，fuzzing 9/0/9）。真实端到端 SPA 交换（[client+server] 类）全通过——`fw_rule_created=1`、iptables 实际安装 `ACCEPT tcp dpt:22 /* _exp_<ts> */` 并到期移除。34 项失败分类：11 项 pcap 测试因初次 `--enable-udp-server` 构建排除 pcap（pcap 构建重跑 17/4/21 通过，含 portrange filter 验证 PCAP_PORT_RANGE 无回归）；其余环境相关（hardening/interface/raw-socket/NAT/fko-wrapper）。**test 28 绑定修复**（`d368f761`）：device_id 错误码 + 多处漂移，从 libfko 重建 perl/python 绑定 143 个权威值。Fork 回归 27/27（系统工具链）。**结论：Stage 2/4/5+ 零回归**。
- 2026-08-13：**阶段 2/4/6/5+ 在 Linux 实现并验证**。基线构建修复（`lib/Makefile.am` fko_utests LDADD 同目录相对引用）。阶段 2 `PCAP_PORT_RANGE`→`udp dst portrange` BPF（commit `6ade35dd`）。阶段 4a 指纹白名单+TOFU+`REQUIRE_TOTP_PORT_MATCH`（`46c683e2`）。阶段 4b 结构化 JSON 审计+Prometheus 指标（`ec205b82`）。阶段 4c `fwknopd-admin` CLI + 凭证/QR 发放 + `fko_encrypt_buf`（`4cf4386a`）。阶段 4d 客户端 `fwknop import`（`83d93479`）。阶段 6 无 root 回归脚本 `test/run_fork_tests.sh`（`7440971f`）。阶段 5+：WebUI 运维面板 Go（`8b5b62a8`）、TUI 管理壳（`2b692138`）、`fwknop profile list`（`395d4d48`）。回归 27/27 PASS。凭证加密改为复用 rij_encrypt 的 AES-256-CBC（非新原语，比方案 v2.1 的 scrypt+AES-GCM 更务实）。
- 2026-08-13：细化服务端管理易用性方案（用户决策：CLI 先行 / 凭证默认加密 / TOFU 默认启用）——`fwknopd-admin` CLI、授权 QR（`fwknop://`）、凭证文件（JSON v1，scrypt+AES-GCM）、TOFU 首次使用绑定；方案文档 v2.0 → v2.1（§7.6/附录 E）；阶段 4 升级为「零信任硬化 + 审计/指标 + 服务端管理工具」。
- 2026-07-23：阶段 1 完成（`9a097500`）——TOTP 引擎 + 端口映射 + 客户端端口跳变；MinGW 验证 6/6 RFC 向量 + 端口确定性。
- 2026-07-23：阶段 3 完成（`d734a35b`+`05d11c67`）——SPA v4 device_id；v4/v3 单测 33/33 PASS；客户端 `--device-id` 冒烟通过。
- 2026-07-23：阶段 5（CLI 易用性）完成（`31a5c958`）——指纹 + setup 向导 + knock + lint；冒烟全通过。
- 2026-07-23：可移植性修复（`98feade3`）——指纹移入 lib 为公开 API、客户端仅用导出 `fko_*`、补齐 `Makefile.am`；Linux 链接 libfko.so 不再 undefined。
- 2026-07-23：**Windows 可编译/可验证部分全部完成**；编写本文档作为 Linux 迁移交接。下一步在 Linux 续作阶段 2/4/6。
