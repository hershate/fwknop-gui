# scripts/ — fwknop fork 辅助脚本

> 本目录为 Zurker fork（非官方）自有的辅助脚本说明。

## quickstart.sh — 一键启动 / 演示

在本机拉起一套完整自包含的 fwknop 系统并做端到端验证：构建项目、生成
配对密钥、启动 fwknopd（loopback pcap 抓包）+ 运维 WebUI，从客户端发出
真实的 SPA 数据包，并验证 iptables「开门」规则生效（随后到期自动失效）。

```bash
./scripts/quickstart.sh            # demo（默认）：构建 + 启动 + 敲门 + 验证
./scripts/quickstart.sh demo       # 同上
./scripts/quickstart.sh build      # 确保存在 pcap 模式的构建产物
./scripts/quickstart.sh setup-sudo # 为 fwknopd+iptables 配置窄范围 NOPASSWD sudo
./scripts/quickstart.sh knock 443  # 发送 SPA 包以开放 tcp/443
./scripts/quickstart.sh dashboard  # 仅（重）启动 WebUI
./scripts/quickstart.sh status     # 查看 fwknopd + 面板状态
./scripts/quickstart.sh stop       # 停止 fwknopd + 面板
./scripts/quickstart.sh clean      # 停止并删除演示工作目录
```

### `demo` 做了什么

1. 若尚未构建，则构建 fwknop/fwknopd/fwknopd-admin（pcap 模式）。
2. 为 `fwknopd` + `iptables` 配置窄范围免密 sudo（需输入一次 sudo 密码），
   以便管理后台运行的守护进程。
3. 在工作目录中生成全新的配对密钥（默认 `/tmp/fwknop-quickstart`，可用
   `FWKNOPQS_WORK=...` 覆盖）。
4. 启动 `fwknopd`（`lo` 上 pcap 抓包，UDP 端口 62201，开启结构化审计）和
   http://127.0.0.1:8088 上的 `fwknop-dashboard` WebUI（需已安装 Go）。
5. 从客户端发送真实 SPA 包（`tcp/22`），并验证 iptables `FWKNOP_INPUT`
   规则出现（`ACCEPT tcp dpt:22 /* _exp_<时间戳> */`）。

上线之后：

| 内容 | 位置 |
| --- | --- |
| WebUI | http://127.0.0.1:8088 |
| fwknopd 日志 | `tail -f $WORK/fwknopd.log` |
| 审计日志 | `tail -f $WORK/run/fwknopd_audit.log` |
| 指标 | `cat $WORK/run/fwknopd.metrics` |
| 再开一扇门 | `./scripts/quickstart.sh knock 443` |
| 停止 | `./scripts/quickstart.sh stop` |

### 依赖

- **构建**：`gcc make autoconf automake libtool pkg-config libpcap0.8-dev`
  （缺少时脚本会提示）。
- **运行**：`sudo`（iptables/fwknopd 需要）。演示会在 loopback 上安装真实
  的 iptables 规则，操作防火墙需要 root。
- **可选**：`golang-go`（WebUI）、`qrencode`/`zbarimg`（二维码功能）。

### 环境变量覆盖

- `FWKNOPQS_WORK` — 工作目录（默认 `/tmp/fwknop-quickstart`）。
- `FWKNOPQS_DPORT` — SPA 目的端口（默认 `62201`）。
- `FWKNOPQS_DASH_ADDR` — 面板监听地址（默认 `127.0.0.1:8088`）。

### 关于演示安全模型的说明

演示把一切都绑定在 loopback 上，并使用 30 秒的防火墙超时，仅用于在本地
演示这套机制。真正的远程防护请使用正式的 `access.conf` 部署 fwknopd（见
[`note/release/2.1.0.md`](../note/release/2.1.0.md)）——演示在 `$WORK`
中生成的 `access.conf`/`fwknopd.conf` 是很好的起步模板。
