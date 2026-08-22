# fwknop - 单包授权（Single Packet Authorization）

> **【关于本仓库】**
> 本项目是 **Zurker** 维护的 fwknop **非官方 fork**（仓库名 fwknop-gui），
> 基于上游 [mrash/fwknop](https://github.com/mrash/fwknop) 2.6.11 二次开发，
> 与上游作者及官方 fwknop 项目无任何隶属关系，上游不对本 fork 的改动负责。
>
> 本 fork 在上游基础上新增了：TOTP 动态端口跳变（SPA 协议升级为 4.0.0）、
> 设备指纹绑定 + TOFU、结构化审计与 Prometheus 指标、服务端管理工具
> `fwknopd-admin`、凭证签发与 `fwknop import`、全中文 WebUI 运维面板
> （服务控制/可视化配置编辑/配置方案一键切换）、Windows 托盘客户端等。
> 详见 [`note/`](note/README.md) 目录与 [`note/release/`](note/release/) 发版说明。
>
> 本文件为中文译本（由本 fork 翻译维护）；英文原文见
> [`README.en.md`](README.en.md)。许可证见 [`COPYING`](COPYING)
> （非官方中文译本见 [`COPYING.zh-CN`](COPYING.zh-CN)，以英文原文为准）。

## 简介
fwknop 实现了一种称为单包授权（Single Packet Authorization，SPA）的授权
机制，用于实现高强度的服务隐藏。SPA 只需要一个经过加密、防重放、并通过
HMAC 认证的数据包，即可向隐藏在「默认丢弃」防火墙之后的服务传达访问请求。
SPA 的主要应用是让防火墙丢弃对 SSH 等服务的所有连接尝试，从而使漏洞利用
（无论是 0-day 还是未打补丁的代码）变得更加困难。由于没有任何开放端口，
被 SPA 隐藏的服务自然无法被 Nmap 扫描到。fwknop 项目支持四种防火墙：
iptables、firewalld、PF 和 ipfw，覆盖 Linux、OpenBSD、FreeBSD 和
Mac OS X。同时还支持自定义脚本，使 fwknop 能够适配 ipset、nftables 等
其他基础设施。

SPA 本质上是下一代端口敲门（Port Knocking，PK），它在保留 PK 核心优势的
同时解决了 PK 的诸多局限。PK 的局限包括：普遍难以防御重放攻击；通常无法
可靠支持非对称密码与 HMAC 方案；只需向 PK 序列中伪造一个额外的数据包即可
轻易对 PK 服务器发起 DoS 攻击（从而让 PK 服务器误以为客户端不知道正确的
序列）。这些缺陷都被 SPA 解决。与此同时，SPA 将服务隐藏在默认丢弃的
防火墙策略之后，被动地获取 SPA 数据（通常通过 libpcap 或其他手段），并为
SPA 数据包的认证与加解密实现标准的密码学操作。

fwknop 生成的 SPA 数据包利用 HMAC 实现「先加密后认证」（encrypt-then-
authenticate）模式的认证加密。尽管 HMAC 目前是可选的（通过 `--use-hmac`
命令行开关启用），但强烈建议启用，理由有三：

   1. 没有 HMAC，fwknop 就无法实现密码学意义上的强认证——除非使用 GnuPG，
      但即使那样也应再叠加 HMAC。
   2. 在加密之后施加 HMAC 可以防御针对 CBC 模式的密码分析填充预言攻击，
      例如 Vaudenay 攻击及类似手法（如针对 SSL 的较新「Lucky 13」攻击）。
   3. fwknopd 守护进程验证 HMAC 所需的代码远比解密 SPA 数据包的代码简单，
      因此没有合法 HMAC 的 SPA 数据包甚至不会进入解密例程。

上述最后一条也是即使 SPA 数据包已用 GnuPG 加密仍应使用 HMAC 的原因：除非
HMAC 先校验通过，否则 SPA 数据根本不会送入 libgpgme 函数。GnuPG 和
libgpgme 是相对庞大复杂的代码体，通过 HMAC 操作限制潜在攻击者与这些代码
交互的能力，有助于维持更强的安全态势。为 SPA 通信生成 HMAC 需要一把独立于
常规加密密钥的专用密钥，两者都可以用 `--key-gen` 选项生成。

fwknop 使用 Rijndael 分组密码或 GnuPG 及其非对称密码来加密 SPA 数据包。
如果选择对称加密方式，加密密钥照例在客户端与服务端之间共享（详见
`/etc/fwknop/access.conf` 文件）。Rijndael 加密实际使用的密钥通过标准的
PBKDF1 密钥派生算法生成，并使用 CBC 模式。如果选择 GnuPG 方式，加密密钥
则来自 GnuPG 密钥环。

## 本 fork（Zurker）的功能特性

在上游 2.6.11 功能之上，本 fork 新增了以下能力（全部有测试覆盖，
`./test/run_fork_tests.sh` 当前 **61/61 PASS**）：

 * **TOTP 动态端口跳变**：SPA 包的目的端口由当前 TOTP 值（RFC 6238，
   HMAC-SHA256，30 秒步长）映射到配置端口段。客户端用 `--totp-port`
   `--totp-seed` `--port-range`（或 rc 指令 `USE_TOTP_PORT`/
   `TOTP_SEED_BASE64`/`PORT_RANGE`）；服务端用 `PCAP_PORT_RANGE`
   （pcap 模式下自动生成 `udp dst portrange` BPF 过滤器）和
   access.conf 的 `TOTP_SEED_BASE64`/`TOTP_PORT_RANGE`/
   `TOTP_PORT_DIGITS`/`REQUIRE_TOTP_PORT_MATCH`。
 * **SPA 协议 4.0.0 + 设备身份**：SPA 包可携带可选的 device_id 末字段
   （`--device-id` / rc 指令 `DEVICE_ID`），完整向后兼容 v3 客户端。
 * **设备指纹 + TOFU 绑定**：access.conf 支持 `FINGERPRINT`（多行白名单）、
   `REQUIRE_FINGERPRINT`、`FINGERPRINT_TOFU_TIMEOUT`（TOFU 首用绑定宽
   限期）；绑定持久化在 `<run_dir>/fwknop_tofu.state`。
 * **结构化审计与指标**：fwknopd 输出 JSON 行审计日志
   （`<run_dir>/fwknopd_audit.log`，8 类事件）与 Prometheus 指标
   （`<run_dir>/fwknopd.metrics`），由 `ENABLE_AUDIT`/`AUDIT_FILE`/
   `METRICS_FILE` 控制。
 * **服务端管理工具 `fwknopd-admin`**：签发授权（密钥 + TOTP 种子 +
   指纹 + QR + 加密凭证文件）、`user list`（密钥掩码）/`user rm`
   （可逆禁用+备份+热加载）/`user qr`、`tofu list/unbind`、`lint`、
   `status`。
 * **客户端易用性子命令**：`fwknop setup`（交互向导）、`fwknop knock
   <配置名>`、`fwknop lint`、`fwknop import <fwknop://URI|cred.json|qr.png>`、
   `fwknop profile list`。
 * **全中文 WebUI 运维面板**（`server/dashboard/`，单二进制零依赖）：
   服务启停/重启/热加载（强制配置预检）、fwknopd.conf 与 access.conf
   stanza 可视化编辑（预检→备份→原子替换→SIGHUP）、配置方案一键切换、
   审计导出、TOFU 解绑。
 * **Windows 便携版托盘客户端**（`client/tray/`）与 **TUI 管理外壳**
   （`extras/tui/`）。
 * **一键演示**：`./scripts/quickstart.sh` 构建并拉起完整自包含演示。

## 使用场景
使用单包授权（SPA）或其安全性堪忧的「表亲」端口敲门（PK）的人，通常是要
访问与 SPA/PK 软件部署在同一系统上的 SSHD。也就是说，主机上的防火墙对所有
传入的 SSH 连接采取默认丢弃策略，使 SSHD 无法被扫描；而 SPA 守护进程会重新
配置防火墙，临时向通过被动认证的 SPA 客户端授予访问权：

![SPA-basic-access-SSHD](doc/images/SPA_basic.png "通过 SPA 访问 SSHD 的基本用法")

fwknop 支持上述用法，但还更进一步——对 NAT 做了稳健的利用（适用于
iptables/firewalld 防火墙）。毕竟，*重要的*防火墙通常是网络之间的网关，
而不仅仅部署在独立主机上。此类防火墙普遍使用 NAT（至少对 IPv4 通信而言），
为 RFC 1918 地址空间的内部网络提供互联网访问，也允许外部主机访问内部系统
上托管的服务。

由于 fwknop 与 NAT 集成，外部互联网上的用户可以借助 SPA *穿过*防火墙访问
内部服务。这一能力在现代传统网络上有大量应用，同时也让 fwknop 能够支持
Amazon AWS 等云计算环境：

![SPA-Amazon-AWS-cloud](doc/images/SPA_AWS_network_setup.png "SPA 在 Amazon AWS 云环境中的用法")

## 用户界面
官方跨平台 fwknop 客户端图形界面 *fwknop-gui*
（[下载](https://incomsystems.biz/fwknop-gui/)，[github](https://github.com/jp-bennett/fwknop-gui)）
由 Jonathan Bennett 开发。绝大多数主要的客户端 SPA 模式都已支持，包括 NAT
请求、HMAC 与 Rijndael 密钥（尚不支持 GnuPG）、fwknoprc stanza 保存等。
目前 fwknop-gui 运行于 Linux、Mac OS X 和 Windows——下图为 OS X 截图：
![fwknop-gui-OS-X-screenshot](doc/images/fwknop-gui-OSX.png "Mac OS X 上的 fwknop-gui")
此外，还有一个更新的
[Android 客户端](https://github.com/jp-bennett/Fwknop2)
[可供使用](https://incomsystems.biz/fwknop-gui/android.php)。

> 注：本仓库（Zurker fork）名为 fwknop-gui，但**不包含**上述上游 GUI
> 客户端的代码；本仓库是 fwknop 的 C 核心加上本 fork 的二次开发扩展
> （含自研的全中文 WebUI 运维面板与 Windows 托盘客户端）。

## 教程
完整的 fwknop 教程见：

[http://www.cipherdyne.org/fwknop/docs/fwknop-tutorial.html](http://www.cipherdyne.org/fwknop/docs/fwknop-tutorial.html)


## 功能特性
以下是 fwknop 项目支持功能的完整列表：

 * 围绕 Linux 上的 iptables 和 firewalld 防火墙、*BSD 和 Mac OS X 上的
   ipfw 防火墙、以及 OpenBSD 上的 PF 实现单包授权。
 * fwknop 客户端运行于 Linux、Mac OS X、*BSD 以及 Cygwin 下的 Windows。
   此外还有一个用于生成 SPA 数据包的
   [Android 应用](https://github.com/jp-bennett/Fwknop2/releases)。
 * 支持 Rijndael 与 GnuPG 两种 SPA 数据包加解密方式。
 * 对 Rijndael 与 GnuPG 均支持 HMAC 认证加密。运算顺序为先加密后认证，
   以避免各类密码分析问题。
 * 通过对合法传入 SPA 数据包做 SHA-256 摘要比对来检测并挫败重放攻击。
   也支持其他摘要算法，但默认使用 SHA-256。
 * SPA 数据包通过 libpcap 从网络上被动嗅探。fwknopd 服务端也可以从独立
   以太网嗅探器写入的文件（如 `tcpdump -w <文件>`）、iptables ULOG pcap
   写入器获取报文数据，或在 `--udp-server` 模式下直接经 UDP 套接字获取。
 * 对于 iptables 防火墙，fwknop 添加的 ACCEPT 规则会被加入自定义的
   iptables 链，并在（可配置的）超时后从中删除，因此 fwknop 不会干扰系统
   上可能已加载的任何现有 iptables 策略。
 * 支持经认证的 SPA 通信使用入站 NAT 连接（目前仅限 iptables 防火墙）。
   这意味着可以把 fwknop 配置为创建 DNAT 规则，使你能够从开放的互联网
   访问运行在内网 RFC 1918 地址上的服务（如 SSH）。也支持 SNAT 规则，
   这实际上把 fwknopd 变成一个
   [SPA 认证网关](https://www.cipherdyne.org/blog/2015/04/nat-and-single-packet-authorization.html)，
   供内网访问互联网。
 * fwknop 服务端支持多用户，每个用户都可以通过 /etc/fwknop/access.conf
   文件被分配独立的对称或非对称加密密钥。
 * 通过 [https://www.cipherdyne.org/cgi-bin/myip](https://www.cipherdyne.org/cgi-bin/myip)
   自动解析外部 IP 地址（当 fwknop 客户端运行在 NAT 设备之后时很有用）。
   由于此模式下外部 IP 地址被加密进每个 SPA 数据包中，中间人（MITM）攻击
   ——即内联设备截获 SPA 包后仅从另一 IP 转发以图获取访问权——会被挫败。
 * 支持 SPA 数据包目的端口的
   [端口随机化](https://www.cipherdyne.org/blog/2008/06/single-packet-authorization-with-port-randomization.html)，
   以及借助 iptables NAT 能力对后续连接端口的随机化。后者适用于转发到内部
   服务的连接，也适用于授予运行 fwknopd 的系统本地套接字的访问。
 * 与 Tor 集成（见这份
   [DefCon 14](http://www.cipherdyne.org/fwknop/docs/talks/dc14_fwknop_slides.pdf)
   演讲）。注意：由于 Tor 使用 TCP 传输，经由 Tor 网络发送 SPA 数据包要求
   每个 SPA 包都在已建立的 TCP 连接上发送，因此严格来说这打破了「单包授权」
   中「单包」的一面。不过在某些部署中，Tor 提供的匿名性收益可能超过这一
   考量。
 * 为 SPA 通信实现了带版本号的协议，便于扩展协议以提供新的 SPA 消息类型，
   同时保持与旧版 fwknop 客户端的向后兼容。
 * 支持代表合法的 SPA 数据包执行 shell 命令。
 * fwknop 服务端可以配置为对入站 SPA 数据包施加除加密密钥与重放检测之外
   的多重限制，包括报文年龄、源 IP 地址、远程用户、请求端口的访问权限等。
 * fwknop 随附一套全面的测试套件，包含一系列旨在验证 fwknop 客户端与服务
   端是否正常工作的测试。这些测试包括：在本地回环接口上嗅探 SPA 数据包、
   构建临时防火墙规则并根据测试配置检查相应访问是否生效、解析 fwknop
   客户端与 fwknopd 服务端的输出以寻找每个测试的预期标记。测试套件的输出
   可以方便地做匿名化处理，以便交给第三方分析。
 * fwknop 是第一个把端口敲门与被动操作系统指纹识别相结合的程序。不过单包
   授权提供了远超端口敲门的安全收益，因此端口敲门工作模式总体上已被弃用。


## 许可证
fwknop 项目以 **GNU 通用公共许可证（GPL v2）**或（由你选择的）任何后续
版本的条款作为开源软件发布。最新版本见
[http://www.cipherdyne.org/fwknop/](http://www.cipherdyne.org/fwknop/)

许可证原文见 [`COPYING`](COPYING)；非官方中文译本见
[`COPYING.zh-CN`](COPYING.zh-CN)（仅供参考，以英文原文为准）。


## 快速上手（本 fork）

一条命令即可构建项目并拉起一套自包含演示（loopback 上的 fwknopd +
全中文 WebUI + 一次真实的 SPA 敲门打开 iptables「大门」）：

```bash
./scripts/quickstart.sh          # 构建 + 启动 + 敲门 + 验证（默认 demo）
./scripts/quickstart.sh status   # 查看运行中的 fwknopd + 面板
./scripts/quickstart.sh knock 443   # 再开一扇门
./scripts/quickstart.sh stop     # 停止全部
```

全部子命令与选项见 [`scripts/README.md`](scripts/README.md)；本 fork 的
完整功能集（TOTP 端口跳变、设备指纹 + TOFU、结构化审计/指标、经
`fwknopd-admin` 的凭证签发、客户端 `fwknop import`、WebUI 运维面板）见
[`note/release/2.3.0.md`](note/release/2.3.0.md) 及
[`note/release/2.1.0.md`](note/release/2.1.0.md)。

## 当前状态
本仓库是上游 2.6.11 基线 + Zurker fork 二次开发的当前状态（fork 各版本
演进见 [`note/release/`](note/release/)：2.1.0 零信任硬化与服务端管理工具、
2.2.0 WebUI 重设计汉化、2.3.0 WebUI 全功能化）。

上游原文对「当前状态」的描述（截至 2013 年 7 月的 2.5 版本）：项目包含
防火墙敲门操作符库 `libfko` 的实现，以及 fwknop 客户端与服务端应用程序。
该库为其他 fwknop 组件所使用的单包授权（SPA）数据提供 API 与后端功能。
它也可以被其他需要 SPA 功能的程序使用（示例见 `perl` 目录中的 FKO perl
模块，`python` 目录中也有 python 绑定）。


## 升级
如果你从旧版本 fwknop 升级（包括最初的 perl 实现），请阅读以下链接以确保
平稳过渡到 fwknop-2.5 或更高版本：

[http://www.cipherdyne.org/fwknop/docs/fwknop-tutorial.html#backwards-compatibility](http://www.cipherdyne.org/fwknop/docs/fwknop-tutorial.html#backwards-compatibility)

## 杂项
 * 关于 fwknop 的问题或评论请发往
[fwknop 邮件列表](http://lists.sourceforge.net/lists/listinfo/fwknop-discuss])。
 * 静态分析方面，fwknop 使用 CLANG 静态分析器以及强大的
Coverity Scan 工具：[![](https://scan.coverity.com/projects/403/badge.svg)](https://scan.coverity.com/projects/fwknop)

## 构建 fwknop
本发行版使用 GNU autoconf 进行构建配置。使用 autoconf 的一般基础说明见
`INSTALL` 文件。

有一些 fwknop 特有的 "configure" 选项（摘自 *./configure --help*）：

      --disable-client        不构建 fwknop 客户端组件。默认构建客户端。
      --disable-server        不构建 fwknop 服务端组件。默认构建服务端。
      --with-gpgme            使用 libgpgme 支持 gpg 加密
                              [默认=自动检测]
      --with-gpgme-prefix=PFX GPGME 的安装前缀（可选）
      --with-gpg=/path/to/gpg 指定 gpgme 将使用的 gpg 可执行文件路径
                              [默认=自动检测路径]
      --with-firewalld=/path/to/firewalld
                              指定 firewalld 可执行文件路径
                              [默认=自动检测路径]
      --with-iptables=/path/to/iptables
                              指定 iptables 可执行文件路径
                              [默认=自动检测路径]
      --with-ipfw=/path/to/ipfw
                              指定 ipfw 可执行文件路径 [默认=自动检测路径]
      --with-pf=/path/to/pfctl
                              指定 pf 可执行文件路径 [默认=自动检测路径]
      --with-ipf=/path/to/ipf 指定 ipf 可执行文件路径 [默认=自动检测路径]

    示例：

    ./configure --disable-client --with-firewalld=/bin/firewall-cmd
    ./configure --disable-client --with-iptables=/sbin/iptables --with-firewalld=no

## 说明
### 从 Perl 版 fwknop 迁移
如果你正在使用 Perl 版本并计划迁移到本版本，需要注意以下几点：

 * 基于 Perl 的 fwknop 并非所有功能都移植到了本实现。我们认为保持 C 版本
   的精简与轻量十分重要。大多数被省略的功能（如邮件告警）可以通过其他
   手段实现（即用外部脚本监控日志文件，并根据相应的日志消息告警）。

 * fwknop 的配置文件与访问文件的指令和取值存在一些差异，有些相当细微。
   请仔细阅读这些文件中的文档与注释。


### 致 fwknop 开发者
如果你是从 git 拉取本发行版，应运行 `autogen.sh` 脚本来生成 autoconf
文件。如果遇到缺少目录或文件的错误，请尝试再运行一次 `autogen.sh`。之后
当你想重新生成配置时可以运行 `autoreconf -i`。如果 autoreconf 出于某种
原因不可用，`autogen.sh` 脚本也足够了。

fwknop 与 fwknopd 手册页的 nroff 源文件包含在各自目录（client 与
server）中。这些 nroff 文件派生自 doc 目录中的 asciidoc 源文件。详见
doc 目录中的 README。
