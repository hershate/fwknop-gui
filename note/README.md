# fwknop-gui 项目笔记

> 本目录是「理解本项目」的入口笔记，面向快速建立全局认识。
> 执行级细节（逐文件改动清单、阶段验收）在 [`REF/`](../REF/) 下，本文档做概要并交叉引用。

## 一句话

本仓库是 **fwknop（FireWall KNock OPerator，单包授权 SPA）** 的二次开发 fork，
在上游 `mrash/fwknop@2.6.11` 基础上扩展了 **TOTP 驱动的动态端口跳变 + 设备身份绑定 + CLI 易用性**，
目标是把 fwknop 从「专家级 CLI 工具」升级为「安装即用、可隐身、可运维」的零信任访问系统。

## 笔记目录

| 文档 | 内容 |
| --- | --- |
| [01-项目总览.md](01-项目总览.md) | fwknop / SPA 是什么、与端口敲门的区别、本 fork 的定位与版本状态 |
| [02-架构与代码结构.md](02-架构与代码结构.md) | 三大组件（libfko / fwknop / fwknopd）、SPA 数据格式与加密流水线、目录树 |
| [03-二次开发增强方案.md](03-二次开发增强方案.md) | 四大净新增：TOTP 端口跳变、SPA v4 device_id、CLI 易用性、待办的零信任/UX/服务端管理易用性 |
| [04-开发进度与构建验证.md](04-开发进度与构建验证.md) | 已完成/待办状态、构建与验证方法、关键不变量、提交规范 |
| [05-Windows便携版托盘.md](05-Windows便携版托盘.md) | Windows 便携版托盘程序（子进程调用 fwknop.exe 真实敲门） |

## 关键事实速查

- **上游**：`mrash/fwknop`，基线版本 `2.6.11`（见 [VERSION](../VERSION)、[configure.ac](../configure.ac)）。
- **协议版本**：`FKO_PROTOCOL_VERSION` 由上游 `3.0.0` 升级为 **`4.0.0`**（[lib/fko.h:56](../lib/fko.h#L56)）。
- **客户端版本号**：仍是 `2.6.11`（`fwknop client 2.6.11, FKO protocol version 4.0.0`）。
- **已完成并验证**（Windows / MinGW）：阶段 1（TOTP+端口跳变）、阶段 3（v4 device_id）、阶段 5（CLI 易用性）、**Windows 便携版托盘程序**（[client/tray/](../client/tray/)）。
- **待办**（需 Linux）：阶段 2（服务端 NFQ 范围监听）、阶段 4（零信任硬化+审计+**服务端管理工具 `fwknopd-admin`/授权 QR/凭证文件/TOFU**）、阶段 6（测试/打包/迁移）、阶段 5+（透明代理/GUI/TUI+WebUI 管理壳/运维面板）。
- **服务端管理决策（2026-08-13）**：CLI 先行、凭证默认加密（scrypt+AES-GCM）、TOFU 指纹绑定默认启用。详见 [03-二次开发增强方案.md §6](03-二次开发增强方案.md)。
- **许可证**：GPL v2+（见 [COPYING](../COPYING)）。
- **二次开发记录**：[REF/stage.md](../REF/stage.md)（进度与 Linux 迁移交接）、[REF/plan/Port Knocking.md](../REF/plan/Port%20Knocking.md)（完整方案 v2.0）。

## 命名澄清

「fwknop-gui」这个名字容易引起误解：
- 上游有一个**独立的**跨平台 GUI 客户端 `jp-bennett/fwknop-gui`（Qt），由 Jonathan Bennett 开发，**本仓库不包含其代码**。
- 本仓库是 fwknop 的 **C 核心**（libfko + fwknop 客户端 + fwknopd 服务端）+ 作者的二次开发扩展。
