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

## 性能专项报告

- [report/perf/R0-baseline.md](report/perf/R0-baseline.md) — 性能基线（C/Go 双侧，方法与判读）
- [report/perf/R1-b64-sha.md](report/perf/R1-b64-sha.md) — 基础算子：base64 位打包 + SHA-256 展开（验包 2.8×）
- [report/perf/R2-urandom-fd.md](report/perf/R2-urandom-fd.md) — urandom fd 缓存（产包累计 3.4×）
- [report/perf/R3-cache.md](report/perf/R3-cache.md) — dashboard 轮询热路径 mtime 缓存（稳态 18~23×）
- [report/perf/R4-http-gzip-etag.md](report/perf/R4-http-gzip-etag.md) — 页面预压缩 + 强 ETag（首载 1/3，重复访问 304）
- [report/perf/R5-oplog.md](report/perf/R5-oplog.md) — 操作日志读尾缓存（~132×，登录/轮询路径）
- [report/perf/R6-audit-cold.md](report/perf/R6-audit-cold.md) — 审计尾读冷启动窗口化（16.3×，成本与日志体积解耦）

## 安全审计报告

- [report/security-audit-2026-09-05.md](report/security-audit-2026-09-05.md) — 网络暴露面五轮安全/稳定性审计（3 类 9 项修复 + 掩码红线测试固化）

## 发版说明

- [release/2.9.1.md](release/2.9.1.md) — WebUI 2.9.1：一键体检成熟化（7→14 项+钻取闭环+可信度工程）+ 后端解析层修复，42 项提交，回归 124 PASS（2026-08-25）

- [release/2.9.0.md](release/2.9.0.md) — WebUI UX 第七批：排障定位闭环 + 方案迁移闭环 + 一键体检，80 项提交（2026-08-24）
- [release/2.8.0.md](release/2.8.0.md) — WebUI UX 第六批：凭证分发与排查效率主题，100 项提交（2026-08-24）
- [release/2.7.0.md](release/2.7.0.md) — WebUI UX 第五批：操作日志轮转、审计链路批查等 39 项提交（2026-08-24）
- [release/2.6.0.md](release/2.6.0.md) — WebUI UX 第四批：「重发 URI」等 44 项提交，回归升至 115 PASS（2026-08-23）
- [release/2.5.0.md](release/2.5.0.md) — WebUI UX 第三批：侧栏徽标预警、键盘闭环、搜索语法升级（2026-08-23）
- [release/2.4.9.md](release/2.4.9.md) — WebUI UX 第二批：排查现场可分享/可还原等 50 项迭代（2026-08-23）
- [release/2.4.8.md](release/2.4.8.md) — 自助改密 + 键盘流贯通 + 可见性打磨（2026-08-23）
- [release/2.4.7.md](release/2.4.7.md) — 跨配置一致性校验 + 反查闭环 + 可访问性补齐（2026-08-23）
- [release/2.4.6.md](release/2.4.6.md) — 批量操作与一致性打磨（2026-08-23）
- [release/2.4.5.md](release/2.4.5.md) — 审计备份生命周期 + 排查效率 + 安全硬化（2026-08-23）
- [release/2.4.4.md](release/2.4.4.md) — 可访问性补齐 + 失败态兜底 + 效率微交互（2026-08-23）
- [release/2.4.3.md](release/2.4.3.md) — 一键签发即生效 + 体验持续打磨（2026-08-23）
- [release/2.4.2.md](release/2.4.2.md) — WebUI 体验深化（约 60 项迭代汇总）（2026-08-23）
- [release/2.4.1.md](release/2.4.1.md) — WebUI 默认管理模式（写操作默认开启）（2026-08-23）
- [release/2.4.0.md](release/2.4.0.md) — WebUI 首次启动初始化与强制鉴权（2026-08-23）
- [release/2.3.0.md](release/2.3.0.md) — WebUI 全功能化：服务控制 / 可视化配置编辑 / 方案一键切换（2026-08-23）
- [release/2.2.0.md](release/2.2.0.md) — WebUI 全面重设计（汉化）+ 服务端管理闭环（2026-08-23）
- [release/2.1.0.md](release/2.1.0.md) — 零信任硬化 + 服务端管理易用性（阶段 2/4/6，2026-08-13）

## 关键事实速查

- **上游**：`mrash/fwknop`，基线版本 `2.6.11`（见 [VERSION](../VERSION)、[configure.ac](../configure.ac)）。
- **协议版本**：`FKO_PROTOCOL_VERSION` 由上游 `3.0.0` 升级为 **`4.0.0`**（[lib/fko.h:56](../lib/fko.h#L56)）。
- **客户端版本号**：仍是 `2.6.11`（`fwknop client 2.6.11, FKO protocol version 4.0.0`）。
- **已完成并验证**（Windows / MinGW）：阶段 1（TOTP+端口跳变）、阶段 3（v4 device_id）、阶段 5（CLI 易用性）、**Windows 便携版托盘程序**（[client/tray/](../client/tray/)）。
- **已完成并验证**（Linux）：阶段 2（服务端范围监听）、阶段 4（零信任硬化+审计+`fwknopd-admin` 全命令集/授权 QR/凭证文件/TOFU）、阶段 6 测试（`test/run_fork_tests.sh` **124/124 PASS**）、阶段 5+ 的 **WebUI 运维面板（当前 2.9.1：服务启停/配置可视化编辑/方案一键切换/签发闭环/一键体检 14 项，完全汉化）** 与 TUI 壳。
- **待办**：透明代理 / Qt GUI（大型 greenfield）、打包与迁移文档。
- **服务端管理决策（2026-08-13）**：CLI 先行、凭证默认加密（scrypt+AES-GCM）、TOFU 指纹绑定默认启用。详见 [03-二次开发增强方案.md §6](03-二次开发增强方案.md)。
- **许可证**：GPL v2+（见 [COPYING](../COPYING)）。
- **二次开发记录**：[REF/stage.md](../REF/stage.md)（进度与 Linux 迁移交接）、[REF/plan/Port Knocking.md](../REF/plan/Port%20Knocking.md)（完整方案 v2.0）。

## 命名澄清

「fwknop-gui」这个名字容易引起误解：
- 上游有一个**独立的**跨平台 GUI 客户端 `jp-bennett/fwknop-gui`（Qt），由 Jonathan Bennett 开发，**本仓库不包含其代码**。
- 本仓库是 fwknop 的 **C 核心**（libfko + fwknop 客户端 + fwknopd 服务端）+ 作者的二次开发扩展。
