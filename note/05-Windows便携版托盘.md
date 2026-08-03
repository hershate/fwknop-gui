# 05 · Windows 便携版托盘程序

> 对应目标：便携版启动出现托盘图标表示运行状态、右键菜单、Windows 上真正端口敲门。
> 源码在 [client/tray/](../client/tray/)，构建产物 `fwknop-tray.exe` + `fwknop.exe`。

## 1. 目标与方案

需求拆解为三件事，对应实现：

| 需求 | 实现 |
| --- | --- |
| 便携版启动后出现托盘图标表示运行状态 | 纯 Win32 API 托盘程序（`Shell_NotifyIconW`）；图标颜色随状态变化（绿=空闲 / 黄=敲门中 / 红=失败） |
| 对应的右键菜单 | `TrackPopupMenu`：动态列出 `~/.fwknoprc` profile + Setup/Lint/编辑rc/重载/状态/关于/退出 |
| Windows 上真正端口敲门 | 托盘程序调用同目录 `fwknop.exe -n <profile> -R` 发送真实 v4 SPA 包（含 TOTP 端口跳变 + device_id） |

### 关键架构决策：子进程调用而非内嵌 libfko

客户端核心构造函数（`set_message_type`/`get_keys`/`get_totp_port` 等）都是 `static`，封装在 [client/fwknop.c](../client/fwknop.c) 的 `main` 里。提取为公开 API 需重构且风险高。因此托盘程序选择**子进程调用随附的 `fwknop.exe`**——零侵入已验证的客户端代码，敲门逻辑（v4 编码、TOTP 端口、发送）全部复用，托盘程序只负责 UI 与状态。

- 便携包 = 文件夹（`fwknop-tray.exe` + `fwknop.exe`），解压即用。
- 单 exe（内嵌 libfko）为后续可选优化。

## 2. 文件清单

| 文件 | 作用 |
| --- | --- |
| [client/tray/fwknop-tray.c](../client/tray/fwknop-tray.c) | 托盘 GUI 主程序（Win32 API，`-mwindows`，约 600 行） |
| [client/tray/tray.rc](../client/tray/tray.rc) | 资源文件：嵌入 manifest |
| [client/tray/tray.manifest](../client/tray/tray.manifest) | Common Controls v6（现代主题）+ DPI 感知 + asInvoker |
| [client/tray/Makefile](../client/tray/Makefile) | MinGW 构建：libfko.a → fwknop.exe + fwknop-tray.exe + 便携包 |
| [client/tray/README-tray.txt](../client/tray/README-tray.txt) | 面向最终用户的使用说明 |

## 3. 设计要点

- **图标运行时生成**：`make_icon(COLORREF)` 用 `CreateIconIndirect`（mask 决定圆形形状、color 决定颜色）生成三色图标，**无需携带 .ico 二进制资源**，便携且状态可变。
- **异步敲门**：`_beginthreadex` 起 `knock_thread`，`CreateProcessW(CREATE_NO_WINDOW)` + 管道捕获 stdout/stderr，`PostMessage(WM_KNOCK_DONE, exit_code)` 回主线程，UI 不阻塞；30s 超时保护（防 resolve 卡死）。
- **状态反馈**：`Shell_NotifyIconW(NIF_INFO)` 气泡通知 + 图标颜色切换 + 「状态」对话框存最近输出。
- **单实例**：命名 mutex `fwknop-tray-singleton`。
- **explorer 重启恢复**：注册 `TaskbarCreated` 消息，收到后 `NIM_ADD` 重建图标。
- **DPI 感知**：manifest + `SetProcessDPIAware()`，高分辨率下图标清晰。
- **路径便携**：`GetModuleFileName` 取 tray.exe 目录拼 fwknop.exe；rc 路径用 `%USERPROFILE%\.fwknoprc`。

## 4. 构建与验证结果（MinGW GCC 15.2.0）

构建命令：`make -C client/tray all`（产物在 `client/tray/build/`）。

验证结果：
- ✅ `fwknop-tray.exe`（27KB，PE32+ GUI x86-64）启动并驻留（PID 检测通过），`Shell_NotifyIconW(NIM_ADD)` 成功——托盘图标实际出现。
- ✅ `fwknop.exe --version` → `fwknop client 2.6.11, FKO protocol version 4.0.0`。
- ✅ v4 包构造（`--rc-file REF/build/test.fwknoprc -n good -T`）：`FKO Version: 4.0.0`，末字段 `ZnBmcGZwZnA` = base64("fpfpfpfp") = device_id 正确编码。
- ✅ tray 路径解析正确（启动时定位同目录 fwknop.exe）。

> 端到端「真正开门」需 Linux 端 fwknopd（服务端范围监听属阶段 2，进行中）；客户端侧 v4 敲门链路已验证。

## 5. 顺带修复：win32 VS 工程文件

阶段 1/3/5 新增源文件此前**未纳入 VS 工程**（VS 工程在阶段开发前建立，之后未更新；阶段验证都靠 MinGW 手工编译）。本次补齐：
- [win32/libfko.vcxproj](../win32/libfko.vcxproj)：加 `fko_totp.c`/`fko_device_id.c`/`fko_fingerprint.c` 及头文件。
- [win32/fwknop-client.vcxproj](../win32/fwknop-client.vcxproj)：加 `wizard.c`/`cli_subcmds.c` 及头文件。

修复后 VS 也能编译出带 v4 能力的 libfko 与 fwknop.exe（与 MinGW 产物等价）。

## 6. 已知限制 / 后续

- 便携包为双 exe（tray + fwknop）。单 exe 内嵌 libfko 可后续做（需把客户端 static 构造函数重构为可复用入口）。
- 敲门调用 `-R` 会解析外网 IP（HTTPS），离线时该步失败；可用固定 `ALLOW_IP` 规避。
- 透明自动敲门、GUI 配置管理属阶段 5+（greenfield），见 [03-二次开发增强方案.md §5](03-二次开发增强方案.md)。
