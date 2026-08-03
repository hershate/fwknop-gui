fwknop SPA 便携版 — Windows 托盘敲门客户端
==================================================

【这是什么】
基于 fwknop 单包授权（SPA）的 Windows 便携版端口敲门工具。
运行后在系统托盘显示彩色圆形图标，右键即可对已配置的服务器发起
端口敲门（SPA v4 协议：TOTP 动态目的端口跳变 + device_id 设备身份绑定）。

【便携包内容】
  fwknop-tray.exe   托盘程序（双击运行，本程序不依赖 libfko）
  fwknop.exe        fwknop 敲门客户端（被托盘程序调用，无需单独运行）

  便携：解压到任意目录即可，无需安装，不写注册表。

【快速开始】
1. 解压到任意目录。
2. 双击 fwknop-tray.exe，系统托盘出现彩色圆图标：
     绿色 = 空闲
     黄色 = 敲门中
     红色 = 上次敲门失败
3. 右键托盘图标 → “Setup (配置向导)…”，按提示生成 Rijndael/HMAC 密钥、
   TOTP 种子与设备指纹，结果写入：
     %USERPROFILE%\.fwknoprc
   同时终端会打印对应的服务端 access.conf 片段（粘贴到 Linux 端 fwknopd）。
4. 右键托盘图标 → 选择你的 profile（例如 [prod-ssh]）→ 自动发起敲门。
   托盘程序调用：fwknop.exe -n <profile> -R
5. 敲门结果以气泡通知显示；“状态…” 可查看完整输出。

【右键菜单说明】
  <profile 列表>     点击即发起敲门
  Setup (配置向导)…  交互式生成密钥/种子/指纹 + otpauth
  Lint (检查配置)    校验 .fwknoprc 各 stanza 完整性
  编辑 .fwknoprc     用记事本打开配置
  重新加载 profile   修改配置后刷新菜单
  状态…              查看最近一次敲门输出
  关于 / 退出

【配置文件位置】
  %USERPROFILE%\.fwknoprc     （即 C:\Users\<你>\.fwknoprc）

【从源码构建】（需要 MinGW-w64 GCC + windres + ar）
  cd client/tray
  make              # 构建 build/fwknop-tray.exe + build/fwknop.exe
  make portable     # 打包到 dist/fwknop-portable/

【注意事项】
- fwknop.exe 必须与 fwknop-tray.exe 放在同一目录。
- 客户端与服务端时钟需基本同步（TOTP 步长 30s）。
- “真正开门”还需服务端运行 fwknopd 并监听对应端口范围
  （服务端范围监听 / 指纹校验属进行中的阶段 2/4）。
- 单实例运行：重复启动会自动退出。

License: GPL v2 or later（与 fwknop 一致）。
