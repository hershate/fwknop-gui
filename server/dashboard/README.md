# fwknop-dashboard — fwknopd 运维面板（WebUI，阶段 5+）

轻量级 Web 运维面板，可视化阶段 4b 产出的结构化审计日志与 Prometheus 指标
（`<run_dir>/fwknopd_audit.log` 与 `fwknopd.metrics`），展示授权与 TOFU 绑定状态，
并把管理操作全部包装在 `fwknopd-admin` CLI（阶段 4c）之上——密钥生成与配置修改的
唯一权威来源始终是 `fwknopd-admin`，面板只做「视图 + 薄壳」。

界面为单页中文 UI（`go:embed` 内嵌，无任何外部依赖），整个面板编译为**单个
自包含二进制**。

**2.4.0 起面板强制鉴权**：首次启动须先完成初始化（设置管理员密码），之后凭
密码登录才能使用任何 API——不存在未认证即可管理的模式。

设计依据：`REF/plan/Port Knocking.md` §7.4/§7.6。

## 构建

```bash
cd server/dashboard
go build -o fwknop-dashboard .
```

需要 Go 1.21+（仅用标准库 `net/http` + `embed`，零第三方依赖）。

## 运行

```bash
# 常规方式：首次打开页面时按向导设置管理员密码
./fwknop-dashboard -run-dir /var/run/fwknop -addr 127.0.0.1:8088

# 启用管理写操作（签发/撤销/解绑/配置编辑/服务控制）
./fwknop-dashboard -run-dir /var/run/fwknop -enable-write

# 无头/CI 场景：用令牌代替密码初始化（Bearer 对全部 API 有效）
DASHBOARD_TOKEN=<随机长令牌> ./fwknop-dashboard \
    -run-dir /var/run/fwknop -enable-write
```

然后打开 http://127.0.0.1:8088 。

### 首次启动初始化

未设置 `DASHBOARD_TOKEN` 且不存在认证文件时，面板进入**初始化模式**：
除 `/api/auth/state`、`/api/setup`、`/api/login`、`/api/logout` 与静态页外，
所有 API 一律返回 `401 {"needs_setup":true}`。打开页面会显示初始化向导，
设置管理员密码（至少 8 位）后自动登录。

密码以 PBKDF2-HMAC-SHA256（10 万轮、16 字节随机盐）散列后存入
`<run-dir>/dashboard_auth.json`（权限 0600，原子落盘）；面板任何路径都不会
输出密码或其散列。如需重置密码，删除该文件并重启面板即可重新初始化。

### 登录与会话

- 登录成功后签发服务端会话：32 字节随机令牌，写入 `HttpOnly` +
  `SameSite=Strict` Cookie（TLS 下追加 `Secure`），有效期 12 小时。
- 登录按客户端 IP 限流：5 分钟内失败 5 次锁定 60 秒（HTTP 429）。
- Cookie 会话发起的写操作必须携带 `X-Fwknop-Request: 1` 自定义头（防 CSRF，
  前端已自动附带）；`Authorization: Bearer` 凭证不经过浏览器，豁免该检查。
- 登录时也接受 `DASHBOARD_TOKEN` 的值作为凭证（便于无头部署的操作者进入界面）。

### 完整参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-run-dir` | `/var/run/fwknop` | fwknopd 运行目录（审计/指标/TOFU 状态/认证文件所在） |
| `-addr` | `127.0.0.1:8088` | 监听地址 |
| `-admin` | `fwknopd-admin` | fwknopd-admin 可执行文件路径 |
| `-fwknopd` | `fwknopd` | fwknopd 可执行文件路径（服务控制 / 配置预检） |
| `-access-conf` | `/etc/fwknop/access.conf` | 授权配置（界面中密钥一律掩码显示） |
| `-fwknopd-conf` | `/etc/fwknop/fwknopd.conf` | 服务配置（配置页数据源） |
| `-pid-file` | `/var/run/fwknop/fwknopd.pid` | PID 文件（进程探测 / 停止 / SIGHUP） |
| `-profile-dir` | `<run-dir>/profiles` | 配置方案存放目录 |
| `-enable-write` | 关 | 启用写操作（签发/撤销/解绑/配置编辑/服务控制） |

环境变量 `DASHBOARD_TOKEN`：设置后跳过密码初始化要求，作为 Bearer 凭证
对全部 `/api` 有效（面向无头/CI；浏览器登录也可用该值作为密码）。

## 页面与功能

| 页面 | 内容 |
| --- | --- |
| **概览** | **服务控制**（启动[强制预检]/停止/重启/热加载/校验配置/防火墙规则查看）、进程状态与启动时间、审计/指标文件新鲜度；8 类事件计数卡 + 迷你趋势图；放行率/拦截率/最近事件汇总 |
| **SPA 事件** | 最近 500 条审计事件：类型筛选（带计数）、全文搜索、分页、相对时间；**审计日志导出**（JSONL） |
| **用户与授权** | stanza 卡片列表（密钥掩码）；签发新凭证（全选项）；**stanza 在线编辑**（仅非密钥指令，预检+备份+热加载）；撤销授权；**已禁用授权一键恢复** |
| **TOFU 绑定** | 结构化绑定列表，复制指纹、解绑 |
| **服务配置** | fwknopd.conf 生效指令分组中文解读；**结构化编辑器**（增/改/删、Y/N 开关、指令补全）与**原文编辑**，保存前预检+备份+热加载 |
| **配置方案** | 当前配置快照保存为命名方案；预览（密钥掩码）；**一键应用**（校验方案→备份当前→替换→热加载）；删除 |
| **关于** | 版本、文件路径、安全说明 |

UX 细节：明/暗主题切换（记忆）、自动刷新（3/5/10/30 秒，标签页隐藏时自动暂停）、
骨架屏加载、空状态引导、toast 反馈、危险操作二次确认、连接状态指示、
只读模式自动隐藏管理控件、移动端适配。

## API

| 端点 | 方法 | 认证 | 说明 |
| --- | --- | --- | --- |
| `/api/auth/state` | GET | 公开 | 初始化/登录状态（前端据此切换向导/登录页/主界面） |
| `/api/setup` | POST | 公开 | 首次初始化设置管理员密码（已初始化返回 409） |
| `/api/login` | POST | 公开 | 管理员密码登录（按 IP 限流：5 次/5 分钟 → 锁 60 秒） |
| `/api/logout` | POST | 公开 | 注销当前会话 |
| `/api/overview` | GET | 登录 | 服务/文件/管理工具状态汇总 |
| `/api/metrics` | GET | 登录 | 解析后的 Prometheus 计数器 |
| `/api/events` | GET | 登录 | 最近 500 条审计事件（新→旧） |
| `/api/audit/download` | GET | 登录 | 审计日志下载（JSONL） |
| `/api/tofu` | GET | 登录 | 结构化 TOFU 绑定 |
| `/api/users` | GET | 登录 | access.conf stanza 列表（密钥掩码）+ 已禁用授权 |
| `/api/config` | GET | 登录 | fwknopd.conf 生效指令 + 原文 |
| `/api/admin/add` | POST | 登录+写+CSRF | 包装 `fwknopd-admin user add`（全选项） |
| `/api/admin/rm` | POST | 登录+写+CSRF | 包装 `fwknopd-admin user rm`（撤销授权） |
| `/api/admin/tofu/unbind` | POST | 登录+写+CSRF | 包装 `fwknopd-admin tofu unbind` |
| `/api/service/validate` | POST | 登录+写+CSRF | 配置预检（`--exit-parse-config`） |
| `/api/service/start` `stop` `restart` `reload` | POST | 登录+写+CSRF | 服务控制 |
| `/api/service/fwrules` | GET | 登录 | 活动防火墙规则（`--fw-list`） |
| `/api/config/fwknopd` | POST | 登录+写+CSRF | 保存 fwknopd.conf（structured / raw，预检+备份+热加载） |
| `/api/config/stanza` | POST | 登录+写+CSRF | 编辑 stanza 非密钥指令 |
| `/api/config/stanza/enable` | POST | 登录+写+CSRF | 恢复被禁用的授权 |
| `/api/profiles` | GET | 登录 | 配置方案列表 |
| `/api/profiles/view` | GET | 登录 | 方案预览（密钥掩码） |
| `/api/profiles/save` `apply` `delete` | POST | 登录+写+CSRF | 方案保存 / 一键应用 / 删除 |

「登录」= 会话 Cookie 或 `Authorization: Bearer $DASHBOARD_TOKEN`；「写」=
启动时加 `-enable-write`；「CSRF」= Cookie 会话须带 `X-Fwknop-Request: 1`
（Bearer 豁免）。

## 安全说明

- **强制鉴权**：未初始化时所有 API 返回 401 要求先设置管理员密码；初始化后
  所有 API 要求会话登录（或 `DASHBOARD_TOKEN` Bearer）。密码以
  PBKDF2-HMAC-SHA256（10 万轮）存储，登录限流（5 次/5 分钟 → 锁 60 秒）。
- **默认仅监听 localhost**；暴露到不受信网络时请置于 TLS 反向代理之后
  （TLS 下会话 Cookie 自动加 `Secure` 属性）。
- 写操作默认关闭，需显式 `-enable-write`；Cookie 会话的写操作另需
  `X-Fwknop-Request: 1` 自定义头，配合 `SameSite=Strict` Cookie 抵御 CSRF。
- 面板**不读取密钥原文**：access.conf 解析只记录「是否配置」布尔值，方案预览中密钥一律掩码；stanza 在线编辑在服务端强校验拒绝密钥字段。
- 所有配置落盘都遵循 **预检（fwknopd --exit-parse-config）→ 备份（`.bak-时间戳`）→ 原子替换 → SIGHUP 热加载**；服务启动/重启强制预检，预检失败拒绝执行。
- 撤销/解绑/方案切换均为**可恢复**操作（自动备份）。
- 外部命令全部以参数数组执行（不经过 shell）；方案名白名单正则校验（防路径穿越）。
- 所有响应带 `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`。

## 测试

由 `test/run_fork_tests.sh` 覆盖：构建、全部 API 探针、未认证/未初始化 401、
初始化向导（短密码/不一致/成功/重复 409）、会话 Cookie 访问、CSRF 403 与
放行、注销失效、重新登录、登录限流 429、签发→列表→编辑→撤销→恢复、
TOFU 解绑、配置保存（含坏配置拒绝）、方案保存/预览/应用/删除全链路
（针对样例数据，无需 root）。
