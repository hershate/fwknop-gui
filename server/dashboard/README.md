# fwknop-dashboard — fwknopd 运维面板（WebUI，阶段 5+）

轻量级 Web 运维面板，可视化阶段 4b 产出的结构化审计日志与 Prometheus 指标
（`<run_dir>/fwknopd_audit.log` 与 `fwknopd.metrics`），展示授权与 TOFU 绑定状态，
并把管理操作全部包装在 `fwknopd-admin` CLI（阶段 4c）之上——密钥生成与配置修改的
唯一权威来源始终是 `fwknopd-admin`，面板只做「视图 + 薄壳」。

界面为单页中文 UI（`go:embed` 内嵌，无任何外部依赖），整个面板编译为**单个
自包含二进制**。

设计依据：`REF/plan/Port Knocking.md` §7.4/§7.6。

## 构建

```bash
cd server/dashboard
go build -o fwknop-dashboard .
```

需要 Go 1.21+（仅用标准库 `net/http` + `embed`，零第三方依赖）。

## 运行

```bash
# 只读模式，仅监听本机（默认，推荐）
./fwknop-dashboard -run-dir /var/run/fwknop -addr 127.0.0.1:8088

# 启用管理写操作（签发/撤销/解绑），并用令牌保护
DASHBOARD_TOKEN=<随机长令牌> ./fwknop-dashboard \
    -run-dir /var/run/fwknop -enable-write
```

然后打开 http://127.0.0.1:8088 。

### 完整参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-run-dir` | `/var/run/fwknop` | fwknopd 运行目录（审计/指标/TOFU 状态文件所在） |
| `-addr` | `127.0.0.1:8088` | 监听地址 |
| `-admin` | `fwknopd-admin` | fwknopd-admin 可执行文件路径 |
| `-fwknopd` | `fwknopd` | fwknopd 可执行文件路径（服务控制 / 配置预检） |
| `-access-conf` | `/etc/fwknop/access.conf` | 授权配置（界面中密钥一律掩码显示） |
| `-fwknopd-conf` | `/etc/fwknop/fwknopd.conf` | 服务配置（配置页数据源） |
| `-pid-file` | `/var/run/fwknop/fwknopd.pid` | PID 文件（进程探测 / 停止 / SIGHUP） |
| `-profile-dir` | `<run-dir>/profiles` | 配置方案存放目录 |
| `-enable-write` | 关 | 启用写操作；设置 `DASHBOARD_TOKEN` 后需 Bearer 令牌 |

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

| 端点 | 方法 | 说明 |
| --- | --- | --- |
| `/api/overview` | GET | 服务/文件/管理工具状态汇总 |
| `/api/metrics` | GET | 解析后的 Prometheus 计数器 |
| `/api/events` | GET | 最近 500 条审计事件（新→旧） |
| `/api/audit/download` | GET | 审计日志下载（JSONL） |
| `/api/tofu` | GET | 结构化 TOFU 绑定 |
| `/api/users` | GET | access.conf stanza 列表（密钥掩码）+ 已禁用授权 |
| `/api/config` | GET | fwknopd.conf 生效指令 + 原文 |
| `/api/admin/add` | POST | 包装 `fwknopd-admin user add`（全选项） |
| `/api/admin/rm` | POST | 包装 `fwknopd-admin user rm`（撤销授权） |
| `/api/admin/tofu/unbind` | POST | 包装 `fwknopd-admin tofu unbind` |
| `/api/service/validate` | POST | 配置预检（`--exit-parse-config`） |
| `/api/service/start` `stop` `restart` `reload` | POST | 服务控制 |
| `/api/service/fwrules` | GET | 活动防火墙规则（`--fw-list`） |
| `/api/config/fwknopd` | POST | 保存 fwknopd.conf（structured / raw，预检+备份+热加载） |
| `/api/config/stanza` | POST | 编辑 stanza 非密钥指令 |
| `/api/config/stanza/enable` | POST | 恢复被禁用的授权 |
| `/api/profiles` | GET | 配置方案列表 |
| `/api/profiles/view` | GET | 方案预览（密钥掩码） |
| `/api/profiles/save` `apply` `delete` | POST | 方案保存 / 一键应用 / 删除 |

## 安全说明

- **默认仅监听 localhost**，不要直接暴露到不受信网络；远程访问请置于带认证的反向代理之后。
- 写操作默认关闭；启用后若设置 `DASHBOARD_TOKEN`，所有写端点要求 `Authorization: Bearer <token>`。
- 面板**不读取密钥原文**：access.conf 解析只记录「是否配置」布尔值，方案预览中密钥一律掩码；stanza 在线编辑在服务端强校验拒绝密钥字段。
- 所有配置落盘都遵循 **预检（fwknopd --exit-parse-config）→ 备份（`.bak-时间戳`）→ 原子替换 → SIGHUP 热加载**；服务启动/重启强制预检，预检失败拒绝执行。
- 撤销/解绑/方案切换均为**可恢复**操作（自动备份）。
- 外部命令全部以参数数组执行（不经过 shell）；方案名白名单正则校验（防路径穿越）。
- 所有响应带 `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`。

## 测试

由 `test/run_fork_tests.sh` 覆盖：构建、全部 API 探针、令牌守卫、
签发→列表→编辑→撤销→恢复、TOFU 解绑、配置保存（含坏配置拒绝）、
方案保存/预览/应用/删除全链路（针对样例数据，无需 root）。
