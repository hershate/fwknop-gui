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
| `-access-conf` | `/etc/fwknop/access.conf` | 授权配置（界面中密钥一律掩码显示） |
| `-fwknopd-conf` | `/etc/fwknop/fwknopd.conf` | 服务配置（配置页数据源） |
| `-pid-file` | `/var/run/fwknop/fwknopd.pid` | PID 文件（用于探测 fwknopd 存活与 SIGHUP） |
| `-enable-write` | 关 | 启用写操作；设置 `DASHBOARD_TOKEN` 后需 Bearer 令牌 |

## 页面与功能

| 页面 | 内容 |
| --- | --- |
| **概览** | 服务进程存活（PID 探测）、审计/指标文件新鲜度、写模式、管理工具可用性；8 类事件计数卡 + 前端采样迷你趋势图；放行率/拦截率/最近事件汇总 |
| **SPA 事件** | 最近 500 条审计事件：类型筛选（带计数）、全文搜索（用户/IP/指纹/原因）、分页、相对时间（悬停看绝对时间） |
| **用户与授权** | access.conf stanza 卡片列表（密钥掩码，仅显示「已配置」）；签发新凭证（`user add` 全选项：TOTP/端口范围/指纹/TOFU 宽限期/端口匹配）；撤销授权（`user rm`，注释禁用 + 备份 + SIGHUP） |
| **TOFU 绑定** | 结构化绑定列表（设备指纹/来源/用户/端口），复制指纹、解绑（`tofu unbind`，备份 + SIGHUP） |
| **服务配置** | fwknopd.conf 生效指令按功能分组展示，附中文说明；可切换查看原文 |
| **关于** | 版本、文件路径、安全说明 |

UX 细节：明/暗主题切换（记忆）、自动刷新（3/5/10/30 秒，标签页隐藏时自动暂停）、
骨架屏加载、空状态引导、toast 反馈、危险操作二次确认、连接状态指示、移动端适配。

## API

| 端点 | 方法 | 说明 |
| --- | --- | --- |
| `/api/overview` | GET | 服务/文件/管理工具状态汇总 |
| `/api/metrics` | GET | 解析后的 Prometheus 计数器 |
| `/api/events` | GET | 最近 500 条审计事件（新→旧） |
| `/api/tofu` | GET | 结构化 TOFU 绑定 |
| `/api/users` | GET | access.conf stanza 列表（密钥掩码） |
| `/api/config` | GET | fwknopd.conf 生效指令 + 原文 |
| `/api/admin/add` | POST | 包装 `fwknopd-admin user add`（全选项） |
| `/api/admin/rm` | POST | 包装 `fwknopd-admin user rm`（撤销授权） |
| `/api/admin/tofu/unbind` | POST | 包装 `fwknopd-admin tofu unbind` |

## 安全说明

- **默认仅监听 localhost**，不要直接暴露到不受信网络；远程访问请置于带认证的反向代理之后。
- 写操作默认关闭；启用后若设置 `DASHBOARD_TOKEN`，所有写端点要求 `Authorization: Bearer <token>`。
- 面板**不读取密钥原文**：access.conf 解析只记录「是否配置」布尔值；密钥只由 `fwknopd-admin` 生成，仅在签发响应中出现一次。
- 撤销/解绑均为**可恢复**操作：改动前自动创建 `.bak-<时间戳>` 备份，并向 fwknopd 发送 SIGHUP 热加载。
- 所有响应带 `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`。

## 测试

由 `test/run_fork_tests.sh` 覆盖：构建、全部 API 探针、令牌守卫、
签发→列表→撤销→解绑写路径（针对样例数据）。
