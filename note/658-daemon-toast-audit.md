# 658 轮排查结论备忘：写操作「热加载」文案全量审计（已实施）

> 状态：✅ 已实施（commit `6e1def31`，2026-08-24）：配置保存 toast 按
> `r.output` 中 sighupBestEffort 实报分态，回归 115/115 PASS。
> 可选升级项（657 签发 toast 改 output 判定）未做——批量路径仍用轮询态，非必须。

## 审计方法

对 index.html 全部「热加载」出现点逐条分类（结果承诺 vs 功能描述），
并核服务端 output 文案真实性。教训：657 轮排查时 `head -10` 截断导致
漏看 7967——全量审计不得截断。

## 核心发现：服务端 sighupBestEffort 本就诚实（confedit.go:63）

```go
func sighupBestEffort() string {
	if pid, err := readPID(); err == nil && procAlive(pid) {
		if out, err := serviceReload(); err == nil { return out }
	}
	return "fwknopd 未在运行，配置将在下次启动时生效"
}
```

调用点（output 均含实报文案）：confedit.go:116/237/309/359/559/735
（appendStanza、updateStanza、enableStanza、saveFwknopdConf、
applyProfile、restoreConfigBackup）——这些路径的 r.output 可直接
` /未在运行/.test(r.output) ` 判定，比 657 用的 S.overview 轮询态
**更精确**（无轮询滞后）且与输出区文案一致。

## 失实清单（结果承诺类，需修）

| # | 位置 | 现状 | 修法 |
|---|------|------|------|
| 1 | index.html:7967 配置保存成功 | `toast('配置已保存并热加载','ok')` | 据 `r.output` 实报分态（见下定稿） |
| 2 | 657 已修的签发 toast（5620） | 用 S.overview 轮询态判定 | 可升级为 output 实报（appendStanza msg 含 sighupBestEffort，confedit.go:309）——一致性好但非必须 |

## 已证无失实（勿再评估）

- 恢复备份 infoModal：r.output 含 sighupBestEffort 实报 ✓
- serviceReload 成功文案（service.go:119）：能发 SIGHUP 即活进程，真实 ✓
- 撤销 toast（4424）/ 恢复授权 toast（4393）/ stanza 保存「授权已更新」：无热加载承诺 ✓
- 按钮 title / 确认框流程说明类 15+ 处（725/831/949/955/1022/1032/1037/
  1039/1131/4185/4215/4387/4466/6434/6457/6460/6955/7114/7128/7896/8080/
  8153/8154）：操作前预期描述，非结果承诺，失真度低——不做全面分态（过度工程）

## 实施定稿（配置保存 toast，index.html:7967）

```js
else {
  /* 「并热加载」以服务端 output 实报为准：sighupBestEffort 在 fwknopd 未运行时
     返回「未在运行，配置将在下次启动时生效」——toast 摘要同步分态，避免与
     下方输出区（conf-save-out）的实报文案自相矛盾 */
  const reloadDead = /未在运行/.test(r.output || '');
  toast(reloadDead ? '配置已保存；fwknopd 未在运行，新配置将在服务启动后生效'
                   : '配置已保存并热加载', reloadDead ? 'warn' : 'ok');
  clearConfDirty();
  ...（其余原样）
}
```

可选升级（657 签发 toast 同改 output 判定，单签 r.output 含 [面板] 前缀
+ sighup 实报；批量路径 oks 逐份 output 未汇总展示，保留轮询态即可）。

## 流水线（实施时照旧）

符号断言 + 括号平衡基线 `{'()':0,'{}':3,'[]':0}` + HTML 配对 +
`/home/fwknop/fwknop-gui/test/run_fork_tests.sh`（基线 115/115）+
无 co-author 细粒度提交。
