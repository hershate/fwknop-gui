# 审计事件链路完整性批查（2026-08-24，面板 2.6.0+）

对 fwknopd 审计写点 → 面板呈现的全链路做了一次静态批查。

## 结论：两层映射零缺口，一处上游级功能缺口

### ✅ 事件类型映射 8/8 对齐

`server/audit.h` 枚举 `audit_event_t` 与面板 `EVT_ORDER`（web/index.html:1673）一一对应：

| 枚举 | JSON "event" | 面板徽章 | 调用点 |
|---|---|---|---|
| AUDIT_OPEN | open | ✓ | incoming_spa.c:1404 |
| AUDIT_CLOSE | close | ✓ | **无（见缺口）** |
| AUDIT_REJECT | reject | ✓ | **无（见缺口）** |
| AUDIT_REPLAY | replay | ✓ | incoming_spa.c:402 |
| AUDIT_UNKNOWN_FINGERPRINT | unknown_fingerprint | ✓ | incoming_spa.c:870/895/908 |
| AUDIT_PORT_MISMATCH | port_mismatch | ✓ | incoming_spa.c:969 |
| AUDIT_AGED | aged | ✓ | incoming_spa.c:333 |
| AUDIT_TOFU_BIND | tofu_bind | ✓ | incoming_spa.c:927 |

### ✅ 原因（reason）中文映射 100% 覆盖

`reasonZh()`（web/index.html:2748）对全部 6 个静态 reason
（accepted / replay_digest_hit / fingerprint_required_but_missing /
device_id_not_in_whitelist / tofu_grace_expired / tofu_bound）及
2 个动态格式（`aged_%ds`、`arrived=%u_expected=%u`）均有映射，
与 server 侧构造（incoming_spa.c:331 `snprintf("aged_%ds")`、
:967 `snprintf("arrived=%u_expected=%u")`）逐字核对一致。

### ⚠ 缺口：AUDIT_CLOSE / AUDIT_REJECT 全代码树零调用点

- **影响**：面板事件页的 close/reject 徽章、类型芯片、筛选设施全部
  现成，但这两类事件永远不会产生。类型芯片只渲染有计数的类型
  （`EVT_ORDER.filter(e => counts[e])`），用户侧无误导呈现，故无
  前端缺陷。
- **close 的合理写点**：各防火墙后端 `check_firewall_rules()` →
  `rm_expired_rules()`（fw_util_{iptables,ipfw,ipf,pf,firewalld}.c
  五套变体）。难点：删除点只有 iptables -L 文本行可反解
  src_ip/端口，且 `chk_rm_all` 垃圾回收模式会删非 fwknopd 自加的
  规则，审计语义需区分；五后端均需改且无法在本机实测防火墙行为。
- **reject 的定性**：generic policy 兜底类型。现有拒绝路径均落具体
  类型（replay/unknown_fingerprint/port_mismatch/aged），无明确
  待补场景，可视为协议保留位。
- **建议**：列为上游级增强候选（close 事件 = 开门/关门成对呈现，
  排障「连接怎么断了」的直接答案），需独立排期与防火墙测试环境，
  不混入面板 UX 迭代。

## 方法备注

- 调用点提取：`grep -rn 'audit_log_event' server/*.c`（8 处均在
  incoming_spa.c），逐处展开多行调用的 reason 实参。
- reasonZh 映射与构造语句逐字对照（含 `%d`/`%u` 与正则 `\d+` 的对应）。
