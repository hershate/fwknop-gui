# AGENTS.md — 本仓库的代理协作规则

任何 AI 代理/助手在本仓库工作时的硬规则（与全局层规则一致，此处入库以便跨工具生效）：

1. **禁止编造、虚构**；所有引用附完整链接。
2. **指令有歧义必须询问**，不得猜测；无法决定直接问，禁止过度思考。
3. **git**：任何阶段操作后细粒度 commit；**严禁 co-author/协作者**（除非用户显式允许）；必要时建分支保护主分支，分支稳定后合并。
4. **版本与文档**：版本号随改动更新（当前见 `VERSION` / dashboard `version` 常量）；要点写入 `note/`，性能报告写入 `note/report/perf/`，版本改动写入 `note/release/<版本号>.md`。
5. **Release**：大版本更新或分支合并后用 gh 发布，Tag=版本号，描述精简专业，附件为已编译产物。
6. **临时文件**：测试用的临时目录/文件收尾必须清理。
7. **纯文字模型**：禁止读取图片等多模态内容。

## 本仓库补充要点

- 提交信息风格沿用历史：`type(scope): 中文摘要`（fix/perf/test/docs/feat）。
- 构建：`./autogen.sh && ./configure && make`（面板：`cd server/dashboard && go build`）。
- 性能基准：`benchmark/run_bench.sh`（改动 lib/ 或 dashboard 解析层后必跑对比）。
