# 项目交接文档（更新于 2026-07-31）

本文件用于在新的对话窗口继续 **AI 网络安全检测、验证与治理平台**。它替代此前已过期的交接内容；项目需求应以用户重新提供的原始 `01.pptx`、`README.md` 和本文件共同判断，不能只依赖旧对话记录。

## 1. 交接起点与协作规则

- 正式仓库：`D:\project\PYproject\AI网安项目`
- GitHub：`https://github.com/hezia1/01AIproject.git`
- 分支：`main`
- 旧目录 `C:\Users\hezia\Documents\AI网络安全项目` 不再是工作仓库，不应在其中修改代码。
- 新窗口先读取 `README.md` 与本文档，再执行：

```powershell
Set-Location 'D:\project\PYproject\AI网安项目'
git status --short --branch
git log -5 --oneline
```

- 如新窗口没有原始 `01.pptx`，请用户重新上传；PPT 是功能边界和页面语义的需求来源之一。
- 通用协作规则仍是：**每次改代码前先说明准备实现的功能，取得用户确认后再修改；每次代码更新后都要提交并推送 GitHub。** 文档、只读检查和测试不属于代码修改。
- `artifacts/` 存放本地离线镜像与漏洞库，已被 Git 忽略，绝不能纳入提交。

## 2. 当前 Git 快照

本文件更新时工作区已干净，`main` 已推送至 `origin/main`。

```text
53bcaab Complete SCA governance workflow
29f2633 Add SCA exception approval panel
546f69f Expose SCA impact path type
14d3f5c Add SCA impact paths gates and HTML report
f7609d9 Add SCA policy exception workflow
f10ac63 Add SCA policy exception persistence
314b53c Complete SCA offline scanning foundations
0e72eb9 Persist SCA dependency snapshots and offline status
```

最近一次更新已验证：

```powershell
$env:PYTHONPATH='apps\api'
.\.venv\Scripts\python.exe -m compileall -q apps\api\app
.\.venv\Scripts\python.exe -m pytest apps\api\tests -q

Set-Location apps\web
npm run build
```

结果：后端 `15 passed`，前端生产构建成功。后续改动仍应运行与改动范围相称的验证。

## 3. 当前架构与重要目录

```text
AI网安项目/
├─ apps/
│  ├─ api/                         # FastAPI、服务层、Alembic 迁移、后端测试
│  │  ├─ app/routers/              # project/module/sca/sast/agent/dast/sandbox/aspm/findings API
│  │  ├─ app/services/             # 扫描、依赖图谱、证据关联、复测、报告等业务逻辑
│  │  └─ app/rules/                # 本地 SCA 漏洞与许可证规则 JSON
│  └─ web/src/                     # Vue 3 + Vite；Router、Pinia、API 与业务页面已拆分
├─ infra/docker-compose.yml        # PostgreSQL / Redis
├─ outputs/                        # SCA、SAST、AGENT 演示输入
├─ artifacts/sca-offline/          # 本地离线资源（忽略，不提交）
├─ docs/PROJECT_HANDOFF_2026-07-26.md
└─ README.md
```

运行链路：`Vue 前端 → /api → FastAPI routers → services → PostgreSQL`。`routers` 负责接口和参数，`services` 负责扫描、关联、图谱、复测和导出。2026-08-07 已完成 React → Vue 3 整体迁移，后端接口与数据库结构未改动。

## 4. 平台级已完成能力

- 项目创建、切换、资产配置与资产探测。
- “安全检测”合并模块接入与任务执行：用户自主选择 SCA、SAST、AGENT、DAST、SANDBOX，并可一键按 `SCA → SAST → AGENT → DAST → SANDBOX` 执行；单模块失败不会中断后续模块。
- PostgreSQL 持久化项目、模块、扫描批次、组件、Finding、DAST 验证、SANDBOX 证据和 SCA 例外。
- 治理总览可在综合视图和已接入模块视图间切换；多条结果统一每页 10 条、支持翻页与筛选，并将高级内容放在按需展开区。
- 显式证据链：SAST/SCA/AGENT Finding 可关联 DAST 验证与 SANDBOX 取证；只有用户明确选择，或高置信度推荐经执行确认的关联才进入证据图谱和攻击链。
- SCA、SAST、AGENT 的重扫结果可对比“仍然存在、已消失、新增、发生变化”。
- 项目安全报告预览与 JSON/HTML 导出已实现；HTML 适合演示或浏览器打印为 PDF。

平台级仍缺少：登录/权限/租户、后台任务队列和 Worker、SLA/工单、完整审计日志、完整 CI/CD 集成、合规报告体系、图数据库或 AI 图推理。

## 5. 各模块进度

### SCA：供应链风险分析（当前完成度最高）

已完成：

- 解析 `package.json`、`requirements.txt`、`pom.xml`、`go.mod` 及主流 npm/Python 锁文件，生成组件、来源、依赖类型和风险字段。
- OSV 查询可用时使用外部情报；离线或失败时明确降级为本地规则，绝不把降级结果说成完整外部情报。
- 本地漏洞规则和许可证策略；高危/严重漏洞、许可证风险和版本缺失都会进入统一 Finding 与 ASPM 闭环。
- CycloneDX、SPDX SBOM；扫描历史、批次差异、依赖图谱、升级杠杆与风险影响路径。
- npm 原生依赖树；项目内 `.venv/venv` 的 Python 已安装包和依赖关系读取。扫描快照保存依赖边，历史结论不会因环境后来变化被改写。
- Syft、Grype、Trivy 离线增强扫描；工具预检明确 Docker、镜像和离线数据库状态。
- API：政策、组件、SBOM、依赖图、历史、差异、JSON/HTML 报告、门禁、例外审批均已实现。
- 前端高级供应链分析已展示：工具预检、扫描历史、SBOM/报告导出、本地策略、风险例外审批、依赖图与风险影响路径。
- 例外必须从当前风险组件中选择；可记录理由、申请人、失效日期，支持批准/拒绝/撤销。批准且未到期的例外在**下一次扫描**标为“已接受风险”，但不会删除原始漏洞证据；门禁会忽略该已接受风险。

当前不需要额外下载即可继续的 SCA 核心工作已完成。暂缓/未完成项：

- Maven、Go 的完整原生依赖环境与更多生态的真实包文件哈希。
- OSV 本地镜像、组织级策略编辑/启停与多级审批权限。
- 更深层影响分析、CI 流水线的实际调用与门禁编排。

离线资源现状（均在本地、被 Git 忽略）：

```text
artifacts/sca-offline/
├─ images/          # syft.tar、grype.tar、trivy.tar
├─ grype-cache/     # 已导入 Grype 离线漏洞库
└─ trivy-cache/     # trivy.db 与 trivy-java.db
```

不要删除或提交它们。若将来在新沙箱使用，需将整个 `artifacts/sca-offline` 一并带入，并先在 Docker 中加载镜像 tar。

关键文件：

- `apps/api/app/routers/sca.py`
- `apps/api/app/services/sca_parser.py`
- `apps/api/app/services/sca_dependency_graph.py`
- `apps/api/app/services/sca_native_tree.py`
- `apps/api/app/services/sca_python_environment.py`
- `apps/api/app/services/sca_tool_scanner.py`
- `apps/api/app/services/sca_artifacts.py`
- `apps/api/app/rules/sca_vulnerability_rules.json`
- `apps/api/app/rules/sca_license_policies.json`

### SAST：智能静态审计

已完成：本地规则扫描（密钥、危险命令、动态执行、SQL 拼接、SSRF、路径穿越、弱加密、反序列化等）、Semgrep CLI/Docker 兜底、Finding 持久化、规则化复核流水线（`scanner_agent`、`review_agent`、`evidence_agent`、`fix_agent`）与前端筛选/分页/复测展示。

重要边界：当前所谓 sub-agent 是**规则化的本地编排，不是真实外部 AI Agent**；不会调用大模型自动修复。

待完成：已知 `Failed to fetch` 问题排查、稳定 Semgrep 配置与镜像管理、自定义规则管理、AST/数据流/污点分析、真实 AI 复核、补丁生成，以及与 DAST/SANDBOX 的自动化联动。

### AGENT：Agent 供应链安全

已完成：扫描 `.md/.yaml/.yml/.json/.toml`、`AGENTS.md`、`CLAUDE.md`、`mcp.json`、`plugin.json` 等配置/说明文件；识别环境变量和密钥读取、Shell、文件写删、外部请求、宽松 MCP 权限和提示词安全覆盖等风险；支持 Finding、分类、修复建议和前端结果页。

待完成：不运行真实 Agent、不连接真实 MCP、不调用插件工具；没有完整权限矩阵、行为回放或外部 AI 信任评分。

### DAST：漏洞动态验证

已完成：围绕选定的 SAST/SCA/AGENT 风险做轻量 Web 基础验证，持久化目标、策略、范围、限制、请求响应、三色裁决和修复提示；未关联的 URL 检查会明确标为基础检查，不进入漏洞证据链。支持关联建议，但建议只有随执行确认才落库。

重要边界：不是 SQL 注入、鉴权绕过等业务漏洞的真实利用证明；未实现爬虫、登录态、payload 生成、ZAP/Nuclei、自动复现与自动复测。用户此前要求 DAST 深化后置。

### SANDBOX：沙箱动态证据链

已完成：Docker 隔离执行、禁网、只读挂载、CPU/内存/PID 限制、危险命令拦截、输出脱敏、执行时间线和结构化账本；可从 Finding 或 DAST 验证发起并形成显式证据关系。

重要边界：当前账本主要记录隔离策略和执行摘要，并非 eBPF/Sysmon 等真实文件访问、网络连接、完整进程树或工具调用探针；不支持交互式程序、复杂多步骤编排和恶意样本级强隔离。

### ASPM：治理与交付

已完成：项目风险汇总、来源/等级/状态统计、Finding 负责人/备注/截止时间、证据图谱、可信攻击链、修复复测、治理闭环、模块级结果视图、安全知识中枢第一版与项目安全报告。

待完成：CVSS/EPSS/资产暴露面进入风险分，SLA/工单/审批，登录权限和组织隔离，完整审计与 CI/CD，趋势报表，图数据库或语义推理。

## 6. 新窗口建议的第一步

1. 先按第 1 节执行只读检查，确认没有其他人新增的提交或未提交改动。
2. 读取 README、本文档和用户提供的原始 PPT；重新列出每个模块的“已完成 / 未完成 / 前端可见性”。
3. 当前优先级应在用户确认后重新决定。若不改变既有方向，建议转向 **SAST 的稳定性与真实扫描质量**，先定位并修复 `Failed to fetch`/工具链可解释性，再考虑真实 Agent 或更深扫描能力。
4. 若用户要求演示优先，先用现有 SCA 离线资源跑一次完整扫描，确认高级供应链分析中的工具预检、扫描快照、例外、影响路径和 HTML 报告均可在前端看见。

## 7. 新窗口可直接使用的提示词

```text
继续完善 D:\project\PYproject\AI网安项目。请不要依赖旧对话记录，先读取 README.md 和 docs/PROJECT_HANDOFF_2026-07-26.md，再执行 git status --short --branch 和 git log -5 --oneline 确认当前状态。

我会提供原始 01.pptx。请把 PPT、README 和交接文档共同作为需求来源，重新列出每个模块已完成、未完成，以及已实现内容是否已经在前端可见。不要直接改代码；先给出最推荐推进的模块和明确实现范围，等我确认。

规则：每次写代码前，先说明本次要实现的功能并获得我确认；每次代码更新后提交并推送 GitHub。正式仓库仅使用 D:\project\PYproject\AI网安项目，不要修改旧的 C 盘仓库。
```
