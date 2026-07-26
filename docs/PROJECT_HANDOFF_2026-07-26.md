# 项目交接文档 2026-07-26

本文档用于在新的对话窗口继续 `AI 网络安全检测、验证与治理平台` 项目。新的对话窗口不要依赖旧对话记录，应先读取本文件、README 和用户重新发送的原始 PPT，再继续推进。

## 1. 当前仓库状态

- 本地项目路径：`D:\project\PYproject\AI网安项目`
- GitHub 仓库：`https://github.com/hezia1/01AIproject.git`
- 当前分支：`main`
- 本文档最初创建提交：`0eaf28b Add project handoff document`
- 当前最新提交应以 `git log -1 --oneline` 为准；本文档已补充 ASPM 跨模块证据关联第二版。
- 重要规则：后续继续遵守用户要求，每次写代码前先说明要实现的功能，得到确认后再修改代码；每次代码更新后同步 GitHub。

最近关键提交：

```text
bc29958 Add npm native SCA dependency tree
5238093 Add SCA toolchain health check
a9d5f43 Use Syft SBOM for Grype SCA scan
0fa9e6a Clarify SCA governance summary
e7ab384 Create findings from SCA risks
```

## 2. 新窗口需要先做的事

1. 让用户发送原始 PPT。用户会在新的对话窗口发送 README 中提到的原始 `01.pptx`，该 PPT 应作为需求来源之一。
2. 读取本交接文档和 README。
3. 执行基础检查：

```powershell
cd D:\project\PYproject\AI网安项目
git status --short --branch
git log -5 --oneline
Get-Content README.md -Encoding utf8
```

4. 对照 PPT、README、本交接文档，重新确认当前项目进度，不要只依赖旧对话记忆。

## 3. 平台级能力

### 已完成

- FastAPI 后端和 React + Vite 前端基础框架。
- 项目创建、删除、查询、切换。
- 项目资产配置：源码路径、运行地址、API 地址、沙箱命令、沙箱镜像。
- 六个模块可单独启用或停用：SCA、SAST、AGENT、DAST、SANDBOX、ASPM。
- 项目资产探测：根据源码目录识别 SCA、SAST、AGENT 可执行任务。
- 统一任务中心：可触发 SCA、SAST、AGENT、DAST、SANDBOX。
- PostgreSQL 持久化：项目、模块配置、扫描任务、组件、Finding、DAST 记录、SANDBOX 证据。
- Alembic 正式迁移基线和跨模块证据关联首个版本：`20260726_0001`。
- 前端多页面视图：项目管理、项目资产、模块接入、任务中心、SCA、SAST、AGENT、DAST、SANDBOX、ASPM。

### 还未完成

- 用户登录、权限、租户隔离。
- 扫描任务队列和后台 Worker。
- CI/CD 接入。
- 完整审计日志。
- 统一报告导出体系。

## 4. SCA 供应链风险分析

SCA 是当前推进最多的模块。新的对话建议继续围绕 SCA 收尾，除非用户要求切换模块。

### 已完成

- 解析依赖文件并生成组件清单。
- 支持：
  - `package.json`
  - `requirements.txt`
  - `pom.xml`
  - `go.mod`
  - `package-lock.json`
  - `yarn.lock`
  - `pnpm-lock.yaml`
  - `poetry.lock`
  - `Pipfile.lock`
- 组件去重、依赖类型、直接/传递依赖标记、来源文件、包管理器字段。
- 接入 OSV 漏洞库查询。
- 本地漏洞规则库第一版：
  - 独立 JSON 文件：`apps/api/app/rules/sca_vulnerability_rules.json`
  - 覆盖 npm、PyPI、Maven、Go 示例规则。
  - 支持简单版本范围：`<1.2.3`、`<=1.2.3`、`>=1.0.0,<2.0.0`。
- 许可证策略第一版：
  - 独立 JSON 文件：`apps/api/app/rules/sca_license_policies.json`
  - 归一化为 `allowed`、`review_required`、`restricted`、`unknown`。
  - 输出许可证义务说明和例外审批建议。
- SBOM 导出：
  - CycloneDX JSON 第一版。
  - SPDX 2.3 JSON 第一版。
  - CycloneDX `dependencies` 关系第一版。
  - SBOM 元数据增强：项目负责人、仓库、源码路径、运行地址、组件统计、OSV 状态等。
- 依赖边质量标注：
  - `manifest_direct`
  - `lockfile_inferred`
  - `native_tree`
- 依赖图谱：
  - 图谱 API：`GET /api/sca/projects/{project_id}/dependency-graph`
  - 前端 SVG 可视化。
  - 风险节点标注。
  - 完整图谱界面。
  - 升级杠杆分析。
- npm 原生依赖树第一版：
  - 新增服务：`apps/api/app/services/sca_native_tree.py`
  - 尝试执行 `npm ls --json --all`
  - 采集真实父子依赖边 `native_tree`
  - 图谱优先使用 `native_tree`
  - 失败时自动回退 manifest / lockfile 推断，不影响扫描成功。
- Syft / Grype Docker 镜像增强：
  - `anchore/syft:latest`
  - `anchore/grype:latest`
  - Syft 生成 CycloneDX SBOM。
  - Grype 优先使用 Syft SBOM 输入扫描。
  - Syft 失败时 Grype 回退目录扫描。
  - 记录 `grype_input`：`syft-sbom` 或 `directory`。
- SCA 工具链预检：
  - API：`GET /api/sca/tool-health`
  - 检查 Docker CLI、Docker Engine、Syft 镜像、Grype 镜像、Grype 漏洞库。
  - 前端 SCA 页面有“工具链预检”卡片。
- SCA 扫描历史：
  - 历史快照。
  - 扫描 diff。
  - 历史详情点击框。
- SCA 报告 API 第一版：
  - `GET /api/sca/projects/{project_id}/report`
- SCA 风险自动进入 ASPM：
  - 漏洞编号命中生成 `source = "SCA"` Finding。
  - 许可证风险生成 `SCA-LICENSE` Finding。
  - 版本缺失复核生成 `SCA-VERSION` Finding。
  - 高风险兜底生成 `SCA-RISK` Finding。
- ASPM 治理总览新增 SCA 供应链治理卡片：
  - 最新扫描组件数。
  - 风险组件数。
  - 漏洞组件数。
  - SCA Finding 数。
  - Syft / Grype 状态。
  - Grype 输入来源。
  - Top 风险组件。

### 重要口径说明

- SCA 组件风险清单是组件维度。
- ASPM 模块来源统计是 Finding 维度。
- 一个组件可能因为多个 CVE、许可证风险、版本复核而生成多条 Finding。
- 因此“漏洞组件数”和“SCA Finding 数”不一定相等。
- 风险组件范围大于或等于漏洞组件，包含漏洞、许可证风险、版本复核、高危组件等。

### 还未完成

- 真实组件包文件哈希采集。
- Python / Maven / Go 原生完整依赖树。
- 更深度的传递影响分析和真实父子依赖树。
- 基于图数据库或 AI 推理的深层跨模块攻击链。
- 组织级许可证策略配置、策略启停、审批流持久化、例外记录管理。
- 本地漏洞规则来源扩展、规则覆盖面、规则启停、组织级规则管理。
- Trivy 等更多专业工具接入。
- Syft / Grype 漏洞库更新时间展示和离线模式。
- 离线漏洞库缓存。
- SCA HTML / PDF 报告导出和报告模板。

### 推荐下一步

如果继续完善 SCA，推荐优先级：

1. Python 原生依赖树第一版：接入 `pipdeptree --json-tree`，图谱支持 PyPI 真实父子依赖边。
2. SCA 报告可视化页面：把现有报告 API 做成前端报告页，再考虑 HTML/PDF 导出。
3. 组件包哈希采集：对本地已安装依赖或 lockfile 记录补充包哈希、PURL、registry 来源。
4. 许可证治理页面：策略配置、例外审批记录、许可证义务展示。

## 5. SAST 智能静态审计

### 已完成

- 本地规则扫描：
  - 硬编码密钥。
  - 危险命令执行。
  - 动态代码执行。
  - SQL 拼接。
  - SSRF。
  - 路径穿越。
  - 弱加密。
  - 反序列化。
- Semgrep 接入：
  - 优先使用本机 `semgrep`。
  - 没有时尝试 Docker 镜像 `semgrep/semgrep:latest`。
- 噪声过滤：跳过构建产物、依赖目录、压缩文件等。
- SAST Finding 持久化。
- 规则化 agent 编排第一版：
  - `scanner_agent`
  - `review_agent`
  - `evidence_agent`
  - `fix_agent`
- 复核结果包含分类、语言、误报可能性、证据摘要、修复策略、优先级。
- 前端 SAST 页面展示风险列表、分类统计、严重等级统计。

### 还未完成

- 用户之前提到的 SAST `Failed to fetch` 问题暂时跳过，尚未继续处理。
- 更稳定的 Semgrep 镜像拉取和配置管理。
- 自定义规则库管理页面。
- AST / 数据流 / 污点分析。
- 外部 AI 复核接入。
- 修复补丁生成。
- 与 DAST、SANDBOX 的自动联动验证。

### 推荐后续方向

- 如果切换到 SAST，建议先处理前端 `Failed to fetch` 和 Semgrep 工具链状态可解释性，再做自定义规则库管理。

## 6. AGENT 供应链安全

### 已完成

- 扫描 Agent / MCP / 插件相关配置和说明文件。
- 支持：
  - `.md`
  - `.yaml`
  - `.yml`
  - `.json`
  - `.toml`
  - `AGENTS.md`
  - `CLAUDE.md`
  - `mcp.json`
  - `plugin.json`
- 识别风险：
  - 环境变量/密钥读取。
  - Shell 执行。
  - 文件写入/删除。
  - 外部网络请求。
  - MCP 权限过宽。
  - 提示词覆盖安全策略。
- 增强 MCP 协议配置扫描。
- 输出 Finding、风险分类、修复建议和信任影响。
- 前端 AGENT 页面支持分页、分类统计和严重等级统计。

### 还未完成

- 不运行真实 Agent。
- 不连接真实 MCP Server。
- 不执行插件工具调用。
- 不生成完整工具权限矩阵。
- 不做 Agent 行为回放。
- 不做外部 AI 驱动的信任评分。

### 推荐后续方向

- 若切换到 AGENT，建议先做工具权限矩阵和 MCP Server 实例识别，再做行为回放。

## 7. DAST 漏洞动态验证

### 已完成

- 人工 DAST 验证记录。
- 自动轻量探测第一版：
  - 对目标 URL 发起 GET 请求。
  - 检查 HTTP/HTTPS。
  - 检查状态码、响应时间、Server Header、基础安全响应头。
- 根据轻量规则生成裁决：
  - `exploitable`
  - `uncertain`
  - `not_exploitable`
- 支持项目运行地址作为默认目标。
- DAST 验证可显式关联 Finding 或 SCA 组件，关联信息包含来源与可信度。
- 前端 DAST 页面可查看验证记录。

### 还未完成

- 用户之前要求暂时跳过 DAST 深化，计划后面再做。
- 不做爬虫。
- 不生成攻击 payload。
- 不做登录态管理。
- 不接 OWASP ZAP / Nuclei。
- 不做漏洞复现链自动生成。
- 不做自动复测。

### 推荐后续方向

- 若切换到 DAST，先做目标健康检查和验证模板，再考虑 ZAP/Nuclei 等工具接入。

## 8. SANDBOX 沙箱动态证据链

### 已完成

- 人工证据记录。
- Docker 隔离执行第一版。
- 用户可填写沙箱命令。
- 支持项目级默认沙箱命令和沙箱镜像。
- 根据项目文件自动推荐命令模板和镜像。
- Docker 执行策略：
  - `--network none`
  - `--read-only`
  - 源码目录只读挂载到 `/workspace`
  - `--cpus 1`
  - `--memory 512m`
  - `--pids-limit 128`
  - `--security-opt no-new-privileges`
  - `/tmp` 使用受限 tmpfs
- 阻止明显危险命令，例如递归删除、格式化磁盘、关机等。
- 采集退出码、标准输出、错误输出、耗时、超时状态和证据摘要。
- 输出内容会对疑似密钥字段做简单脱敏。
- 结构化记录执行事件、隔离策略、输出摘要、运行时间线。
- SANDBOX 证据可显式关联 Finding、SCA 组件或 DAST 验证，并继承验证链上下文。
- 前端 SANDBOX 页面展示执行结果、输出摘要、策略账本、时间线事件。

### 还未完成

- 不采集真实文件访问事件。
- 不采集真实网络连接事件，因为当前默认禁网。
- 不采集进程树详情。
- 不接 eBPF、Sysmon 或审计探针。
- 不支持交互式程序。
- 不支持复杂多步骤场景编排。
- 不做恶意样本级强隔离，只适合本地开发验证。

### 推荐后续方向

- 若切换到 SANDBOX，建议先做 Docker 工具链预检和模板配置管理，再做文件/进程/网络事件采集。

## 9. ASPM 平台治理与交付

### 已完成

- 聚合项目模块启用状态、组件数量、Finding 数量、DAST 验证数量、SANDBOX 证据数量、扫描任务数量。
- 按来源、严重等级、状态、DAST 裁决做统计。
- 风险分计算第一版。
- Finding 治理字段：
  - 状态。
  - 负责人。
  - 备注。
  - 到期时间。
- 攻击链第二版：
  - 只基于显式 Finding、组件、DAST、SANDBOX 关联生成。
  - 删除“同项目第一条风险 + 第一条验证/证据”的弱关联方式。
  - 输出关联依据、可信度、时间和可追溯证据步骤。
- 证据图谱 API：`GET /api/aspm/projects/{project_id}/evidence-graph`。
- 证据图谱节点覆盖项目、组件、Finding、DAST 验证和 SANDBOX 证据。
- 证据图谱关系覆盖 `reported_by`、`validated_by`、`observed_by`。
- 前端治理总览展示项目摘要、风险分、统计和风险列表。
- 前端 DAST / SANDBOX 页面支持显式选择关联对象，ASPM 展示关系审计表。
- SCA 供应链治理卡片：
  - 最新扫描组件数。
  - 风险组件数。
  - 漏洞组件数。
  - SCA Finding 数。
  - Top 风险组件。
  - Syft / Grype 增强状态。
  - Grype 输入来源。
  - 错误摘要。

### 还未完成

- 风险分规则较简单，尚未接 CVSS、EPSS、资产暴露面、业务重要性。
- 当前是显式关系图，不是真正的图数据库或 AI 图谱推理。
- 没有 SLA 管理。
- 没有工单系统接入。
- 没有完整整改闭环流程。
- 没有合规报告。
- 没有管理层报表导出。
- 历史 DAST / SANDBOX 数据没有显式关联，需要重新执行关联验证后才会生成可信攻击链。

### 推荐后续方向

- ASPM 下一步建议增加风险趋势、复测状态和 SLA 第一版，再考虑图数据库或 AI 推理。

## 10. 当前重要技术文件

SCA 相关：

- `apps/api/app/routers/sca.py`
- `apps/api/app/services/sca_parser.py`
- `apps/api/app/services/sca_risk_analyzer.py`
- `apps/api/app/services/sca_vulnerability_rules.py`
- `apps/api/app/services/sca_license_policy.py`
- `apps/api/app/services/sca_sbom.py`
- `apps/api/app/services/sca_dependency_graph.py`
- `apps/api/app/services/sca_native_tree.py`
- `apps/api/app/services/sca_tool_scanner.py`
- `apps/api/app/rules/sca_vulnerability_rules.json`
- `apps/api/app/rules/sca_license_policies.json`

ASPM 相关：

- `apps/api/app/routers/aspm.py`
- `apps/api/app/services/aspm_evidence_graph.py`
- `apps/api/app/routers/findings.py`
- `apps/api/app/models.py`
- `apps/api/app/db_models.py`
- `apps/api/migrations/versions/20260726_0001_evidence_links.py`

前端主文件：

- `apps/web/src/main.tsx`
- `apps/web/src/styles.css`

文档：

- `README.md`
- `docs/PROJECT_HANDOFF_2026-07-26.md`

## 11. 验证命令

常用验证：

```powershell
cd D:\project\PYproject\AI网安项目
python -m compileall apps\api\app
cd apps\web
npm run build
```

新增服务导入检查可用项目虚拟环境：

```powershell
cd D:\project\PYproject\AI网安项目
$env:PYTHONPATH='apps\api'
.\.venv\Scripts\python.exe -c "from app.services.sca_native_tree import build_native_dependency_edge_records; from app.services.sca_dependency_graph import graph_dependency_edges; print('native tree imports ok')"
```

## 12. 新对话窗口推荐初始提示词

下面这段可直接复制到新的对话窗口：

```text
继续完善 D:\project\PYproject\AI网安项目 这个项目。请不要依赖旧对话记录，先读取 README.md 和 docs/PROJECT_HANDOFF_2026-07-26.md，再执行 git status --short --branch 和 git log -5 --oneline 确认当前状态。

我会在这个新对话窗口发送原始的 01.pptx，请把 PPT 作为需求来源之一，结合 README 和交接文档重新判断项目当前进度。

当前规则仍然是：每次写代码前先说明要实现的功能，得到我确认后再修改代码；每次代码更新后同步 GitHub。

请先完成以下事项：
1. 检查项目当前 Git 状态和最新提交。
2. 阅读 README.md 与 docs/PROJECT_HANDOFF_2026-07-26.md。
3. 等我发送原始 PPT 后，结合 PPT、README、交接文档，重新列出每个模块已完成和未完成内容。
4. 给出下一步最推荐推进的模块和具体实现范围，不要直接改代码，先等我确认。
```
