# AI 网安项目

本项目实现 `01.pptx` 所描述的本地安全治理平台：围绕一个已存在的项目，接入本地源码、运行地址与运行入口，提供 SCA、SAST、AGENT、DAST、SANDBOX 和 ASPM 六个模块的扫描、验证、证据关联与治理汇总。

本文档反映 **2026-08-07** 的代码状态。所有“已实现”均指仓库中已有后端实现，且已从当前 Vue 控制台开放；没有把计划能力写成已完成能力。

## 2026-08-07 前端整体迁移

- 前端已从 React 19 整体迁移到 Vue 3 + TypeScript + Vite，使用 Vue Router 管理页面路由、Pinia 管理项目与安全数据状态。
- Vue 页面以迁移前提交 `2d43a7c` 为视觉与交互基准：保留原五入口侧栏、项目资产、安全能力接入、ASPM 闭环、知识中枢及各模块治理工作台的原有结构，不因框架迁移重新设计界面。
- SCA、SAST、AGENT、DAST、SANDBOX 使用独立输入与运行状态；单模块操作只调用并刷新本模块，一键执行是唯一主动编排多个模块的入口。ASPM 汇总和证据图会在结果变化后只读刷新，但这不代表其他模块被执行。
- 项目管理、资产、安全检测、治理总览、知识中枢及 SCA、SAST、AGENT、DAST、SANDBOX、ASPM/任务入口均已迁移；FastAPI 接口和 PostgreSQL 数据结构不变。
- SCA 仍默认启用 Syft/Grype 增强扫描，保留扫描快照、复测口径、SBOM/报告、离线情报、风险例外和 VEX；所有时间统一按北京时间展示。
- 旧 React 入口与依赖已删除，生产构建使用 `vue-tsc --noEmit && vite build`。

## 2026-08-03 SAST 与交付更新（本节覆盖下方较早的状态描述）

- 平台当前按单机本地模式运行：前端直接进入项目控制台，不要求注册、登录、令牌、租户或成员关系。为兼容已有 PostgreSQL 数据，历史身份与租户表保留但不参与 API 访问控制。
- SAST 默认使用仓库内置的离线 Semgrep YAML 规则包。项目可在当前 SAST 治理页面校验、发布、启停、版本化自定义 YAML 规则包；运行时仅会将已启用包 materialize 到 `D:\project\PYproject\AI网安项目\artifacts\sast-offline\runtime-rules`，不会自动下载规则或镜像。
- 本地扫描新增 Python 标准库 AST 的同函数和直接本地跨函数 Source → Sink → Sanitizer 检查，以及 JS/TS 保守本地数据流检查，覆盖 SQL、命令执行、SSRF、路径穿越和不安全反序列化。它们是有边界的静态线索，不是全程序数据流或可利用性证明。
- SAST 扫描可记录 Git 基线差异和历史密钥标识：历史扫描只保存路径、信号摘要，绝不保存历史密钥值。API/前端提供 JSON、HTML、SARIF、扫描趋势、按分支/阈值/新增项/排除规则可配置的质量门禁、人工确认后的 DAST/SANDBOX 建议和“仅草案”修复补丁。
- 项目 Semgrep YAML 规则包支持草稿、结构校验、已预载本地 CLI/Docker 引擎预检、审批发布、版本和启停；只有 enabled + published 包才 materialize 并参与扫描。
- `scripts/sast_ci.py` 支持 Git 基线/差异文件与历史密钥参数；仓库同时提供 GitHub Actions、GitLab CI、Jenkins 和 Azure DevOps 的离线 CI 模板，会保存 JSON/SARIF 证据并执行本地门禁。
- 扫描任务 API 提供持久化排队、并发上限、开始、进度、取消和重试事件；`scripts/sast_worker.py` 可作为常驻轮询 Worker 运行（`--once` 用于一次性处理），部署方应将它纳入自己的进程守护体系。

仍未实现、也不应被宣称为已实现的是：真实外部模型或 Sub-agent 复核、自动提交修复补丁/PR、跨服务或动态调度的全程序污点分析、联网规则/镜像自动拉取，以及 DAST/SANDBOX 的自动攻击性执行。

## 当前架构

- `apps/api/`：FastAPI 后端，提供项目、模块、扫描、Finding、证据和治理 API。
- `apps/web/`：Vue 3 + TypeScript + Vite 前端控制台；路由、Pinia 状态、API 和业务页面分别位于 `src/router.ts`、`src/stores/`、`src/api.ts` 与 `src/views/`。
- `infra/`：本地 PostgreSQL / Redis Docker Compose 配置。
- `.github/workflows/`：SCA 本地 CI 与部署 API 门禁示例。
- `scripts/sca_ci.py`、`scripts/sast_ci.py`：无需启动平台 API 的本地 SCA/SAST CLI，支持 JSON、SARIF 与退出码。

运行链路：`Vue 前端 → /api → FastAPI routers → services → PostgreSQL`。路由层处理接口和参数，服务层处理扫描、证据关联、图谱、复测、门禁和导出。

## 本地启动

### 1. 启动基础设施

先启动 Docker Desktop，再执行：

```powershell
cd D:\project\PYproject\AI网安项目
docker compose -f infra\docker-compose.yml up -d
```

### 2. 安装后端依赖并迁移数据库

```powershell
cd D:\project\PYproject\AI网安项目
.\.venv\Scripts\python.exe -m pip install -r apps\api\requirements.txt
.\.venv\Scripts\python.exe -m alembic -c alembic.ini upgrade head
```

### 3. 启动后端

```powershell
cd D:\project\PYproject\AI网安项目\apps\api
..\..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

健康检查：`GET http://127.0.0.1:8000/api/health`。

### 4. 启动前端

```powershell
cd D:\project\PYproject\AI网安项目\apps\web
npm install
npm run dev
```

## 平台级能力

### 已实现并在前端可见

- 项目创建、编辑、删除、切换，以及项目资产配置（本地源码路径、运行地址、API 地址、沙箱命令和镜像）。
- 六个安全模块可逐项目启用、停用；资产探测会提示可执行的 SCA、SAST 与 AGENT 任务。
- “安全检测”按 `SCA → SAST → AGENT → DAST → SANDBOX` 执行已接入模块，并显示等待、运行、完成、失败或跳过状态。
- PostgreSQL 持久化项目、模块配置、扫描任务、组件、Finding、DAST 验证和 SANDBOX 证据；迁移由 Alembic 管理。
- 治理总览、项目资产视图和安全知识中枢均在主导航中可访问；高级分析折叠收纳，避免淹没日常治理信息。
- 项目安全报告 API 和前端预览支持 JSON、HTML 导出；SCA 另有独立 HTML、CycloneDX 和 SPDX 导出。

### 平台仍缺少的共性能力

- 用户登录、真实权限校验、组织/租户隔离与防篡改审计。
- 扫描任务队列、后台 Worker、定时计划与失败重试。
- 跨模块的正式合规报告、签名与报表模板体系。
- 覆盖全部模块的 CI/CD API、SDK 和外部系统集成；目前只有 SCA 已提供本地 CLI 和远程 API 门禁示例。

## 模块完成度与边界

| 模块 | 已实现（后端 + 前端） | 当前未完成的主要能力 |
| --- | --- | --- |
| SCA | 多生态依赖解析、风险和许可证分析、SBOM、依赖图、历史差异、哈希证据、OSV/离线情报、策略/例外/VEX、可配置门禁、本地 CI CLI；所有治理和高级分析入口均已在 SCA 页面开放。 | 实时情报同步、签名校验、商业情报适配；真实 IAM/租户审批；所有生态的完整原生依赖树；语义图推理与全平台 CI 集成。 |
| SAST | 本地规则扫描、项目自定义正则规则（校验/样例预览/启停/版本）、固定版 Semgrep 可选增强、规则化 Agent 复核、项目级扫描配置/版本、工具健康与降级记录、规则/路径豁免、扫描历史/差异、SARIF 导出、本地离线 CI CLI 和 Finding 统一治理；入口均已在 SAST 治理页开放。 | 自定义 Semgrep YAML 规则编辑/发布、离线 Semgrep 镜像和规则包自动分发、AST/数据流/污点分析、真实外部 AI 复核和补丁生成。 |
| AGENT | Agent/MCP/插件配置与说明文件静态扫描，识别危险命令、敏感路径、网络能力、密钥风险；结果和统计已在 AGENT 页面开放。 | 不运行真实 Agent、不连接 MCP Server、不执行工具调用；缺少权限矩阵、行为回放与信任评分。 |
| DAST | 人工验证、轻量 Web 基础检查、验证策略、显式风险/组件关联与可解释的关联建议；动态验证中心和历史已在前端开放。 | 爬虫、登录态管理、攻击 payload、业务漏洞利用证明、OWASP ZAP/Nuclei 集成、自动复现与自动复测。 |
| SANDBOX | 受控 Docker 运行、命令模板、危险命令拦截、禁网/只读/资源限制、输出脱敏、人工证据和显式证据链；工作台已在前端开放。 | 真实文件/网络/进程/工具调用探针、eBPF/Sysmon、交互程序、复杂多步骤编排和恶意样本级强隔离。 |
| ASPM / 治理 | 汇总模块状态、组件、Finding、DAST、SANDBOX、扫描任务；证据图谱、攻击链、整改字段、复测对比、项目报告和知识中枢均已可见。 | 项目级 CVSS/EPSS/资产暴露面/业务权重风险模型、趋势与 SLA、工单与审批、图数据库/语义推理、全局审计与后台任务。 |

## SCA 供应链风险分析

### 已实现且已在前端开放

- 解析 npm、PyPI、Maven、Go、Ruby/Bundler、Composer、Cargo、NuGet 的常见清单和锁文件；Python 项目存在 `.venv`/`venv` 时，使用 `pip inspect` 读取实际安装包及其依赖关系，不执行项目业务代码。
- 组件清单支持生态、依赖类型、风险状态、严重等级和许可证策略筛选，以及直接/传递依赖和影响链统计。
- 依赖图优先使用 npm `npm ls`、Python `pip inspect`、Maven `mvn dependency:tree`、Go `go mod graph`；无法使用工具或缓存时明确标注回退到锁文件/清单推断。
- 组件证据 SHA-256、扫描输入指纹、依赖来源、策略和情报结论都随扫描批次快照保存。哈希只覆盖本地实际可读取的证据文件，不伪造第三方二进制哈希。
- 本地漏洞规则、许可证策略、项目/平台覆盖和变更审计；高危/严重、版本风险和许可证风险会转为统一 Finding，进入 ASPM 整改闭环。
- 本地 OSV 镜像、离线 CVSS/EPSS/KEV 情报导入。组件快照保存综合风险分、KEV 标识、修复版本、情报来源和降级状态。
- VEX 支持“未受影响、已修复、受影响、调查中”，保留原始漏洞证据；例外支持申请、批准、拒绝、撤销、失效日期、角色字段及审批历史。当前角色仅用于流程和审计，尚不等同真实 IAM。
- 可配置门禁可按严重等级、许可证策略、综合风险分、KEV、扫描新鲜度和关键漏洞情报完整性阻断；返回机器可读的 `pass`/`block` 和 CI 退出码。
- SCA 高级区已提供扫描历史、批次差异、依赖图、升级杠杆、工具链预检、策略、例外、VEX、情报、门禁、证据、SBOM 和 HTML 报告入口。
- `scripts/sca_ci.py` 支持独立本地扫描和 JSON/SARIF 输出；`.github/workflows/sca-local.yml` 可直接消费它，`.github/workflows/sca-gate.yml` 用于调用部署后的 API 门禁。

### 常用 SCA API

```text
POST /api/sca/scan
GET  /api/sca/projects/{project_id}/components
GET  /api/sca/projects/{project_id}/scan-history
GET  /api/sca/projects/{project_id}/scan-diff
GET  /api/sca/projects/{project_id}/dependency-graph
GET  /api/sca/projects/{project_id}/sbom?format=cyclonedx|spdx
GET  /api/sca/projects/{project_id}/report
GET  /api/sca/projects/{project_id}/report.html
GET  /api/sca/projects/{project_id}/gate
GET  /api/sca/projects/{project_id}/evidence
GET  /api/sca/projects/{project_id}/vex
POST /api/sca/projects/{project_id}/vex
GET  /api/sca/projects/{project_id}/exceptions
POST /api/sca/projects/{project_id}/exceptions
GET  /api/sca/intelligence/status
POST /api/sca/intelligence/import
GET  /api/sca/osv-mirror/status
POST /api/sca/osv-mirror/import
GET  /api/sca/tool-health
```

### 本地 SCA CI

```powershell
cd D:\project\PYproject\AI网安项目
.\.venv\Scripts\python.exe scripts\sca_ci.py --source . --offline --json sca-result.json --sarif sca-result.sarif --fail-on-block
```

`--offline` 禁止在线情报访问；`--fail-on-block` 在门禁阻断时返回非零退出码。Git 忽略的 `artifacts/sca-offline/` 可放置 OSV、Grype、Trivy 的离线资源；数据导入、更新频率、签名校验与可信来源由部署环境负责。

Syft/Grype/Trivy 增强扫描在页面和 API 中默认开启：需要 Docker、镜像和相应离线/在线漏洞库。若 Syft 无法从锁文件或已安装目录识别组件，平台会用基础解析结果生成 CycloneDX SBOM 供 Grype 扫描；`artifacts/sca-offline/grype-cache/` 中已有数据库归档但尚未导入时，首次扫描会自动完成本地导入。离线 Grype 数据库最多允许使用 30 天，超过后会明确提示更新；任一工具不可用时基础解析扫描仍会完成，并分别展示 Syft、Grype、Trivy 状态和降级原因。

## 其他模块的接口与实际边界

- SAST：`POST /api/sast/scan`、`GET /api/sast/projects/{project_id}/findings`、`POST /api/sast/projects/{project_id}/agent-review`、`GET/PATCH /api/sast/projects/{project_id}/profile`、`GET/POST/PATCH /api/sast/projects/{project_id}/rules`、`POST /api/sast/rules/validate`、`POST/PATCH /api/sast/projects/{project_id}/suppressions`、`GET /api/sast/projects/{project_id}/scan-history`、`GET /api/sast/projects/{project_id}/scan-diff`、`GET /api/sast/projects/{project_id}/sarif`、`GET /api/sast/projects/{project_id}/ci-config`、`GET /api/sast/tool-health`。本地扫描是规则匹配；Agent 复核是规则化编排，不宣称调用外部大模型。
- AGENT：`POST /api/agent/scan`、`GET /api/agent/projects/{project_id}/findings`。仅分析本地配置和文本，不执行 Agent/MCP/插件。
- DAST：`POST /api/dast/probe`、`POST /api/dast/validations`、`GET /api/dast/projects/{project_id}/validations`。基础检查只验证 HTTP/HTTPS、状态、耗时、Server Header 和基础安全响应头；不能证明 SQL 注入、鉴权绕过等业务漏洞可利用。
- SANDBOX：`POST /api/sandbox/run`、`POST /api/sandbox/evidence`、`GET /api/sandbox/projects/{project_id}/evidence`。默认使用受限 Docker 容器；执行摘要和隔离策略不等同系统级行为取证。
- ASPM：`GET /api/aspm/projects/{project_id}/summary`、`GET /api/aspm/projects/{project_id}/evidence-graph`、`GET /api/aspm/projects/{project_id}/report`。证据图只基于显式关系和确认后的高置信度建议，不是图数据库或 AI 推理结论。

## 前端可见性说明

- 当前控制台存在项目管理、项目资产、安全检测、治理总览和安全知识中枢导航。
- SCA 高级治理、SAST Agent 复核、DAST 验证策略、SANDBOX 模板/证据和 ASPM 整改/图谱不再依赖旧的不可访问导航，均在当前项目工作区可打开。
- 未配置必要资产时，前端会提示条件不足或显示降级状态，而不会把未执行的能力标为已完成。

## 使用前的外部条件

- 基础 SCA/SAST/AGENT 需要被测项目的本地源码路径。
- Syft/Grype/Trivy 增强需要 Docker、镜像及相应漏洞库；Semgrep 增强需要本机 CLI 或 Docker 镜像。
- SAST 默认固定 Docker 镜像为 `semgrep/semgrep:1.95.0`，也可通过 `SAST_SEMGREP_IMAGE` 显式替换。离线运行时请将镜像和规则资源置于 `D:\project\PYproject\AI网安项目\artifacts\sast-offline\`；该目录已忽略，不会自动下载或提交运行资源。
- DAST 需要可访问的目标 Web 地址；SANDBOX 需要 Docker Desktop 和可用镜像。
- 当前没有登录、权限或租户隔离，不应直接暴露到公网。

## 验证命令

```powershell
cd D:\project\PYproject\AI网安项目\apps\api
..\..\.venv\Scripts\python.exe -m pytest tests -q

cd D:\project\PYproject\AI网安项目\apps\web
npm run build
```

### 本地 SAST CI

```powershell
cd D:\project\PYproject\AI网安项目
.\.venv\Scripts\python.exe scripts\sast_ci.py --source . --offline --json sast-result.json --sarif sast-result.sarif --fail-on high
```

`--offline` 使用本地规则且不依赖在线 Semgrep 规则包；`.github/workflows/sast-local.yml` 提供对应的 GitHub Actions 示例。

## 下一步最推荐的模块

建议优先推进 **ASPM 项目级风险优先级与 SLA**：把 SCA 已有的 CVSS/EPSS/KEV 信号与资产暴露面、业务重要性和整改时限汇总为可解释的项目风险排序，再增加趋势与工单/审批接口。它能让现有六个模块的结果形成真正可执行的治理闭环；真实身份权限和后台任务应与该阶段一并规划。

## 当前代码结构

```text
apps/
  api/
    app/
      routers/       # 项目、模块、SCA、SAST、AGENT、DAST、SANDBOX、ASPM API
      services/      # 扫描、情报、门禁、证据、图谱、报告和复测逻辑
      migrations/    # Alembic 数据库迁移
      rules/         # SCA 本地漏洞与许可证规则
    tests/           # 后端测试
  web/
    src/main.tsx     # 当前页面、状态和 API 调用集中处
infra/               # PostgreSQL / Redis Compose 配置
scripts/sca_ci.py    # 本地 SCA CI CLI
scripts/sast_ci.py   # 本地 SAST CI CLI
.github/workflows/   # SCA/SAST 本地 CI 与 API 门禁示例
docs/                # 交接与专题文档
outputs/             # 本地演示输入和验证材料
```
