# AI 网络安全检测、验证与治理平台

本项目用于逐步实现 `01.pptx` 中描述的平台：围绕一个已经存在的项目，读取本地源代码、运行地址和运行入口，完成 SCA、SAST、AGENT、DAST、SANDBOX、ASPM 六个模块的可选接入、检测、验证和治理汇总。

当前阶段目标是先形成一个本地可跑通的完整平台，再逐步补齐每个模块的深度能力。

## 当前架构

- `apps/api/`：FastAPI 后端，提供项目、模块、扫描、证据、治理汇总 API。
- `apps/web/`：React + Vite 前端控制台。
- `infra/`：本地 PostgreSQL / Redis Docker Compose 配置。
- `docs/`：需求、架构和模块设计文档。
- `.agents/`：后续 Agent 编排相关说明或配置。

## 本地启动

### 1. 启动基础设施

先打开 Docker Desktop，确认 Docker Engine 处于 Running 状态。

```powershell
cd D:\project\PYproject\AI网安项目
docker compose -f infra/docker-compose.yml up -d
```

### 2. 执行数据库迁移

```powershell
cd D:\project\PYproject\AI网安项目
.\.venv\Scripts\python.exe -m alembic -c alembic.ini upgrade head
```

### 3. 启动后端

```powershell
cd D:\project\PYproject\AI网安项目
.\.venv\Scripts\python.exe -m pip install -r apps\api\requirements.txt
cd apps\api
..\..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

后端健康检查：

```text
http://localhost:8000/api/health
```

### 4. 启动前端

```powershell
cd D:\project\PYproject\AI网安项目\apps\web
npm install
npm run dev
```

前端访问：

```text
http://localhost:5173
```

## 平台级能力

### 已实现

- 项目创建、删除、查询、切换。
- 项目资产配置：本地源码路径、运行地址、API 地址、沙箱命令、沙箱镜像。
- 六个安全模块可单独启用或停用。
- 项目资产探测：根据源码目录识别 SCA、SAST、AGENT 可执行任务。
- “安全检测”合并模块接入和任务执行：用户自主选择 SCA、SAST、AGENT、DAST、SANDBOX，页面提示模块关系与缺失配置。
- 一键检测按 `SCA -> SAST -> AGENT -> DAST -> SANDBOX` 顺序执行已接入模块，并逐模块展示等待、执行、完成、失败或跳过状态。
- PostgreSQL 持久化：项目、模块配置、扫描任务、组件、Finding、DAST 记录、SANDBOX 证据。
- Alembic 迁移基线与跨模块证据关联迁移第一版。
- 前端主导航为项目管理、项目资产、安全检测、治理总览和安全知识中枢。
- 治理总览支持在综合总览和已接入模块之间切换；未接入模块不会显示，证据图谱默认收起为高级信息。
- 前端采用“默认简洁、详情按需展开”的展示方式：默认页只显示当前风险、下一步动作和每页 10 条结果；所有多条结果（含高级分析、攻击链、证据关系、扫描历史、图谱节点和单条风险的验证/取证记录）统一每页 10 条并提供翻页；单条风险可展开完整 DAST 请求/响应、SANDBOX 隔离策略与行为账本；综合总览可展开完整整改闭环、全部攻击链和项目级证据图谱。
- SCA 模块的扫描历史、批次差异、依赖图谱、升级杠杆、工具链预检以及 CycloneDX / SPDX / SCA 报告导出均保留在“高级供应链分析”折叠区，避免占用日常治理视图。
- SAST 模块的规则化 Agent 复核入口、SAST / AGENT 的风险分类与严重等级统计，均保留在各自的“高级分析与复核信息”折叠区；SANDBOX 的安全命令模板保留在运行时取证工作台。
- DAST 现提供随上游风险变化的验证策略：策略会明确“本次会检查什么、只会做什么、不能证明什么”，并将策略、范围和能力边界随验证记录持久化；SANDBOX 会将取证目的、隔离策略和能力边界随运行证据持久化。

### 还缺少

- 用户登录、权限、租户隔离。
- 扫描任务队列和后台 Worker。
- 报告导出。
- CI/CD 接入。
- 完整审计日志。

### 前端展示与能力边界

- “代码中存在”不等同于“前端已开放”。本仓库已将现有的 SCA 高级分析、SAST Agent 复核、SANDBOX 模板、ASPM 完整整改闭环和证据图谱接回当前治理页；不再依赖不可访问的旧导航页面。
- DAST 当前是**关联风险后的轻量 Web 基础验证**：会请求目标 URL，并检查 HTTP/HTTPS、响应状态、响应耗时、Server Header 和基础安全响应头。新的基础检查风险会标为“需要进一步确认”，不会再被标记为“确认可利用”；它不能替代 SQL 注入、鉴权绕过等业务漏洞的真实利用证明。
- SANDBOX 当前是 Docker 受控执行：禁网、只读挂载、CPU/内存/PID 限制、危险命令拦截、输出脱敏及执行摘要均已实现；“文件、网络、进程、工具调用”当前主要是隔离策略与执行摘要，尚不是 eBPF/Sysmon 级真实行为探针。
- 证据链只由用户明确选择的风险/DAST 记录，或高置信度推荐经执行确认后写入。独立 URL 检查和独立命令运行会明确标为不计入漏洞证据链。

## 模块完成度

### 1. SCA 供应链风险分析

已实现：

- 解析依赖文件并生成组件清单。
- 支持 `package.json`、`requirements.txt`、`pom.xml`、`go.mod`。
- 支持 lockfile 解析第一版：`package-lock.json`、`yarn.lock`、`pnpm-lock.yaml`、`poetry.lock`、`Pipfile.lock`。
- 组件去重、依赖类型、直接/传递依赖标记、来源文件、包管理器字段。
- 接入 OSV 漏洞库查询。
- 本地漏洞规则库第一版：独立 JSON 规则文件，覆盖 npm、PyPI、Maven、Go 示例规则。
- 本地规则支持简单版本范围：`<1.2.3`、`<=1.2.3`、`>=1.0.0,<2.0.0`。
- 许可证策略第一版：独立 JSON 策略文件，归一化为 `allowed`、`review_required`、`restricted`、`unknown`。
- 许可证义务说明与例外审批建议第一版：输出保留声明、NOTICE、源码披露、授权证明、法务/安全/业务审批等建议。
- CycloneDX JSON SBOM 导出第一版。
- CycloneDX `dependencies` 关系导出第一版：项目到直接依赖、直接依赖到同生态传递依赖。
- SPDX 2.3 JSON SBOM 导出第一版，包含项目包、组件包、PURL 外部引用和 `DEPENDS_ON` 关系。
- SBOM 元数据增强第一版：项目负责人、仓库、源码路径、运行地址、组件统计、依赖类型、风险状态、OSV 状态和哈希采集状态。
- 依赖边质量标注第一版：区分 `manifest_direct` 与 `lockfile_inferred`，并在 SBOM 和前端概览展示依赖边数量。
- 依赖图谱与升级杠杆第一版：新增图谱 API、SVG 可视化、风险节点标注和直接依赖升级杠杆分析。
- npm 原生依赖树第一版：尝试运行 `npm ls --json --all` 采集真实父子依赖边，图谱优先使用 `native_tree` 边；失败时自动回退到现有 manifest / lockfile 推断。
- 输出风险状态、漏洞编号、严重等级、风险摘要、修复建议、风险来源、OSV 查询状态。
- 前端组件风险清单分页，每页 10 条，并展示依赖类型分布、许可证策略分布、CycloneDX 和 SPDX 导出按钮。
- 前端组件清单支持按生态、依赖类型、风险状态、严重等级和许可证策略筛选。
- 前端展示直接 / 传递依赖、风险传递依赖和影响链数量概览。
- Docker 镜像方式接入 Syft / Grype 第一版：Syft 生成 CycloneDX SBOM，Grype 优先使用 Syft SBOM 输入执行漏洞扫描，Syft 失败时才回退目录扫描。
- 增强扫描状态持久化：记录 Syft 组件数、Grype 漏洞数、Grype 输入来源和错误摘要。
- SCA 风险自动转为统一 Finding，并进入 ASPM 治理闭环。

主要 API：

```text
POST /api/sca/scan
GET  /api/sca/projects/{project_id}/components
GET  /api/sca/projects/{project_id}/sbom?format=cyclonedx|spdx
GET  /api/sca/projects/{project_id}/dependency-graph
GET  /api/sca/projects/{project_id}/scan-history
GET  /api/sca/projects/{project_id}/scan-diff
GET  /api/sca/projects/{project_id}/report
GET  /api/sca/tool-health
```

可选增强：

- SCA 扫描支持通过 Docker 镜像 `anchore/syft:latest` 和 `anchore/grype:latest` 做专业工具增强。
- SCA 页面提供工具链预检，检查 Docker CLI、Docker Engine、Syft 镜像、Grype 镜像和 Grype 漏洞库状态。
- 前端可勾选“Syft/Grype 增强”后执行扫描。
- 需要本机 Docker 可用，并提前拉取镜像或允许首次扫描时自动拉取：
  - `docker pull anchore/syft:latest`
  - `docker pull anchore/grype:latest`
- 如果 Docker 或镜像不可用，基础 SCA 扫描仍可运行。
- 增强扫描状态会写入扫描历史和 SCA 报告，包含 Syft 组件数、Grype 漏洞数、Grype 输入来源和错误信息。
- SCA 高危/严重漏洞、漏洞编号命中、许可证风险和版本缺失风险会自动转为统一 Finding，进入 ASPM 治理闭环。

还缺少：

- 真实组件包文件哈希采集。
- Python / Maven / Go 等更多包管理器原生完整依赖树。
- 更深度的传递影响分析、真实父子依赖树和基于图谱推理的跨模块攻击链。
- 更完整的组织级许可证策略配置、策略启停、审批流持久化和例外记录管理。
- 更完整的本地漏洞规则来源、规则覆盖面、规则启停和组织级规则管理。
- Trivy 等更多专业工具接入。
- Syft / Grype 漏洞库更新时间展示和离线模式。
- 离线漏洞库缓存。

### 2. SAST 智能静态审计

已实现：

- 本地规则扫描：硬编码密钥、危险命令执行、动态代码执行、SQL 拼接、SSRF、路径穿越、弱加密、反序列化等。
- Semgrep 接入：优先使用本机 `semgrep`，没有时尝试使用 Docker 镜像 `semgrep/semgrep:latest`。
- 噪声过滤：跳过常见构建产物、依赖目录、压缩文件等。
- SAST Finding 持久化。
- 规则化 agent 编排第一版：`scanner_agent`、`review_agent`、`evidence_agent`、`fix_agent`。
- 复核结果包含分类、语言、误报可能性、证据摘要、修复策略、优先级。
- 前端 SAST 审计页展示风险列表、分类统计和严重等级统计。

主要 API：

```text
POST /api/sast/scan
GET  /api/sast/projects/{project_id}/findings
POST /api/sast/projects/{project_id}/agent-review
```

还缺少：

- SAST 的 `Failed to fetch` 网络问题尚未继续处理，已按用户要求暂时跳过。
- 更稳定的 Semgrep 镜像拉取和配置管理。
- 自定义规则库管理页面。
- AST / 数据流 / 污点分析。
- 外部 AI 复核接入。
- 修复补丁生成。
- 与 DAST、SANDBOX 的自动联动验证。

### 3. AGENT 供应链安全

已实现：

- 扫描 Agent / MCP / 插件相关配置和说明文件。
- 支持 `.md`、`.yaml`、`.yml`、`.json`、`.toml`、`AGENTS.md`、`CLAUDE.md`、`mcp.json`、`plugin.json`。
- 识别环境变量/密钥读取、Shell 执行、文件写入/删除、外部网络请求、MCP 权限过宽、提示词覆盖安全策略等风险。
- 增强 MCP 协议配置扫描。
- 输出 Finding、风险分类、修复建议和信任影响。
- 前端 AGENT 页面支持分页、分类统计和严重等级统计。

主要 API：

```text
POST /api/agent/scan
GET  /api/agent/projects/{project_id}/findings
```

还缺少：

- 不运行真实 Agent。
- 不连接真实 MCP Server。
- 不执行插件工具调用。
- 不生成完整工具权限矩阵。
- 不做 Agent 行为回放。
- 不做外部 AI 驱动的信任评分。

### 4. DAST 漏洞动态验证

已实现：

- 人工 DAST 验证记录。
- 自动轻量探测第一版：对目标 URL 发起 GET 请求。
- 检查 HTTP/HTTPS、状态码、响应时间、Server Header、基础安全响应头。
- 根据轻量规则生成 `exploitable`、`uncertain`、`not_exploitable` 裁决。
- 支持项目运行地址作为默认目标。
- DAST 验证可显式关联 Finding 或 SCA 组件，并记录关联来源与可信度。
- 自动关联建议第一版：根据 URL 路径、CVE/CWE、漏洞类型、风险来源和等级对 Finding 候选评分。
- 推荐结果展示匹配理由和高/中/低置信度；80 分及以上可预选，但只有用户执行验证后才写入关系。
- 治理总览的 DAST 视图调整为动态验证中心：先选择一条 SAST / SCA / AGENT 风险，再配置运行目标并执行验证。
- DAST 历史记录显示关联风险名称、验证目标、三色裁决、请求响应、复现过程和修复提示；未关联记录明确标记为 Web 基础检查，不计入漏洞证据链。

主要 API：

```text
POST  /api/dast/validations
POST  /api/dast/probe
POST  /api/dast/link-suggestions
GET   /api/dast/projects/{project_id}/strategies?finding_id={finding_id}
GET   /api/dast/projects/{project_id}/validations
PATCH /api/dast/validations/{validation_id}
```

还缺少：

- 已按用户要求暂时跳过 DAST 深化，计划最后再做。
- 不做爬虫。
- 不生成攻击 payload。
- 不做登录态管理。
- 不接 OWASP ZAP / Nuclei。
- 不做漏洞复现链自动生成。
- 不做自动复测。

### 5. SANDBOX 沙箱动态证据链

已实现：

- 人工证据记录。
- Docker 隔离执行第一版。
- 用户可填写沙箱命令。
- 支持项目级默认沙箱命令和沙箱镜像。
- 根据项目文件自动推荐命令模板和镜像。
- Docker 执行策略包含：
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
- 结构化记录执行事件：命令、镜像、工作目录、退出码、耗时、超时状态。
- 结构化记录隔离策略：禁网、只读挂载、CPU / 内存 / PID 限制、tmpfs、`no-new-privileges`。
- 结构化记录输出摘要：标准输出摘要、错误输出摘要、截断状态和脱敏状态。
- 结构化记录运行时间线：准备、执行、完成或超时阶段。
- 治理总览的 SANDBOX 视图调整为运行时取证中心：优先从已关联 DAST 验证进入，也可直接选择 Finding，再配置验证命令和隔离镜像。
- SANDBOX 历史记录显示上游风险 / 验证、隔离执行、观察结论和文件、网络、进程、工具调用账本；独立命令运行不计入漏洞证据链。
- SANDBOX 证据可显式关联 Finding、SCA 组件或 DAST 验证，并继承验证链上下文。
- 自动关联建议第一版：结合运行命令、风险文件、已选 Finding/组件及 DAST 裁决推荐证据链上游。
- 可利用或不确定的 DAST 验证优先进入候选；推荐仍需随执行动作确认，不会静默落库。

主要 API：

```text
POST  /api/sandbox/evidence
POST  /api/sandbox/run
POST  /api/sandbox/link-suggestions
GET   /api/sandbox/projects/{project_id}/templates
GET   /api/sandbox/projects/{project_id}/evidence
PATCH /api/sandbox/evidence/{evidence_id}
```

还缺少：

- 不采集真实文件访问事件。
- 不采集真实网络连接事件，因为当前默认禁网。
- 不采集进程树详情。
- 不接 eBPF、Sysmon 或审计探针。
- 不支持交互式程序。
- 不支持复杂多步骤场景编排。
- 不做恶意样本级强隔离，只适合本地开发验证。

### 6. ASPM 平台治理与交付

已实现：

- 聚合项目模块启用状态、组件数量、Finding 数量、DAST 验证数量、SANDBOX 证据数量、扫描任务数量。
- 按来源、严重等级、状态、DAST 裁决做统计。
- 风险分计算。
- Finding 治理字段：状态、负责人、备注、到期时间。
- 跨模块攻击链第二版：只基于显式 Finding / 组件 / DAST / SANDBOX 关联生成攻击链，不再按同项目首条记录机械拼接。
- 证据图谱 API 第一版：输出项目、组件、Finding、DAST 验证和 SANDBOX 证据节点，以及 `reported_by`、`validated_by`、`observed_by` 关系。
- 关系边记录关联依据、可信度和时间，攻击链支持证据溯源。
- 前端治理总览顶部可选择“综合总览”或任一已接入模块，一次只展示一个范围。
- 综合总览按照“多源发现 → 等待验证 → DAST 验证 → SANDBOX 取证 → 整改/复测 → 已闭环”展示风险生命周期。
- 漏洞证据闭环优先展示已有动态证据的风险，以可读时间线呈现发现、验证、取证和治理状态，并可直接发起 DAST 或 SANDBOX。
- 跨模块攻击链重新进入综合总览，只展示基于显式关系形成的可信链路。
- SCA、SAST、AGENT、DAST、SANDBOX 各自使用统一的简洁结构：模块状态、四项核心指标、完整结果筛选、每页 10 条分页和建议动作。
- 每个可独立运行的模块都提供执行入口；SCA、SAST、AGENT 支持保留扫描批次并按“仍然存在、已经消失、新增、发生变化”展示修复复测结果。
- 自动关联建议由一键执行流程使用；只有高置信度候选进入关联。风险清单可按单个 Finding 展开其显式 DAST / SANDBOX 证据链，未验证风险会明确标记。
- 安全知识中枢前端第一版：组织项目上下文、规则与 Skill、动态验证经验、运行时证据、修复和误报结论；尚未实现的规则自动生成、跨项目推荐和自主演进会明确标注能力边界。

主要 API：

```text
GET   /api/aspm/projects/{project_id}/summary
GET   /api/aspm/projects/{project_id}/evidence-graph
GET   /api/findings/projects/{project_id}/retest-comparison?source=SAST
PATCH /api/findings/{finding_id}/governance
PATCH /api/findings/{finding_id}/status
```

还缺少：

- 风险分规则还比较简单，尚未接 CVSS、EPSS、资产暴露面、业务重要性。
- 自动关联目前是可解释的规则评分，不是语义模型或图谱推理；弱信号候选不会自动预选。
- 证据图谱目前是显式关系图，不是真正的图数据库或 AI 图谱推理。
- 没有 SLA 管理。
- 没有工单系统接入。
- 已有扫描复测对比，但还没有包含审批、工单和 SLA 的完整整改闭环流程。
- 没有合规报告。
- 没有管理层报表导出。
- 旧数据没有显式关联字段，需要重新执行关联验证后才会生成可信攻击链。

## 当前关键限制

- 平台目前主要面向本地开发环境。
- 需要被检测项目的本地源码路径。
- DAST 只有目标项目有 Web 地址时才有意义。
- SANDBOX 需要 Docker Desktop 正常运行，并且需要提前准备对应镜像。
- Semgrep 依赖本机 CLI 或 Docker 镜像，网络和镜像状态会影响 SAST 结果。
- 当前没有用户权限系统，请不要暴露到公网。

## 下一步建议

1. 增加 ASPM 风险趋势和 SLA 第一版，并把复测结果纳入项目级趋势。
2. 回头处理 SAST 前端 `Failed to fetch` 问题。
3. 为 SCA 增加 Python 原生完整依赖树。
4. 增加扫描任务队列和后台 Worker。
5. 补充报告导出和审计日志。
