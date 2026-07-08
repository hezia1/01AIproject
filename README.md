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

### 2. 启动后端

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

### 3. 启动前端

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
- 统一任务中心：触发 SCA、SAST、AGENT、DAST、SANDBOX。
- PostgreSQL 持久化：项目、模块配置、扫描任务、组件、Finding、DAST 记录、SANDBOX 证据。
- 前端多页面视图：项目管理、项目资产、模块接入、任务中心、组件清单、SAST 审计、AGENT 安全、DAST 验证、SANDBOX 证据、ASPM 治理总览。

### 还缺少

- 正式 Alembic 数据库迁移。
- 用户登录、权限、租户隔离。
- 扫描任务队列和后台 Worker。
- 报告导出。
- CI/CD 接入。
- 完整审计日志。

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
- 许可证策略归一化第一版：`allowed`、`review_required`、`restricted`、`unknown`。
- CycloneDX JSON SBOM 导出第一版。
- CycloneDX `dependencies` 关系导出第一版：项目到直接依赖、直接依赖到同生态传递依赖。
- SPDX 2.3 JSON SBOM 导出第一版，包含项目包、组件包、PURL 外部引用和 `DEPENDS_ON` 关系。
- 输出风险状态、漏洞编号、严重等级、风险摘要、修复建议、风险来源、OSV 查询状态。
- 前端组件风险清单分页，每页 10 条，并展示依赖类型分布、许可证策略分布、CycloneDX 和 SPDX 导出按钮。
- 前端组件清单支持按生态、依赖类型、风险状态、严重等级和许可证策略筛选。
- 前端展示直接 / 传递依赖、风险传递依赖和影响链数量概览。

主要 API：

```text
POST /api/sca/scan
GET  /api/sca/projects/{project_id}/components
GET  /api/sca/projects/{project_id}/sbom?format=cyclonedx|spdx
```

还缺少：

- 更完整的 SBOM 元数据、组件哈希和精确依赖边。
- 更完整的依赖图谱、升级杠杆和传递影响分析。
- 更完整的许可证义务说明、例外审批和组织级策略配置。
- 更完整的本地漏洞规则来源、规则覆盖面、规则启停和组织级规则管理。
- Syft / Trivy / Grype 等专业工具接入。
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
- 前端 DAST 页面可查看验证记录。

主要 API：

```text
POST  /api/dast/validations
POST  /api/dast/probe
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
- 前端 SANDBOX 证据页展示执行结果、输出摘要、策略账本和时间线事件。

主要 API：

```text
POST  /api/sandbox/evidence
POST  /api/sandbox/run
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
- 攻击链第一版：从 Finding、DAST、SANDBOX 证据中生成简单攻击链视图。
- 前端治理总览展示项目摘要、风险分、统计和风险列表。

主要 API：

```text
GET   /api/aspm/projects/{project_id}/summary
PATCH /api/findings/{finding_id}/governance
PATCH /api/findings/{finding_id}/status
```

还缺少：

- 风险分规则还比较简单，尚未接 CVSS、EPSS、资产暴露面、业务重要性。
- 攻击链还只是规则化聚合，不是真正的图谱推理。
- 没有 SLA 管理。
- 没有工单系统接入。
- 没有整改闭环流程。
- 没有合规报告。
- 没有管理层报表导出。

## 当前关键限制

- 平台目前主要面向本地开发环境。
- 需要被检测项目的本地源码路径。
- DAST 只有目标项目有 Web 地址时才有意义。
- SANDBOX 需要 Docker Desktop 正常运行，并且需要提前准备对应镜像。
- Semgrep 依赖本机 CLI 或 Docker 镜像，网络和镜像状态会影响 SAST 结果。
- 当前没有用户权限系统，请不要暴露到公网。

## 下一步建议

1. 增强 ASPM 攻击链：把 SCA、SAST、AGENT、DAST、SANDBOX 的证据串联得更清晰。
2. 回头处理 SAST 前端 `Failed to fetch` 问题。
3. 为 SCA 增加 lockfile 解析和 SBOM 导出。
4. 增加正式数据库迁移和任务队列。
5. 补充报告导出和审计日志。
