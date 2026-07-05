# HANDOFF

## Project Root

`D:\project\PYproject\AI网安项目`

后续所有开发、测试、运行命令都应在这个目录下进行。旧目录 `C:\Users\hezia\Documents\AI网络安全项目` 只作为迁移前来源，不再作为主要工作区。

## Current Project Goal

基于用户提供的 `01.pptx`，构建一个 AI 原生应用安全检测、动态验证、供应链治理与 ASPM 平台。

平台目标不是单一扫描器，而是模块化安全治理平台：

- 用户可以按项目选择接入六个安全模块。
- 每个模块都有第一版可运行能力。
- 各模块结果统一进入项目治理视图。
- 后续再逐步增强每个模块的深度能力。

六个模块来自 PPT 第三页：

1. `SAST`：智能静态审计
2. `SCA`：供应链风险分析
3. `AGENT`：Agent 供应链安全
4. `DAST`：漏洞动态验证
5. `SANDBOX`：沙箱动态证据链
6. `ASPM`：平台治理与交付

## Completed Work

### 1. Project Skeleton

已创建基础工程结构：

```text
apps/
  api/
  web/
docs/
infra/
README.md
.gitignore
```

### 2. Documentation

已生成项目文档：

- `docs/README.md`
- `docs/prd.md`
- `docs/architecture.md`
- `docs/mvp-roadmap.md`
- `docs/module-system.md`

这些文档把 PPT 需求拆成 PRD、架构、MVP 路线图和六模块设计。

### 3. Backend Base

后端使用 FastAPI。

已完成：

- FastAPI 应用入口
- CORS 配置
- Pydantic API models
- SQLAlchemy 数据库连接
- 开发模式自动建表
- PostgreSQL 持久化基础
- 统一路由结构

关键文件：

- `apps/api/app/main.py`
- `apps/api/app/models.py`
- `apps/api/app/db.py`
- `apps/api/app/db_models.py`
- `apps/api/app/repositories/mappers.py`
- `apps/api/requirements.txt`
- `apps/api/.env.example`

### 4. Infrastructure

`infra/docker-compose.yml` 已定义：

- `postgres:16`
- `redis:7`

用户已手动拉取过镜像。若需要启动：

```powershell
cd D:\project\PYproject\AI网安项目
docker compose -f infra\docker-compose.yml up -d
```

### 5. Module Registry

已实现六模块注册表：

- `apps/api/app/module_registry.py`
- `apps/api/app/routers/modules.py`

后端模块接口：

```text
GET   /api/modules
GET   /api/modules/{module_key}
GET   /api/modules/projects/{project_id}
POST  /api/modules/projects/{project_id}
PATCH /api/modules/projects/{project_id}/{module_key}
```

### 6. Project / Scan / Finding APIs

已实现基础项目、扫描任务、漏洞发现接口，并切到 PostgreSQL 持久化。

路由：

- `apps/api/app/routers/projects.py`
- `apps/api/app/routers/scans.py`
- `apps/api/app/routers/findings.py`

### 7. SCA First Version

SCA 第一版已完成：组件清单生成。

能力：

- 解析 `package.json`
- 解析 `requirements.txt`
- 解析 `pom.xml`
- 解析 `go.mod`
- 生成组件清单
- 写入 `components` 表
- 前端可触发扫描并查看组件清单

接口：

```text
POST /api/sca/scan
GET  /api/sca/projects/{project_id}/components
```

关键文件：

- `apps/api/app/services/sca_parser.py`
- `apps/api/app/routers/sca.py`

当前边界：

- 不做 CVE 匹配
- 不做许可证风险判断
- 不解析 lockfile 传递依赖
- 不接 Syft / Grype / Trivy / OSV

### 8. SAST First Version

SAST 第一版已完成：基础规则扫描。

能力：

- 硬编码密码检测
- API Key / Secret 检测
- 命令执行调用检测
- `eval` / `exec` 动态代码执行检测
- SQL 字符串拼接检测
- 疑似 SSRF 请求检测
- 路径穿越风险检测
- 弱哈希/弱加密检测

接口：

```text
POST /api/sast/scan
GET  /api/sast/projects/{project_id}/findings
```

关键文件：

- `apps/api/app/services/sast_scanner.py`
- `apps/api/app/routers/sast.py`

结果写入统一 `findings` 表，`source = "SAST"`。

### 9. AGENT First Version

AGENT 第一版已完成：Agent/MCP/插件配置风险扫描。

能力：

- 扫描 `.md`、`.yaml`、`.yml`、`.json`、`.toml`
- 扫描 `AGENTS.md`、`CLAUDE.md`、`mcp.json`、`plugin.json`
- 检测读取环境变量/密钥
- 检测 Shell/命令执行能力
- 检测文件写入/删除能力
- 检测外部网络请求能力
- 检测 MCP/插件权限过宽
- 检测提示词覆盖/绕过安全策略

接口：

```text
POST /api/agent/scan
GET  /api/agent/projects/{project_id}/findings
```

关键文件：

- `apps/api/app/services/agent_scanner.py`
- `apps/api/app/routers/agent.py`

结果写入统一 `findings` 表，`source = "AGENT"`。

### 10. DAST First Version

DAST 第一版已完成：人工动态验证裁决与证据记录。

能力：

- 创建动态验证记录
- 可关联 finding
- 记录目标 URL
- 记录三态裁决：
  - `exploitable`
  - `uncertain`
  - `not_exploitable`
- 记录验证人、证据摘要、请求摘要、响应摘要、复现步骤、修复建议

接口：

```text
POST  /api/dast/validations
GET   /api/dast/projects/{project_id}/validations
PATCH /api/dast/validations/{validation_id}
```

关键文件：

- `apps/api/app/routers/dast.py`
- `apps/api/app/db_models.py` 中的 `DastValidationRecord`

当前边界：

- 不做自动爬虫
- 不生成 payload
- 不主动攻击目标
- 不接 OWASP ZAP / Nuclei

### 11. SANDBOX First Version

SANDBOX 第一版已完成：运行策略与证据链记录。

能力：

- 记录运行命令
- 记录运行环境 profile
- 记录网络策略
- 记录文件系统策略
- 记录观察到的文件访问
- 记录观察到的网络访问
- 记录观察到的进程行为
- 记录观察到的工具调用
- 记录证据摘要和操作人

接口：

```text
POST  /api/sandbox/evidence
GET   /api/sandbox/projects/{project_id}/evidence
PATCH /api/sandbox/evidence/{evidence_id}
```

关键文件：

- `apps/api/app/routers/sandbox.py`
- `apps/api/app/db_models.py` 中的 `SandboxEvidenceRecord`

当前边界：

- 不真实执行 `run_command`
- 不启动 Docker 沙箱
- 不采集真实运行时事件
- 不接 eBPF / Sysmon

### 12. ASPM First Version

ASPM 第一版已完成：统一治理视图 API。

能力：

- 按项目聚合启用模块
- 统计组件数量
- 统计 findings 数量
- 统计 DAST 验证记录数量
- 统计 SANDBOX 证据数量
- 统计扫描任务数量
- 按 source / severity / status 聚合 findings
- 按 verdict 聚合 DAST
- 计算临时风险分

接口：

```text
GET /api/aspm/projects/{project_id}/summary
```

关键文件：

- `apps/api/app/routers/aspm.py`
- `apps/api/app/models.py` 中的 `AspmProjectSummary`

临时风险分规则：

- critical finding: +12
- high finding: +8
- medium finding: +4
- low finding: +1
- exploitable DAST verdict: +10
- uncertain DAST verdict: +3
- sandbox evidence: 每条 +2，最多 +10
- 总分封顶 100

### 13. Frontend

前端使用 React + TypeScript + Vite。

关键文件：

- `apps/web/src/main.tsx`
- `apps/web/src/styles.css`
- `apps/web/package.json`

当前前端视图：

- 模块接入
- 任务中心
- SCA 清单
- 治理总览
- 项目资产占位

当前前端能力：

- 自动连接 API
- 自动获取/创建演示项目
- 启用/停用六个模块
- 触发 SCA 扫描
- 触发 SAST 扫描
- 触发 AGENT 扫描
- 创建 DAST 人工验证记录
- 创建 SANDBOX 证据记录
- 查看 SCA 组件清单
- 查看 ASPM 汇总、风险分、findings 统计和最新风险发现

## Key Design Conventions

1. 所有模块必须按项目启用。
2. SCA 产物写入 `components`。
3. SAST 和 AGENT 产物写入统一 `findings`。
4. DAST 产物写入 `dast_validations`。
5. SANDBOX 产物写入 `sandbox_evidence`。
6. ASPM 不独立造数据，第一版聚合已有表。
7. 当前所有第一版能力以“可跑通闭环”为目标，不追求深度检测。
8. 所有结果必须能按 `project_id` 隔离。
9. 当前前端是单项目演示流，会自动使用第一个项目；后续应改为多项目切换。
10. DAST 和 SANDBOX 当前只是人工记录，不执行真实攻击或沙箱命令。

## Recently Modified / Important Files

后端：

- `apps/api/app/main.py`
- `apps/api/app/models.py`
- `apps/api/app/db.py`
- `apps/api/app/db_models.py`
- `apps/api/app/repositories/mappers.py`
- `apps/api/app/module_registry.py`
- `apps/api/app/routers/projects.py`
- `apps/api/app/routers/modules.py`
- `apps/api/app/routers/scans.py`
- `apps/api/app/routers/findings.py`
- `apps/api/app/routers/sca.py`
- `apps/api/app/routers/sast.py`
- `apps/api/app/routers/agent.py`
- `apps/api/app/routers/dast.py`
- `apps/api/app/routers/sandbox.py`
- `apps/api/app/routers/aspm.py`
- `apps/api/app/services/sca_parser.py`
- `apps/api/app/services/sast_scanner.py`
- `apps/api/app/services/agent_scanner.py`

前端：

- `apps/web/src/main.tsx`
- `apps/web/src/styles.css`
- `apps/web/package.json`
- `apps/web/package-lock.json`

文档/配置：

- `README.md`
- `docs/*.md`
- `infra/docker-compose.yml`
- `.gitignore`

## Test / Verification Results

最近多次验证通过：

```powershell
python -m compileall apps\api\app
npm run build
```

已验证扫描器：

### SCA Parser

样例目录：

```text
D:\project\PYproject\AI网安项目\outputs\sca-sample
```

结果：

- 解析出 6 个组件
- 覆盖生态：`go`、`maven`、`npm`、`pypi`

### SAST Scanner

样例目录：

```text
D:\project\PYproject\AI网安项目\outputs\sast-sample
```

结果：

- 命中 6 条风险
- 覆盖规则：
  - `SAST.CMD.OS_SYSTEM`
  - `SAST.CODE.EVAL_EXEC`
  - `SAST.SECRET.API_KEY`
  - `SAST.SECRET.HARDCODED_PASSWORD`
  - `SAST.SQL.STRING_CONCAT`
  - `SAST.SSRF.USER_CONTROLLED_REQUEST`

### AGENT Scanner

样例目录：

```text
D:\project\PYproject\AI网安项目\outputs\agent-sample
```

结果：

- 命中 6 条风险
- 覆盖规则：
  - `AGENT.FS.WRITE_ACCESS`
  - `AGENT.NET.EXTERNAL_REQUEST`
  - `AGENT.PROMPT.INSTRUCTION_OVERRIDE`
  - `AGENT.SECRET.READ_ENV`
  - `AGENT.TOOL.SHELL_EXEC`

## Known Issues / Attention Points

1. 当前仓库 Git 状态基本都是未跟踪文件，尚未提交。
2. 项目已经从旧目录迁移到 `D:\project\PYproject\AI网安项目`，后续不要再改旧目录。
3. Docker 镜像 `postgres:16` 和 `redis:7` 用户已表示 Docker Desktop images 中已有。
4. 如果数据库表已经在旧结构下自动创建过，新增表一般会由 `Base.metadata.create_all` 创建，但已有表新增列不会自动迁移。当前新增内容多为新表；后续正式阶段应引入 Alembic。
5. 当前前端默认使用第一个项目，仍是单项目演示流。
6. DAST/SANDBOX 是人工记录，不做自动攻击或真实执行。
7. SCA/SAST/AGENT 是基础解析/正则扫描，不是生产级引擎。
8. 当前 API 没有认证和权限控制。
9. 当前没有真实 Git 仓库拉取能力。
10. 当前没有任务队列 Worker，扫描是同步接口。

## How To Run Locally

### Start Infrastructure

```powershell
cd D:\project\PYproject\AI网安项目
docker compose -f infra\docker-compose.yml up -d
docker compose -f infra\docker-compose.yml ps
```

### Start API

```powershell
cd D:\project\PYproject\AI网安项目\apps\api
..\..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

Health check:

```text
http://localhost:8000/api/health
```

Expected:

```json
{"status":"ok"}
```

### Start Web

```powershell
cd D:\project\PYproject\AI网安项目\apps\web
npm run dev
```

Open:

```text
http://localhost:5173
```

## Unfinished Tasks

High priority:

1. 项目创建向导与多项目切换。
2. 前端补充项目列表、项目选择器、新建项目表单。
3. 任务历史页面。
4. Finding 详情页和状态流转交互。
5. DAST 和 SANDBOX 前端详情页。
6. 将当前自动创建演示项目逻辑改为显式项目创建。

Medium priority:

1. 引入 Alembic 正式迁移。
2. Git 仓库接入和本地代码拉取。
3. Redis + Worker 异步任务队列。
4. SCA 增强：CVE/OSV 匹配、许可证风险、lockfile 传递依赖。
5. SAST 增强：Semgrep、自定义规则库、更多语言规则。
6. AGENT 增强：MCP 工具矩阵、信任评分、AI 审计。
7. DAST 增强：ZAP/Nuclei/Playwright 联动。
8. SANDBOX 增强：Docker 隔离执行和行为采集。
9. ASPM 增强：SLA、攻击链、报表导出、CI/CD 门禁。

Low priority / later:

1. 用户认证与 RBAC。
2. 审计日志。
3. 报告中心。
4. 多租户/组织空间。
5. OpenSearch / Neo4j / MinIO 等扩展设施。

## Recommended Next Step

下一步建议做：**项目创建向导与多项目切换**。

目标：

- 不再自动只使用第一个演示项目。
- 前端可以展示项目列表。
- 用户可以新建项目。
- 用户可以切换当前项目。
- 切换项目后，模块配置、任务中心、SCA 清单、ASPM 总览都刷新到当前项目。

建议先做前端为主，后端已有基础接口：

```text
GET  /api/projects
POST /api/projects
GET  /api/projects/{project_id}
```

需要前端新增：

- 项目选择器
- 新建项目表单
- 当前项目状态
- 创建项目后默认启用 `SCA + SAST + ASPM`
- 切换项目后重新加载：
  - `/api/modules/projects/{project_id}`
  - `/api/sca/projects/{project_id}/components`
  - `/api/findings?project_id={project_id}`
  - `/api/dast/projects/{project_id}/validations`
  - `/api/sandbox/projects/{project_id}/evidence`
  - `/api/aspm/projects/{project_id}/summary`

## Suggested Prompt For New Chat

在新的对话窗口中可以这样开始：

```text
请继续 D:\project\PYproject\AI网安项目 这个项目。先读取 HANDOFF.md，然后基于其中的状态继续开发。下一步请实现“项目创建向导与多项目切换”：前端增加项目列表、项目选择器、新建项目表单；创建项目后默认启用 SCA + SAST + ASPM；切换项目后刷新模块配置、任务中心、SCA 清单和 ASPM 治理总览。每次编写代码前先说明这一部分做什么、是否需要主机下载东西，得到允许后再写代码。
```
