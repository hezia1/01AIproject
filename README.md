# AI 原生应用安全平台

面向本地代码仓库和受控运行环境的一体化应用安全平台。项目将 SCA、SAST、Agent 供应链审计、DAST、SANDBOX 和 ASPM 治理串成一条证据链，用于完成从静态发现、动态验证到整改交付的闭环。

> 当前版本是单机研发与演示环境，默认没有登录鉴权、组织/租户隔离和生产级审计保护。请勿直接暴露到公网，也不要对未获授权的目标执行动态验证。

## 目录

- [主要能力](#主要能力)
- [系统架构](#系统架构)
- [技术栈](#技术栈)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [使用流程](#使用流程)
- [新项目适配范围](#新项目适配范围)
- [本地扫描与 CI](#本地扫描与-ci)
- [测试](#测试)
- [验收基线](#验收基线)
- [项目结构](#项目结构)
- [能力边界与安全说明](#能力边界与安全说明)
- [项目文档](#项目文档)

## 主要能力

| 模块 | 当前能力 | 主要输出 |
| --- | --- | --- |
| SCA | 多生态依赖解析、SBOM、漏洞与许可证分析、依赖图、VEX、例外和质量门禁 | 组件清单、风险、依赖关系、CycloneDX/SPDX、门禁结果 |
| SAST | 本地规则、固定版本社区/项目 Semgrep YAML 规则、有限数据流分析、Git 基线与历史密钥证据、可选 DeepSeek 七角色复核 | 代码 Finding、证据、SARIF、修复草案、扫描差异 |
| AGENT | 解析 Agent 指令、Prompt、Skill、MCP、工具和插件配置，归一化权限与资源边界 | Agent 资产、权限矩阵、信任评分、差异与门禁结果 |
| DAST | 将可动态验证的 SAST/AGENT Finding 转换为受控策略，执行同源 HTTP、浏览器及差分验证 | 验证队列、运行快照、证据链、三色裁决、专项报告 |
| SANDBOX | 识别常见项目启动信息，在隔离 Docker 网络中启动目标和受控依赖，执行固定探针 | 目标实例、任务事件、HAR/截图/控制台/时延等运行证据 |
| ASPM | 汇总组件、Finding、验证、沙箱证据和整改状态 | 项目总览、证据图、复测对比、项目安全报告 |
| 安全知识中枢 | 将项目 Finding、动态证据和治理结论组织为可追溯经验 | 候选审核、版本回滚、租户级发布、跨项目匹配推荐 |

平台数据保存在 PostgreSQL 中。已经完成的 DAST 运行、证据和三色裁决会随项目恢复，不依赖当前浏览器页面状态。

## 系统架构

```text
React Web 控制台
        │
        ▼
FastAPI REST API
        │
        ├── SCA / SAST / AGENT 扫描与治理服务
        ├── DAST 策略、审批、执行与裁决服务
        ├── SANDBOX 启动规划、Docker 编排与证据执行器
        └── ASPM 汇总、证据图、复测与报告服务
        │
        ├── PostgreSQL：项目、任务、Finding、验证和证据
        └── Redis：本地基础设施预留的队列/缓存服务

被测源码 ──► 静态发现 ──► DAST 候选 ──► SANDBOX/受控执行 ──► 三色裁决 ──► ASPM
```

API 路由只负责请求与参数处理；扫描、策略、证据、门禁和报告逻辑位于服务层。SANDBOX 不导入项目专用执行代码，项目差异通过源码路径、运行地址、启动计划和声明式验证合同传递。

## 技术栈

- 前端：React 19、TypeScript、Vite 7
- 后端：Python、FastAPI、Pydantic、SQLAlchemy、Alembic
- 数据库：PostgreSQL 16
- 缓存/队列基础设施：Redis 7
- 隔离执行：Docker、内部网络、只读文件系统、资源限制和固定探针
- 可选扫描器：Semgrep、Syft、Grype、Trivy
- 可选 AI：DeepSeek API

## 环境要求

- Git
- Python 3.12（项目 CI 使用的版本）
- Node.js `^20.19.0` 或 `>=22.12.0`
- npm
- Docker Desktop 或兼容的 Docker Engine，并支持 Docker Compose
- Windows PowerShell（下方命令以 Windows 为例）

基础 SCA、SAST 和 AGENT 扫描只需要本地源码。SANDBOX、浏览器证据及增强型扫描器还需要相应 Docker 镜像和运行资源。

## 快速开始

### 1. 获取代码并启动基础设施

进入克隆后的仓库根目录，然后执行：

```powershell
docker compose -f infra\docker-compose.yml up -d
```

该 Compose 文件会启动：

- PostgreSQL：`localhost:5432`
- Redis：`localhost:6379`

### 2. 创建后端环境

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r apps\api\requirements.txt
Copy-Item apps\api\.env.example apps\api\.env
python -m alembic -c alembic.ini upgrade head
```

`apps/api/.env` 已被 Git 忽略。真实 API Key 只能写入该文件，不要写入 README、`.env.example`、前端代码或提交记录。

### 3. 启动后端

```powershell
cd apps\api
..\..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

启动后可访问：

- 健康检查：<http://127.0.0.1:8000/api/health>
- Swagger API：<http://127.0.0.1:8000/docs>
- ReDoc：<http://127.0.0.1:8000/redoc>

### 4. 启动前端

另开一个 PowerShell 窗口：

```powershell
cd apps\web
npm ci
npm run dev
```

控制台默认地址：<http://127.0.0.1:5173>

### 5. 停止基础设施

```powershell
docker compose -f infra\docker-compose.yml down
```

如需同时删除本地 PostgreSQL 数据卷，请明确执行 `docker compose -f infra\docker-compose.yml down -v`。该操作会永久删除平台数据库数据。

## 配置说明

### 后端环境变量

配置模板位于 [`apps/api/.env.example`](apps/api/.env.example)。

| 变量 | 用途 | 默认值/说明 |
| --- | --- | --- |
| `DATABASE_URL` | PostgreSQL 连接 | 本地 `ai_security` 数据库 |
| `REDIS_URL` | Redis 连接 | `redis://localhost:6379/0` |
| `PROJECT_IMPORT_ROOT` | ZIP/Git 受管源码目录 | 默认 `artifacts/project-imports`；删除对应项目时自动清理受管副本 |
| `DEEPSEEK_API_KEY` | SAST 七角色 AI 复核 | 默认留空，项目级能力默认关闭 |
| `DEEPSEEK_BASE_URL` | SAST AI 服务地址 | `https://api.deepseek.com` |
| `DEEPSEEK_MODEL` | SAST 发现/分析模型 | 见环境变量模板 |
| `DEEPSEEK_REVIEW_MODEL` | SAST 独立终审模型 | 见环境变量模板 |
| `DAST_DEEPSEEK_API_KEY` | DAST 业务流程草案 | 应使用独立 Key，默认留空 |
| `SANDBOX_EXECUTOR_IMAGE` | 固定 HTTP/探针执行器镜像 | `python:3.12-slim` |
| `SANDBOX_BROWSER_IMAGE` | 固定 Playwright 证据镜像 | 本地锁定的项目镜像 |

DeepSeek 只是一项可选增强能力。未配置或调用失败时，本地静态扫描仍会保留结果并明确显示降级状态。启用前请确认被测代码允许发送给第三方模型服务。

### 项目资产

每个项目可独立配置以下资产：

| 字段 | 用途 |
| --- | --- |
| `source_path` | 后端机器上可读取的项目源码绝对路径 |
| `repository_url` / `default_branch` | 仓库标识和默认分支 |
| `runtime_url` | 已启动 Web 应用的入口地址 |
| `api_base_url` | API 入口地址 |
| `sandbox_image` | SANDBOX 使用的受信运行时镜像 |
| `sandbox_command` | 经过白名单校验的应用启动命令 |

项目可以逐项启用或停用六个模块。未满足运行条件的模块会显示阻塞或降级原因，不会把未执行任务标记为完成。

## 使用流程

1. 在控制台通过本地目录、HTTP(S) Git 仓库或 ZIP 上传接入项目；Git/ZIP 会进入 `PROJECT_IMPORT_ROOT` 管理目录。
2. 查看“项目资产”的接入准备度，确认源码、全部受支持依赖清单、Agent 配置以及 DAST/SANDBOX 可选运行条件。
3. 现场陌生项目优先使用“快速演示”：基础扫描按文件数、体积和软时限形成有界结果；SCA 在网络可用时仍查询在线 OSV，网络失败时自动回退人工准备的本地 OSV 镜像和本地规则。用户明确启用的 SCA Docker 或 Semgrep 仍会真实执行并记录状态。预先准备的项目再使用不设这些快速范围上限的深度扫描。
4. 按项目启用需要的安全模块并执行 SCA、SAST 和/或 AGENT。SCA 按概览、风险组件、依赖影响、例外与 VEX、历史与报告组织；SAST 按概览、代码风险、AI 辅助复核、扫描策略、例外与报告组织，Semgrep 作为补充本地规则覆盖面的 SAST 增强引擎在“扫描策略”中直接可见，不属于 SCA。AGENT 治理页面按概览、风险、资产与边界、动态验证、策略与交付五个工作区复核 Finding、扫描覆盖、运行证据和降级原因。风险页只把可处置 Finding 计入“正式问题”，覆盖缺口等内容单列为“扫描提示”，动态验证按“运行条件 → 安全副本 → 验证方式 → 确认执行 → 查看证据”逐步展开。治理页面的说明、限制和证据摘要统一使用中文，业务时间统一标注为北京时间；运行探针等需要精确匹配的授权确认口令保留原始英文。
5. DAST 从当前批次中选择支持动态验证且上下文足够的 SAST/AGENT Finding，生成待审批策略。
6. 在 Dry Run 中检查目标、路径、身份引用、请求上限和证据标准。
7. 由 DAST 有界执行器验证已上线目标，或交给 SANDBOX 启动隔离实例并采集证据。
8. 根据已归档事实形成裁决，并在 ASPM 中跟踪整改和复测。

### DAST 三色裁决

- **红色—可利用**：存在满足策略要求的明确利用证据。
- **黄色—不确定**：观察到异常，但证据不足、运行不完整或目标能力未接入。
- **绿色—不可利用**：至少两组规定探针完成且证据支持防护有效。
- **未验证**：任务尚未执行、被策略阻止、目标不可达或执行器缺失。未验证不属于三色裁决。

SAST Finding 总数与 DAST 队列数量不必相等。只有适合运行态验证、属于当前项目/当前扫描批次，并且能够构造目标与证据标准的 SAST/AGENT Finding 才进入 DAST；SCA 组件风险不进入 DAST 队列。

源码证据中的动态 URL 模板（例如 `${PORT}`）只作为代码上下文，不会被当作可连接目标，也不会导致整批 DAST 候选加载失败。DAST 的“三色裁决”只统计已经完成且证据完整的运行任务；候选队列有内容但尚未执行时，三色裁决仍可为 0。

自动生成的 DAST 策略名称会在保留用途后缀的前提下限制到数据库字段上限，上游规则的超长标题不再导致生成失败。对同一候选重复点击会校验并打开当前策略，不会重复创建；生成成功或失败会在按钮旁直接显示。CSRF 中间件缺失会映射到 CSRF 隔离会话策略，并优先选择状态变更 HTTP 方法，不再被误分为 XSS。

### SANDBOX 生命周期

- 目标容器使用平台管理标签、内部网络、能力删除、只读根文件系统和资源上限。
- 页面关闭时，前端会请求后端停止当前浏览器会话创建的 SANDBOX 目标。
- 目标记录和已归档证据保存在数据库中；容器停止不会删除历史裁决。
- 浏览器异常退出或请求未送达时，仍应由部署环境定期清理过期的受管容器。

## 新项目适配范围

平台以通用项目配置和声明式适配为主，不应依赖某一个测试项目：

- 本地目录直接引用，不复制也不在删除项目时移除；ZIP 上传和 HTTP(S) Git 浅克隆写入受管目录，删除项目时只清理该受管副本。
- ZIP 接入限制为 500 MiB、20000 个条目和 1 GiB 解压体积，并拒绝绝对路径、`..` 路径穿越、符号链接及超大单文件。
- Git 接入禁用交互式凭据提示和 LFS 自动下载，URL 不得内嵌密码或令牌；私有仓库需依赖主机已配置的安全 Git 凭据。
- 准备度页把静态检测条件和 DAST/SANDBOX 可选运行条件分开：缺少运行地址不会阻塞 SCA/SAST，缺少源码或可识别资产才会阻塞快速检测。
- 快速模式限制为最多 200 个依赖文件、3000 个组件、1200 个源码文件、60 MiB 源码内容和每个本地模块 45 秒软时限；限制命中会以部分覆盖返回，不会伪装成深度扫描。快速模式只限制基础扫描范围，不再覆盖用户明确勾选的增强引擎：勾选 SCA Docker 或在项目配置中启用 Semgrep 后，本次扫描会真实尝试执行，并在批次历史中记录成功、降级或失败原因。

- SCA 支持 npm、PyPI、Maven、Go、Bundler、Composer、Cargo 和 NuGet 的常见清单/锁文件。启用 Docker 增强后，只有 `package.json` 而没有锁文件/安装目录的 npm 项目会在排除常见生成目录的临时源码副本中，通过固定 Node 镜像执行 `npm install --package-lock-only --ignore-scripts`；临时目录会清理，原项目不写入 `package-lock.json` 或 `node_modules`。
- Docker 增强按职责执行：Syft 只生成一次 CycloneDX SBOM，Grype 直接读取该 SBOM 做组件漏洞匹配，Trivy 默认只扫描配置错误和明文密钥。Grype 健康检查失败时，Trivy 才在同一次源码扫描中启用漏洞匹配作为回退；Grype 健康时，Grype 与 Trivy 并行执行。SCA“扫描引擎与漏洞情报源”提供 Grype 数据库有效期检测，并在数据库过期或缺失时允许用户显式联网更新；更新与扫描复用 `artifacts/sca-offline/grype-cache`，扫描本身仍禁止自动更新。Trivy 回退命中可确认漏洞，但未命中不会代替完整 SBOM 匹配而把组件自动标记为安全。配置和密钥结果单独保存并展示，不计入组件漏洞数量；疑似密钥的原始匹配值不会保存。
- SAST 对常见 Python、JavaScript/TypeScript 等源码执行本地规则和有限语义分析，并可接入已发布的项目 Semgrep 规则。Semgrep 社区安全规则只在治理界面由用户确认许可证后显式更新到 `artifacts/sast-offline/community-rules`；更新固定官方仓库提交 SHA，扫描阶段不联网，并按源码语言与配置类型只加载本地匹配目录。JavaScript/TypeScript 本地规则覆盖命令执行、SQL 模板、对象越权、批量赋值、JWT 算法、Cookie、CORS、用户正则、敏感请求日志和错误披露等高价值模式；同一规则的多处命中归并为一个 Finding，并保留全部代码位置。
- AGENT 扫描 Markdown Frontmatter、JSON、YAML、TOML 及常见 Agent/MCP/插件配置。
- SANDBOX 会读取 `package.json`、Python 依赖文件、`pom.xml`、Gradle、`go.mod`、Dockerfile、Compose、Procfile 和 README 等上下文，生成受限启动计划。
- 项目专属 Docker 目标健康后，SANDBOX 可通过常见 HTML 表单或 JSON 注册/登录 API 创建两名普通一次性测试用户；凭据仅保存在 API 进程内存中。非 Docker/已上线目标不会被自动注册账号，非通用身份流程仍需显式适配器或管理员密钥引用。
- Node.js 启动端口会结合 `.env`、`package.json` 的 `main`/`module`/启动脚本以及根目录、`src/`、`server/`、`config/` 下的常见 JS/TS 入口识别；启动前页面会显示并允许校正容器端口和健康检查路径。
- Compose 只作为依赖提示；项目自带的宿主端口、挂载、密钥和任意命令不会直接照搬。目前自动编排的辅助服务限定为 PostgreSQL 和 Redis。

新项目能否零配置启动取决于入口是否明确、运行镜像是否在白名单内、依赖是否可获取以及应用是否兼容只读/非 root/受限网络策略。自动识别不充分时，需要人工填写 `sandbox_image`、`sandbox_command`，并在 SANDBOX 启动前确认端口和健康检查路径；健康检查失败时页面会显示网关实际使用的容器端口及修正建议。无法满足策略时系统应返回阻塞原因，而不是伪造验证结果。

## 本地扫描与 CI

以下 CLI 不要求启动 Web 或 API 服务。

### SCA

```powershell
.\.venv\Scripts\python.exe scripts\sca_ci.py `
  --source . `
  --offline `
  --json sca-result.json `
  --sarif sca-result.sarif `
  --fail-on-block
```

### SAST

```powershell
.\.venv\Scripts\python.exe scripts\sast_ci.py `
  --source . `
  --offline `
  --json sast-result.json `
  --sarif sast-result.sarif `
  --fail-on high
```

如需与平台中的项目规则、抑制项和门禁保持一致，先从 SAST 页面导出配置，再增加：

```text
--profile sast-ci-config.json
```

### AGENT

```powershell
.\.venv\Scripts\python.exe scripts\agent_ci.py `
  --source . `
  --offline `
  --json agent-result.json `
  --sarif agent-result.sarif `
  --html agent-result.html `
  --fail-on-block
```

### SAST Worker

```powershell
.\.venv\Scripts\python.exe scripts\sast_worker.py --concurrency 2
```

仓库还提供：

- [SCA 本地工作流](.github/workflows/sca-local.yml)
- [SAST 本地工作流](.github/workflows/sast-local.yml)
- [SCA API 门禁](.github/workflows/sca-gate.yml)
- [GitLab CI 示例](.gitlab-ci.yml)
- [Jenkins SAST 示例](ci/sast/Jenkinsfile)
- [Azure Pipelines SAST 示例](azure-pipelines-sast.yml)

## 测试

### 后端测试

```powershell
$testTemp = Join-Path (Resolve-Path .) '.tmp\pytest'
New-Item -ItemType Directory -Force -Path $testTemp | Out-Null
$env:TEMP = $testTemp
$env:TMP = $testTemp
$env:TMPDIR = $testTemp
cd apps\api
..\..\.venv\Scripts\python.exe -m pytest tests -q
```

Agent 运行时暂存目录必须位于 `D:` 盘；直接沿用系统默认的 `C:` 盘临时目录会触发安全边界测试失败。上述目录已被 Git 忽略。

### 前端构建

```powershell
cd apps\web
npm ci
npm run build
npm run test:sandbox-ui
```

部分 SANDBOX 和增强扫描能力依赖本机 Docker、固定镜像或离线漏洞库；缺少外部条件时，相应测试或能力会按设计显示跳过、阻塞或降级。

## 验收基线

仓库使用机器可读的 [`acceptance/criteria.json`](acceptance/criteria.json) 记录当前证据和缺口，并通过 [`scripts/acceptance_check.py`](scripts/acceptance_check.py) 校验。P0 门禁只验证已经具备可复现证据的交付项；精确率、召回率、DAST 复现率、完整生态兼容率和生产就绪度在缺少版本化语料时保持“未建立基线”，不得用演示数据替代。

```powershell
.\.venv\Scripts\python.exe scripts\acceptance_check.py --profile p0
```

详见 [`docs/acceptance-baseline.md`](docs/acceptance-baseline.md)。

## 项目结构

```text
.
├── apps/
│   ├── api/
│   │   ├── app/
│   │   │   ├── routers/       # FastAPI 路由
│   │   │   ├── services/      # 扫描、验证、沙箱、证据和报告逻辑
│   │   │   └── rules/         # 内置离线规则
│   │   ├── migrations/        # Alembic 数据库迁移
│   │   └── tests/             # 后端测试
│   └── web/
│       └── src/               # React 控制台
├── ci/                         # Jenkins 等 CI 示例
├── docs/                       # 架构、产品和专题说明
├── infra/                      # PostgreSQL/Redis Compose
├── scripts/                    # SCA/SAST/AGENT CLI 与 SAST Worker
├── alembic.ini
└── README.md
```

`artifacts/`、`outputs/`、`.env`、虚拟环境、依赖和构建产物均为本地数据，不应提交真实密钥、客户源码或敏感扫描证据。

## 能力边界与安全说明

- 静态分析结果是证据和线索，不等同于完整的可利用性证明，也不能保证零误报或零漏报。
- DAST/SANDBOX 只执行审批范围内的同源目标、固定探针和声明式步骤，不接受任意攻击脚本或不受控 Shell 命令。
- AI 输出只用于候选发现、解释和草案；不会自动修改被测源码、提交补丁或直接代替证据裁决。
- 缺少运行目标、测试身份、固定执行镜像或必要证据时，平台应保持“未验证”或“黄色”，不能推断为安全。
- 当前没有生产级 IAM、租户隔离、签名报告、分布式任务系统或敏感证据独立加密存储。
- 仅在获得明确授权的代码和运行环境中使用本项目。

## 项目文档

| 文档 | 内容 |
| --- | --- |
| [`docs/prd.md`](docs/prd.md) | 产品目标、用户、范围和验收方向 |
| [`docs/acceptance-baseline.md`](docs/acceptance-baseline.md) | P0 量化验收状态、命令与未建立基线项 |
| [`docs/deferred-work.md`](docs/deferred-work.md) | 暂缓事项、重新启动条件、完成标准和进展记录 |
| [`docs/architecture.md`](docs/architecture.md) | 架构原则、模块和数据流 |
| [`docs/module-system.md`](docs/module-system.md) | 六模块职责与关系 |
| [`docs/sandbox-adapter-protocol.md`](docs/sandbox-adapter-protocol.md) | SANDBOX 通用适配与运行证据协议 |
| [`docs/SAST_CI_INTEGRATIONS.md`](docs/SAST_CI_INTEGRATIONS.md) | SAST CI 集成方式 |
| [`docs/sca-ci-gate.md`](docs/sca-ci-gate.md) | SCA 质量门禁 |
| [`docs/mvp-roadmap.md`](docs/mvp-roadmap.md) | 已交付里程碑与后续路线 |
| [`docs/PROJECT_HANDOFF_2026-07-26.md`](docs/PROJECT_HANDOFF_2026-07-26.md) | 当前交接快照（沿用历史文件名） |

## 许可证

当前仓库未包含开源许可证。对外使用、复制或分发前，请先由项目所有者补充并确认适用的许可证。
