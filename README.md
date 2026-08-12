# AI 网安项目

本项目实现 `01.pptx` 所描述的本地安全治理平台：围绕一个已存在的项目，接入本地源码、运行地址与运行入口，提供 SCA、SAST、AGENT、DAST、SANDBOX 和 ASPM 六个模块的扫描、验证、证据关联与治理汇总。

本文档反映 **2026-08-12** 的代码状态。所有“已实现”均指仓库中已有后端实现，且已从当前 React 控制台开放；没有把计划能力写成已完成能力。

## 2026-08-12 AGENT 过滤 staging 与无害夹具更新

- 新增 `POST /api/agent/projects/{project_id}/runtime-staging`。只有操作人先对同一组命令、digest 镜像和目标完成预检，再单独确认创建副本，后端才会执行复制；计划 SHA-256 变化时拒绝使用旧确认。
- 构建器只写入仓库 `artifacts/agent-sandbox/staging/<project-id>/<build-id>` 下的唯一 D 盘目录，绝不覆盖已有构建。它排除 `.env`、凭据/私钥命名、高置信密钥内容、链接/联接点、版本库、依赖、缓存、构建输出和平台 artifacts，并拒绝路径越界、非普通文件、大小/数量超限与复制期间发生变化的源文件。
- 每个副本包含逐文件 SHA-256、整体 staging SHA-256、manifest SHA-256、复制/排除清单和安全边界；完成原子改名后会重新读取 manifest 和全部文件校验，额外文件、缺失文件或内容篡改均会失败。
- AGENT 前端已提供独立的“创建并校验过滤副本”确认框和按钮，展示 D 盘位置、复制/排除数量与摘要。该动作不会联系 Docker、拉取镜像、运行无害夹具或运行真实 Agent。
- 仓库新增确定性离线无害夹具 `apps/api/tests/fixtures/agent_runtime_safe`，仅供复制、摘要和后续隔离策略测试。本阶段的测试没有执行该夹具。
- 下一阶段建议只用该无害夹具和本地已有、digest 固定的基础镜像验证容器禁网/只读/drop-all/资源限制；开始前仍需单独确认。若本地没有合适镜像，必须先说明用途、体积与 D 盘存储位置，再由用户决定是否下载。

## 2026-08-12 AGENT 受控运行预检与证据模型更新

- AGENT 已增加独立的运行预检计划，但本阶段强制保持 `mode=preflight-only`、`execution_enabled=false`：不会创建工作副本、联系 Docker daemon、拉取镜像、安装依赖或运行 Agent。
- 预检要求 SANDBOX 模块、有效源码目录、非链接根目录、操作人明确选择的单条命令、无下载/安装/提权/嵌套容器/密钥枚举/Shell 控制符、按 `name@sha256:<digest>` 固定的本地镜像、Docker CLI、禁网、只读、drop-all、无宿主 Socket/环境变量、资源限制和逐目标确认。
- 未来运行不能直接挂载项目源码目录。预检只按文件名与后缀统计 `.env`、凭据、私钥/证书等敏感文件类别，不读取或返回内容；独立二次确认的 staging 动作可在 `D:\project\PYproject\AI网安项目\artifacts\agent-sandbox\staging\<project-id>\<build-id>` 创建并哈希过滤副本，但预检不会自动选择或信任任何已有副本，因此运行仍保持阻断。
- 运行证据模板已定义计划 SHA-256、镜像/工作副本摘要、隔离策略、进程、文件访问、网络尝试、工具调用和静态数据流路径关联。路径结果严格区分 `observed`、`blocked_by_policy`、`not_observed`、`not_instrumented`/`not_run`；“未观察”不会被写成“不可利用”。
- 新增 `POST /api/agent/projects/{project_id}/runtime-preflight`，仅重新计算预检，不持久化也不执行。AGENT 快照、JSON/HTML 报告、离线 CI 和前端均显示计划、阻断原因、D 盘 staging 位置、候选高风险路径及证据边界。
- 过滤副本构建器和无害测试夹具已在独立确认后完成；指定真实 Agent、镜像与命令仍需另一次明确批准。如需下载镜像，必须提前说明用途、体积和 D 盘位置。

## 2026-08-11 AGENT Prompt → 工具 → 资源静态数据流更新

- AGENT 现在把 Prompt/指令、Agent 资产、工具能力和资源范围建模为节点与有向边，并为每条边记录 `explicit-asset-type`、`explicit-permission`、`co-declared` 或 `conservative-inference` 依据及高/中/低置信度。
- 同一资产内可形成 `Prompt → Agent → 工具 → 资源` 路径；当可疑指令与高风险工具位于不同配置文件时，只生成明确标记为低置信度的项目级保守推断，不冒充真实运行时调用。
- 新增 Prompt 到 Shell/进程、文件写入、密钥、网络等敏感能力路径，以及“密钥访问 + 网络外联”的潜在外传路径；每条路径显示已声明审批/资源范围、治理例外和缺失控制。Allowlist/例外不会被当成运行时防护，审批声明也明确标记为尚未验证执行。
- 数据流 Finding 已接入例外审批、质量门禁、扫描快照、JSON/SARIF/HTML 和离线 CI；默认阻断严重/高风险数据流 Finding。图模型限制为最多 1,000 个节点、2,000 条边和 300 条路径。
- 前端新增“Prompt → 工具 → 资源静态路径”面板，显示路径序列、证据、来源/工具配置位置、置信度、已有控制和缺失控制。
- 该能力仍是静态配置模型，不会运行 Agent、调用工具或证明数据真实传输。外部资源在没有方向性配置证据时不会被假定进入模型上下文。

## 2026-08-11 AGENT 离线漏洞与恶意包情报更新

- AGENT 会把来源证据中的 npm/PyPI 包名和精确版本转换为包坐标与 purl，并复用仓库内置 SCA 漏洞规则和可选本地 OSV 镜像；扫描过程不请求网络。
- 结果严格区分“命中漏洞”“已配置本地源未命中”“本地源未覆盖”“版本未解析”和“暂不支持”。“未命中”仅描述当前本地数据，不会显示成“无漏洞”。
- 可选本地恶意包情报支持明确的包记录和受保护包名列表；只有本地记录精确命中或配置包名与受保护名称编辑距离为 1 时才生成 Finding，不内置或伪造恶意包结论。
- 漏洞、恶意包和包名混淆会进入统一 Finding、例外审批、质量门禁、JSON/SARIF/HTML 与离线 CI。覆盖缺口和已配置情报过期可选择性阻断，默认不会因未配置外部情报文件直接失败。
- 前端“依赖漏洞与恶意包情报”面板展示情报源状态、路径、条目数、更新时间、年龄、逐包覆盖与命中详情。

本地 OSV 镜像默认读取 `D:\project\PYproject\AI网安项目\artifacts\sca-offline\osv-mirror.json`（可用 `SCA_OSV_MIRROR_PATH` 覆盖）；恶意包情报默认读取 `D:\project\PYproject\AI网安项目\artifacts\agent-offline\threat-intelligence.json`（可用 `AGENT_THREAT_INTELLIGENCE_PATH` 覆盖）。两者均为可选文件，平台不会自动下载。恶意包情报 JSON 使用 `ai-security-platform.agent-threat-intelligence/v1`，包含 `updated_at`、可选 `sources`、`entries`（`id/ecosystem/package/affected/severity/summary/source/references`）和 `protected_packages`（`ecosystem/package/source`）。

## 2026-08-11 AGENT 来源完整性更新

- AGENT 现在从 MCP、插件、Skill 和 Agent 配置中提取包名、版本、Registry/Git/容器/远程服务/本地来源与安装方式，区分不可变锁定、固定标签、浮动版本、缺失版本和不适用。
- 每个可读配置文件都会记录精确字节的 SHA-256；项目内的插件和 Skill 目录还会在最多 2,000 个文件、32 MiB 的安全边界内生成确定性目录 SHA-256。符号链接、项目外路径、不可读文件和超限范围会明确标记为部分证据。
- 新增未锁定版本、HTTP 来源、来源 URL 凭据、本地路径逃逸、来源未知和目录哈希不完整规则；URL 凭据不会写入 Finding、快照或报告。
- 批次差异会单独统计来源声明和完整性变化；质量门禁可阻断未锁定/不安全/未知来源、部分哈希、来源变化与哈希变化，JSON/SARIF/HTML 和离线 CI 使用同一证据。
- 前端已增加“来源与完整性证据”清单。发布者仍是配置声明，SHA-256 只证明本地字节是否变化；当前没有联网 Registry 身份校验或数字签名验证。已知漏洞匹配仅限内置规则和可选本地 OSV 镜像。

## 2026-08-10 AGENT 治理与交付更新

- AGENT 项目配置现支持停用规则、扫描路径 glob 排除、强制审批能力和权限 Allowlist；扫描快照会保存实际使用的策略版本。
- Finding 与权限例外采用“申请 → 批准/拒绝 → 撤销”流程，要求理由和审批说明，支持失效时间并保留项目级审计记录。批准的 Finding 例外从下一次扫描开始写为 `false_positive` 或 `accepted_risk`，不会改写历史批次。
- 质量门禁可按等级、只看新增、最大阻断数、通配权限、解析失败、跳过文件、权限扩大和高风险审批声明进行裁决；门禁结论和具体原因随扫描快照持久化并在前端显示。
- AGENT 专项 JSON、SARIF 2.1.0、HTML 报告和项目 CI 配置均可从治理页导出。`scripts/agent_ci.py` 复用同一策略在本地离线扫描，可使用上一份 JSON 报告作为基线，并通过 `--fail-on-block` 将阻断映射为退出码 1。
- 上述能力仍是本地静态治理：不会连接或执行 Agent、MCP Server、插件或工具。项目审计中的“操作人”是调用方提供的治理标识；当前平台没有登录、IAM 或租户级权限校验，不能把它表述为可信身份认证。

## 2026-08-09 SCA/SAST 准确性与交付更新（本节覆盖下方较早的状态描述）

- 平台当前按单机本地模式运行：前端直接进入项目控制台，不要求注册、登录、令牌、租户或成员关系。为兼容已有 PostgreSQL 数据，历史身份与租户表保留但不参与 API 访问控制。
- SAST 默认使用仓库内置的离线 Semgrep YAML 规则包。项目可在当前 SAST 治理页面校验、发布、启停、版本化自定义 YAML 规则包；运行时仅会将已启用包 materialize 到 `D:\project\PYproject\AI网安项目\artifacts\sast-offline\runtime-rules`，不会自动下载规则或镜像。
- SCA 现在对每个组件记录版本解析质量和漏洞情报验证状态。只有锁文件、实际安装环境、Syft 等提供精确版本且 OSV/本地镜像/Grype/Trivy 已完成验证时，才能显示“已验证未发现”；版本范围、缺失版本或情报不可用统一显示“需要复核”，默认门禁会阻断未验证组件。扫描快照、证据、报告和前端均显示覆盖率、已验证/未验证数量及原因。
- 本地扫描新增 Python 标准库 AST 的同函数和直接本地跨函数 Source → Sink → Sanitizer 检查，以及 JS/TS 保守本地数据流检查，覆盖 SQL、命令执行、SSRF、路径穿越、不安全反序列化、开放重定向、原始 HTML 输出和 XXE 线索。它们是有边界的静态证据，不是全程序数据流或可利用性证明。
- SAST 扫描可记录 Git 基线差异和历史密钥证据：历史扫描只接受高熵赋值、已知令牌格式和私钥头等高置信信号，排除文档、锁文件和占位符，并且只保存路径、信号摘要和提交短标识，绝不保存历史密钥值。API/前端提供 JSON、HTML、SARIF、扫描趋势、按分支/阈值/新增项/排除规则可配置的质量门禁、人工确认后的 DAST/SANDBOX 建议和“仅草案”修复补丁。
- 项目 Semgrep YAML 规则包支持草稿、结构校验、已预载本地 CLI/Docker 引擎预检、审批发布、版本和启停；只有 enabled + published 包才 materialize 并参与扫描。
- `scripts/sast_ci.py` 支持加载前端导出的项目 SAST 配置，统一使用项目自定义规则、已发布 YAML 规则包、抑制项、Git 基线和质量门禁；仓库同时提供 GitHub Actions、GitLab CI 和 Jenkins 的离线 CI 模板，会保存 JSON/SARIF 证据并执行本地门禁。
- 扫描任务 API 提供持久化排队、并发上限、开始、进度、取消和重试事件；`scripts/sast_worker.py` 可作为常驻轮询 Worker 运行（`--once` 用于一次性处理），部署方应将它纳入自己的进程守护体系。
- SAST 已接入可选的 DeepSeek 七角色 Sub-agent 深度审计：策略、漏洞发现、初审、证据验证、本地历史知识关联、修复草案和独立终审。它既可随 SAST 扫描自动运行，也可手动运行；客户端会识别截断响应、兼容代码围栏/前后说明/尾逗号并重试，且只有七个角色全部返回必需结构时才标记完成。调用记录、模型、各角色状态、未完成角色、Token、费用估算、候选数、确认数和分歧会持久化并在前端显示。
- AI 代码上下文限定在项目 `source_path` 内，按项目配置限制文件和字符数；上传前会脱敏常见密钥并屏蔽疑似提示注入。只有“独立终审确认为 confirmed + 证据充分 + 达到项目置信度阈值”的新候选才会进入正式 Finding。服务不可用时 SAST 会明确降级，但本地规则扫描结果仍保留。
- SAST 前端分为“日常检测”和默认折叠的“高级管理”：日常仅展示引擎状态、最近扫描、风险列表和 DeepSeek；Git 基线、Semgrep YAML/正则规则开发、异步 Job/Worker、CI 门禁、豁免和报告导出集中在高级区。重复的 Semgrep 发布入口已合并，修复草案改从单条高风险 Finding 的证据详情生成。

仍未实现、也不应被宣称为已实现的是：自动修改源码或提交补丁/PR、可执行工具的自治 Agent、跨服务或动态调度的全程序污点分析、外部漏洞知识库/RAG 自动学习、联网规则/镜像自动拉取，以及 DAST/SANDBOX 的自动攻击性执行。当前七角色由平台顺序编排真实模型调用，不是可自行执行命令或操作仓库的自治进程。

### DeepSeek 配置

- `apps/api/.env.example` 是可提交到 Git 的配置模板，只保留变量名、安全默认值和空的 Key；它不会被后端当作真实密钥文件。
- 将真实 `DEEPSEEK_API_KEY` 填在被 Git 忽略的 `apps/api/.env`。不要把真实 Key 写入 `.env.example`、README、前端代码或提交记录。
- 后端默认使用 `https://api.deepseek.com`，发现/分析模型和独立复核模型均可在 `.env` 中配置。结构化 Agent 默认使用非思考模式，以降低空 JSON、延迟和费用；可通过 `DEEPSEEK_THINKING_ENABLED=true` 显式开启。前端 SAST 页可测试连接，但不会显示完整 Key。
- 项目级 DeepSeek 能力默认关闭，避免无意上传代码或消耗额度；在 SAST 页开启并保存后，可选择随扫描自动执行。AI 生成的补丁始终是人工评审草案，不会直接写入被测源码。

## 当前架构

- `apps/api/`：FastAPI 后端，提供项目、模块、扫描、Finding、证据和治理 API。
- `apps/web/`：React + Vite 前端控制台；功能目前集中在 `src/main.tsx`。
- `infra/`：本地 PostgreSQL / Redis Docker Compose 配置。
- `.github/workflows/`：SCA 本地 CI 与部署 API 门禁示例。
- `scripts/sca_ci.py`、`scripts/sast_ci.py`：无需启动平台 API 的本地 SCA/SAST CLI，支持 JSON、SARIF 与退出码。

运行链路：`React 前端 → /api → FastAPI routers → services → PostgreSQL`。路由层处理接口和参数，服务层处理扫描、证据关联、图谱、复测、门禁和导出。

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
- 在治理页单独执行 SCA、SAST、AGENT、DAST 或 SANDBOX 时，只锁定并刷新当前模块；其他模块不会被置灰或触发执行。“一键执行”是唯一按顺序运行多个模块的入口。
- PostgreSQL 持久化项目、模块配置、扫描任务、组件、Finding、DAST 验证和 SANDBOX 证据；迁移由 Alembic 管理。
- 治理总览、项目资产视图和安全知识中枢均在主导航中可访问；高级分析折叠收纳，避免淹没日常治理信息。
- 项目安全报告 API 和前端预览支持 JSON、HTML 导出；SCA 另有独立 HTML、CycloneDX 和 SPDX 导出。

### 平台仍缺少的共性能力

- 用户登录、真实权限校验、组织/租户隔离与防篡改审计。
- 全模块统一任务队列、定时计划和分布式 Worker；目前 SAST 已有持久化队列、手动/常驻 Worker、取消与失败重试，其余模块仍是同步执行。
- 跨模块的正式合规报告、签名与报表模板体系。
- 覆盖全部模块的 CI/CD API、SDK 和外部系统集成；目前 SCA、SAST、AGENT 已提供本地 CI CLI，SCA 另有远程 API 门禁示例。

## 模块完成度与边界

| 模块 | 已实现（后端 + 前端） | 当前未完成的主要能力 |
| --- | --- | --- |
| SCA | 多生态依赖解析、版本解析质量、漏洞情报覆盖证明、风险和许可证分析、SBOM、依赖图、历史差异、哈希证据、OSV/离线情报、策略/例外/VEX、未验证组件门禁、本地 CI CLI；所有治理和可信度入口均已在 SCA 页面开放。 | 实时情报同步、签名校验、商业情报适配；真实 IAM/租户审批；所有生态的完整原生依赖树。目标项目没有锁文件/实际环境且离线库不覆盖时，平台会正确给出“部分验证/阻断”，不能给出完整无漏洞结论。 |
| SAST | 本地规则扫描、项目自定义正则规则、内置及项目自定义 Semgrep YAML 规则包（校验/预检/发布/启停/版本）、固定版 Semgrep 离线增强、Python AST 与有限跨函数污点分析、JS/TS 保守数据流、开放重定向/原始 HTML/XXE 线索、低噪声 Git 历史密钥证据、Git 基线、规则/路径豁免、扫描历史/差异、JSON/HTML/SARIF 导出、项目策略一致的离线 CI、持久化任务队列和 Finding 统一治理；另有可选 DeepSeek 七角色真实模型审计、AI 漏洞发现、证据终审、审计历史和人工修复草案；入口均已在当前 SAST 页面开放。 | 自动写入修复或提交 PR；可执行工具的自治 Agent；跨语言、跨服务、全程序数据流；运行态和业务权限漏洞的完整证明；外部漏洞知识库/RAG 和自动学习；全模块分布式调度。 |
| AGENT | 识别 Agent 指令、Prompt、Skill、MCP、工具和插件配置；结构化解析 Markdown Frontmatter、JSON、YAML、TOML，归一化资产、权限和审批边界；提取包/版本/来源/安装方式，记录文件及受限本地目录 SHA-256；以严格离线方式关联内置漏洞规则、可选本地 OSV 镜像和可选恶意包/受保护包名情报；建立带证据、依据和置信度的 Prompt→工具→资源静态路径；提供强制不执行的运行预检、敏感文件名清点、二次确认保护的 D 盘过滤 staging、逐文件/整体哈希复核和路径证据模板；项目策略、Allowlist、例外审批、质量门禁、审计、JSON/SARIF/HTML 和离线 CI 均已在 AGENT 治理页开放。 | 已能创建过滤 staging，但尚未执行无害夹具或真实 Agent，也不连接 MCP Server、不执行工具调用；静态路径不等于运行时数据流证明。本地哈希不等同远端制品认证，发布者仅为声明，本地情报未命中也不等于无漏洞。尚缺真实文件/网络/进程/工具调用观测、数字签名/Registry 身份、在线情报同步、复杂 Schema/引用解析、跨服务全程序数据流、AGENT 专用 AI 复核、可信 IAM 审批和行为回放。 |
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

- SAST：`POST /api/sast/scan`、`GET /api/sast/projects/{project_id}/findings`、`POST /api/sast/projects/{project_id}/agent-review`、`GET /api/sast/ai-health`、`POST /api/sast/ai-health/test`、`GET /api/sast/projects/{project_id}/agent-runs`、`GET/PATCH /api/sast/projects/{project_id}/profile`、`GET/POST/PATCH /api/sast/projects/{project_id}/rules`、`POST /api/sast/rules/validate`、`POST/PATCH /api/sast/projects/{project_id}/suppressions`、`GET /api/sast/projects/{project_id}/scan-history`、`GET /api/sast/projects/{project_id}/scan-diff`、`GET /api/sast/projects/{project_id}/sarif`、`GET /api/sast/projects/{project_id}/ci-config`、`GET /api/sast/tool-health`。基础扫描使用本地规则/静态分析；项目启用 AI 后，Agent 复核会真实调用 DeepSeek 七个角色，并按证据与置信度门槛写回结果。
- AGENT：`POST /api/agent/scan`；`GET /api/agent/projects/{project_id}/findings|scan-history|snapshot|scan-diff|gate|report|sarif|report.html|ci-config`；`POST /api/agent/projects/{project_id}/runtime-preflight|runtime-staging`；`GET/PATCH /api/agent/projects/{project_id}/profile`；`POST /api/agent/projects/{project_id}/exceptions`；`PATCH /api/agent/projects/{project_id}/exceptions/{exception_id}`。扫描路径必须位于项目配置的源码目录内；仅返回最新完成批次 Finding，并保存资产、权限、情报覆盖、静态数据流图/路径、预检计划、策略、门禁和批次历史。预检不复制文件；staging 接口只在二次确认和计划摘要匹配后创建过滤副本。两者都不拉取镜像或执行命令，规则或静态路径命中也不等于已完成人工、AI 或运行时复核。
- AGENT 单文件上限为 512 KiB，单资产最多持久化 500 条去重权限；超过上限会在快照元数据和前端资产结果中明确显示截断数量。
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
- SAST 默认固定 Docker 镜像为 `semgrep/semgrep:1.167.0`，也可通过 `SAST_SEMGREP_IMAGE` 显式指定另一份本地已有镜像。运行前会先执行本地镜像检查，Docker 命令固定使用 `--pull=never`；平台不会自动下载 Registry 规则或镜像。项目 YAML 规则运行副本只写入 `D:\project\PYproject\AI网安项目\artifacts\sast-offline\`，该目录已忽略。
- DeepSeek SAST Sub-agent 需要在 `apps/api/.env` 中配置有效 Key，并由后端访问 DeepSeek API；启用前应确认被测代码允许发送给第三方服务。`.env.example` 只是模板，不能填写真实密钥。
- DAST 需要可访问的目标 Web 地址；SANDBOX 需要 Docker Desktop 和可用镜像。
- 当前没有登录、权限或租户隔离，不应直接暴露到公网。

## 验证命令

2026-08-09 使用 `D:\project\PYproject\dvna` 做过真实本地验收：SAST 的 Semgrep 与本地规则均完成，生成 28 条证据，其中 Git 历史密钥证据为 2 条高置信路径；SCA 的 Docker 增强链路中 Grype、Trivy 均成功，Syft 因目标项目没有锁文件/已安装依赖而回退，19 个声明组件中仅 3 个固定版本完成漏洞匹配覆盖，16 个版本范围保持未验证，整体正确标记为 `partial` 而不是“安全”。这些数字仅是该 DVNA 快照的验收证据，不代表对任意项目保证零误报或零漏报。

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

`--offline` 使用本地规则且不依赖在线 Semgrep 规则包；`.github/workflows/sast-local.yml` 提供对应的 GitHub Actions 示例。若要让 CI 与平台项目配置完全一致，先在 SAST 页面导出 `sast-ci-config.json`，再执行：

```powershell
.\.venv\Scripts\python.exe scripts\sast_ci.py --source . --offline --profile sast-ci-config.json --json sast-result.json --sarif sast-result.sarif
```

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
