# 项目交接文档（更新于 2026-08-10）

本文件用于在新窗口继续完善 **AI 网络安全检测、验证与治理平台**。下一阶段由用户重新发送原始 `01.pptx`，并重点完善 **AGENT 供应链安全模块**。新窗口不得依赖旧对话结论，应以重新提供的 PPT、仓库根目录 `README.md`、本文件和实际代码共同判断需求与完成度。

用户已经明确选择 AGENT 作为下一阶段；因此 `README.md` 末尾较早写入的“下一步推荐 ASPM”不再代表当前优先级。除这一优先级外，README 中的架构、启动方式和模块边界仍是有效参考。

## 1. 新窗口必须先做的事情

正式仓库只有：

```text
D:\project\PYproject\AI网安项目
```

不要读取或修改旧目录：

```text
C:\Users\hezia\Documents\AI网络安全项目
```

收到用户重新发送的 `01.pptx` 后，先完整读取 PPT、`README.md` 和本文档，再执行：

```powershell
Set-Location 'D:\project\PYproject\AI网安项目'
git status --short --branch
git log -5 --oneline
```

随后应重新核对：

1. PPT 对 AGENT 模块的原始目标、页面语义和与其他模块的关系。
2. AGENT 已有后端能力、前端可见性和实际检测准确性。
3. PPT 要求但代码未实现的内容，以及页面上可能超前宣传的能力。
4. 在修改代码前，先向用户列出推荐实现范围并等待确认。

协作规则：

- 每次修改代码前，先说明本次要实现的功能和范围，等待用户确认。
- 每次代码更新后都要提交并推送 GitHub。
- 文档、只读检查和测试不属于代码修改；但文档更新也应提交、推送以便交接。
- 如需下载 AGENT 规则、镜像或测试资源，只能放在 D 盘。建议统一使用 `D:\project\PYproject\AI网安项目\artifacts\agent-offline\`，并保持 Git 忽略；创建或下载前仍应说明用途。
- 不打印、不提交 `apps/api/.env` 中的 DeepSeek Key；`.env.example` 只能保留变量名和安全示例。

## 2. 当前 Git 和验证基线

更新本文档前的代码基线：

```text
18991cb Harden SCA and SAST scan assurance
0933a71 Simplify SAST governance workspace
0307fe9 Complete DeepSeek SAST sub-agent integration
bd482d1 Complete SAST offline governance fixes
47bbc0f Isolate module execution state and refresh
```

本文档更新前 `main` 与 `origin/main` 一致，工作区无未提交代码。实际状态始终以新窗口执行的 Git 命令为准。

最近一次完整验证：

- 后端：`56 passed`。
- 前端：TypeScript 与 Vite 生产构建成功。
- DVNA SAST：Semgrep 与本地规则均完成，生成 28 条静态证据；Git 历史密钥证据收敛为 2 条高置信路径。
- DVNA SCA Docker 增强：Grype、Trivy 成功；Syft 因目标缺少锁文件/安装目录而回退；19 个组件中 3 个固定版本完成漏洞覆盖，16 个版本范围保持未验证，整体正确显示 `partial`。

常用验证命令：

```powershell
Set-Location 'D:\project\PYproject\AI网安项目\apps\api'
$env:PYTHONPATH='.'
..\..\.venv\Scripts\python.exe -m pytest -q

Set-Location 'D:\project\PYproject\AI网安项目\apps\web'
npm run build
```

## 3. 当前架构与启动方式

```text
React + Vite 前端 → /api → FastAPI routers/services → PostgreSQL
```

重要目录：

```text
apps/api/app/routers/       API 路由
apps/api/app/services/      扫描与治理逻辑
apps/api/app/rules/         本地规则
apps/api/tests/             后端测试
apps/web/src/main.tsx       当前 React 控制台主要页面和 API 调用
infra/docker-compose.yml    PostgreSQL / Redis
artifacts/                  本地离线资源，Git 忽略
```

本地启动：

```powershell
Set-Location 'D:\project\PYproject\AI网安项目'
docker compose -f infra\docker-compose.yml up -d
.\.venv\Scripts\python.exe -m alembic -c alembic.ini upgrade head

Set-Location 'D:\project\PYproject\AI网安项目\apps\api'
..\..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

另开终端：

```powershell
Set-Location 'D:\project\PYproject\AI网安项目\apps\web'
npm run dev
```

前端通常为 `http://127.0.0.1:5173`，后端健康检查为 `http://127.0.0.1:8000/api/health`。平台当前是本地单机模式，不要求登录、注册或租户初始化。

## 4. SCA 与 SAST 当前状态

### SCA

SCA 已具备多生态依赖解析、锁文件/实际环境版本解析、SBOM、依赖图、历史差异、OSV/离线情报、Syft/Grype/Trivy、许可证策略、例外、VEX、证据、报告和 CI 门禁。当前会区分“已验证未发现”和“未验证”：版本范围、缺失版本或情报不可用不会被误报为安全，默认门禁阻断未验证组件。可信度和覆盖率已在前端显示。

仍有明确边界：没有锁文件、实际安装环境或可用漏洞情报时，只能输出部分验证；实时商业情报、所有生态完整原生依赖树、真实 IAM/租户审批仍未实现。

### SAST

SAST 已具备本地规则、固定版离线 Semgrep、自定义正则/YAML 规则治理、Python AST 与有限跨函数数据流、JS/TS 保守数据流、Git 基线与低噪声历史密钥证据、豁免、历史差异、JSON/HTML/SARIF、CI 配置和持久化 Job/Worker。

SAST 还接入了真实 DeepSeek 七角色流水线：策略、漏洞发现、漏洞复核、证据分析、历史知识、修复建议和独立复核。只有七个角色全部返回必需结构才标记完成，失败会明确降级且保留本地扫描结果。

注意：**SAST 的 DeepSeek Sub-agent 与本次要完善的 AGENT 供应链安全模块不是同一个模块。** 前者用于复核源码漏洞；后者用于评估 Agent 指令、MCP、工具和插件本身的供应链与权限风险。

## 5. AGENT 模块当前真实实现

关键文件：

- `apps/api/app/routers/agent.py`
- `apps/api/app/services/agent_scanner.py`
- `apps/api/app/services/agent_intelligence.py`
- `apps/api/app/services/agent_dataflow.py`
- `apps/api/app/services/agent_runtime_validation.py`
- `apps/api/app/services/agent_staging.py`
- `apps/api/app/services/agent_fixture_runtime.py`
- `apps/api/app/services/agent_target_runtime.py`
- `apps/api/app/services/agent_trust.py`
- `apps/web/src/main.tsx` 中当前实际渲染的 `FindingModuleGovernance` 与 Agent 扫描覆盖面板
- 通用 Finding、DAST/SANDBOX 关联和 ASPM 展示代码

### 已实现的后端能力

- `POST /api/agent/scan`：验证项目和 AGENT 模块启用状态，并强制扫描路径位于项目配置的源码目录内；同步扫描、创建扫描任务并持久化 AGENT Finding。
- `GET /api/agent/projects/{project_id}/findings`：只读取最新完成批次的 AGENT Finding；重扫时旧的活动 Finding 会关闭并标记为已被新批次替代。
- `GET /api/agent/projects/{project_id}/scan-history`：返回最近扫描状态、资产覆盖、Finding 数量和规则版本。
- `GET /api/agent/projects/{project_id}/snapshot`：返回最新完成批次的逐资产清单、能力权限矩阵和跳过文件原因。
- `GET /api/agent/projects/{project_id}/scan-diff`：比较最近两个完成批次，区分资产新增/移除/变化和权限扩大/收缩。
- 先识别 Agent 资产再扫描：指令文件、Prompt、Skill、MCP 配置、插件清单、工具定义和 Agent 专用配置；不再把普通 Markdown/JSON/YAML/TOML 一概当作 Agent 资产。
- 结构化解析 Markdown YAML Frontmatter、JSON、YAML 与 TOML；从 MCP、插件、Skill、Prompt 和工具配置中提取名称、版本、发布者、传输方式、启动入口、工具/资源/Prompt 声明。
- 生成“资产—主体—能力—访问方式—资源类型—范围—审批—风险—配置路径”权限矩阵，并对命令参数、URL 凭据和密钥值进行脱敏。
- 忽略 `.git`、`node_modules`、虚拟环境、构建产物等目录，并跳过超过 512 KiB 的文件。
- 文本规则识别：读取环境密钥、Shell/命令执行、文件写删、外部网络访问、MCP/插件通配权限、安全指令覆盖和内联令牌。
- JSON 结构化检查：无效 JSON、通配权限、Shell/文件写入/网络能力和内联凭据；MCP 另检查危险启动命令、危险参数、敏感路径、Header/环境凭据和远程地址。
- Finding 保存规则 ID、等级、分类、文件位置、脱敏证据、说明、修复建议和信任影响；本地规则元数据明确标记为 `local_rule / not_reviewed`。
- AGENT Finding 可进入通用 Finding 治理，并可与 DAST、SANDBOX 和 ASPM 的证据链能力关联。
- 项目级治理策略已接入：规则停用、路径排除、强制审批能力、权限 Allowlist，以及带版本和审计记录的策略保存。
- Finding/权限例外已接入申请、批准、拒绝、撤销和失效时间；仅批准且未过期的例外会影响后续扫描，历史批次不改写。
- 扫描会计算质量门禁：严重等级/最大数量、仅新增、通配权限、解析失败、跳过文件、权限扩大和高风险审批声明；裁决与原因随快照保存。
- 已提供 JSON、SARIF 2.1.0、HTML 报告、CI 配置导出和 `scripts/agent_ci.py` 本地离线 CLI；CLI 可读取上一份 JSON 报告作为基线。
- 已从 MCP、插件、Skill 和 Agent 配置提取包名、版本、来源类型/引用和安装方式，识别未锁定版本、HTTP/含凭据来源、本地路径逃逸与来源未知。
- 每个可读资产记录精确文件 SHA-256；项目内插件/Skill 目录在 2,000 文件、32 MiB 上限内生成目录 SHA-256，链接、越界、不可读或超限会标记为部分证据。
- 批次差异和门禁已接入来源变化、完整性变化、未锁定/不安全/未知来源与部分哈希；报告和本地 CI 使用同一证据模型。
- 已将 npm/PyPI 来源转换为包坐标与 purl，使用内置规则和可选本地 OSV 镜像做精确版本关联；严格区分命中、已覆盖未命中、未覆盖、版本未解析和不支持。
- 已支持可选本地恶意包记录与受保护包名混淆检查；本地文件未配置时明确显示 `not_configured`，不生成虚假恶意结论。
- 情报来源、覆盖、更新时间/年龄和逐包证据会进入扫描快照、Finding、门禁、JSON/SARIF/HTML 和离线 CI；漏洞/恶意包/混淆默认阻断，覆盖缺口和过期阻断为可选策略。
- 已建立 Prompt/指令、Agent、工具和资源节点及有向边；边记录显式资产类型、显式权限、同资产共同声明或保守推断依据，并标注高/中/低置信度。
- 已生成同资产 Prompt→Agent→工具→资源路径、可疑指令跨配置文件到高风险工具的低置信度项目级路径，以及密钥访问到网络外联的潜在路径；路径包含已声明控制、缺失控制和逐步证据。
- 数据流 Finding、严重/高风险路径门禁、快照、JSON/SARIF/HTML 和离线 CI 已接入；Allowlist/例外不会被误当成运行时防护，审批声明也不会被描述成已验证执行。
- 已实现 AGENT 运行预检计划和 `POST /api/agent/projects/{project_id}/runtime-preflight`；当前硬编码 `preflight-only / execution_enabled=false`，不创建 staging、不联系 Docker daemon、不拉取镜像、不安装依赖、不运行命令。
- 预检强制检查显式单命令、危险/下载/安装/提权/嵌套容器/密钥枚举/Shell 控制符、digest 固定镜像、Docker CLI、禁网、只读、drop-all、无宿主环境/Socket、资源限制和人工确认。
- 项目源码不会作为未来 AGENT 运行时的直接挂载源；预检只按名称统计敏感文件类别且自身不复制。独立二次确认的 staging 接口现可在 `artifacts/agent-sandbox/staging/<project-id>/<build-id>` 创建排除 `.env`/凭据/私钥/VCS 元数据的过滤副本并生成摘要。
- 已定义运行证据模板与纯函数关联：计划/镜像/staging 摘要，进程、文件、网络、工具调用，以及静态路径的 observed / blocked_by_policy / not_observed / not_run 状态；测试使用合成事件，不执行目标程序。
- 已实现二次确认保护的过滤 staging 构建：绑定精确预检 SHA-256，在 D 盘唯一目录原子创建且不覆盖，排除敏感命名/内容信号、链接、VCS/依赖/缓存/构建与 artifacts，拒绝越界、非普通文件、源文件竞态和数量/字节超限。
- staging manifest 记录逐文件/整体/manifest SHA-256、复制与排除清单；落盘后重新验证全部清单文件并拒绝额外、缺失或篡改内容。该动作不联系 Docker，也不产生运行证据。
- 仓库包含 `apps/api/tests/fixtures/agent_runtime_safe` 无害离线夹具；复制层测试覆盖排除、摘要、防覆盖和防篡改，运行层只执行固定 `policy_probe.py`。
- 已实现固定无害夹具容器策略验收：只发现本地 Python digest 镜像，强制 `--pull=never` 和固定参数数组；Docker 配置与容器内探针共同验证禁网、根/工作区只读、非 root、drop-all、no-new-privileges、无宿主环境/Socket、tmpfs、CPU/内存/PID 和超时。
- 2026-08-12 最终真实夹具验收使用本地 `python@sha256:423ed6ab…` 和本机 named-pipe Docker Context，未下载；30/30 检查通过，退出码 0、未超时、临时容器已删除。staging SHA-256 `c4488238e024…`，证据 SHA-256 `12b6ba8666b6…`；证据位于 D 盘忽略目录，不提交生成物。
- fixture evidence 明确标记 `scope=repository-harmless-fixture-only` 和 `execution_enabled_for_real_agents=false`，不能作为真实 Agent、MCP 或插件的运行证明。
- 已实现可解释、可复算的 AGENT 信任评分：资产发现/解析 15、来源/版本/哈希 20、离线情报 20、权限/审批 15、Prompt→工具→资源路径 20、受控运行验证 10。
- 评分保存分项、扣分证据、证据数量、证据完整度、置信度、评分上限、改进建议和确定性 `trust_sha256`，并接入快照、JSON/HTML 报告、离线 CI 和可选质量门禁。
- 未执行目标 Agent 时只给运行预检 3/10 且静态总分最高 90、置信度最高为中；无害夹具证据不增加目标分数，情报 `checked_no_match` 不会被表达成安全结论，接受风险不会擦除技术扣分，误报只取消对应 Finding 的直接扣分，独立底层证据仍可能扣分。
- 已实现指定项目 Agent 的安全执行器代码和接口，项目策略默认关闭；执行前强制核对扫描/计划/命令/镜像/超时/staging/manifest 绑定，并在容器创建后、启动前复核固定 Docker 隔离策略。
- 真实目标容器固定 `--pull=never`、禁网、只读、非 root、drop-all、no-new-privileges、无宿主环境或 Socket、IPC/PID 隔离、资源/超时/日志上限和关闭镜像 Healthcheck；命令使用参数数组，不经过 Shell。日志正文不保存或返回，只记录脱敏后的长度、摘要与截断状态。
- 当前目标证据只观察主进程、容器策略和工作区前后完整性，子进程、逐文件访问、网络尝试目的地和工具调用明确为未插桩，因此只给运行分 7/10、总分最高 95、置信度最高为中。
- 2026-08-14 已在用户单独批准后，对仓库内自建代表性 MCP 集成目标完成首次真实目标验证；没有修改 DVNA、没有下载镜像或依赖。独立项目 ID `76292d96-1c24-4284-aded-27938798a053`，扫描批次 `a08de58b-59ba-41d8-badf-693b620f4146`，5 个资产、3 个静态 Finding、8 个 staging 文件，24/24 项运行策略检查通过，退出码 0、未超时、容器已删除，信任分 82。
- 本次精确绑定：计划 SHA-256 `793e8bdae5ec14112a878b9a71e356f3e81a7dd2d312e23f2187f89389731660`，staging SHA-256 `6128a33146ed2b9933bf9c7c31494b7c571c466d3cd03254227a5c5d55b15893`，manifest SHA-256 `c64d029b8463824c4ecd8b22368f830611a569420b0f1a884203b66881391eff`，目标证据 SHA-256 `96475d9a5ab1a9af662bec6684c8bf5a10410f74f6f7e74a102a6d19c2595800`。生成物位于 D 盘 Git 忽略目录，不提交仓库。
- 真实运行暴露并修复了 Docker `local` 日志驱动 `max-file=1` 与默认压缩不兼容的问题；执行器现在显式使用 `compress=false` 并在 inspect 检查中验证，仍保留 1 MiB 单文件上限。
- 代表性 MCP 夹具的离线协议测试已完成 initialize、tools/list、tools/call、resources/list/read、prompts/list/get；真实目标证据仍只观察主进程、容器策略和工作区完整性，工具调用、子进程、文件访问和网络目的地未插桩，不得把本次结果表述为完整行为取证或生产安全认证。

### 已在前端可见

- AGENT 页面可填写源码路径并单独执行扫描。
- 显示最新扫描状态、资产数量、解析成功/失败/跳过数量、规则版本、Finding 总数、严重/高危数、待人工复核数、风险分类和严重等级分布。
- 显示逐资产清单、版本/发布者/传输/入口、工具/资源/Prompt 声明、权限矩阵、审批状态以及资产和权限语义差异。
- AGENT 治理页已显示项目扫描策略、Allowlist、例外申请/审批、当前门禁原因、项目策略审计以及 JSON/SARIF/HTML/CI 导出入口。
- AGENT 治理页已显示来源/安装/版本锁定、发布者声明状态、文件或目录 SHA-256、完整性问题及批次变化。
- AGENT 治理页已显示本地漏洞/恶意包情报源状态、路径、条目、年龄、逐包覆盖状态、CVE/规则命中和包名混淆信号；页面明确说明本地源未命中不等于无漏洞。
- AGENT 治理页已显示 Prompt→工具→资源路径序列、等级、置信度、证据、Prompt/工具资产位置、已声明控制和缺失控制，并明确区分静态声明与运行时事实。
- AGENT 治理页已显示受控运行预检、阻断原因、拟定命令/镜像（敏感参数脱敏）、D 盘过滤 staging 位置、隔离策略、高风险候选路径和未来证据模型；“只执行安全预检”按钮不会运行命令。
- 同一面板已提供独立二次确认的“创建并校验过滤副本”入口，显示唯一 D 盘目录、复制/排除数量、staging/manifest SHA-256；页面明确说明该动作不授权 Agent 或容器执行。
- 折叠的“无害夹具容器策略验收”区显示本地 digest 镜像、真实运行确认、最近结果、策略通过数、证据 SHA-256 和 D 盘位置，并明确限定为仓库夹具。
- AGENT 治理页已显示可解释信任总分、六个分项、扣分依据、证据完整度/置信度、评分上限、改进建议和证据摘要哈希；低分门禁默认关闭，可由项目显式启用并配置阈值。
- 受控运行面板已将预检、创建过滤副本、无害夹具和指定项目 Agent 真实运行分成四个入口；真实目标入口显示项目默认关闭策略、绑定副本、固定确认短语、最近策略结果、有限插桩范围和证据位置，不展示 Agent 标准输出。
- 列表展示等级、分类、标题、文件/行号、证据、修复建议和信任影响，支持每页 10 条分页。
- 单独执行 AGENT 时只锁定 AGENT 模块，不应导致其他模块置灰或触发扫描。

### 尚未完善或容易产生歧义的部分

- 静态扫描本身仍不会启动 Agent、连接 MCP Server 或调用插件工具。指定目标执行器默认关闭；现已对仓库内代表性 MCP 目标完成一次单独批准的真实运行，但任何其他项目仍须单独开启策略、完成精确绑定和二次确认。
- 已形成跨 Markdown Frontmatter、JSON、YAML、TOML 的统一资产与权限快照；仍缺少各厂商完整 Schema 校验、复杂继承/引用解析和模型 Provider 的专用适配。
- 已展示文件系统范围、命令与参数标志、网络目的地、密钥字段、工具能力和人工审批，并形成带置信度的静态路径；仍缺少不可信输入跨 Prompt/工具/资源传播的运行时证明。
- 已有批次级可解释、可复算的项目信任分；尚未下钻为逐资产独立分，也不应把该分数表述为安全认证或发布者身份验证。
- 已有扫描历史、规则版本、语义差异、例外、质量门禁、JSON/SARIF/HTML 专项报告和本地 CI CLI；“只阻断新增”已进入门禁，但前端尚无单独的“仅新增 Finding”列表视图。
- 已具备本地来源声明、版本锁定状态、文件/目录 SHA-256 和本地漏洞/恶意包情报关联，但哈希只用于本地批次比较，发布者仍是未验证声明；数字签名、Registry 身份、远端制品哈希、在线情报同步和商业情报适配尚未实现。
- 已完成配置级 Prompt/指令→工具→资源的静态信任边界和可复核路径；仍缺少运行时外部内容进入上下文的真实观测、复杂 sanitizer 语义、跨进程/跨服务传播和动态可利用性证明。
- 已增加 AGENT 专项测试，覆盖资产识别、否定语句、正向能力、结构化权限、证据脱敏、标准 npx MCP、无效 JSON，以及自建 stdio MCP 的工具/资源/Prompt 协议冒烟与受控运行链路；仍需扩充真实第三方生态样例矩阵。
- SAST 的 DeepSeek Key 和七角色流水线不会自动让 AGENT 模块获得 AI 分析能力。若 PPT 要求 AGENT 使用第三方模型，需要单独设计数据边界、提示词、审计、费用和降级策略，并再次获得用户确认。

## 6. 新窗口推荐的 AGENT 推进顺序

最终范围必须等用户重新发送 PPT 后再确定。建议按以下顺序评估，不要直接全部实现：

1. **PPT 需求映射与事实审计（已完成）**：已逐条核查已实现、未实现、前端可见和页面误导项。
2. **准确扫描基础（已完成）**：已识别 Agent/MCP/插件/Skill/Prompt 资产，增加多格式解析、证据脱敏、噪声排除、规则版本和专项测试。
3. **权限模型（已完成）**：已建立资产—主体—能力—访问—资源范围—审批—风险矩阵和批次语义差异，并已纳入可解释信任评分。
4. **治理与交付（已完成）**：扫描历史、批次差异、项目策略、Allowlist、例外审批、质量门禁、报告、SARIF/JSON/HTML 和本地 CI 已实现并从前端开放。
5. **来源完整性（已完成本地基础）**：包/版本/来源/安装方式、文件及受限目录 SHA-256、来源与哈希差异和门禁已实现；签名和 Registry 身份仍是后续阶段。
6. **离线漏洞与恶意包情报（已完成本地基础）**：内置规则、可选本地 OSV 镜像、可选恶意包和受保护包名情报已关联到精确包坐标、门禁、报告和前端；不会自动下载或联网同步，未命中不代表无漏洞。
7. **Prompt → 工具 → 资源数据流建模（已完成静态基础）**：已建立带依据/置信度的节点、边、风险路径、控制缺口、Finding、门禁、报告和前端；它不是运行时传播证明。
8. **受控沙箱预检与证据模型（已完成第一阶段）**：已完成强制不执行的计划、敏感文件名清点、隔离策略、D 盘 staging 要求、静态路径候选和证据结构；预检自身不复制、不拉取镜像、不运行目标。
9. **过滤 staging 与无害夹具（已完成）**：可审计复制、排除规则、链接/越界拒绝、竞态检查、字节/文件上限、唯一构建、摘要与复核已完成；无害夹具与代表性 MCP 目标均已完成受控执行验收。
10. **无害夹具容器策略验收（已完成）**：固定夹具、本地 digest 镜像、禁拉取、双重策略证据、超时和临时容器清理均已实现并完成一次 30/30 真实验收；这不证明真实 Agent 安全。
11. **可解释信任评分（已完成批次级基础）**：六个固定分项、扣分证据、置信度、评分上限、改进建议、快照/报告/CI/前端和可选低分门禁已实现；当前不是资产级评分或安全认证。
12. **指定 Agent 运行时验证（执行器与首次代表性目标验收已完成）**：默认关闭、绑定清单、固定 Docker 策略、有限观测证据、报告/前端/信任分接入已实现，并已完成一次自建代表性 MCP 目标的真实受控运行；DVNA 和外部生产 Agent 未执行。完整子进程/文件/网络尝试/工具调用插桩仍未完成，后续每个新目标仍须用户明确批准具体目录、digest 镜像、命令和资源边界，并提前说明任何下载。
13. **可选真实 AI 分析**：只有用户批准代码/配置发送边界和 API 费用后，才可设计 AGENT 专用模型复核；它不能复用文案冒充已实现能力。

每个阶段都应先给出本次具体实现范围、测试方式、前端变化和明确边界，等待用户确认后再改代码。

## 7. 其他模块边界

- DAST 当前是人工关联和轻量 HTTP 基础检查，不是 SQL 注入、鉴权绕过等业务漏洞的自动利用证明。
- SANDBOX 当前提供受限 Docker 执行、资源限制、禁网/只读、输出脱敏和执行摘要；不是 eBPF/Sysmon 级完整行为取证。
- ASPM 当前汇总 Finding、证据、攻击链和整改状态；真实 IAM、SLA/工单、完整审计和图数据库推理仍未实现。
- 平台前端仍是 React + Vite，不是 Vue；不要再次进行未经单独确认的整体前端迁移。

## 8. 新窗口可直接使用的提示词

```text
继续完善 D:\project\PYproject\AI网安项目，本窗口重点完善 AGENT 模块。

请不要依赖旧对话记录。先完整读取我重新提供的原始 01.pptx、README.md、docs/PROJECT_HANDOFF_2026-07-26.md 和当前代码，再执行：

git status --short --branch
git log -5 --oneline

正式仓库只使用 D:\project\PYproject\AI网安项目，不要修改 C:\Users\hezia\Documents\AI网络安全项目。

请先根据 PPT 和实际代码重新列出 AGENT 已完成、未完成以及前端可见性，指出页面是否存在超前或误导文案。不要直接改代码；先给出最推荐的下一步和明确实现范围，等我确认。

规则：每次修改代码前先说明功能并等待确认；每次代码更新后提交并推送 GitHub。如需下载规则、镜像或测试资源，只放 D 盘并先说明用途。
```
