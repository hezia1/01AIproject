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
- `apps/web/src/main.tsx` 中的 `AgentView`
- 通用 Finding、DAST/SANDBOX 关联和 ASPM 展示代码

### 已实现的后端能力

- `POST /api/agent/scan`：验证项目和 AGENT 模块启用状态，同步扫描本地源码路径，创建扫描任务并持久化 AGENT Finding。
- `GET /api/agent/projects/{project_id}/findings`：读取项目 AGENT Finding。
- 扫描 `.md`、`.yaml`、`.yml`、`.json`、`.toml`，以及 `Dockerfile`、`AGENTS.md`、`CLAUDE.md`、`mcp.json`、`.mcp.json`、`mcp.config.json`、`claude_desktop_config.json`、`plugin.json`、`tools.json`。
- 忽略 `.git`、`node_modules`、虚拟环境、构建产物等目录，并跳过超过 512 KiB 的文件。
- 文本规则识别：读取环境密钥、Shell/命令执行、文件写删、外部网络访问、MCP/插件通配权限、安全指令覆盖和内联令牌。
- MCP JSON 结构化检查：无效 JSON、危险启动命令、危险参数、内联环境密钥、敏感路径和网络能力。
- Finding 保存规则 ID、等级、分类、文件位置、脱敏证据、说明、修复建议和信任影响。
- AGENT Finding 可进入通用 Finding 治理，并可与 DAST、SANDBOX 和 ASPM 的证据链能力关联。

### 已在前端可见

- AGENT 页面可填写源码路径并单独执行扫描。
- 显示 Finding 总数、严重/高危数、风险分类和严重等级分布。
- 列表展示等级、分类、标题、文件/行号、证据、修复建议和信任影响，支持每页 10 条分页。
- 单独执行 AGENT 时只锁定 AGENT 模块，不应导致其他模块置灰或触发扫描。

### 尚未完善或容易产生歧义的部分

- 当前主要是规则表达式和有限 MCP JSON 检查，不会启动真实 Agent、连接 MCP Server、调用插件工具或验证运行时行为。
- 扫描器会检查大量通用 Markdown/JSON/YAML/TOML 文件，尚未先建立“真实 Agent 资产清单”，可能把普通项目文档或配置误判为 Agent 资产。
- 缺少针对不同格式的完整结构化解析：Agent 指令层级、MCP transport/tool/resource/prompt、插件 manifest、Skill/Prompt 包、模型/Provider 配置和工具 Schema 尚未形成统一资产模型。
- 缺少能力与权限矩阵：文件系统范围、命令参数、网络目的地、密钥作用域、人工审批、可写资源和跨工具数据流没有统一展示。
- 页面文案提到“信任评分”，但当前代码只有 Finding 的 `trust_impact` 文本，没有可解释、可复算的项目/资产信任分。新窗口必须修复这种前端超前表达。
- 缺少扫描历史快照、批次差异、仅新增风险、抑制/例外、规则版本、质量门禁、JSON/SARIF/HTML 专项报告和本地 CI CLI。
- 当前查询可能混合展示历次 AGENT Finding；需要核查重扫时旧 Finding 的关闭、去重和“当前批次”语义。
- 缺少来源与完整性证据：配置/插件来源、版本、包哈希、签名、发布者、锁定版本、安装方式和已知漏洞没有形成供应链结论。
- 缺少提示注入信任边界和数据流建模：外部内容如何进入模型上下文、如何影响工具调用、是否有 sanitizer/审批/allowlist，目前没有可复核路径。
- 缺少 AGENT 专项准确性测试和真实样例矩阵；现有后端测试主要覆盖平台通用能力，不能证明 AGENT 对实际项目稳定准确。
- SAST 的 DeepSeek Key 和七角色流水线不会自动让 AGENT 模块获得 AI 分析能力。若 PPT 要求 AGENT 使用第三方模型，需要单独设计数据边界、提示词、审计、费用和降级策略，并再次获得用户确认。

## 6. 新窗口推荐的 AGENT 推进顺序

最终范围必须等用户重新发送 PPT 后再确定。建议按以下顺序评估，不要直接全部实现：

1. **PPT 需求映射与事实审计**：逐条对应 PPT，列出已实现、未实现、前端可见和页面误导项。
2. **准确扫描基础**：先识别 Agent/MCP/插件/Skill/Prompt 资产，再按格式结构化解析；增加证据脱敏、噪声排除、规则版本和测试样例。
3. **权限与信任模型**：建立资产—能力—资源—边界矩阵，设计可解释信任评分，评分必须能追溯到具体证据，不能用虚构 AI 分数。
4. **治理与交付**：增加扫描历史、批次差异、抑制/例外、质量门禁、报告、SARIF/JSON 和本地 CI；保证前端只展示真实能力。
5. **可选动态验证**：只有 PPT 和用户明确要求时，才考虑在 SANDBOX 内启动受控 MCP/Agent、采集工具调用和行为证据；不得直接在宿主机执行未知 Agent 或插件。
6. **可选真实 AI 分析**：只有用户批准代码/配置发送边界和 API 费用后，才可设计 AGENT 专用模型复核；它不能复用文案冒充已实现能力。

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
