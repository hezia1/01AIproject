# AI 原生应用安全检测、验证与治理平台

本仓库用于逐步实现 `01.pptx` 中描述的平台：面向软件供应链、复杂业务系统和 AI Agent 生态的应用安全检测、动态验证与治理平台。

当前阶段为 MVP 工程启动阶段，已建立：

- `docs/`：PRD、技术架构、MVP 路线图。
- `apps/api/`：FastAPI 后端骨架。
- `apps/web/`：React 控制台骨架。
- `infra/`：本地基础设施配置。

## MVP 闭环

第一版目标是跑通：

```text
项目创建 -> 仓库接入 -> 扫描任务 -> SCA/SAST 结果 -> AI 复核 -> 漏洞治理 -> 报告导出
```

## 本地开发

### API

```powershell
cd apps/api
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

健康检查：

```text
http://localhost:8000/api/health
```

### Web

```powershell
cd apps/web
npm install
npm run dev
```

访问：

```text
http://localhost:5173
```

## 下一步开发顺序

1. 接入 PostgreSQL，替换内存数据。
2. 将六个安全模块配置持久化。
3. 前端模块能力中心接入真实 API。
4. 实现 Worker 与本地仓库扫描目录。
5. 实现 SCA 模块，先做依赖文件解析和组件清单。
6. 实现 SAST 模块，先覆盖硬编码密钥和危险调用。
7. 接入 AI 复核网关。

## 六个可选安全模块

平台按 PPT 第三页拆为六个可选接入模块：

- SAST：智能静态审计
- SCA：供应链风险分析
- AGENT：Agent 供应链安全
- DAST：漏洞动态验证
- SANDBOX：沙箱动态证据链
- ASPM：平台治理与交付

详细设计见 `docs/module-system.md`。

## PostgreSQL 持久化进度

当前后端已经从内存存储切到数据库模型，开发模式下会在 FastAPI 启动时自动创建表。

新增环境变量示例见：

```text
apps/api/.env.example
```

启动顺序：

```powershell
# 1. 先打开 Docker Desktop，确认 Docker Engine 已 Running

# 2. 启动 PostgreSQL 和 Redis
docker compose -f infra/docker-compose.yml up -d

# 3. 安装后端依赖
.\.venv\Scripts\python.exe -m pip install -r apps\api\requirements.txt

# 4. 启动 API
cd apps/api
..\..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

当前已持久化的对象：

- projects
- project_modules
- scan_tasks
- findings

后续要补：

- Alembic 正式迁移
- security_modules 表或版本化模块注册快照
- components / SBOM 组件表
- reports 报告表
- worker_jobs 扫描执行表

## SCA 第一版组件清单扫描

当前已实现 SCA 基础扫描，不依赖外部安全工具，使用 Python 标准库解析：

- package.json
- requirements.txt
- pom.xml
- go.mod

接口：

```text
POST /api/sca/scan
GET  /api/sca/projects/{project_id}/components
```

扫描请求示例：

```json
{
  "project_id": "<project uuid>",
  "source_path": "D:\\path\\to\\source-code",
  "clear_previous": true
}
```

当前输出字段：

- ecosystem
- name
- version
- dependency_type
- source_file
- package_manager
- license
- risk_status

当前边界：

- 只生成组件清单。
- 暂不匹配 CVE。
- 暂不判断许可证风险。
- 暂不解析 lockfile 的传递依赖。
- 后续 SCA 二期再接 Syft、Grype、Trivy 或 OSV。 

## SAST 第一版基础规则扫描

当前已实现 SAST 基础扫描，不依赖 Semgrep 等外部工具，使用 Python 标准库正则规则扫描源码目录。

接口：

```text
POST /api/sast/scan
GET  /api/sast/projects/{project_id}/findings
```

扫描请求示例：

```json
{
  "project_id": "<project uuid>",
  "source_path": "D:\\path\\to\\source-code",
  "clear_previous": true
}
```

当前覆盖规则：

- 疑似硬编码密码
- 疑似硬编码 API Key 或 Secret
- 危险命令执行调用
- 危险动态代码执行
- 疑似 SQL 字符串拼接
- 疑似用户可控 SSRF 请求
- 疑似路径穿越风险
- 弱加密或弱哈希算法使用

当前边界：

- 只做文本规则扫描。
- 不做 AST 分析。
- 不做跨函数数据流。
- 不做 AI 复核。
- 不做多 Agent 审计。
- 后续可接 Semgrep、自定义规则库和 AI 复核流程。

## AGENT 第一版配置风险扫描

当前已实现 AGENT 基础扫描，不运行 Agent，不调用模型，只扫描 Agent/MCP/插件相关配置与说明文件中的危险能力声明。

接口：

```text
POST /api/agent/scan
GET  /api/agent/projects/{project_id}/findings
```

扫描请求示例：

```json
{
  "project_id": "<project uuid>",
  "source_path": "D:\\path\\to\\agent-configs",
  "clear_previous": true
}
```

当前扫描文件：

- .md
- .yaml
- .yml
- .json
- .toml
- AGENTS.md
- CLAUDE.md
- mcp.json
- plugin.json

当前覆盖规则：

- Agent 配置允许读取环境变量或密钥
- Agent 工具暴露 Shell 或命令执行能力
- Agent 工具具备文件写入或删除能力
- Agent 工具允许外部网络请求
- MCP 或插件权限范围过宽
- 提示词包含忽略安全策略或覆盖指令风险

当前边界：

- 不运行 Agent。
- 不执行 MCP Server。
- 不连接插件源。
- 不做真实工具调用矩阵。
- 不做信任评分模型。
- 后续可扩展为规则检测 + AI 审计 + 覆盖矩阵 + 信任评分。

## DAST 第一版动态验证记录

当前已实现 DAST 第一版，不做自动攻击探测，不调用 OWASP ZAP，不发送 payload。第一版用于记录人工动态验证裁决和证据摘要。

接口：

```text
POST  /api/dast/validations
GET   /api/dast/projects/{project_id}/validations
PATCH /api/dast/validations/{validation_id}
```

创建验证记录示例：

```json
{
  "project_id": "<project uuid>",
  "finding_id": "<optional finding uuid>",
  "target_url": "https://example.com/login",
  "verdict": "exploitable",
  "validator": "security-user",
  "evidence_summary": "验证账号可复现越权访问。",
  "request_summary": "GET /api/admin/users",
  "response_summary": "返回非授权用户列表。",
  "reproduction_steps": "登录普通账号后直接访问接口。",
  "remediation_hint": "补充服务端权限校验。"
}
```

裁决值：

- exploitable
- uncertain
- not_exploitable

当前边界：

- 不做自动爬虫。
- 不生成 payload。
- 不主动攻击目标。
- 不接 ZAP/Nuclei。
- 后续可扩展为静态发现联动验证、策略生成、请求响应证据归档和自动复测。

## SANDBOX 第一版运行策略与证据链记录

当前已实现 SANDBOX 第一版，不真实启动容器，不执行命令，不做运行时监控。第一版用于记录沙箱运行策略和人工观察到的动态证据。

接口：

```text
POST  /api/sandbox/evidence
GET   /api/sandbox/projects/{project_id}/evidence
PATCH /api/sandbox/evidence/{evidence_id}
```

创建证据记录示例：

```json
{
  "project_id": "<project uuid>",
  "finding_id": "<optional finding uuid>",
  "run_command": "python agent_runner.py",
  "runtime_profile": "python-agent",
  "network_policy": "restricted",
  "filesystem_policy": "readonly",
  "observed_files": [{"path": ".env", "action": "read"}],
  "observed_network": [{"host": "api.example.com", "action": "connect"}],
  "observed_processes": [{"command": "python agent_runner.py"}],
  "observed_tool_calls": [{"tool": "shell", "arguments": "whoami"}],
  "evidence_summary": "Agent 尝试读取 .env 并调用 shell 工具。",
  "operator": "security-user"
}
```

当前边界：

- 不真实执行 run_command。
- 不启动 Docker 沙箱。
- 不采集真实文件、网络、进程事件。
- 不接 eBPF/Sysmon。
- 后续可扩展为容器隔离执行、运行时行为采集、工具调用账本和 AI 驱动动态验证。

## ASPM 第一版统一治理视图 API

当前已实现 ASPM 第一版，不新增独立治理表，直接聚合各模块已有数据，按项目输出统一治理概览。

接口：

```text
GET /api/aspm/projects/{project_id}/summary
```

当前聚合字段：

- enabled_modules
- risk_score
- component_count
- finding_count
- dast_validation_count
- sandbox_evidence_count
- scan_task_count
- findings_by_source
- findings_by_severity
- findings_by_status
- dast_by_verdict

临时风险分规则：

- critical finding: +12
- high finding: +8
- medium finding: +4
- low finding: +1
- exploitable DAST verdict: +10
- uncertain DAST verdict: +3
- sandbox evidence: 每条 +2，最多 +10
- 总分封顶 100

当前边界：

- 不做 SLA。
- 不做攻击链。
- 不做工单流转。
- 不做 CI/CD 安全门禁。
- 不做合规报告导出。
- 后续可扩展为治理看板、整改闭环、门禁策略和报告中心。

## 前端统一模块任务中心与治理总览

当前前端已新增统一任务中心和 ASPM 治理总览，将六个模块第一版从 API 能力推进到页面可操作。

新增视图：

- 模块接入：启用/停用六个安全模块。
- 任务中心：触发 SCA、SAST、AGENT，录入 DAST 验证和 SANDBOX 证据。
- SCA 清单：查看组件清单。
- 治理总览：查看 ASPM 项目汇总、风险分、findings 统计和最新风险发现。

当前页面可调用：

```text
POST /api/sca/scan
POST /api/sast/scan
POST /api/agent/scan
POST /api/dast/validations
POST /api/sandbox/evidence
GET  /api/aspm/projects/{project_id}/summary
```

当前边界：

- 仍是单项目演示流。
- DAST 和 SANDBOX 是人工记录，不执行真实动态测试。
- SAST 和 AGENT 是基础规则扫描。
- 后续需要补项目创建向导、多项目切换、任务历史和更完整的详情页。
