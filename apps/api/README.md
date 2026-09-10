# API 服务

FastAPI 服务承载项目、模块、SCA、SAST、AGENT、DAST、SANDBOX、ASPM 和项目图谱 API。项目、任务、Finding、组件、动态验证、证据和图谱快照均持久化到 PostgreSQL，数据库结构通过 Alembic 管理。代码图谱只读源码，业务图谱只聚合已存储的项目事实，两者都不执行项目代码。

文档按 2026-09-10 仓库实现复核；最新运行结果见 [检测基准维护核实记录](../../docs/maintenance-verification-2026-09-10-benchmarks.md)。

当前 SAST 后台任务由 `scripts/sast_worker.py` 轮询 PostgreSQL 队列；本地基础设施包含 Redis，但 SAST 队列仍使用 PostgreSQL，尚不是生产级分布式任务系统。

API 已启用本地用户名/密码登录、数据库持久化会话和 `user` / `admin` 两角色权限。密码保存为 scrypt 哈希，会话使用 `ai_security_session` HttpOnly Cookie；公开注册只创建普通用户，用户与规则/平台策略管理等操作由后端检查管理员权限。首次启动通过 Web 或 `POST /api/auth/bootstrap` 初始化管理员；平台不提供默认账号。除健康检查和身份初始化/登录/注册状态接口外，请求需要有效会话；未登录通常返回 401，管理员尚未初始化时返回 503，普通用户越权返回 403。

目前仍为共享的本地工作区，没有生产级项目/租户隔离、外部身份源、MFA、密码恢复或完整会话管理。Cookie 当前设置为 `SameSite=Lax`、`Secure=false`；这些本地开发设置不能视作生产部署加固。`AUTH_DISABLED=true` 会绕过登录并提供测试管理员身份，只能用于隔离测试，不能用于绕过实际 CI 接入所需的鉴权。生产身份与隔离待办见 [deferred-work.md](../../docs/deferred-work.md)。

## 本地启动

```powershell
cd apps/api
..\..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

首次运行应先在仓库根目录创建虚拟环境、安装 `apps/api/requirements.txt`、复制 `.env.example`，并执行：

```powershell
python -m alembic -c alembic.ini upgrade head
```

健康检查：<http://127.0.0.1:8000/api/health>。它检查 API、PostgreSQL、Redis、Docker、固定 SCA 工具镜像和 Semgrep：必需依赖失败返回 HTTP 503，可选依赖失败返回 HTTP 200 与 `degraded`。认证初始化可使用 `?include_optional_tools=false` 跳过较慢的本机工具探测。项目级 `GET /api/projects/{project_id}/diagnostics` 另行聚合情报时效、已保存模型调用证据、目标和最近任务的派生状态；默认 168 小时时效阈值可通过 `.env.example` 中四项诊断变量配置。工具就绪或任务完成不代表无漏洞。接口文档：<http://127.0.0.1:8000/docs>；当前中间件也保护文档路径，请先在同一主机名下完成登录。

SCA 门禁接口只在扫描派生状态为 `succeeded` 且风险政策通过时返回 pass；失败、部分、未完成、缺失、无效和陈旧任务均阻断。GitHub Actions 使用专用普通用户的现有 Cookie 登录，不增加权限；配置及退出码见 [SCA CI 门禁说明](../../docs/sca-ci-gate.md)。

## 测试

下面的 `tests` 命令执行完整后端测试；它是操作说明，不代表本轮已运行。日常修改仍应先选择直接相关测试，记录实际执行范围与结果。

Agent 运行时安全边界要求临时目录位于 `D:` 盘：

```powershell
cd ..\..
$testTemp = Join-Path (Resolve-Path .) '.tmp\pytest'
New-Item -ItemType Directory -Force -Path $testTemp | Out-Null
$env:TEMP = $testTemp
$env:TMP = $testTemp
$env:TMPDIR = $testTemp
cd apps\api
..\..\.venv\Scripts\python.exe -m pytest tests -q
```
