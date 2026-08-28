# API 服务

FastAPI 服务承载项目、模块、SCA、SAST、AGENT、DAST、SANDBOX 和 ASPM API。项目、任务、Finding、组件、动态验证和证据均持久化到 PostgreSQL，数据库结构通过 Alembic 管理。

当前 SAST 后台任务由 `scripts/sast_worker.py` 轮询 PostgreSQL 队列；Redis 已随本地基础设施启动，但尚不是生产级分布式任务系统。API 当前没有可用的登录鉴权和生产级租户隔离，不应直接暴露到公网。

## 本地启动

```powershell
cd apps/api
..\..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

首次运行应先在仓库根目录创建虚拟环境、安装 `apps/api/requirements.txt`、复制 `.env.example`，并执行：

```powershell
python -m alembic -c alembic.ini upgrade head
```

健康检查：<http://127.0.0.1:8000/api/health>；接口文档：<http://127.0.0.1:8000/docs>。

## 测试

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
