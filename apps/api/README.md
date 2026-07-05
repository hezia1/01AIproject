# API 服务

MVP 后端采用 FastAPI，当前版本先提供内存数据实现，用于确定接口契约和前端联调。

后续阶段会替换为 PostgreSQL、Redis 队列和扫描 Worker。

## 本地启动

```powershell
cd apps/api
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

