# 项目交接快照

> 文件名因历史链接保留；正文已更新到 **2026-08-28**，不再代表 2026-07-26 的实现状态。

## 当前结论

六模块的研发与演示闭环已经存在：SCA、SAST、AGENT 可执行静态扫描；DAST 可从受支持的 SAST/AGENT Finding 生成有界验证；SANDBOX 可在 Docker 中启动一次性目标并采集固定探针证据；ASPM 可在单项目范围汇总、关联、整改、复测和出报告。

当前不是生产级企业平台。最重要的未完成项是：能力声明与量化验收基线、生产 IAM/租户隔离、前端工程化测试与拆分、可靠分布式任务、部署与敏感证据保护、跨项目治理。

## 已验证状态

- 分支：`main`，远端：`origin`。
- API、Web、PostgreSQL、Redis 可在本地启动；API 健康检查正常。
- Alembic 数据库迁移已到 `20260817_0013 (head)`。
- 后端测试在 `D:` 盘临时目录下为 **291 passed, 1 skipped**；使用默认 `C:` 盘临时目录会因 Agent 暂存安全规则出现预期失败。
- 前端生产构建通过；当前主包约 539 kB，Vite 有分包体积告警，且没有自动化前端测试。
- 本地数据库已有 SCA/SAST/AGENT/DAST/SANDBOX/ASPM 联调数据；这些数据是本机状态，不是仓库交付物或通用性能基准。

## 启动顺序

```powershell
docker compose -f infra\docker-compose.yml up -d
python -m alembic -c alembic.ini upgrade head
```

后端：

```powershell
cd apps\api
..\..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

前端：

```powershell
cd apps\web
npm ci
npm run dev
```

完整配置、扫描流程和测试命令以根目录 [`README.md`](../README.md) 为准。

## 当前能力边界

### SAST

- 已有项目规则、有限语义分析、Git 基线和可选七角色 AI 复核。
- `security_skill` 是单次复核输出，知识关联主要来自当前项目历史；没有已交付的企业 Skill 库、行业历史漏洞库或跨项目自动学习。

### DAST

- 当前候选来自 SAST/AGENT，SCA 不进入队列。
- 源码动态映射主要覆盖 EJS 与 JavaScript/TypeScript 文件族。
- 红/绿裁决必须满足类型专属证据条件；证据不足保持黄色或未验证。

### SANDBOX

- 已有受控启动规划、Docker 隔离、固定探针、事件和证据摘要。
- 自动辅助服务只覆盖 PostgreSQL/Redis。
- 没有完整文件、网络、进程、环境变量、系统调用监控，也没有 AI 自主攻击。

### ASPM

- 已有单项目总览、证据图、攻击链、整改、复测和报告。
- 没有项目组、跨项目趋势/关联、SLA、工单、授权配额、完整审计中心或生产合规报告。

### 平台

- 数据库虽有身份/租户模型，但请求链路没有可用的生产身份中间件；大部分接口仍使用开发租户。
- Redis 当前不是核心队列；API/Web 没有生产部署编排。
- 真实密钥、客户源码、离线情报和运行证据不得提交 Git。

## 下一执行顺序

1. P0：校准模块注册表、前端回退文案和报告边界，建立量化验收基线。
2. P1：前端拆分和自动化测试、可靠任务系统、API/Web 部署工程化。
3. P2：IAM/租户隔离、证据保护、跨项目治理和企业运维能力。

## 交接纪律

- 规划不能写成现有能力；外部依赖必须标记为有条件实现。
- 不得把未验证、阻塞或黄色解释为安全。
- 不得为准确率、召回率、误报率、DAST 复现率和兼容率填造数据。
- 每次修改都应运行与风险相称的测试、形成独立 Git 提交并推送远端。
- `.tmp/`、`artifacts/`、`outputs/` 和 `.env` 中的本地内容不进入提交。
