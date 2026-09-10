# P0 量化验收基线

基线 ID：`2026-09-10-security-benchmarks`。机器可读事实位于 [`acceptance/criteria.json`](../acceptance/criteria.json)，校验器位于 [`scripts/acceptance_check.py`](../scripts/acceptance_check.py)。本轮命令与环境证据见 [维护核实记录](maintenance-verification-2026-09-10-benchmarks.md)。

## 结论

文档对齐、能力声明、模块真实诊断、CI 状态/认证、完整后端回归、前端生产构建和数据库迁移检查已形成当前证据。十一组已记录界面冒烟中十组具备通过证据，AGENT 冒烟因当前验收项目没有 AGENT 扫描基线而失败，因此机器可读 P0 当前仍不通过。当前版本仍是单机研发/演示基线，不具备生产发布资格。

项目所有者已决定暂时忽略由 `testproject` 不包含 AGENT 内容导致的 AGENT 综合冒烟失败。该决定只调整当前实施优先级，不把失败改写为通过；机器可读 P0 清单在验收口径另行调整前仍保持失败。PPT 最终平台的完整差距和优先级见 [`platform-target-gap-register.md`](platform-target-gap-register.md)。

检测效果和 DAST 已有最小版本化基线，但下列范围仍不完整：

- SCA/SAST/AGENT 只有少量规则与成对样本，不能外推全平台指标。
- DAST 只有合同四态、两类成对目标和 `testproject` 四类探针，不是全策略复现率。
- 所有声明生态、语言和版本的兼容成功率。
- SANDBOX 的完整隔离负例、逃逸抵抗和独立安全评估。
- IAM、租户隔离、部署、备份、恢复和证据保护等生产就绪度。

现有测试数量、Finding 数量和演示项目结果不能替代这些质量指标。

## 当前记录

| 检查 | 状态 | 当前证据 | 主要限制 |
| --- | --- | --- | --- |
| 当前文档对齐 | 已验证 | 2026-09-10 对照 HEAD、数据库迁移、当前验收项目、完整后端结果、生产构建与界面冒烟 | 文档核对不替代检测效果基准 |
| 能力声明校准 | 已验证 | 注册表、前端回退、报告边界与回归测试 | 不替代扫描效果评估 |
| 后端自动化测试 | 已验证 | D 盘真实临时目录下完整套件 `444 passed, 1 skipped`，无失败 | 32 条 `datetime.utcnow()` 与 2 条 FastAPI `on_event` 弃用告警；符号链接用例因当前 Windows 账号不允许创建链接而跳过 |
| 前端生产构建与冒烟 | 部分验证 | `npm run build`、模块诊断 1440px/390px、`test:dev-server` 和 IPv4 HTTP 成功；认证故障、Skill、图谱及此前业务冒烟有通过证据 | AGENT 冒烟在 `testproject` 无 AGENT 扫描基线时失败；主包 661.92 kB，仍有分包告警 |
| 项目模块真实诊断 | 已验证 | SCA/SAST/AGENT/DAST/SANDBOX 独立展示任务派生状态、情报时效、模型调用证据和目标状态；`testproject` 只读 API 与双视口冒烟通过 | 默认时效阈值 168 小时；不主动访问任意目标或调用付费模型；诊断正常不表示无漏洞 |
| CI 状态与认证 | 已验证（当前本地身份范围） | API/CLI 状态矩阵、失败 JSON/SARIF、HTTPS 认证客户端、401/403/伪成功负例和真实 login/gate/logout；`testproject` 平台 stale、本地 partial 均退出 2 | GitHub 托管执行器尚未连接真实可达 HTTPS 平台；本地用户会话不等于生产 OIDC 或细粒度服务账号 |
| 管理员配置归位 | 已验证 | 管理员创建/版本/发布 Skill，并选择 SCA/SAST/AGENT 完成触发；普通用户只能读取和手动执行已发布版本 | Skill 仅复核现有 Finding；外部包安装/签名、定时或其他事件触发、命令/资源上限和 DAST 公共映射未完成 |
| 数据库迁移 | 已验证 | `20260909_0019 (head)`；5 个内置 Skill，`testproject` 代码/业务图谱均为 v1 | 已在当前开发数据库完成 `0019 → 0018 → 0019`；回退会按设计删除图谱快照，不是生产备份/回复验证 |
| 陌生项目冷启动 | 已验证 | 本地目录、受控 ZIP、HTTP(S) Git 接入；准备度 API；有界快速扫描；API 冒烟 | 私有仓库仍依赖主机 Git 凭据；DAST/SANDBOX 仍需授权运行目标 |
| 检测准确率/召回率 | 部分验证 | 最小 v1 的 SAST 5 规则、AGENT 3 规则、SCA 1 对样本；`testproject` 官方清单 15/30 | 内部 100% 只适用于小语料，缺第二外部来源与更多生态 |
| DAST 复现率 | 部分验证 | 四态合同 12 次、成对实际目标 12 次均一致；`testproject` 四类探针 12/12 exploitable | 只覆盖当前策略子集，身份、初始化、超时与更多执行器负例暂缓 |
| 生态兼容率 | 部分验证 | 解析器与代表性测试 | 缺少完整版本矩阵 |
| SANDBOX 隔离 | 部分验证 | 策略测试与安全/MCP fixture | 无完整观测或独立逃逸评估 |
| 本地两角色登录 | 部分验证 | scrypt 密码哈希、HttpOnly 会话、首次管理员初始化、公开注册固定为普通用户、普通用户管理员接口 403、双角色浏览器冒烟 | 不等于生产 IAM；尚无外部身份源、密码恢复、项目级隔离和独立安全评估 |
| 生产就绪度 | 未建立基线 | 无 | 生产 IAM、租户、部署与运维控制未完成 |

## 执行命令

先验证清单结构和所有状态语义：

```powershell
.\.venv\Scripts\python.exe scripts\acceptance_check.py --profile baseline
```

P0 门禁要求所有 P0 项均为 `verified`：

```powershell
.\.venv\Scripts\python.exe scripts\acceptance_check.py --profile p0
```

生产门禁当前应失败，并列出尚未完成的指标：

```powershell
.\.venv\Scripts\python.exe scripts\acceptance_check.py --profile production
```

后端测试：

```powershell
$testTemp = Join-Path (Resolve-Path .) '.tmp\pytest'
New-Item -ItemType Directory -Force -Path $testTemp | Out-Null
$env:TEMP = $testTemp
$env:TMP = $testTemp
$env:TMPDIR = $testTemp
cd apps\api
..\..\.venv\Scripts\python.exe -m pytest tests -q
```

前端构建：

```powershell
cd apps\web
npm ci
npm run build
npm run test:feedback-ui
npm run test:pagination-ui
npm run test:auth-ui
npm run test:admin-ui
npm run test:agent-ui
npm run test:governance-ui
npm run test:sandbox-ui
npm run test:skill-ui
npm run test:graphs-ui
npm run test:diagnostics-ui
```

数据库迁移：

```powershell
python -m alembic -c alembic.ini current
```

## 后续补齐方式

扩展任一基线都需要继续固定语料版本、样本来源、正负标签、重复次数、计算公式、阈值、失败样例和产物哈希。不能把当前小样本数值外推，也不能仅修改文档中的数字。

当前决定暂缓的检测语料、DAST 重放、生产 IAM 和 SANDBOX 完整安全评估统一在 [`deferred-work.md`](deferred-work.md) 跟踪；任一事项开始或完成时必须同步更新该文档。
