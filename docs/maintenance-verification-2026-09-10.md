# 2026-09-10 模块级真实诊断维护核实

本记录只描述本轮“情报时效、模型服务、被测目标及扫描任务状态”实现和现场证据。仓库、数据库与实际运行结果优先于历史文档；诊断结果不是新的目标扫描，也不构成检测效果或无漏洞证明。

## 仓库与数据基线

- 开始时仓库位于 `main`，工作区干净；HEAD 与 `origin/main` 同为 `f1c35c7a94def27414d90e95fe80add4ffca1d37`，领先/落后 `0/0`，远端为 `https://github.com/hezia1/01AIproject.git`。
- 数据库和仓库迁移链均为 `20260909_0019 (head)`；本轮没有新增数据库迁移，也没有改写扫描任务、项目、账号、会话、模型配置或动态目标。
- 当前验收对象仅为数据库项目 `test01`（`3968feaf-f278-437f-a5a7-1e810dae4f19`）及源码 `D:\project\PYproject\testproject`。源码仓库为干净 `main`，HEAD 为 `1f8fed353712940752a7bd9d7ddff06a65fb4791`。未使用 `D:\project\PYproject\test_project` 或 DVNA。

## 根因与实现

根因是基础 `/api/health` 只能证明 API、数据库、Redis、Docker 和已准备扫描工具的当前就绪情况；模块证据分散在扫描元数据、情报文件、模型运行、目标健康和动态任务表中。数据库的 `completed` 不能单独表达范围不完整或证据陈旧，模型密钥存在不能证明服务调用成功，历史 HTTP 200 也不能覆盖目标已经停止的事实。前端此前没有统一入口展示这些差异。

本轮增加以下通用实现：

- 新增统一时效合同和任务派生状态。持久化状态原样保留，API 另行返回 `diagnostic_status`、完整性、陈旧标志、年龄和理由；静态扫描可派生为 `partial`，超过默认 168 小时可派生为 `stale`。
- 新增 `GET /api/projects/{project_id}/diagnostics`，按 SCA、SAST、AGENT、DAST、SANDBOX 聚合最近任务、SCA 在线 OSV/本地镜像/补充情报/Grype 数据库、SAST 与 DAST 模型配置和已保存调用、SANDBOX 目标健康证据。
- 检测页增加“模块真实诊断”。接口失败显示“状态未知”，模型只有配置时显示“已配置未验证”，已停止目标不因旧探测成功显示为可用；状态口径明确说明任务成功不等于无漏洞。
- 时效上限可通过 `SCAN_DIAGNOSTIC_MAX_AGE_HOURS`、`SCA_INTELLIGENCE_MAX_AGE_HOURS`、`SCA_OSV_MIRROR_MAX_AGE_HOURS`、`MODEL_DIAGNOSTIC_MAX_AGE_HOURS` 配置，默认均为 168 小时。

实现没有 `testproject` 文件名、路由、变量、行号或目录分支。AGENT 的“不适用”来自通用项目资产盘点：模块已启用、没有扫描记录且没有识别到 Agent/MCP/插件资产时才成立。接口不主动访问任意外部目标，不为诊断发起付费模型调用，没有改变扫描器、工具编排或角色权限。

## 实际 testproject 诊断

在一次性 `AUTH_DISABLED=true` 的 8001 API 和 5174 Vite 服务上，对精确项目 ID、名称和源码路径三者一致的 `test01` 进行只读请求：

| 模块 | 模块状态 | 最近任务派生状态 | 现场依据 |
| --- | --- | --- | --- |
| SCA | `degraded` | `stale` | 原状态仍为 `completed`，约 205.4 小时；保证元数据为部分完成，在线 OSV 为 `offline_degraded` 且 1 个组件查询错误；本地 OSV 镜像和补充情报未配置；Grype 数据库为 `current` |
| SAST | `ok` | `succeeded` | 原状态为 `completed`，约 110.5 小时；Semgrep 执行完整；模型已配置但没有保存的成功调用证据，该模型检查为可选项 |
| AGENT | `not_applicable` | `not_applicable` | 源码盘点未识别到 Agent、MCP 或插件配置，且没有 AGENT 任务；这与项目所有者暂时忽略 AGENT 综合冒烟的决定一致，但不写成扫描通过 |
| DAST | `degraded` | `stale` | 最近动态运行约 205.3 小时；目标持久化状态为 `stopped`，旧 HTTP 200 仅作为历史详情；模型已配置但没有成功调用证据 |
| SANDBOX | `degraded` | `stale` | 最近任务约 205.3 小时；关联目标当前为 `stopped` |

项目整体为 `degraded`。`GET /api/scans` 的 6 条历史静态任务也返回派生字段：最新 SAST 为 `succeeded`，SCA 和 4 条更早 SAST 为 `stale`；数据库原状态均未改变。两次早期只读核实因 PowerShell 对 JSON 数组的筛选方式错误形成包含多个 UUID 的请求，API 正确返回 422；随后使用已核实的唯一项目 ID 并校验名称和源码路径后取得上述结果，没有读取 DVNA 诊断或修改数据。

## 验证结果

- 定向后端：`186 passed, 30 warnings`，覆盖诊断合同、项目路由、平台健康、SCA 保证与治理、SAST 治理、AGENT、SANDBOX 和 DAST 策略。
- Python 编译检查：`python -B -m compileall -q app` 通过。
- 完整后端：D 盘专用临时目录下 `428 passed, 1 skipped, 34 warnings`，无失败。唯一跳过为当前 Windows 账号不能创建 symlink；告警为 32 条既有 `datetime.utcnow()` 和 2 条 FastAPI `on_event` 弃用提示。
- 前端生产构建：通过；最大 JavaScript 包 `661.92 kB`，gzip `190.51 kB`，Vite 大包告警仍存在。
- 项目诊断界面：真实 `test01` 在 1440px 和 390px 均通过，页面宽度分别为 `1440/1440`、`390/390`，没有横向溢出；五模块、情报、模型、目标和状态合同均可见。
- 日常服务：现场 8000 与 5173 均在监听，`http://127.0.0.1:5173` 返回 HTTP 200；`test:dev-server` 通过。
- 数据库迁移：从仓库根目录执行 Alembic，返回 `20260909_0019 (head)`。一次从 `apps/api` 错误目录执行因找不到根目录配置而失败，随后按仓库实际配置位置更正；这不是迁移失败。

完整测试专用目录已删除，隔离 API/Vite 已停止，8001/5174 均无监听。本轮没有创建测试账号、会话、项目、扫描、模型调用、目标或配置。AGENT 综合冒烟按项目所有者决定未运行，机器可读 P0 中该既有失败仍保留。

## 剩余事项

- 下一优先级仍是 `CI-002`：让 CI 门禁按失败、部分、排队/运行、缺失和陈旧状态阻断，再处理 `CI-001` 的受控认证。
- 模块诊断只基于当前配置和已保存证据，不主动探测任意目标；若将来增加显式连接测试，必须有权限、超时、费用和数据出境边界。
- 前端主包分包、检测效果语料、DAST 重放、生产 IAM/租户隔离、可靠任务和 SANDBOX 安全评估仍按差距总表与暂缓清单跟踪。
