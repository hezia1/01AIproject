# 维护核实记录（2026-09-08）

本记录用于说明本轮文档更新实际核对了什么、执行了什么，以及哪些状态仍不能宣称通过。仓库实现、数据库和当次命令结果优先于历史文档。

## 仓库与验收目标

- 本轮 Skill 实现起点为 `main`，`HEAD` 与 `origin/main` 同为 `9ef98fa9fc9375b5405e81c56f52f8e6549151a4`，领先/落后为 `0/0`，工作区干净；该提交已包含前端 IPv4 地址修复和此前重新核验的文档。
- 当前验收源码仅使用 `D:\project\PYproject\testproject`。该仓库为干净的 `main`，提交 `1f8fed3`。没有使用 `D:\project\PYproject\test_project`，也没有把数据库中的 DVNA 记录当作当前验收项目。
- PostgreSQL 中与当前路径精确匹配的项目为 `test01`，ID `3968feaf-f278-437f-a5a7-1e810dae4f19`。本轮未重新执行 SCA、SAST、AGENT、DAST 或 SANDBOX 目标扫描；存量完成状态不作为本轮扫描成功证据。
- 最新只读查询显示该项目有 5 个历史完成 SAST 任务、1 个历史完成 SCA 任务和 122 条存量 Finding；没有 AGENT 扫描任务。这些数字只描述数据库存量，不代表本轮重新扫描或检测效果。

## 数据库与服务

- 声明式 Skill 表迁移后，`python -m alembic -c alembic.ini current` 返回 `20260908_0017 (head)`，与仓库迁移链头一致。
- PostgreSQL 16 与 Redis 7 容器处于运行状态。
- `GET http://127.0.0.1:8000/api/health` 返回 `{"status":"ok"}`。该接口实现只证明 HTTP 路由响应，不检查数据库、Redis、Docker、扫描器、情报新鲜度或任务成功状态。

## 后端验证

在 `apps/api` 下创建并使用真实存在的 D 盘临时目录，将 `TEMP`、`TMP`、`TMPDIR` 指向该目录后执行：

```powershell
python -B -m pytest tests -q -rs -p no:cacheprovider
```

加入 4 个 Skill 清单/匹配/权限边界测试后的最终结果：`402 passed, 1 skipped, 32 warnings`，无失败。唯一跳过项是符号链接创建用例，原因是当前 Windows 账号不允许创建符号链接。32 条告警来自 `datetime.utcnow()` 弃用提示，未作为测试通过以外的质量结论。

此前以 `35e8fdc` 为实现基线的文档更新曾运行完整套件，历史结果为 `398 passed, 1 skipped, 32 warnings`。本轮 Skill 实现后的当前结果以上述 `402 passed, 1 skipped, 32 warnings` 为准。两次测试临时目录均位于仓库 `.tmp` 下，结束后已核对绝对路径并清理；历史计数不得冒充未来提交的测试结果。

为获取跳过原因，曾在未先创建新临时目录的情况下再次设置临时目录变量；Python 回退到 `C:` 系统临时目录，18 个 Agent 暂存安全边界用例按设计失败。该环境无效运行不计入最终测试结论；创建 D 盘目录后重新执行即得到上述最终通过结果。

## 前端构建与界面冒烟

正在运行的 Vite 服务最初锁住 esbuild，第一次 `npm ci` 返回 `EPERM`，构建未开始。核实进程确属当前仓库后临时停止服务，重新执行 `npm ci` 和 `npm run build`，生产构建通过：

- Vite `7.3.6`；
- 主 JavaScript 包 `642.59 kB`，gzip `184.73 kB`；
- Vite 仍报告大于 500 kB 的分包告警。

随后重新启动 Vite 并运行七组界面冒烟：

- 通过：`test:feedback-ui`、`test:pagination-ui`、`test:auth-ui`、`test:admin-ui`、`test:governance-ui`、`test:sandbox-ui`。
- 失败：`test:agent-ui` 在 1600px 的“动态验证不是五步向导”断言失败。数据库核实当前 `testproject` 没有 AGENT 扫描任务，因此页面没有运行计划可供五步流程渲染；本轮不借用 DVNA 数据，也不把这一结果写成通过。
- AGENT 脚本在断言后未及时退出，定向终止了该脚本的两个子进程；Vite 与 API 服务未被终止。

随后提交 `35e8fdc` 将 Vite 固定监听 `127.0.0.1:5173` 并启用严格端口。本次实际验证 `test:dev-server`、IPv4 HTTP 访问、生产构建和双角色登录界面冒烟均通过；第二个 Vite 实例在 5173 已占用时按预期明确失败，没有静默改用其他端口。该定向结果不改变上述 AGENT 冒烟的未解决状态。

界面测试使用唯一临时管理员。管理中心脚本创建的临时项目和普通用户已清理；首次删除临时管理员时，`user_sessions` 外键要求先删除会话，清理事务回滚。随后按会话、审计、成员关系、用户的顺序完成清理，并把维护策略版本、操作者和更新时间恢复到测试前状态。最终核实临时账号和临时项目数量均为 0。

## 验收结论与边界

- 声明式 Skill 定向测试 `4 passed`；真实数据库路由函数完成创建、发布、对 `testproject` 执行和历史读取。执行读取 42 条当前有效 Finding，匹配 14 条高危/严重且具位置证据的 SAST Finding；这不是重新扫描或检测效果指标。临时 Skill、运行记录和 3 条对应审计已清理。
- 当前环境缺少 Starlette `TestClient` 所需的 `httpx2`，因此没有把 HTTP 客户端路径写成通过；同一路由函数和真实 PostgreSQL 会话验证通过。新增 `npm run test:skill-ui`，前端使用独立 `AUTH_DISABLED=true` 测试服务做 1440px/390px 浏览器冒烟，入口、能力边界和无横向溢出断言通过，随后停止独立测试服务；原 5173/8000 服务保持运行。

- 已审核根目录、API、Web、产品、架构、模块、路线图、管理配置、CI、SANDBOX、交接、反馈和验收文档；测试 fixture 内的 README 仅描述测试输入，不作为项目现状文档改写。
- `acceptance/criteria.json` 已通过严格 JSON 解析和重复键检查；本轮删除了会被普通 JSON 解析器静默覆盖的重复 `status` 字段，并统一基线 ID 与实现来源提交。
- 仓库内 Markdown 本地链接检查通过，未发现缺失目标；未发现遗留合并冲突标记。
- `acceptance_check.py --profile baseline` 用于校验清单结构；它不会自动运行测试、检查链接或连接数据库。
- `--profile baseline` 通过；`--profile p0` 因 `frontend_production_build` 仍为部分验证而失败；`--profile production` 按预期列出六个尚未满足的项目并失败。
- 完整后端套件已具备当前证据，`backend_test_suite` 可标记为 `verified`。
- 前端生产构建通过，但七组冒烟未全部通过，因此前端综合项保持 `partially_verified`，P0 门禁仍应失败。
- 检测准确率、召回率、误报率、DAST 重放率、生态兼容率和生产就绪度均没有新增基准，不得从本轮测试或存量数据库推导数值。
