# 维护核实记录（2026-09-08）

本记录用于说明本轮文档更新实际核对了什么、执行了什么，以及哪些状态仍不能宣称通过。仓库实现、数据库和当次命令结果优先于历史文档。

## 仓库与验收目标

- 核实起点为 `main`，`HEAD` 与 `origin/main` 同为 `7a384b3f9690ed445e48db622c61b0fff4ebd31b`，领先/落后为 `0/0`。
- 开始时已有 16 个未提交文件，共 185 行新增、84 行删除；这些内容作为用户已有修改保留并继续完成，没有撤销或清理。
- 当前验收源码仅使用 `D:\project\PYproject\testproject`。该仓库为干净的 `main`，提交 `1f8fed3`。没有使用 `D:\project\PYproject\test_project`，也没有把数据库中的 DVNA 记录当作当前验收项目。
- PostgreSQL 中与当前路径精确匹配的项目为 `test01`，ID `3968feaf-f278-437f-a5a7-1e810dae4f19`。本轮未重新执行 SCA、SAST、AGENT、DAST 或 SANDBOX 目标扫描；存量完成状态不作为本轮扫描成功证据。

## 数据库与服务

- `python -m alembic -c alembic.ini current` 返回 `20260904_0016 (head)`，与仓库迁移链头一致。
- PostgreSQL 16 与 Redis 7 容器处于运行状态。
- `GET http://127.0.0.1:8000/api/health` 返回 `{"status":"ok"}`。该接口实现只证明 HTTP 路由响应，不检查数据库、Redis、Docker、扫描器、情报新鲜度或任务成功状态。

## 后端验证

在 `apps/api` 下创建并使用真实存在的 D 盘临时目录，将 `TEMP`、`TMP`、`TMPDIR` 指向该目录后执行：

```powershell
python -B -m pytest tests -q -rs -p no:cacheprovider
```

最终结果：`398 passed, 1 skipped, 32 warnings`，无失败。唯一跳过项是符号链接创建用例，原因是当前 Windows 账号不允许创建符号链接。32 条告警来自 `datetime.utcnow()` 弃用提示，未作为测试通过以外的质量结论。

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

界面测试使用唯一临时管理员。管理中心脚本创建的临时项目和普通用户已清理；首次删除临时管理员时，`user_sessions` 外键要求先删除会话，清理事务回滚。随后按会话、审计、成员关系、用户的顺序完成清理，并把维护策略版本、操作者和更新时间恢复到测试前状态。最终核实临时账号和临时项目数量均为 0。

## 验收结论与边界

- `acceptance_check.py --profile baseline` 用于校验清单结构；它不会自动运行测试、检查链接或连接数据库。
- 完整后端套件已具备当前证据，`backend_test_suite` 可标记为 `verified`。
- 前端生产构建通过，但七组冒烟未全部通过，因此前端综合项保持 `partially_verified`，P0 门禁仍应失败。
- 检测准确率、召回率、误报率、DAST 重放率、生态兼容率和生产就绪度均没有新增基准，不得从本轮测试或存量数据库推导数值。
