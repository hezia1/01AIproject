# P0 量化验收基线

基线 ID：`2026-08-28-p0`。机器可读事实位于 [`acceptance/criteria.json`](../acceptance/criteria.json)，校验器位于 [`scripts/acceptance_check.py`](../scripts/acceptance_check.py)。

## 结论

P0 的文档对齐、能力声明、后端回归、前端构建和数据库迁移检查已形成可复现证据。当前版本仍是单机研发/演示基线，不具备生产发布资格。

以下指标没有版本化标注语料，当前值必须保持“未建立基线”：

- SCA/SAST/AGENT 精确率、误报率和召回率。
- DAST 重复运行裁决一致率和证据完整率。
- 所有声明生态、语言和版本的兼容成功率。
- SANDBOX 的完整隔离负例、逃逸抵抗和独立安全评估。
- IAM、租户隔离、部署、备份、恢复和证据保护等生产就绪度。

现有测试数量、Finding 数量和演示项目结果不能替代这些质量指标。

## 当前记录

| 检查 | 状态 | 当前证据 | 主要限制 |
| --- | --- | --- | --- |
| 历史文档对齐 | 已验证 | 提交 `b19dcaf` | 只证明文档口径一致 |
| 能力声明校准 | 已验证 | 注册表、前端回退、报告边界与回归测试 | 不替代扫描效果评估 |
| 后端自动化测试 | 已验证 | 295 passed、1 skipped、0 failed | 必须使用 D 盘临时目录 |
| 前端生产构建 | 已验证 | `npm run build` 成功 | 主包约 539.72 KiB；无 UI 自动化测试 |
| 数据库迁移 | 已验证 | `20260817_0013 (head)` | 不是生产升级/回滚验证 |
| 检测准确率/召回率 | 未建立基线 | 无 | 缺少标注正负样本集 |
| DAST 复现率 | 未建立基线 | 无 | 缺少版本化重放语料 |
| 生态兼容率 | 部分验证 | 解析器与代表性测试 | 缺少完整版本矩阵 |
| SANDBOX 隔离 | 部分验证 | 策略测试与安全/MCP fixture | 无完整观测或独立逃逸评估 |
| 生产就绪度 | 未建立基线 | 无 | IAM、租户、部署与运维控制未完成 |

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
```

数据库迁移：

```powershell
python -m alembic -c alembic.ini current
```

## 后续补齐方式

每个未建立基线的指标都需要固定语料版本、样本来源、正负标签、重复次数、计算公式、阈值、失败样例和产物哈希。完成测量后更新 `criteria.json` 的 `current`、`evidence` 与 `status`，并将语料或可验证引用纳入版本控制；不能仅修改文档中的数字。
