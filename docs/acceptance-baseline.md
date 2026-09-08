# P0 量化验收基线

基线 ID：`2026-09-04-action-feedback`。机器可读事实位于 [`acceptance/criteria.json`](../acceptance/criteria.json)，校验器位于 [`scripts/acceptance_check.py`](../scripts/acceptance_check.py)。

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
| 历史文档对齐 | 已验证 | 2026-08-31 冷启动接入、AGENT 与 SCA/SAST 治理界面基线及 Git 历史 | 只证明文档口径一致 |
| 能力声明校准 | 已验证 | 注册表、前端回退、报告边界与回归测试 | 不替代扫描效果评估 |
| 后端自动化测试 | 定向验证 | 2026-09-04 前一轮维护配置：维护策略、SCA/SAST 策略、SCA 工具、SANDBOX、配置权限六个文件合计 120 passed；此前 62 passed 和全量 317 passed/1 skipped 为历史记录 | 最新按钮反馈仅修改前端，未重跑后端测试；不能将先前结果当作本轮重跑结果 |
| 前端生产构建 | 已验证 | `npm run build` 成功；统一反馈、分页、管理中心、双角色登录，以及 AGENT、SCA/SAST、SANDBOX 七组浏览器冒烟通过 | 主包约 642.59 kB；Vite 仍有分包体积告警 |
| 管理员配置归位 | 已验证 | 1600px/390px 模块分类布局、临时项目真实配置保存、普通用户写入 403、启停不重置政策、DAST 普通用户授权确认 | 另通过 10/10/3 分页、SCA/SAST 编辑、维护策略并发与权限验证；未执行新的目标扫描；命令/资源上限、DAST 公共映射和新 Skill 系统未完成 |
| 数据库迁移 | 已验证 | `20260904_0016 (head)` | 不是生产升级/回滚验证 |
| 陌生项目冷启动 | 已验证 | 本地目录、受控 ZIP、HTTP(S) Git 接入；准备度 API；有界快速扫描；API 冒烟 | 私有仓库仍依赖主机 Git 凭据；DAST/SANDBOX 仍需授权运行目标 |
| 检测准确率/召回率 | 未建立基线 | 无 | 缺少标注正负样本集 |
| DAST 复现率 | 未建立基线 | 无 | 缺少版本化重放语料 |
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
npm run test:agent-ui
npm run test:governance-ui
npm run test:sandbox-ui
```

数据库迁移：

```powershell
python -m alembic -c alembic.ini current
```

## 后续补齐方式

每个未建立基线的指标都需要固定语料版本、样本来源、正负标签、重复次数、计算公式、阈值、失败样例和产物哈希。完成测量后更新 `criteria.json` 的 `current`、`evidence` 与 `status`，并将语料或可验证引用纳入版本控制；不能仅修改文档中的数字。

当前决定暂缓的检测语料、DAST 重放、生产 IAM 和 SANDBOX 完整安全评估统一在 [`deferred-work.md`](deferred-work.md) 跟踪；任一事项开始或完成时必须同步更新该文档。
