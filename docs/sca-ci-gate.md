# SCA CI 门禁接入

状态：平台 API 门禁、本地 CLI 状态语义和 GitHub Actions Cookie 认证已在当前单机研发范围实现。2026-09-10 的状态矩阵、真实 `testproject` 与认证链路证据见 [维护核实记录](maintenance-verification-2026-09-10-ci.md)。

## 平台 API 门禁

```text
GET /api/sca/projects/{project_id}/gate?scan_task_id={scan_task_id}
```

门禁先检查扫描执行，再检查风险政策。只有 `scan_status=succeeded`、`result_complete=true` 且风险政策未命中时才返回 `decision=pass` 和 `exit_code=0`。下列状态固定阻断并返回 `decision=block`、`exit_code=2`：

- `queued` / `running`：尚未形成结果；持久化 `pending` 归一为 `queued`。
- `failed` / `cancelled`：执行失败或取消。
- `partial`：范围、情报或增强引擎证据不完整。
- `stale`：超过项目门禁的 `max_scan_age_hours`，默认 168 小时。
- `not_run` / `invalid`：没有任务、任务不属于项目或不是 SCA 类型。

关闭风险政策只取消严重度、许可证、风险分、KEV 等政策阻断，不会绕过上述执行完整性检查。`pass` 仍只表示该批次满足当前执行合同和政策，不表示不存在未知漏洞。

## GitHub Actions 认证

[`.github/workflows/sca-gate.yml`](../.github/workflows/sca-gate.yml) 是手动触发的既有扫描门禁，不上传或重新扫描源码。仓库需要配置三个 GitHub Actions secret：

```text
SCA_API_BASE=https://your-security-platform.example.com
SCA_CI_USERNAME=<dedicated local CI user>
SCA_CI_PASSWORD=<dedicated user password>
```

工作流使用 [`scripts/sca_api_gate.py`](../scripts/sca_api_gate.py) 完成登录、内存 Cookie 保存、门禁请求和 `finally` 登出；用户名、密码和 Cookie 不写入文件或工作流输出。正式工作流只接受 HTTPS 且拒绝 URL 内嵌凭据。401、403、服务不可达、无效 JSON、合同不一致或“扫描不完整却返回 pass”均失败关闭并退出 `3`。门禁正常阻断退出 `2`，通过退出 `0`。

当前认证仍是平台已有的本地用户名/密码会话，不是生产级 OAuth、OIDC、细粒度服务账号或租户隔离。应创建权限最小、只供 CI 使用的普通用户，并在 GitHub Environment 中限制 secret 和手动工作流的使用范围。不要设置 `AUTH_DISABLED=true` 使 CI 绕过认证。API 必须是 CI 执行器实际可达的 HTTPS 地址；本机 `127.0.0.1` 只用于隔离测试。

## 本地 CLI

```bash
python scripts/sca_ci.py --source . --offline --json sca-result.json --sarif sca-result.sarif --fail-on-block
```

本地 CLI 是一次同步扫描，因此不会产生排队、运行中或陈旧状态。完整性为 `partial` 时即使风险政策关闭也会阻断；扫描或配置异常会写入 `scan_status=failed` 的 JSON 和失败 SARIF，并退出 `3`。风险或完整性阻断退出 `2`，完整且政策通过退出 `0`。不带 `--fail-on-block` 时，风险/完整性阻断仍写入 `decision=block`，但保持历史兼容返回 0；执行错误始终返回 3。因此 CI 必须保留 `--fail-on-block`。

本地 CLI 使用依赖清单、可发现的 Python 环境、本地规则和可用的 OSV/离线镜像，不运行平台 Syft/Grype/Trivy Docker 增强，也不读取平台数据库中的项目 VEX、例外审批、项目策略或历史任务。它与平台门禁共享“结果不完整不得冒充成功”的原则，但能力范围不等价。

仓库的 [本地 SCA 工作流](../.github/workflows/sca-local.yml) 会保存 JSON/SARIF 后再按退出码阻断。离线资源位于 Git 忽略目录，CI 执行器需要自行提供；工作流不会自动携带开发机情报。

## 离线情报与 VEX 边界

管理员可导入本地 OSV 镜像和补充 CVSS/EPSS/KEV 数据。在线查询失败且没有可用镜像时，扫描明确变为部分完成；未验证组件不表示安全。VEX 的 `not_affected`、`fixed` 与已批准例外只在平台数据库门禁中生效，本地 CLI 不读取这些数据。详细情报合同见 [六模块现状](module-system.md)。
