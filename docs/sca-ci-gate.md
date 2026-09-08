# SCA CI 门禁接入

状态：项目级门禁接口与本地 CLI 已实现；远程门禁工作流尚未适配现有登录会话。2026-09-08 按实现和完整后端测试复核，实际验证见 [维护核实记录](maintenance-verification-2026-09-08.md)。

SCA 扫描完成后，可通过下列接口获取稳定、机器可读的门禁结论：

```text
GET /api/sca/projects/{project_id}/gate?scan_task_id={scan_task_id}
```

响应中的 `decision` 为 `pass` 或 `block`；`exit_code` 为 `0` 或 `2`。门禁可按严重度、许可证策略、CVSS/EPSS 综合风险分、KEV、扫描新鲜度和情报完整性配置；`block` 不会删除原始漏洞、扫描快照、VEX 或例外审批记录。`pass` 仅表示没有命中当前启用策略，不等于无漏洞或扫描成功。当前判定没有单独检查扫描任务的所有失败/进行中状态；调用方仍须核实扫描批次状态、引擎结果和情报降级，统一门禁行为见 [deferred-work.md](deferred-work.md)。

仓库提供 [.github/workflows/sca-gate.yml](../.github/workflows/sca-gate.yml) 的手动触发工作流。它目前只读取 GitHub Actions secret：

```text
SCA_API_BASE=https://your-security-platform.example.com
```

该工作流不上传源码、不执行扫描；它只请求既有扫描的门禁结论。API 已启用本地登录，该接口要求有效的 `ai_security_session` Cookie，可通过 `POST /api/auth/login` 建立会话。现有工作流的 `curl` 未登录、未携带 Cookie，配置 `SCA_API_BASE` 后仍会在正常启用鉴权的 API 上收到 401；管理员尚未初始化时为 503。不要通过 `AUTH_DISABLED=true` 绕过鉴权来使工作流通过。

远程 CI 的服务身份、凭据管理及会话生命周期尚未接入此模板，当前不能称为可直接启用的完整平台 CI 集成。后续需完成这一接入，并由受控扫描流程创建和完成扫描，再传入项目及扫描批次 UUID；本轮仅修正文档，没有改动工作流或权限实现。

仓库还提供 [.github/workflows/sca-local.yml](../.github/workflows/sca-local.yml)，可不依赖平台服务器在 GitHub Actions 中执行本地扫描，生成并上传 JSON 与 SARIF。相同命令可在任意 CI 中运行：

```bash
python scripts/sca_ci.py --source . --offline --json sca-result.json --sarif sca-result.sarif --fail-on-block
```

`--offline` 禁止在线 OSV 查询，只使用随平台发布的本地规则和已导入的离线镜像/情报；如存在阻断项，进程返回 `2`。扫描 JSON 包含源码清单指纹，SARIF 可被代码扫描平台消费。

本地 CLI 使用依赖清单、可发现的 Python 环境、本地规则和 OSV/离线镜像进行分析，不运行平台的 Syft/Grype/Trivy Docker 增强，也不读取平台数据库中的项目 VEX、例外审批或策略覆盖。可用 `--policy` 传入本地门禁 JSON，但它的门禁实现不含平台扫描批次新鲜度等全部条件；本地门禁与平台项目门禁不能宣称完全等价。离线资源在 Git 忽略目录中，CI 执行器需要自行提供；工作流不会自动带入本机镜像与情报文件。

## 离线 OSV 镜像

管理员可在 SCA 工作区的“扫描引擎与漏洞情报源”中导入本地 JSON 镜像，管理中心亦有对应资源入口；导入 API 在后端校验管理员权限。镜像仅写入 Git 忽略的 `artifacts/sca-offline/osv-mirror.json`，不会被提交。每项格式为：

```json
[
  {
    "ecosystem": "pypi",
    "package": "example-package",
    "version": "1.2.3",
    "vulnerabilities": [
      {"id": "CVE-2026-0001", "severity": "high", "summary": "example advisory"}
    ]
  }
]
```

默认 API 扫描优先查询在线 OSV；首个精确版本查询失败时整批切到离线回退，后续单项查询失败则对该项回退。网络失败、设置 `SCA_OFFLINE_ONLY=true` 或 CLI 显式使用 `--offline` 时，命中人工导入本地镜像的结果标记为 `osv_mirror`。平台不会自动保存在线查询结果。没有镜像记录且在线查询失败时，平台会明确降级为本地规则与许可证策略，不能视为完整外部情报。

## CVSS / EPSS / KEV 与 VEX

管理员可在“补充风险数据（可选）”中导入形如 `[{"cve":"CVE-2026-0001","cvss":9.8,"epss":0.91,"kev":true,"fixed_version":"2.0.1"}]` 的本地情报。导入数据保存在 Git 忽略的 `artifacts/sca-offline/intelligence.json`；未导入的数据不会被展示为实时情报。

VEX 结论按项目、生态、组件、版本和漏洞 ID 保存，写入要求管理员身份。`not_affected` 与 `fixed` 会在下一次平台扫描中从门禁与新 Finding 中排除，但组件快照仍保留漏洞 ID 和 VEX 依据，便于审计。
