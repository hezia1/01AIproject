# SCA CI 门禁接入

SCA 扫描完成后，可通过下列接口获取稳定、机器可读的门禁结论：

```text
GET /api/sca/projects/{project_id}/gate?scan_task_id={scan_task_id}
```

响应中的 `decision` 为 `pass` 或 `block`；`exit_code` 为 `0` 或 `2`。门禁可按严重度、许可证策略、CVSS/EPSS 综合风险分、KEV、扫描新鲜度和情报完整性配置；`block` 不会删除原始漏洞、扫描快照、VEX 或例外审批记录。

仓库提供 [.github/workflows/sca-gate.yml](../.github/workflows/sca-gate.yml) 的手动触发工作流。启用时需要在 GitHub Actions secrets 中配置：

```text
SCA_API_BASE=https://your-security-platform.example.com
```

该工作流不上传源码、不执行扫描，也不绕过登录或权限边界；它只对已经完成的 SCA 扫描调用门禁接口。应由受控的扫描流程先创建并完成扫描，再将项目和扫描批次 UUID 传给该工作流。

仓库还提供 [.github/workflows/sca-local.yml](../.github/workflows/sca-local.yml)，可不依赖平台服务器在 GitHub Actions 中执行本地扫描，生成并上传 JSON 与 SARIF。相同命令可在任意 CI 中运行：

```bash
python scripts/sca_ci.py --source . --offline --json sca-result.json --sarif sca-result.sarif --fail-on-block
```

`--offline` 禁止在线 OSV 查询，只使用项目内规则和已导入的离线镜像；如存在阻断项，进程返回 `2`。扫描 JSON 包含源码清单指纹，SARIF 可被代码扫描平台消费。

## 离线 OSV 镜像

通过 SCA 高级分析页可导入本地 JSON 镜像。镜像仅写入 Git 忽略的 `artifacts/sca-offline/osv-mirror.json`，不会被提交。每项格式为：

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

命中本地镜像时，扫描结果会标记为 `osv_mirror`；镜像中没有该组件版本时才会尝试在线 OSV。没有镜像且在线查询失败时，平台会明确降级为本地规则与许可证策略，不能视为完整外部情报。

## CVSS / EPSS / KEV 与 VEX

高级分析页可导入形如 `[{"cve":"CVE-2026-0001","cvss":9.8,"epss":0.91,"kev":true,"fixed_version":"2.0.1"}]` 的本地情报。导入数据保存在 Git 忽略的 `artifacts/sca-offline/intelligence.json`；未导入的数据不会被展示为实时情报。

VEX 结论按项目、生态、组件、版本和漏洞 ID 保存。`not_affected` 与 `fixed` 会在下一次扫描中从门禁与新 Finding 中排除，但组件快照仍保留漏洞 ID 和 VEX 依据，便于审计。
