# 检测效果与 DAST 重放基准

当前版本：`security-minimal-v1`。它建立了可重复的最小证据基线，不代表全平台、全生态或生产环境的准确率。

## 运行

```powershell
.\.venv\Scripts\python.exe -B scripts\security_benchmark.py `
  --external-source D:\project\PYproject\testproject `
  --json .tmp\security-benchmark\report.json
```

脚本首先校验外部项目 HEAD 和官方 README 的 SHA-256；不匹配时退出 3，不使用未固定版本计算结果。内部阈值不满足时退出 2，通过时退出 0。报告无时间戳和绝对源码路径，输入不变时可按 SHA-256 比较。

## v1 组成

- SAST：一个通用 JavaScript 正例和一个安全负例，共 5 个标签规则、10 个标签决策。
- AGENT：与验收项目无关的指令正例和否定约束负例，共 3 个标签规则、6 个标签决策。它只验证静态规则，不运行 Agent。
- SCA：固定 `package-lock.json` 中 lodash `4.17.20` / `4.17.21` 成对样本，仅使用仓库内置确定性规则，不请求 OSV、不调用 Docker 工具。
- DAST：红、黄、绿、未验证四种证据合同各重放 3 次，不启动目标、不发网络请求。红色必须有强确认事实，绿色必须有完整阴性覆盖，否则只能为黄色/未验证。
- DAST 实际成对目标：同一版本化 Python 目标分别以 vulnerable/safe 模式运行在固定本机镜像中，代码注入和安全配置两类各重复 3 次；容器只映射 `127.0.0.1`，源码只读挂载并限制能力与资源。
- 外部映射：固定 `vulnerable-node-api` 提交 `1f8fed3`、MIT 许可证和官方 README 哈希，将 30 项逐项映射到模块、通用规则、源码证据或明确未检原因。

配置、标签和阈值位于 [`benchmarks/security/v1/manifest.json`](../benchmarks/security/v1/manifest.json)，30 项映射位于 [`external-testproject.json`](../benchmarks/security/v1/external-testproject.json)，本次可比较摘要位于 [`baseline-summary.json`](../benchmarks/security/v1/baseline-summary.json)。脚本报告会列出缺失规则、非预期规则、混淆矩阵、逐项结果、输入哈希和阈值失败项。

## 2026-09-10 真实结果

| 范围 | 结果 | 可解释边界 |
| --- | --- | --- |
| SAST 内部语料 | precision 1.0、recall 1.0、FPR 0.0 | 只有 5 个规则和 2 个小样本，不可外推 |
| AGENT 内部语料 | precision 1.0、recall 1.0、FPR 0.0 | 只有 3 个指令规则，不含运行时 |
| SCA 内部语料 | 组件召回、漏洞 precision/recall 均为 1.0 | 只有 npm/lodash 成对样本和内置规则 |
| DAST 合同重放 | 4/4 裁决正确，12/12 重放一致，决定性证据完整率 1.0 | 不是真实目标复现率 |
| DAST 成对实际重放 | 漏洞/安全目标共 4 个案例、12/12 裁决正确且一致 | 只覆盖代码注入与安全配置两类合成目标 |
| testproject 官方清单 | 15/30，50% | 只表示固定官方清单逐项映射 |
| testproject 安全范围 | 15/24，62.5% | 排除 6 个明确代码质量项，仍不等于通用召回率 |

`testproject` 已映射到 1、2、3、4、5、7、8、9、10、11、12、13、17、19、20。未覆盖项保留真实原因：缺少 Express 项目级缺失性规则、环境回退/链式响应语义、Git 索引基准、确定性 Express 漏洞情报，或本身属于代码质量而非安全 Finding。没有为提高数字新增绑定该项目文件名、路由、变量或行号的规则。

实际 `testproject` 另以只读源码、一次性 Node 容器、仅本机端口执行代码注入、命令注入、路径穿越和安全配置固定探针，每类 3 次，共 12/12 返回 `exploitable`、裁决一致且证据完整。该目标没有锁文件，容器启动时重新安装了依赖，因此它是本轮真实观察，不并入固定成对复现率；容器及端口已清理，源码工作区仍干净。`baseline-summary.json` 中实际 DAST 报告哈希标识本轮完整运行产物；跨次比较应使用固定镜像 ID、目标源码哈希和聚合指标，因为报告中的临时执行标识与本机端口会变化。

## 尚未完成

- 当前内部 100% 只证明这些小样本没有回归；还需扩大语言、框架、漏洞类型、边界和真实安全项目，才能形成可外推指标。
- QA-002 仍需至少一个不同来源的完整 Node.js/Express 项目和更多安全负例，验证缺失性规则与跨项目迁移；本轮内部夹具只能提供初步通用性证据。
- DAST-001 的最小 v1 已有固定镜像摘要、合成修复前/后目标和重复运行；仍需扩展其他策略、带身份业务流、初始化数据、超时与更多执行器负例。当前数值不得称为全 DAST 漏洞复现率。
