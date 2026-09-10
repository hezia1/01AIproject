# 2026-09-10 CI 门禁状态与认证维护核实

本记录说明 CI-002 与 CI-001 的实现、真实原因和现场证据。仓库、数据库及实际运行结果优先；门禁通过不是无漏洞证明。

## 起点

- 开始时 `main` 工作区干净，HEAD 与 `origin/main` 均为 `418911073a82577fc4871d4f8b7642707be7564e`，领先/落后 `0/0`；远端为 `https://github.com/hezia1/01AIproject.git`。
- 当前数据库迁移仍为 `20260909_0019`，本轮无迁移、扫描器、权限矩阵或角色能力变更。
- 验收项目只使用 `D:\project\PYproject\testproject` 对应的 `test01`，没有使用 `test_project` 或 DVNA。AGENT 缺少适用内容的既有冒烟按项目所有者决定继续暂时忽略。

## 根因

- 平台 `build_sca_gate_result` 只显式处理扫描缺失和按时间计算的陈旧；排队、运行、失败、取消及扫描元数据中的部分完成可能在风险未命中时错误放行。关闭风险政策还会清空任务级阻断。
- 本地 CLI 在计算保证状态之前生成门禁，因而 `assurance=partial` 可能仍返回 pass；异常也没有稳定的机器可读失败合同。
- `.github/workflows/sca-gate.yml` 直接执行未登录 `curl`，正常鉴权下必然为 401，没有会话清理，也无法区分门禁阻断与认证/传输错误。

## 修改

- 平台门禁复用统一扫描诊断，只允许当前、完整的 `succeeded` SCA 批次进入风险政策；缺失、无效、queued/pending、running、failed、cancelled、partial 和 stale 全部失败关闭。风险政策禁用不影响执行完整性阻断；未指定任务时选择最新 SCA 任务而非跳过未完成任务选择更旧成功记录。
- 本地 CLI 先形成 assurance 再门禁。部分结果固定阻断；配置或扫描异常写入失败 JSON/SARIF 并使用退出码 3。输出明确标注 standalone 范围和不读取平台 VEX/例外/项目策略、不执行 Docker 增强的限制。
- 新增无第三方依赖的认证客户端，以专用普通用户登录，Cookie 只存在内存，随后请求门禁并在 `finally` 中登出。正式地址要求 HTTPS；401、403、网络错误、无效响应和伪成功合同退出 3，正常阻断退出 2，通过退出 0。
- GitHub Actions 工作流从 secret 读取 API 地址和专用 CI 用户凭据，不关闭认证、不打印密码或 Cookie，也没有扩大普通用户或管理员权限。

上述实现没有 `testproject` 路由、文件名、变量、固定行号或项目 ID 条件；状态判断来自通用任务字段、扫描元数据和策略。

## 定向与完整验证

- 状态、SCA、认证客户端定向回归：`76 passed, 2 warnings`。
- 完整后端：D 盘专用临时目录下 `441 passed, 1 skipped, 34 warnings`。唯一跳过仍为 Windows 当前账号不能创建 symlink；34 条告警仍是 32 条 `datetime.utcnow()` 和 2 条 FastAPI `on_event` 弃用提示。
- 前端生产构建通过：最大 JavaScript 包 `661.92 kB`，gzip `190.51 kB`，Vite 大包告警仍存在。`test:dev-server`、认证失败五场景（含 1440px/390px）和 `http://127.0.0.1:5173` HTTP 200 通过；本轮没有前端业务代码修改。

## testproject 真实结果

- 平台 API 对数据库中最新 SCA 记录返回 `decision=block`、`exit_code=2`、`scan_status=stale`。原持久化状态仍为 `completed`，现场年龄约 206 小时，且原扫描还记录清单版本证明与 OSV 情报不完整。没有重新执行平台扫描或改写记录。
- 本地 CLI 对 `testproject` 做显式离线只读扫描，识别 7 个组件；6 个只有版本范围、1 个只有清单固定版本，7 个均没有完成漏洞情报验证，因此返回 `scan_status=partial`、`decision=block`、退出码 2。该结果只代表本地 CLI 范围，不与数据库平台扫描的 106 个组件等价。
- 正常启用鉴权的隔离 API 使用一个明确 ID 的临时普通用户完成 `login 200 → gate 200/block → logout 204`，客户端最终退出 2。测试用户及其会话随后按唯一 ID 删除并查询确认不存在；没有修改任何已有用户。

完整测试目录、本地 CLI JSON/SARIF 和隔离服务均已清理，8001/5174 无监听。未创建项目、扫描、目标、模型调用或配置。

## 边界与后续

- GitHub 托管执行器尚未连接一个真实可达的 HTTPS 平台地址，因为当前平台是本机研发环境；本轮证明的是工作流、真实本地认证链路和失败路径，不宣称生产 CI 已部署。
- 本地账号体系仍不是生产服务身份。进入企业部署前仍需 OIDC/OAuth、细粒度服务账号、项目/租户授权、secret 轮换和不可抵赖审计。
- 下一优先级回到 PPT P0 的检测与动态验证基准：QA-001、QA-002、DAST-001。
