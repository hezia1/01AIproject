# Web 控制台

前端采用 React 19、TypeScript 和 Vite 7，已接入真实 FastAPI 接口，覆盖项目配置、五个执行模块（SCA、SAST、AGENT、DAST、SANDBOX）、ASPM 风险治理、安全知识中枢、报告和管理员配置。

文档按 2026-09-10 仓库实现复核；本轮运行结果见 [维护核实记录](../../docs/maintenance-verification-2026-09-10.md)。已实现本地登录、普通用户注册和 `user` / `admin` 两角色界面：两类用户均可使用项目、检测、风险治理、安全知识中枢和报告，管理员另有管理中心；后端继续执行权限检查。普通用户在管理员允许时可人工更新 Grype 数据库和 Semgrep 社区规则。

业务页面仍主要集中在 `src/main.tsx`，登录、应用框架、用户管理、分页、操作反馈、维护策略、Skill 注册表、项目图谱和模块诊断已拆成独立组件。已有十一组 Playwright 浏览器冒烟脚本，尚未建立完整浏览器回归、错误监控和充分分包。当前本地会话与共享工作区不等同于生产级 IAM 或租户隔离，适用边界见 [API README](../api/README.md)。

## 本地启动

```powershell
cd apps/web
npm install
npm run dev
```

默认访问：

```text
http://127.0.0.1:5173
```

开发服务器显式监听 `127.0.0.1:5173` 并启用严格端口模式，避免 Windows/Node 只绑定 IPv6 `::1`，也避免 5173 被占用时静默切换到其他端口。若启动提示端口已占用，应先关闭已有前端进程，再重新执行 `npm run dev`；不要改用 `http://[::1]:5173` 作为日常入口。

开发服务器默认将同源 `/api` 代理到 `http://127.0.0.1:8000`，请先启动后端及 PostgreSQL。部署时应由反向代理在同一站点提供 `/api`；确需分离地址时可设置 `VITE_API_BASE_URL`，并同时正确配置 Cookie 与跨域策略。

## 构建验证

```powershell
cd apps/web
npm ci
npm run build
npm run test:dev-server
```

构建结果以当次命令为准；既有主 JavaScript 包体积告警仍是工程债务，不应描述成已完成生产优化。

## 界面冒烟

`package.json` 提供 `test:auth-ui`、`test:auth-failure-ui`、`test:admin-ui`、`test:governance-ui`、`test:agent-ui`、`test:sandbox-ui`、`test:pagination-ui`、`test:feedback-ui`、`test:skill-ui`、`test:graphs-ui` 和 `test:diagnostics-ui`。浏览器由 `playwright-core` 控制，默认使用本机 Chrome，可通过 `PLAYWRIGHT_CHANNEL` 选择已安装的浏览器通道。

`test:auth-failure-ui` 使用受控路由故障注入，验证认证状态 HTTP 503、身份接口 HTTP 503、API 不可达、请求超时、重试以及 1440px/390px 无横向溢出；它不创建账号、会话或扫描。只有 `/auth/me` 的 HTTP 401 会被解释为未登录，服务和网络错误会展示真实诊断。

登录和业务冒烟需要已启动的 Web/API、可用数据库以及通过环境变量提供的 `UI_TEST_USERNAME` / `UI_TEST_PASSWORD`；权限相关脚本需要测试管理员身份。分页与操作反馈脚本使用模拟数据/接口，不能替代真实扫描验证。具体站点地址可用脚本对应的 `AUTH_UI_BASE_URL`、`ADMIN_UI_BASE_URL`、`GOVERNANCE_UI_BASE_URL`、`AGENT_UI_BASE_URL`、`SANDBOX_UI_BASE_URL` 覆盖。

声明式 Skill 注册表使用 `npm run test:skill-ui` 验证 1440px/390px 布局、5 个内置通用 Skill、管理员自动触发选择和能力边界；站点可通过 `SKILL_UI_BASE_URL` 覆盖。脚本只读取页面，不创建、修改或执行 Skill。

项目图谱使用 `npm run test:graphs-ui` 验证 1440px/390px 布局、代码/业务图谱切换、置信度与局限说明；站点可通过 `GRAPH_UI_BASE_URL` 覆盖。脚本仅读取已有快照，不点击重建按钮。

项目模块诊断使用 `npm run test:diagnostics-ui` 验证 SCA/SAST/AGENT/DAST/SANDBOX、情报、模型、目标、状态口径及 1440px/390px 无横向溢出；站点和项目名可分别通过 `DIAGNOSTICS_UI_BASE_URL`、`DIAGNOSTICS_UI_PROJECT_NAME` 覆盖。脚本只读取项目和诊断接口，不启动扫描或模型调用；真实服务验证建议使用一次性 `AUTH_DISABLED=true` 隔离 API，完成后停止服务。

管理页脚本会建立临时项目/用户并暂时保存配置，登录脚本会建立临时普通用户；执行后必须核实清理及配置恢复，仅清理当次测试产生的数据。不要将页面显示正常、HTTP 200 或模拟测试通过写成实际扫描成功。本轮是否执行及通过情况只记录在对应维护核实记录中。

