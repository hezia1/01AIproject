# Web 控制台

前端采用 React 19、TypeScript 和 Vite 7，已接入真实 FastAPI 接口，覆盖项目配置、六模块工作区、扫描结果、动态验证、沙箱证据和 ASPM 项目级治理。

当前前端仍集中在 `src/main.tsx`，尚无自动化 UI 测试；生产发布前需要补充分包、组件拆分、错误监控和浏览器端回归测试。登录鉴权也尚未启用，因此只适合受控的本地研发与演示环境。

## 本地启动

```powershell
cd apps/web
npm install
npm run dev
```

默认访问：

```text
http://localhost:5173
```

默认 API 地址为 `http://127.0.0.1:8000`，请先启动后端及 PostgreSQL。

## 构建验证

```powershell
cd apps/web
npm ci
npm run build
```

当前构建可以完成，但主 JavaScript 包仍有体积告警；该告警是已知工程债务，不应描述成已经完成的生产优化。

