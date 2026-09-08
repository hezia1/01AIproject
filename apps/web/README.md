# Web 控制台

前端采用 React 19、TypeScript 和 Vite 7，已接入真实 FastAPI 接口，覆盖项目配置、六模块工作区、扫描结果、动态验证、沙箱证据和 ASPM 项目级治理。

当前认证/API/应用外壳/用户管理已经拆分，并提供本地 `user` / `admin` 两角色登录以及多组浏览器冒烟；大型模块页面仍集中在 `src/main.tsx`。生产发布前仍需补充分包、继续拆分组件、错误监控和更完整的浏览器回归，因此只适合受控的本地研发与演示环境。

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

当前构建可以完成，但主 JavaScript 包仍有体积告警；该告警是已知工程债务，不应描述成已经完成的生产优化。

