# AI 安全平台 Web

前端采用 Vue 3 + TypeScript + Vite，并使用 Vue Router 和 Pinia。后端 API 默认地址为 `http://127.0.0.1:8000/api`，也可通过 `VITE_API_BASE_URL` 覆盖。

## 本地启动

```powershell
Set-Location D:\project\PYproject\AI网安项目\apps\web
npm install
npm run dev
```

浏览器访问 `http://localhost:5173`。

## 生产构建

```powershell
npm run build
```

构建会先执行 Vue TypeScript 类型检查，再输出到 `dist/`。
