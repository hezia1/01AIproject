const { chromium } = require("playwright-core");

const baseUrl = process.env.DIAGNOSTICS_UI_BASE_URL || "http://127.0.0.1:5173";
const channel = process.env.PLAYWRIGHT_CHANNEL || "chrome";
const projectName = process.env.DIAGNOSTICS_UI_PROJECT_NAME || "";
const viewports = [{ width: 1440, height: 900 }, { width: 390, height: 844 }];

function assert(condition, message) { if (!condition) throw new Error(message); }

(async () => {
  const browser = await chromium.launch({ channel, headless: true });
  try {
    for (const viewport of viewports) {
      const page = await browser.newPage({ viewport });
      await page.goto(baseUrl, { waitUntil: "networkidle" });
      if (await page.getByLabel("用户名").count()) throw new Error("登录已启用；请对一次性 AUTH_DISABLED=true 隔离 API 运行本脚本");
      if (projectName) await page.getByLabel("当前项目").selectOption({ label: projectName });
      const panel = page.getByLabel("模块真实诊断");
      await panel.waitFor();
      await panel.getByText("SCA 供应链风险分析", { exact: true }).waitFor();
      const content = await panel.innerText();
      for (const expected of ["SAST 智能静态审计", "AGENT 供应链安全", "DAST 动态验证", "SANDBOX 动态证据", "本次在线 OSV", "模型服务", "被测目标"]) {
        assert(content.includes(expected), `缺少诊断内容：${expected}`);
      }
      await panel.locator(".diagnostic-contract summary").click();
      const expanded = await panel.innerText();
      assert(expanded.includes("部分完成") && expanded.includes("已过期") && expanded.includes("不表示项目不存在未覆盖漏洞"), "状态合同或结论边界缺失");
      const dimensions = await page.evaluate(() => ({ viewport: innerWidth, body: document.body.scrollWidth, document: document.documentElement.scrollWidth }));
      assert(dimensions.body <= dimensions.viewport && dimensions.document <= dimensions.viewport, `${viewport.width}px 诊断页面横向溢出：${JSON.stringify(dimensions)}`);
      console.log(`Project diagnostics UI ${viewport.width}px passed: ${dimensions.document}/${dimensions.viewport}`);
      await page.close();
    }
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
