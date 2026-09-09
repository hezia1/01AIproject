const { chromium } = require("playwright-core");

const baseUrl = process.env.AUTH_FAILURE_UI_BASE_URL || "http://127.0.0.1:5173";
const channel = process.env.PLAYWRIGHT_CHANNEL || "chrome";
const viewports = [{ width: 1440, height: 900 }, { width: 390, height: 844 }];

function assert(condition, message) { if (!condition) throw new Error(message); }

function healthPayload(databaseStatus = "ok") {
  return {
    status: databaseStatus === "ok" ? "degraded" : "unavailable",
    checked_at: new Date().toISOString(),
    checks: [
      { key: "api", name: "API", status: "ok", required: true, detail: "HTTP 健康检查路由可以响应。" },
      { key: "database", name: "PostgreSQL", status: databaseStatus, required: true, detail: databaseStatus === "ok" ? "数据库连接成功。" : "数据库连接失败。" },
      { key: "redis", name: "Redis", status: "unavailable", required: false, detail: "Redis 当前不可用。" },
    ],
    limitations: ["诊断不代表扫描成功。"],
  };
}

async function verifyStatusFailureAndRetry(browser, viewport) {
  const page = await browser.newPage({ viewport });
  let statusCalls = 0;
  await page.route("**/api/auth/status", async (route) => {
    statusCalls += 1;
    if (statusCalls <= 2) return route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: "database unavailable" }) });
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ initialized: true }) });
  });
  await page.route("**/api/auth/me", (route) => route.fulfill({ status: 401, contentType: "application/json", body: JSON.stringify({ detail: "Authentication required" }) }));
  await page.route("**/api/health?**", (route) => route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify(healthPayload("unavailable")) }));
  await page.goto(baseUrl, { waitUntil: "networkidle" });
  await page.getByRole("heading", { name: "安全平台依赖服务不可用", exact: true }).waitFor();
  const diagnostics = await page.getByLabel("平台健康诊断").innerText();
  assert(diagnostics.includes("PostgreSQL（必需）") && diagnostics.includes("不可用"), "数据库失败诊断缺失");
  assert((await page.locator("body").innerText()).includes("不能作为“无漏洞”结论"), "扫描结论边界缺失");
  const dimensions = await page.evaluate(() => ({ viewport: innerWidth, body: document.body.scrollWidth, document: document.documentElement.scrollWidth }));
  assert(dimensions.body <= dimensions.viewport && dimensions.document <= dimensions.viewport, `${viewport.width}px 错误页面横向溢出：${JSON.stringify(dimensions)}`);
  await page.getByRole("button", { name: "重试连接", exact: true }).click();
  await page.getByRole("button", { name: "管理员登录", exact: true }).waitFor();
  assert(statusCalls >= 3, `重试后认证状态请求次数错误：${statusCalls}`);
  console.log(`Authentication status failure UI ${viewport.width}px passed`);
  await page.close();
}

async function verifyMeFailureIsNotLoggedOut(browser) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  await page.route("**/api/auth/status", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ initialized: true }) }));
  await page.route("**/api/auth/me", (route) => route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ detail: "identity store unavailable" }) }));
  await page.route("**/api/health?**", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(healthPayload("ok")) }));
  await page.goto(baseUrl, { waitUntil: "networkidle" });
  await page.getByRole("heading", { name: "安全平台暂时不可用", exact: true }).waitFor();
  assert(await page.getByLabel("用户名").count() === 0, "/auth/me 服务失败被错误显示为未登录");
  console.log("Authentication identity-service failure UI passed");
  await page.close();
}

async function verifyApiUnreachable(browser) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  await page.route("**/api/auth/status", (route) => route.abort("connectionrefused"));
  await page.route("**/api/health?**", (route) => route.abort("connectionrefused"));
  await page.goto(baseUrl, { waitUntil: "networkidle" });
  await page.getByRole("heading", { name: "无法连接后端 API", exact: true }).waitFor();
  assert((await page.locator("body").innerText()).includes("健康接口也不可达"), "API 不可达说明缺失");
  console.log("Authentication API-unreachable UI passed");
  await page.close();
}

async function verifyTimeout(browser) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  await page.route("**/api/auth/status", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 8500));
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ initialized: true }) }).catch(() => undefined);
  });
  await page.route("**/api/health?**", (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(healthPayload("ok")) }));
  await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
  await page.getByRole("heading", { name: "连接安全平台超时", exact: true }).waitFor({ timeout: 12000 });
  console.log("Authentication timeout UI passed");
  await page.close();
}

(async () => {
  const browser = await chromium.launch({ channel, headless: true });
  try {
    for (const viewport of viewports) await verifyStatusFailureAndRetry(browser, viewport);
    await verifyMeFailureIsNotLoggedOut(browser);
    await verifyApiUnreachable(browser);
    await verifyTimeout(browser);
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
