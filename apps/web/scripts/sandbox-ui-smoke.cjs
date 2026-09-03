const { chromium } = require("playwright-core");

const baseUrl = process.env.SANDBOX_UI_BASE_URL || "http://localhost:5173";
const channel = process.env.PLAYWRIGHT_CHANNEL || "chrome";
const viewports = [
  { width: 1600, height: 1000 },
  { width: 390, height: 844 },
];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function authenticateIfNeeded(page) {
  const username = page.getByLabel("用户名");
  if (!(await username.count())) return;
  const testUsername = process.env.UI_TEST_USERNAME;
  const testPassword = process.env.UI_TEST_PASSWORD;
  assert(testUsername && testPassword, "登录界面已启用；请设置 UI_TEST_USERNAME 和 UI_TEST_PASSWORD");
  await username.fill(testUsername);
  await page.getByLabel("密码", { exact: true }).fill(testPassword);
  const confirmation = page.getByLabel("确认密码", { exact: true });
  if (await confirmation.count()) await confirmation.fill(testPassword);
  await page.getByRole("button", { name: /登录|创建管理员并登录/ }).click();
  await page.getByRole("button", { name: "风险治理", exact: true }).waitFor();
}

(async () => {
  const browser = await chromium.launch({ channel, headless: true });
  const results = [];

  for (const viewport of viewports) {
    const page = await browser.newPage({ viewport: viewport.width < 760 ? viewports[0] : viewport });
    await page.goto(baseUrl, { waitUntil: "networkidle" });
    await authenticateIfNeeded(page);
    await page.getByRole("button", { name: "风险治理", exact: true }).click();
    await page.getByRole("button", { name: "SANDBOX 沙箱证据", exact: true }).click();
    await page.setViewportSize(viewport);

    const port = page.getByLabel("SANDBOX 容器端口");
    const healthPath = page.getByLabel("SANDBOX 健康检查路径");
    assert(await port.count() === 1, `${viewport.width}px 未显示容器端口确认框`);
    assert(await healthPath.count() === 1, `${viewport.width}px 未显示健康检查路径确认框`);
    await port.fill("3000");
    assert(await port.inputValue() === "3000", `${viewport.width}px 容器端口不可修改`);
    assert((await healthPath.inputValue()).startsWith("/"), `${viewport.width}px 健康检查路径格式错误`);
    await port.fill("70000");
    assert(await page.locator(".sandbox-launch-confirmation .field-error").count() === 1, `${viewport.width}px 非法端口没有即时提示`);
    await port.fill("3000");

    const dimensions = await page.evaluate(() => ({
      body: document.body.scrollWidth,
      document: document.documentElement.scrollWidth,
      viewport: window.innerWidth,
    }));
    assert(dimensions.body <= dimensions.viewport, `${viewport.width}px SANDBOX body 横向溢出`);
    assert(dimensions.document <= dimensions.viewport, `${viewport.width}px SANDBOX document 横向溢出`);
    results.push(`${viewport.width}px: ${dimensions.document}/${dimensions.viewport}`);
    await page.close();
  }

  await browser.close();
  console.log(`SANDBOX UI smoke passed\n${results.join("\n")}`);
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
