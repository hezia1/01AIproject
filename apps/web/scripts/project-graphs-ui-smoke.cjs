const { chromium } = require("playwright-core");

const baseUrl = process.env.GRAPH_UI_BASE_URL || "http://127.0.0.1:5173";
const channel = process.env.PLAYWRIGHT_CHANNEL || "chrome";
const viewports = [{ width: 1440, height: 900 }, { width: 390, height: 844 }];

function assert(condition, message) { if (!condition) throw new Error(message); }

async function authenticateIfNeeded(page) {
  const username = page.getByLabel("用户名");
  if (!(await username.count())) return;
  assert(process.env.UI_TEST_USERNAME && process.env.UI_TEST_PASSWORD, "登录已启用；请设置 UI_TEST_USERNAME 和 UI_TEST_PASSWORD");
  await page.getByRole("button", { name: "管理员登录", exact: true }).click();
  await username.fill(process.env.UI_TEST_USERNAME);
  await page.getByLabel("密码", { exact: true }).fill(process.env.UI_TEST_PASSWORD);
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await page.getByRole("button", { name: "安全知识中枢", exact: true }).waitFor();
}

(async () => {
  const browser = await chromium.launch({ channel, headless: true });
  try {
    for (const viewport of viewports) {
      const page = await browser.newPage({ viewport });
      await page.goto(baseUrl, { waitUntil: "networkidle" });
      await authenticateIfNeeded(page);
      await page.getByRole("button", { name: "安全知识中枢", exact: true }).click();
      await page.getByRole("button", { name: /规则与 Skill/ }).click();
      await page.getByText("代码关系与业务安全上下文", { exact: true }).waitFor();
      const graph = page.locator(".project-graphs");
      let text = await graph.innerText();
      assert(text.includes("代码图谱") && text.includes("业务知识图谱"), "两类图谱入口不完整");
      await graph.locator(".graph-limitations summary").click();
      text = await graph.innerText();
      assert(text.includes("静态、启发式关系快照"), "代码图谱能力边界未展示");
      await graph.locator(".graph-switch button").filter({ hasText: "业务知识图谱" }).click();
      text = await graph.innerText();
      assert(text.includes("单项目视图") && text.includes("不等于组织级跨项目风险图谱"), "业务图谱边界未展示");
      const dimensions = await page.evaluate(() => ({ viewport: innerWidth, body: document.body.scrollWidth, document: document.documentElement.scrollWidth }));
      assert(dimensions.body <= dimensions.viewport && dimensions.document <= dimensions.viewport,
        `${viewport.width}px 页面横向溢出：${JSON.stringify(dimensions)}`);
      console.log(`Project graph UI ${viewport.width}px passed: ${dimensions.document}/${dimensions.viewport}`);
      await page.close();
    }
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
