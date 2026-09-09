const { chromium } = require("playwright-core");

const baseUrl = process.env.SKILL_UI_BASE_URL || "http://127.0.0.1:5173";
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
      await page.getByText("可执行 Skill 注册表", { exact: true }).waitFor();
      const text = await page.locator(".skill-registry").innerText();
      assert(text.includes("不替代专业扫描器"), "Skill 与扫描器边界缺失");
      assert(text.includes("不运行任意代码"), "任意代码执行边界缺失");
      assert(text.includes("对所有项目通用"), "租户级通用范围说明缺失");
      assert(await page.getByText("创建声明式 Skill", { exact: true }).count() === 1, "管理员创建入口缺失");
      assert(await page.locator(".skill-status.builtin").count() === 5, "应展示 5 个平台内置 Skill");
      assert(await page.locator(".skill-automation input[type=checkbox]").count() === 15, "每个内置 Skill 应提供三类自动触发选择");
      const dimensions = await page.evaluate(() => ({ viewport: innerWidth, body: document.body.scrollWidth, document: document.documentElement.scrollWidth }));
      assert(dimensions.body <= dimensions.viewport && dimensions.document <= dimensions.viewport,
        `${viewport.width}px 页面横向溢出：${JSON.stringify(dimensions)}`);
      console.log(`Security Skill UI ${viewport.width}px passed: ${dimensions.document}/${dimensions.viewport}`);
      await page.close();
    }
  } finally { await browser.close(); }
})().catch((error) => { console.error(error); process.exitCode = 1; });
