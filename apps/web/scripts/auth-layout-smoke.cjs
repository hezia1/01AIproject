const { chromium } = require("playwright-core");

const baseUrl = process.env.AUTH_UI_BASE_URL || "http://127.0.0.1:5173";
const adminUsername = process.env.UI_TEST_USERNAME;
const adminPassword = process.env.UI_TEST_PASSWORD;
const channel = process.env.PLAYWRIGHT_CHANNEL || "chrome";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function login(page, username, password, admin = false) {
  if (admin) await page.getByRole("button", { name: "管理员登录", exact: true }).click();
  await page.getByLabel("用户名").fill(username);
  await page.getByLabel("密码", { exact: true }).fill(password);
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await page.getByRole("button", { name: "安全知识中枢", exact: true }).waitFor();
}

(async () => {
  assert(adminUsername && adminPassword, "请设置 UI_TEST_USERNAME 和 UI_TEST_PASSWORD");
  const browser = await chromium.launch({ channel, headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const testUsername = `ui_user_${Date.now()}`;
  const testPassword = "User-Smoke-Password-2026!";
  let userId = null;
  try {
    await page.goto(baseUrl, { waitUntil: "networkidle" });
    await login(page, adminUsername, adminPassword, true);
    await page.getByRole("button", { name: "退出登录", exact: true }).click();
    await page.getByRole("button", { name: "用户注册", exact: true }).click();
    await page.getByLabel("用户名").fill(testUsername);
    await page.getByLabel("密码", { exact: true }).fill(testPassword);
    await page.getByLabel("确认密码", { exact: true }).fill(testPassword);
    await page.getByRole("button", { name: "注册并登录", exact: true }).click();
    await page.getByRole("button", { name: "安全知识中枢", exact: true }).waitFor();
    const registered = await page.evaluate(async () => (await fetch("http://127.0.0.1:8000/api/auth/me", { credentials: "include" })).json());
    userId = registered.id;
    assert(registered.role === "user", `公开注册不得创建管理员，实际身份为 ${registered.role}`);

    const forbiddenStatus = await page.evaluate(async () => (await fetch("http://127.0.0.1:8000/api/auth/users", { credentials: "include" })).status);
    assert(forbiddenStatus === 403, `普通用户调用管理员接口应返回 403，实际为 ${forbiddenStatus}`);

    const navigation = await page.locator(".nav-list > .nav-item, .nav-list > .nav-admin-divider .nav-item").allTextContents();
    assert(JSON.stringify(navigation) === JSON.stringify(["项目", "检测", "风险治理", "安全知识中枢", "报告"]), `普通用户导航不正确：${navigation.join("、")}`);
    assert(await page.getByRole("button", { name: "管理中心", exact: true }).count() === 0, "普通用户看到了管理中心");
    await page.getByRole("button", { name: "安全知识中枢", exact: true }).click();
    assert(await page.locator(".knowledge-command-center").count() === 1, "普通用户无法查看安全知识中枢");

    await page.getByRole("button", { name: "风险治理", exact: true }).click();
    await page.getByRole("button", { name: "SCA 供应链风险", exact: true }).click();
    await page.locator(".sca-workspace summary").filter({ hasText: /^扫描引擎与漏洞情报源$/ }).click();
    assert(await page.getByRole("button", { name: "检测 Grype 数据库", exact: true }).count() === 1, "普通用户缺少 Grype 数据库维护入口");
    assert((await page.locator(".sca-workspace").innerText()).includes("漏洞情报导入及来源策略由管理员维护"), "SCA 使用与管理边界不清晰");

    await page.getByRole("button", { name: "SAST 代码安全", exact: true }).click();
    await page.locator(".sast-workspace .module-workspace-tabs").getByRole("button", { name: /^扫描策略/ }).click();
    assert(await page.getByRole("button", { name: /下载社区规则|检查并更新规则/ }).count() === 1, "普通用户缺少 Semgrep 社区规则更新入口");
    assert(!(await page.locator(".sast-workspace").innerText()).includes("新建专家规则包"), "普通用户看到了管理员规则编写入口");

    await page.getByRole("button", { name: "退出登录", exact: true }).click();
    await login(page, adminUsername, adminPassword, true);
    assert(await page.getByRole("button", { name: "管理中心", exact: true }).count() === 1, "管理员缺少管理中心");
    await page.getByRole("button", { name: "管理中心", exact: true }).click();
    assert(await page.getByRole("heading", { name: "用户管理", exact: true }).count() === 1, "管理中心没有用户管理工作区");
    console.log("Authentication and two-role layout UI smoke passed");
  } finally {
    if (userId) {
      await page.evaluate(async (id) => { await fetch(`http://127.0.0.1:8000/api/auth/users/${id}`, { method: "DELETE", credentials: "include" }); }, userId).catch(() => undefined);
    }
    await browser.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
