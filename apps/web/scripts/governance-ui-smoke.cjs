const { chromium } = require("playwright-core");

const baseUrl = process.env.GOVERNANCE_UI_BASE_URL || "http://localhost:5173";
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

async function assertNoOverflow(page, viewport, label) {
  const dimensions = await page.evaluate(() => ({
    body: document.body.scrollWidth,
    document: document.documentElement.scrollWidth,
    viewport: window.innerWidth,
  }));
  assert(dimensions.body <= dimensions.viewport, `${viewport.width}px ${label} body 横向溢出`);
  assert(dimensions.document <= dimensions.viewport, `${viewport.width}px ${label} document 横向溢出`);
  return `${viewport.width}px ${label}: ${dimensions.document}/${dimensions.viewport}`;
}

async function assertSastControlsFit(page, viewport) {
  const overflowing = await page.locator(".sast-rule-config-panel .inline-check, .sast-community-rules-panel .inline-check, .sast-rule-config-panel button, .sast-community-rules-panel button").evaluateAll((elements) => elements.filter((element) => element.scrollWidth > element.clientWidth + 1).map((element) => element.textContent?.trim()));
  assert(overflowing.length === 0, `${viewport.width}px SAST 配置控件文字横向溢出：${overflowing.join(" | ")}`);
}

(async () => {
  const browser = await chromium.launch({ channel, headless: true });
  const results = [];

  for (const viewport of viewports) {
    const page = await browser.newPage({ viewport: viewport.width < 760 ? viewports[0] : viewport });
    await page.goto(baseUrl, { waitUntil: "networkidle" });
    await authenticateIfNeeded(page);
    await page.getByRole("button", { name: "风险治理", exact: true }).click();
    await page.setViewportSize(viewport);

    await page.getByRole("button", { name: "SCA 供应链风险", exact: true }).click();
    const scaTabs = await page.locator(".sca-workspace .module-workspace-tabs button strong").allTextContents();
    assert(JSON.stringify(scaTabs) === JSON.stringify(["概览", "风险组件", "依赖影响", "例外与 VEX", "历史与报告"]), `${viewport.width}px SCA 工作区不正确`);
    assert(!(await page.locator(".sca-workspace").innerText()).includes("高级设置（可选）"), `${viewport.width}px SCA 仍显示旧高级设置入口`);
    await page.locator(".sca-workspace summary").filter({ hasText: /^扫描引擎与漏洞情报源$/ }).click();
    const scaEngineText = await page.locator(".sca-workspace").innerText();
    assert(scaEngineText.includes("Grype 漏洞数据库") && scaEngineText.includes("检测 Grype 数据库"), `${viewport.width}px SCA 缺少 Grype 数据库检测入口`);
    const grypeControlOverflow = await page.locator(".grype-database-panel button").evaluateAll((elements) => elements.filter((element) => element.scrollWidth > element.clientWidth + 1).map((element) => element.textContent?.trim()));
    assert(grypeControlOverflow.length === 0, `${viewport.width}px Grype 数据库控件文字横向溢出：${grypeControlOverflow.join(" | ")}`);
    for (const tab of scaTabs) {
      await page.locator(".sca-workspace .module-workspace-tabs").getByRole("button", { name: new RegExp(`^${tab}`) }).click();
      results.push(await assertNoOverflow(page, viewport, `SCA-${tab}`));
    }
    await page.locator(".sca-workspace .module-workspace-tabs").getByRole("button", { name: /^风险组件/ }).click();
    if (viewport.width < 760) {
      const firstRiskRow = page.locator(".sca-workspace .mobile-card-table tbody tr").first();
      if (await firstRiskRow.count()) assert(await firstRiskRow.evaluate((row) => getComputedStyle(row).display === "block"), `${viewport.width}px SCA 风险表未转换为移动卡片`);
    }

    await page.getByRole("button", { name: "SAST 代码安全", exact: true }).click();
    const sastTabs = await page.locator(".sast-workspace .module-workspace-tabs button strong").allTextContents();
    assert(JSON.stringify(sastTabs) === JSON.stringify(["概览", "代码风险", "AI 辅助复核", "扫描策略", "例外与报告"]), `${viewport.width}px SAST 工作区不正确`);
    const sastText = await page.locator(".sast-workspace").innerText();
    assert(!sastText.includes("高级管理（规则、Git、CI/Worker、豁免与报告）"), `${viewport.width}px SAST 仍显示旧高级管理入口`);
    for (const tab of sastTabs) {
      await page.locator(".sast-workspace .module-workspace-tabs").getByRole("button", { name: new RegExp(`^${tab}`) }).click();
      results.push(await assertNoOverflow(page, viewport, `SAST-${tab}`));
    }
    await page.locator(".sast-workspace .module-workspace-tabs").getByRole("button", { name: /^扫描策略/ }).click();
    const strategyText = await page.locator(".sast-workspace").innerText();
    assert(strategyText.includes("为什么保留 Semgrep"), `${viewport.width}px SAST 未说明 Semgrep 与本地规则的互补关系`);
    assert(strategyText.includes("固定版 Semgrep") && strategyText.includes("Semgrep YAML 规则包"), `${viewport.width}px SAST 前端缺少 Semgrep 配置与规则包`);
    assert(strategyText.includes("Semgrep 社区安全规则") && strategyText.includes("下载社区规则"), `${viewport.width}px SAST 前端缺少社区规则人工更新入口`);
    assert(strategyText.includes("平台内置离线安全规则"), `${viewport.width}px SAST 基础规则仍使用不清晰的路径输入`);
    await assertSastControlsFit(page, viewport);
    const strategyTabs = await page.locator(".module-segmented-tabs button").allTextContents();
    assert(JSON.stringify(strategyTabs) === JSON.stringify(["Semgrep 增强", "Git 增量", "本地规则", "CI / Worker"]), `${viewport.width}px SAST 策略分类不正确`);
    await page.close();
  }

  await browser.close();
  console.log(`SCA/SAST governance UI smoke passed\n${results.join("\n")}`);
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
