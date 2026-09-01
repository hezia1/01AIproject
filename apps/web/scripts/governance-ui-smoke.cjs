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

(async () => {
  const browser = await chromium.launch({ channel, headless: true });
  const results = [];

  for (const viewport of viewports) {
    const page = await browser.newPage({ viewport: viewport.width < 760 ? viewports[0] : viewport });
    await page.goto(baseUrl, { waitUntil: "networkidle" });
    await page.getByRole("button", { name: "治理总览", exact: true }).click();
    await page.setViewportSize(viewport);

    await page.getByRole("button", { name: "SCA 供应链风险", exact: true }).click();
    const scaTabs = await page.locator(".sca-workspace .module-workspace-tabs button strong").allTextContents();
    assert(JSON.stringify(scaTabs) === JSON.stringify(["概览", "风险组件", "依赖影响", "例外与 VEX", "历史与报告"]), `${viewport.width}px SCA 工作区不正确`);
    assert(!(await page.locator(".sca-workspace").innerText()).includes("高级设置（可选）"), `${viewport.width}px SCA 仍显示旧高级设置入口`);
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
