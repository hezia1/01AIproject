const { chromium } = require("playwright-core");

const baseUrl = process.env.AGENT_UI_BASE_URL || "http://localhost:5173";
const channel = process.env.PLAYWRIGHT_CHANNEL || "chrome";
const viewports = [
  { width: 1600, height: 1000 },
  { width: 390, height: 844 },
];
const tabs = ["概览", "风险", "资产与边界", "动态验证", "策略与交付"];
const governanceWorkspaces = {
  扫描与门禁: ["项目扫描策略", "质量门禁"],
  例外与边界: ["权限 Allowlist", "Finding / 权限例外审批"],
  报告与审计: ["报告、离线 CI 与策略审计"],
};

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

(async () => {
  const browser = await chromium.launch({ channel, headless: true });
  const results = [];

  for (const viewport of viewports) {
    const page = await browser.newPage({
      viewport: viewport.width < 760 ? viewports[0] : viewport,
    });
    await page.goto(baseUrl, { waitUntil: "networkidle" });
    await page.getByRole("button", { name: "治理总览", exact: true }).click();
    await page.getByRole("button", { name: "AGENT 智能体安全", exact: true }).click();
    await page.setViewportSize(viewport);

    for (const tab of tabs) {
      await page.getByRole("button", { name: new RegExp(`^${tab}`) }).click();
      if (tab === "概览") {
        const overviewText = await page.locator(".agent-workspace").innerText();
        assert(!overviewText.includes("active findings meet or exceed"), `${viewport.width}px 概览仍显示英文门禁原因`);
      }
      if (tab === "资产与边界") {
        await page.getByRole("tab", { name: "扫描覆盖", exact: true }).click();
        const trustDetails = page.getByText("查看评分上限、限制与证据哈希", { exact: true });
        if (await trustDetails.count()) await trustDetails.click();
        const assetText = await page.locator(".agent-workspace").innerText();
        assert(!assetText.includes("The score summarizes current scanner evidence"), `${viewport.width}px 评分边界仍显示英文`);
        assert(assetText.includes("评分快照生成") && assetText.includes("北京时间"), `${viewport.width}px 评分缺少北京时间`);
      }
      if (tab === "风险") {
        const riskText = await page.locator(".agent-workspace").innerText();
        assert(riskText.includes("正式问题") && riskText.includes("额外提示"), `${viewport.width}px 风险口径未拆分`);
        assert(!riskText.includes("个待人工复核"), `${viewport.width}px 仍使用混淆的问题/候选口径`);
        if (viewport.width < 760) {
          const firstRiskRow = page.locator(".agent-formal-findings .mobile-card-table tbody tr").first();
          if (await firstRiskRow.count()) assert(await firstRiskRow.evaluate((row) => getComputedStyle(row).display === "block"), `${viewport.width}px 风险表未转换为移动卡片`);
        }
      }
      if (tab === "动态验证") {
        const stepLabels = await page.locator(".agent-runtime-steps button strong").allTextContents();
        assert(JSON.stringify(stepLabels) === JSON.stringify(["运行条件", "安全副本", "验证方式", "确认执行", "查看证据"]), `${viewport.width}px 动态验证不是五步向导`);
        const visibleInputs = await page.locator(".agent-validation-workspace input:visible, .agent-validation-workspace select:visible, .agent-validation-workspace textarea:visible").count();
        assert(visibleInputs <= 5, `${viewport.width}px 动态验证首步仍同时显示过多控件：${visibleInputs}`);
      }
      const dimensions = await page.evaluate(() => ({
        body: document.body.scrollWidth,
        document: document.documentElement.scrollWidth,
        viewport: window.innerWidth,
      }));
      assert(dimensions.body <= dimensions.viewport, `${viewport.width}px ${tab} body 横向溢出`);
      assert(dimensions.document <= dimensions.viewport, `${viewport.width}px ${tab} document 横向溢出`);
      results.push(`${viewport.width}px ${tab}: ${dimensions.document}/${dimensions.viewport}`);
    }

    await page.getByRole("button", { name: /^策略与交付/ }).click();
    await page.locator(".agent-saved-state, .agent-unsaved-banner").first().waitFor();
    assert(await page.locator(".agent-saved-state").count(), `${viewport.width}px 治理策略缺少已保存状态`);
    const runtimeToggle = page.getByLabel(/^允许本项目显示真实目标执行入口/);
    await runtimeToggle.click();
    assert(await page.locator(".agent-unsaved-banner").count(), `${viewport.width}px 治理策略修改后未显示未保存状态`);
    await runtimeToggle.click();
    assert(await page.locator(".agent-saved-state").count(), `${viewport.width}px 治理策略还原后未恢复已保存状态`);
    for (const [workspace, headings] of Object.entries(governanceWorkspaces)) {
      await page.getByRole("button", { name: workspace, exact: true }).click();
      const visibleHeadings = await page.locator(".agent-governance-panels h2").allTextContents();
      assert(JSON.stringify(visibleHeadings) === JSON.stringify(headings), `${workspace} 工作区内容边界不正确`);
    }
    await page.close();
  }

  await browser.close();
  console.log(`AGENT UI smoke passed\n${results.join("\n")}`);
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
