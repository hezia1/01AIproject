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
