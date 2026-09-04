const { chromium } = require("playwright-core");
const assert = require("node:assert/strict");

const baseUrl = process.env.ADMIN_UI_BASE_URL || "http://localhost:5173";
const adminUsername = process.env.UI_TEST_USERNAME;
const adminPassword = process.env.UI_TEST_PASSWORD;

async function api(page, path, method = "GET", body) {
  return page.evaluate(async ({ path, method, body }) => {
    const response = await fetch(`/api${path}`, { method, credentials: "include", headers: { "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) : null };
  }, { path, method, body });
}

async function assertLayout(page, label) {
  const overflows = await page.locator(".admin-workspace").evaluate(root => {
    const width = document.documentElement.clientWidth;
    return [...root.querySelectorAll(".panel, .panel-header, label, button, input, select, textarea, td, th")]
      .filter(el => el.getClientRects().length && (el.getBoundingClientRect().right > width + 2 || el.getBoundingClientRect().left < -2))
      .map(el => `${el.tagName}: ${(el.textContent || el.getAttribute("placeholder") || "").slice(0, 80)}`);
  });
  assert.deepEqual(overflows, [], `${label}: overflow`);
  assert.equal(await page.locator(".admin-config-content .report-error").count(), 0, `${label}: configuration failed to load`);
}

(async () => {
  assert(adminUsername && adminPassword, "Set UI_TEST_USERNAME and UI_TEST_PASSWORD");
  const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || "chrome", headless: true });
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  let projectId, userId;
  try {
    await page.goto(baseUrl, { waitUntil: "networkidle" });
    await page.getByRole("button", { name: "管理员登录", exact: true }).click();
    await page.getByLabel("用户名").fill(adminUsername);
    await page.getByLabel("密码", { exact: true }).fill(adminPassword);
    await page.getByRole("button", { name: "登录", exact: true }).click();
    await page.getByRole("button", { name: "管理中心", exact: true }).waitFor();
    const created = await api(page, "/projects", "POST", { name: `Admin UI acceptance ${Date.now()}`, default_branch: "main", source_path: process.env.ADMIN_UI_SOURCE_PATH || "D:\\project\\PYproject\\testproject" });
    assert.equal(created.status, 201);
    projectId = created.body.id;
    for (const key of ["sca", "sast", "agent", "dast", "sandbox"]) {
      assert.equal((await api(page, `/modules/projects/${projectId}`, "POST", { module_key: key, enabled: true, config: {} })).status, 201);
    }
    const gate = { enabled: true, threshold: "critical", max_blocking_findings: 3 };
    assert.equal((await api(page, `/sast/projects/${projectId}/profile`, "PATCH", { quality_gate: gate })).status, 200);
    const suppression = await api(page, `/sast/projects/${projectId}/suppressions`, "POST", { rule_id: "TEST.LONG.RULE." + "segment".repeat(20), path_pattern: "test/**", reason: "长文本布局验收".repeat(20) });
    assert.equal(suppression.status, 201);
    const suppressionId = suppression.body.suppressions[0].id;
    const vex = await api(page, `/sca/projects/${projectId}/vex`, "POST", { ecosystem: "npm", package_name: "very-long-package-".repeat(12), vulnerability_id: "CVE-TEST-UI", status: "under_investigation", justification: "布局验证依据".repeat(40), actor: "forged-actor" });
    assert.equal(vex.status, 201);
    assert.equal(vex.body.actor, adminUsername, "VEX actor must come from session");
    await page.reload({ waitUntil: "networkidle" });
    await page.locator(".project-switcher select").selectOption(projectId);
    await page.getByRole("button", { name: "管理中心", exact: true }).click();
    await page.getByRole("button", { name: "模块配置", exact: true }).click();
    const groups = { SCA: ["本地规则与门禁", "风险例外", "VEX 适用性", "本地漏洞资源"], SAST: ["本地规则", "Semgrep 规则", "扫描默认配置", "AI 复核配置", "规则与路径抑制", "质量门禁"], AGENT: ["规则、白名单与门禁"], DAST: ["验证范围与流程"], SANDBOX: ["目标与运行配置"] };
    for (const width of [1600, 390]) {
      await page.setViewportSize({ width, height: 1000 });
      for (const [module, categories] of Object.entries(groups)) {
        await page.getByRole("navigation", { name: "管理员模块选择" }).getByRole("button", { name: module, exact: true }).click();
        for (const category of categories) {
          await page.getByRole("navigation", { name: "管理员配置分类" }).getByRole("button", { name: category, exact: true }).click();
          await page.waitForLoadState("networkidle");
          await assertLayout(page, `${width}px ${module}/${category}`);
          if (module === "AGENT") {
            for (const title of [/例外与边界/, /报告与审计/, /扫描与门禁/]) {
              await page.locator(".agent-governance-nav").getByRole("button", { name: title }).click();
              await assertLayout(page, `${width}px AGENT ${title}`);
            }
          }
        }
      }
    }
    const registered = await api(page, "/auth/register", "POST", { username: `admin_policy_user_${Date.now()}`, password: "abc123" });
    assert.equal(registered.status, 201);
    userId = registered.body.id;
    for (const [path, method, body] of [
      [`/sast/projects/${projectId}/profile`, "PATCH", { quality_gate: { enabled: false } }],
      [`/sast/projects/${projectId}/suppressions`, "POST", { rule_id: "*", reason: "bypass" }],
      [`/sast/projects/${projectId}/suppressions/${suppressionId}`, "PATCH", { enabled: false }],
      [`/sca/projects/${projectId}/vex`, "POST", { status: "not_affected" }],
      [`/sca/vex/${vex.body.id}`, "PATCH", { status: "not_affected" }],
      [`/agent/projects/${projectId}/profile`, "PATCH", { disabled_rule_ids: ["*"] }],
      [`/modules/projects/${projectId}`, "POST", { module_key: "sast", enabled: true, config: { sast_profile: {} } }],
      [`/modules/projects/${projectId}/sast`, "PATCH", { config: { sast_profile: {} } }],
      ["/sast/scan", "POST", { project_id: projectId, source_path: process.env.ADMIN_UI_SOURCE_PATH || "D:\\project\\PYproject\\testproject", include_local_rules: false }],
      ["/sast/jobs", "POST", { project_id: projectId, source_path: process.env.ADMIN_UI_SOURCE_PATH || "D:\\project\\PYproject\\testproject", semgrep_config: "other.yml" }],
    ]) assert.equal((await api(page, path, method, body)).status, 403, path);
    const before = await api(page, `/sast/projects/${projectId}/profile`);
    assert.equal((await api(page, `/modules/projects/${projectId}/sast`, "PATCH", { enabled: false })).status, 200);
    assert.equal((await api(page, `/modules/projects/${projectId}`, "POST", { module_key: "sast", enabled: true, config: {} })).status, 201);
    assert.deepEqual((await api(page, `/sast/projects/${projectId}/profile`)).body, before.body, "module re-enable must preserve policy");
    assert.equal((await api(page, `/sast/projects/${projectId}/profile`, "PATCH", { semgrep_enabled: false, community_rules_enabled: false })).status, 200);
    const exception = await api(page, `/sca/projects/${projectId}/exceptions`, "POST", { ecosystem: "npm", package_name: "test", exception_type: "risk_acceptance", reason: "read-only test sample", requester: "forged", requester_role: "admin" });
    assert.equal(exception.status, 201);
    assert.equal(exception.body.requester, registered.body.username);
    assert.equal(exception.body.status, "pending");
    const plan = await api(page, "/dast/plans", "POST", { project_id: projectId, title: "No-network authorization test", target_url: "http://localhost:3000", authorized_scope: "isolated test only", allowed_paths: ["/"], allowed_methods: ["GET"], requester: registered.body.username });
    assert.equal(plan.status, 201);
    assert.equal((await api(page, `/dast/plans/${plan.body.id}`, "PATCH", { approval_status: "approved", approval_reference: "user confirmed test scope", approved_by: registered.body.username })).status, 200, "DAST confirmation must not require admin");
    console.log("Admin module layout (1600/390), configuration permissions, module preservation and DAST user confirmation passed; no scan or target request executed.");
  } finally {
    const login = await api(page, "/auth/login", "POST", { username: adminUsername, password: adminPassword });
    assert.equal(login.status, 200, "cleanup login");
    if (projectId) assert.equal((await api(page, `/projects/${projectId}`, "DELETE")).status, 204, "cleanup test project");
    if (userId) assert.equal((await api(page, `/auth/users/${userId}`, "DELETE")).status, 204, "cleanup test user");
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
