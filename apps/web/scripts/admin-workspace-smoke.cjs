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
  let projectId, userId, baselinePolicy;
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
    for (let index = 0; index < 11; index++) {
      assert.equal((await api(page, `/sast/projects/${projectId}/rules`, "POST", { rule_id: `CUSTOM.PAGINATION.${index}`, title: `Pagination rule ${index}`, pattern: "dangerous_call\\(", severity: "medium", category: "custom", file_extensions: [".py"] })).status, 201);
    }
    const yamlPack = await api(page, `/sast/projects/${projectId}/semgrep-rules`, "POST", { name: "Editable YAML smoke", status: "draft", content: "rules:\n  - id: smoke.example\n    languages: [python]\n    severity: WARNING\n    message: Example\n    pattern: eval(...)\n" });
    assert.equal(yamlPack.status, 201);
    await page.reload({ waitUntil: "networkidle" });
    await page.locator(".project-switcher select").selectOption(projectId);
    await page.getByRole("button", { name: "管理中心", exact: true }).click();
    await page.getByRole("button", { name: "模块配置", exact: true }).click();
    const groups = { SCA: ["本地规则与门禁", "风险例外", "VEX 适用性", "本地漏洞资源"], SAST: ["本地规则", "联网下载策略", "Semgrep 规则", "扫描默认配置", "AI 复核配置", "规则与路径抑制", "质量门禁"], AGENT: ["规则、白名单与门禁"], DAST: ["验证范围与流程"], SANDBOX: ["镜像白名单与联网", "目标与运行配置"] };
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
    await page.setViewportSize({ width: 1600, height: 1000 });
    async function selectAdmin(module, category) {
      await page.getByRole("navigation", { name: "管理员模块选择" }).getByRole("button", { name: module, exact: true }).click();
      await page.getByRole("navigation", { name: "管理员配置分类" }).getByRole("button", { name: category, exact: true }).click();
      await page.waitForLoadState("networkidle");
    }
    await selectAdmin("SAST", "本地规则");
    const localRules = page.locator(".sast-local-rules-panel");
    await localRules.locator("tbody tr").first().waitFor({ state: "attached", timeout: 10000 }).catch(async error => {
      console.error("SAST page diagnostic", (await localRules.innerText()).slice(-1500), "API rule count", (await api(page, `/sast/projects/${projectId}/profile`)).body.custom_rules?.length);
      throw error;
    });
    assert.equal(await localRules.locator("tbody tr").count(), 10);
    await localRules.getByRole("button", { name: "下一页", exact: true }).click();
    assert.equal(await localRules.locator("tbody tr").count(), 1);
    await localRules.getByRole("button", { name: "编辑", exact: true }).click();
    await localRules.getByLabel("标题", { exact: true }).fill("Edited rule on second page");
    await localRules.getByRole("button", { name: "保存修改", exact: true }).click();
    await localRules.getByRole("status").filter({ hasText: "项目自定义规则已保存" }).waitFor();
    const savedRules = (await api(page, `/sast/projects/${projectId}/profile`)).body.custom_rules;
    assert.equal(savedRules.length, 11);
    assert(savedRules.some(rule => rule.title === "Edited rule on second page" && rule.version === 2));
    await selectAdmin("SAST", "Semgrep 规则");
    const yamlEditor = page.locator(".admin-config-content");
    await yamlEditor.getByRole("button", { name: "编辑", exact: true }).click();
    await yamlEditor.getByLabel("规则包名称", { exact: true }).fill("Edited YAML smoke");
    const yamlSaved = page.waitForResponse(response => response.url().includes(`/sast/projects/${projectId}/semgrep-rules/`) && response.request().method() === "PATCH");
    await yamlEditor.getByRole("button", { name: "保存草稿", exact: true }).click();
    assert.equal((await yamlSaved).status(), 200);
    const packs = (await api(page, `/sast/projects/${projectId}/semgrep-rules`)).body.semgrep_rules;
    assert(packs.length === 1 && packs[0].name === "Edited YAML smoke" && packs[0].version === 2 && packs[0].status === "draft");
    await selectAdmin("SCA", "本地规则与门禁");
    const policies = page.locator(".admin-config-content");
    await policies.getByRole("button", { name: "编辑", exact: true }).first().click();
    await policies.getByLabel("漏洞说明", { exact: true }).fill("Temporary UI edit verification");
    await policies.getByRole("button", { name: "保存策略", exact: true }).click();
    await policies.getByRole("status").filter({ hasText: "策略已保存" }).waitFor();
    assert((await api(page, `/sca/policies?project_id=${projectId}`)).body.vulnerability_rules.some(rule => rule.summary === "Temporary UI edit verification"));
    await selectAdmin("SANDBOX", "镜像白名单与联网");
    const sandboxPolicy = page.locator(".admin-config-content");
    assert(await sandboxPolicy.locator("tbody tr").count() <= 10);
    baselinePolicy = (await api(page, "/admin/maintenance-policy")).body;
    await sandboxPolicy.getByLabel("镜像仓库", { exact: true }).fill("acceptance/runtime");
    await sandboxPolicy.getByRole("button", { name: "添加到草稿", exact: true }).click();
    assert.deepEqual((await api(page, "/admin/maintenance-policy")).body.config, baselinePolicy.config, "draft must not affect running policy");
    const reloadPolicy = page.waitForResponse(response => response.url().endsWith("/admin/maintenance-policy") && response.request().method() === "GET");
    await sandboxPolicy.getByRole("button", { name: "重新加载", exact: true }).click();
    await reloadPolicy;
    await page.waitForLoadState("networkidle");
    const savedPolicyResponse = page.waitForResponse(response => response.url().endsWith("/admin/maintenance-policy") && response.request().method() === "PUT");
    await sandboxPolicy.getByRole("button", { name: "保存配置", exact: true }).click();
    assert.equal((await savedPolicyResponse).status(), 200);
    assert.deepEqual((await api(page, "/admin/maintenance-policy")).body.config, baselinePolicy.config, "save preserves existing effective policy");
    const conflict = await api(page, "/admin/maintenance-policy", "PUT", baselinePolicy);
    assert.equal(conflict.status, 409, "stale version must not overwrite policy");
    const registered = await api(page, "/auth/register", "POST", { username: `admin_policy_user_${Date.now()}`, password: "abc123" });
    assert.equal(registered.status, 201);
    userId = registered.body.id;
    for (const [path, method, body] of [
      ["/admin/maintenance-policy", "PUT", { config: {}, version: 0 }],
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
    console.log("Admin module layout (1600/390), 10-row pagination, SAST/SCA editing, maintenance policy persistence/concurrency, configuration permissions and DAST user confirmation passed; no scan or download executed.");
  } finally {
    const login = await api(page, "/auth/login", "POST", { username: adminUsername, password: adminPassword });
    assert.equal(login.status, 200, "cleanup login");
    if (baselinePolicy) {
      const latest = (await api(page, "/admin/maintenance-policy")).body;
      if (latest.actor === adminUsername && JSON.stringify(latest.config) !== JSON.stringify(baselinePolicy.config)) {
        assert.equal((await api(page, "/admin/maintenance-policy", "PUT", { config: baselinePolicy.config, version: latest.version })).status, 200, "restore smoke policy changes");
      }
    }
    if (projectId) assert.equal((await api(page, `/projects/${projectId}`, "DELETE")).status, 204, "cleanup test project");
    if (userId) assert.equal((await api(page, `/auth/users/${userId}`, "DELETE")).status, 204, "cleanup test user");
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
