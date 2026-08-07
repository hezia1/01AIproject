import { computed, ref } from "vue";
import { defineStore } from "pinia";
import { api, download, errorText } from "../api";

export type ModuleKey = "sca" | "sast" | "agent" | "dast" | "sandbox" | "aspm";
export type Entity = Record<string, any>;

const DEFAULT_MODULES: ModuleKey[] = ["sca", "sast", "aspm"];
const FALLBACK_MODULES = [
  { key: "sast", code: "SAST", name: "智能静态审计", subtitle: "规则扫描、语义复核、质量门禁与修复闭环", category: "detection", dependencies: [] },
  { key: "sca", code: "SCA", name: "供应链风险分析", subtitle: "SBOM、漏洞、许可证与依赖影响分析", category: "detection", dependencies: [] },
  { key: "agent", code: "AGENT", name: "Agent 供应链安全", subtitle: "指令、工具协议、插件与信任评分", category: "detection", dependencies: [] },
  { key: "dast", code: "DAST", name: "漏洞动态验证", subtitle: "业务验证、静态发现联动与三色裁决", category: "validation", dependencies: ["sast"] },
  { key: "sandbox", code: "SANDBOX", name: "沙箱动态证据链", subtitle: "隔离运行、行为监控与调用账本", category: "evidence", dependencies: ["agent"] },
  { key: "aspm", code: "ASPM", name: "平台治理与交付", subtitle: "攻击链、趋势、整改、门禁与报告", category: "governance", dependencies: [] },
];

export const usePlatformStore = defineStore("platform", () => {
  const modules = ref<Entity[]>(FALLBACK_MODULES);
  const projects = ref<Entity[]>([]);
  const project = ref<Entity | null>(null);
  const enabledModules = ref<ModuleKey[]>([...DEFAULT_MODULES]);
  const assetProbe = ref<Entity | null>(null);
  const components = ref<Entity[]>([]);
  const scaHistory = ref<Entity[]>([]);
  const scaScanId = ref<string | null>(null);
  const dependencyGraph = ref<Entity | null>(null);
  const scaDiff = ref<Entity | null>(null);
  const findings = ref<Entity[]>([]);
  const validations = ref<Entity[]>([]);
  const evidence = ref<Entity[]>([]);
  const sandboxTemplates = ref<Entity[]>([]);
  const summary = ref<Entity | null>(null);
  const evidenceGraph = ref<Entity | null>(null);
  const retests = ref<Record<string, Entity | null>>({ sca: null, sast: null, agent: null });
  const sourcePath = ref("D:\\project\\PYproject\\AI网安项目");
  const targetUrl = ref("https://example.com/login");
  const runCommand = ref("python agent_runner.py");
  const sandboxImage = ref("python:3.12-slim");
  const scaEnhanced = ref(true);
  const loading = ref(false);
  const status = ref("正在连接 API...");

  const riskComponents = computed(() => components.value.filter((item) => item.risk_status && item.risk_status !== "clean"));
  const severeFindings = computed(() => findings.value.filter((item) => ["critical", "high", "严重", "高危"].includes(String(item.severity).toLowerCase())));
  const counts = computed(() => ({
    components: components.value.length,
    riskComponents: riskComponents.value.length,
    findings: findings.value.length,
    severe: severeFindings.value.length,
    validations: validations.value.length,
    evidence: evidence.value.length,
  }));

  function enabled(key: ModuleKey) { return key === "aspm" || enabledModules.value.includes(key); }
  function clearData() {
    enabledModules.value = ["aspm"];
    assetProbe.value = null; components.value = []; scaHistory.value = []; scaScanId.value = null;
    dependencyGraph.value = null; scaDiff.value = null; findings.value = []; validations.value = [];
    evidence.value = []; sandboxTemplates.value = []; summary.value = null; evidenceGraph.value = null;
  }

  async function bootstrap() {
    loading.value = true;
    try {
      modules.value = await api<Entity[]>("/modules");
      projects.value = await api<Entity[]>("/projects");
      if (!projects.value.length) { project.value = null; clearData(); status.value = "API 已连接，请先创建项目"; return; }
      await selectProject(projects.value.find((item) => item.id === project.value?.id) ?? projects.value[0]);
      status.value = "API 已连接，已加载当前项目数据";
    } catch (error) { status.value = `API 未连接：${errorText(error)}`; }
    finally { loading.value = false; }
  }

  async function selectProject(next: Entity) {
    project.value = next;
    sourcePath.value = next.source_path || sourcePath.value;
    targetUrl.value = next.runtime_url || next.api_base_url || targetUrl.value;
    runCommand.value = next.sandbox_command || runCommand.value;
    sandboxImage.value = next.sandbox_image || sandboxImage.value;
    await refreshContext(next.id);
    status.value = `已切换到项目：${next.name}`;
  }

  async function refreshContext(projectId = project.value?.id, scanId: string | null = scaScanId.value) {
    if (!projectId) return;
    const [settings, probe] = await Promise.all([
      api<Entity[]>(`/modules/projects/${projectId}`),
      api<Entity>(`/projects/${projectId}/asset-probe`),
    ]);
    enabledModules.value = Array.from(new Set([...settings.filter((item) => item.enabled).map((item) => item.module_key), "aspm"])) as ModuleKey[];
    assetProbe.value = probe;
    await refreshData(projectId, scanId);
  }

  async function refreshData(projectId = project.value?.id, scanId: string | null = scaScanId.value) {
    if (!projectId) return;
    const history = await api<Entity[]>(`/sca/projects/${projectId}/scan-history`).catch(() => []);
    const effective = scanId ?? history[0]?.scan_task_id ?? null;
    const query = effective ? `?scan_task_id=${effective}` : "";
    const diffQuery = effective ? `?target_scan_id=${effective}` : "";
    const values = await Promise.all([
      api<Entity[]>(`/sca/projects/${projectId}/components${query}`).catch(() => []),
      api<Entity>(`/sca/projects/${projectId}/dependency-graph${query}`).catch(() => null),
      api<Entity>(`/sca/projects/${projectId}/scan-diff${diffQuery}`).catch(() => null),
      api<Entity[]>(`/findings?project_id=${projectId}`).catch(() => []),
      api<Entity[]>(`/dast/projects/${projectId}/validations`).catch(() => []),
      api<Entity[]>(`/sandbox/projects/${projectId}/evidence`).catch(() => []),
      api<Entity[]>(`/sandbox/projects/${projectId}/templates`).catch(() => []),
      api<Entity>(`/aspm/projects/${projectId}/summary`).catch(() => null),
      api<Entity>(`/aspm/projects/${projectId}/evidence-graph`).catch(() => null),
    ]);
    scaHistory.value = history; scaScanId.value = effective;
    [components.value, dependencyGraph.value, scaDiff.value, findings.value, validations.value, evidence.value, sandboxTemplates.value, summary.value, evidenceGraph.value] = values;
    const comparisons = await Promise.all(["SCA", "SAST", "AGENT"].map((source) => api<Entity>(`/findings/projects/${projectId}/retest-comparison?source=${source}`).catch(() => null)));
    retests.value = { sca: comparisons[0], sast: comparisons[1], agent: comparisons[2] };
  }

  async function createProject(draft: Entity) {
    if (!draft.name?.trim()) return;
    loading.value = true;
    try {
      const created = await api<Entity>("/projects", { method: "POST", body: JSON.stringify({ ...draft, name: draft.name.trim(), default_branch: draft.default_branch || "main" }) });
      await Promise.all(DEFAULT_MODULES.map((key) => api(`/modules/projects/${created.id}`, { method: "POST", body: JSON.stringify({ module_key: key, enabled: true, config: {} }) })));
      projects.value = await api<Entity[]>("/projects"); await selectProject(created); status.value = "项目已创建，默认启用 SCA + SAST + ASPM";
    } catch (error) { status.value = `项目创建失败：${errorText(error)}`; }
    finally { loading.value = false; }
  }

  async function updateProject(draft: Entity) {
    if (!project.value) return;
    loading.value = true;
    try {
      const updated = await api<Entity>(`/projects/${project.value.id}`, { method: "PATCH", body: JSON.stringify(draft) });
      projects.value = await api<Entity[]>("/projects"); await selectProject(updated); status.value = "项目资产配置已保存";
    } catch (error) { status.value = `保存失败：${errorText(error)}`; }
    finally { loading.value = false; }
  }

  async function deleteProject(id: string) {
    if (!confirm("确定删除该项目及其本地检测数据吗？")) return;
    loading.value = true;
    try { await api(`/projects/${id}`, { method: "DELETE" }); projects.value = await api<Entity[]>("/projects"); project.value = projects.value[0] ?? null; project.value ? await selectProject(project.value) : clearData(); status.value = "项目已删除"; }
    catch (error) { status.value = `删除失败：${errorText(error)}`; }
    finally { loading.value = false; }
  }

  async function toggleModule(key: ModuleKey) {
    if (!project.value || key === "aspm") return;
    const next = !enabled(key);
    try {
      await api(`/modules/projects/${project.value.id}/${key}`, { method: "PATCH", body: JSON.stringify({ enabled: next }) });
      if (next) enabledModules.value.push(key); else enabledModules.value = enabledModules.value.filter((item) => item !== key);
      status.value = `${key.toUpperCase()} 已${next ? "启用" : "停用"}`;
    } catch (error) { status.value = `模块更新失败：${errorText(error)}`; }
  }

  async function scan(kind: "sca" | "sast" | "agent") {
    if (!project.value) return;
    loading.value = true;
    try {
      const body: Entity = { project_id: project.value.id, source_path: sourcePath.value, clear_previous: false };
      if (kind === "sca") body.enable_tool_scan = scaEnhanced.value;
      const result = await api<Entity>(`/${kind}/scan`, { method: "POST", body: JSON.stringify(body) });
      if (kind === "sca" && result.scan_task_id) scaScanId.value = result.scan_task_id;
      await refreshContext(project.value.id, scaScanId.value); status.value = `${kind.toUpperCase()} 扫描完成`;
    } catch (error) { status.value = `${kind.toUpperCase()} 扫描失败：${errorText(error)}`; }
    finally { loading.value = false; }
  }

  async function runUnified() {
    for (const key of ["sca", "sast", "agent"] as const) if (enabled(key)) await scan(key);
    status.value = "统一安全检测已执行完成";
  }

  async function selectScaSnapshot(id: string) { scaScanId.value = id; await refreshData(project.value?.id, id); status.value = "SCA 历史快照已切换"; }
  async function updateFinding(id: string, patch: Entity) { await api(`/findings/${id}/governance`, { method: "PATCH", body: JSON.stringify(patch) }); await refreshData(); status.value = "整改信息已更新"; }
  async function exportSbom(format: "cyclonedx" | "spdx") { if (!project.value) return; const suffix = scaScanId.value ? `&scan_task_id=${scaScanId.value}` : ""; await download(`/sca/projects/${project.value.id}/sbom?format=${format}${suffix}`, `${project.value.name}-${format}-sbom.json`); }
  async function exportScaReport() { if (!project.value) return; const query = scaScanId.value ? `?scan_task_id=${scaScanId.value}` : ""; await download(`/sca/projects/${project.value.id}/report.html${query}`, `${project.value.name}-sca-report.html`, "text/html"); }
  async function runSastReview() { if (!project.value) return; loading.value = true; try { await api(`/sast/projects/${project.value.id}/agent-review`, { method: "POST" }); await refreshData(); status.value = "SAST Sub-agent 复核完成"; } catch (error) { status.value = `复核失败：${errorText(error)}`; } finally { loading.value = false; } }

  return { modules, projects, project, enabledModules, assetProbe, components, scaHistory, scaScanId, dependencyGraph, scaDiff, findings, validations, evidence, sandboxTemplates, summary, evidenceGraph, retests, sourcePath, targetUrl, runCommand, sandboxImage, scaEnhanced, loading, status, counts, enabled, bootstrap, selectProject, refreshContext, refreshData, createProject, updateProject, deleteProject, toggleModule, scan, runUnified, selectScaSnapshot, updateFinding, exportSbom, exportScaReport, runSastReview };
});
