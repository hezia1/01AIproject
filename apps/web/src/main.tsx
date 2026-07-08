import React, { useEffect, useMemo, useState } from "react";
import ReactDOM from "react-dom/client";
import { Activity, Boxes, Bug, Check, FlaskConical, FolderKanban, GitBranch, Lock, Network, Play, Plus, ShieldCheck, SlidersHorizontal } from "lucide-react";
import "./styles.css";

type ViewKey = "projects" | "assets" | "modules" | "sca" | "sast" | "agent" | "dast" | "sandbox" | "tasks" | "aspm";
type ModuleKey = "sast" | "sca" | "agent" | "dast" | "sandbox" | "aspm";
type Severity = "critical" | "high" | "medium" | "low" | "info";
type FindingStatus = "open" | "pending" | "confirmed" | "fixing" | "fixed" | "accepted_risk" | "false_positive" | "retest" | "closed";

type SecurityModule = { key: ModuleKey; code: string; name: string; subtitle: string; category: string; description: string; capabilities: { title: string; description: string }[]; dependencies: ModuleKey[]; default_config: Record<string, unknown> };
type Project = { id: string; name: string; business_owner: string | null; security_owner: string | null; repository_url: string | null; source_path: string | null; runtime_url: string | null; api_base_url: string | null; sandbox_command: string | null; sandbox_image: string | null; default_branch: string; risk_score: number; created_at: string };
type ProjectDraft = { name: string; business_owner: string; security_owner: string; repository_url: string; source_path: string; runtime_url: string; api_base_url: string; sandbox_command: string; sandbox_image: string; default_branch: string };
type ProjectAssetDraft = Pick<ProjectDraft, "runtime_url" | "api_base_url" | "sandbox_command" | "sandbox_image">;
type ProjectModule = { project_id: string; module_key: ModuleKey; enabled: boolean; config: Record<string, unknown> };
type ProjectAssetProbe = { project_id: string; source_path: string | null; path_exists: boolean; sca_files: string[]; source_files: string[]; agent_files: string[]; recommended_tasks: ("sca" | "sast" | "agent")[]; message: string };
type Component = { id: string; ecosystem: string; name: string; version: string | null; dependency_type: string; source_file: string; package_manager: string | null; license?: string | null; risk_status?: string; vulnerability_ids?: string[]; severity?: Severity | null; risk_summary?: string | null; remediation?: string | null; license_risk?: string | null; risk_source?: string | null; osv_checked?: boolean; osv_error?: string | null };
type DependencyGraphNode = { id: string; label: string; kind: string; risk_status?: string | null; severity?: Severity | null; dependency_type?: string | null; ecosystem?: string | null; version?: string | null };
type DependencyGraphEdge = { source: string; target: string; quality: string };
type UpgradeLever = { component_id: string; component: string; ecosystem: string; version: string | null; risk_transitive_count: number; highest_severity: Severity | null; affected_components: string[]; recommendation: string };
type DependencyGraph = { project_id: string; nodes: DependencyGraphNode[]; edges: DependencyGraphEdge[]; upgrade_levers: UpgradeLever[]; summary: Record<string, number> };
type AiReview = { summary: string; false_positive_likelihood: string; remediation: string; category?: string | null; cwe?: string | null; owasp?: string | null; language?: string | null; description?: string | null; trust_impact?: string | null; agent_pipeline?: string[]; review_verdict?: string | null; evidence_summary?: string | null; fix_strategy?: string | null; priority?: string | null };
type Finding = { id: string; source: string; rule_id: string; title: string; severity: Severity; file_path: string | null; line_start: number | null; status: FindingStatus; evidence: string | null; ai_review?: AiReview | null; remediation_owner?: string | null; remediation_note?: string | null; remediation_due_at?: string | null; updated_at?: string | null };
type DastValidation = { id: string; target_url: string; verdict: string; validator: string | null; evidence_summary: string | null; request_summary?: string | null; response_summary?: string | null; reproduction_steps?: string | null; remediation_hint?: string | null; created_at: string };
type SandboxEvidence = { id: string; run_command: string; runtime_profile: string | null; network_policy: string; filesystem_policy: string; observed_files: Record<string, unknown>[]; observed_network: Record<string, unknown>[]; observed_processes: Record<string, unknown>[]; observed_tool_calls: Record<string, unknown>[]; evidence_summary: string | null; operator: string | null; created_at: string };
type SandboxTemplate = { name: string; command: string; command_type: string; image: string; risk_level: string; description: string };
type AttackChainStep = { module: string; title: string; evidence: string | null };
type AttackChain = { id: string; name: string; severity: Severity; modules: string[]; evidence_count: number; summary: string; recommended_action: string; steps: AttackChainStep[] };
type AspmSummary = { project_id: string; project_name: string; enabled_modules: ModuleKey[]; risk_score: number; component_count: number; finding_count: number; dast_validation_count: number; sandbox_evidence_count: number; scan_task_count: number; findings_by_source: Record<string, number>; findings_by_severity: Record<string, number>; findings_by_status: Record<string, number>; dast_by_verdict: Record<string, number>; attack_chains: AttackChain[] };

const API_BASE = "http://127.0.0.1:8000/api";
const DEFAULT_ENABLED_MODULES: ModuleKey[] = ["sast", "sca", "aspm"];
const OPTIONAL_MODULES: ModuleKey[] = ["sast", "sca", "agent", "dast", "sandbox"];
const DEFAULT_SOURCE_PATH = "D:\\project\\PYproject\\AI网安项目\\outputs\\sca-sample";
const DEFAULT_SAST_PATH = "D:\\project\\PYproject\\AI网安项目\\outputs\\sast-sample";
const DEFAULT_AGENT_PATH = "D:\\project\\PYproject\\AI网安项目\\outputs\\agent-sample";
const FINDING_WORKFLOW_STATUSES: FindingStatus[] = ["open", "confirmed", "fixing", "fixed", "accepted_risk", "false_positive"];

const fallbackModules: SecurityModule[] = [
  { key: "sast", code: "SAST", name: "智能静态审计", subtitle: "定制化安全 Skill + 多 Sub-agent 编排 + 行业历史漏洞知识库", category: "detection", description: "面向代码仓库执行智能静态审计，将规则扫描、AI 审计、历史漏洞经验和多 Agent 复核组合为代码风险发现能力。", capabilities: [{ title: "定制化安全 Skill", description: "按行业、框架和业务场景生成审计策略。" }, { title: "多 Sub-agent 编排", description: "发现、复核、证据和修复建议分工协同。" }, { title: "行业历史漏洞知识库", description: "沉淀通用漏洞、业务漏洞和误报经验。" }], dependencies: [], default_config: {} },
  { key: "sca", code: "SCA", name: "供应链风险分析", subtitle: "SBOM + 组件漏洞匹配 + 许可证风险归一化 + 依赖影响分析", category: "detection", description: "解析多语言工程依赖，生成 SBOM，识别漏洞、许可证和直接/传递依赖风险，并给出修复优先级。", capabilities: [{ title: "SBOM 生成", description: "生成项目组件清单和依赖来源。" }, { title: "组件漏洞匹配", description: "匹配 CVE、受影响版本和修复版本。" }, { title: "许可证风险归一化", description: "识别许可证类型并归一化风险等级。" }, { title: "依赖影响分析", description: "分析直接/传递依赖、版本归一化和修复影响。" }], dependencies: [], default_config: {} },
  { key: "agent", code: "AGENT", name: "Agent 供应链安全", subtitle: "指令文件 + 工具协议 + 插件扩展 + 信任评分", category: "detection", description: "面向 Agent、MCP、工具协议和插件扩展执行安全检查，识别提示注入、工具滥用、敏感资源访问等新攻击面。", capabilities: [{ title: "指令文件扫描", description: "扫描 Agent 指令文件和 Prompt。" }, { title: "工具协议扫描", description: "扫描 MCP Server 和工具定义。" }, { title: "插件扩展扫描", description: "扫描插件清单和权限边界。" }, { title: "信任评分", description: "生成覆盖矩阵与信任评分。" }], dependencies: [], default_config: {} },
  { key: "dast", code: "DAST", name: "漏洞动态验证", subtitle: "Web 业务验证 + 静态发现联动验证 + 三色裁决", category: "validation", description: "将静态发现、供应链风险和运行时目标联动验证，输出可利用、不确定、不可利用三态裁决和完整验证证据。", capabilities: [{ title: "Web 业务验证", description: "对目标 Web 应用执行业务化安全验证。" }, { title: "静态发现联动验证", description: "将 SAST/SCA/Agent 发现转为验证策略。" }, { title: "三色裁决", description: "输出可利用、不确定、不可利用的验证结论。" }, { title: "证据归档", description: "保留执行日志、请求响应、截图和验证过程。" }], dependencies: ["sast"], default_config: {} },
  { key: "sandbox", code: "SANDBOX", name: "沙箱动态证据链", subtitle: "隔离环境 + 行为监控 + 调用账本 + AI 驱动动态验证", category: "evidence", description: "在隔离环境中运行目标程序、插件或 Agent，采集文件、网络、进程、工具调用和运行时行为证据。", capabilities: [{ title: "隔离环境", description: "以容器或受控运行时隔离目标执行。" }, { title: "行为监控", description: "监控文件访问、网络连接、进程启动和环境变量读取。" }, { title: "调用账本", description: "结构化采集 Agent 工具调用和运行时覆盖。" }, { title: "策略化探测", description: "适配多类 Agent 运行时并支持 AI 驱动验证。" }], dependencies: ["agent"], default_config: {} },
  { key: "aspm", code: "ASPM", name: "平台治理与交付", subtitle: "项目组 + 攻击链 + 风险趋势 + 整改闭环 + 安全门禁", category: "governance", description: "聚合各模块结果，提供跨项目关联、攻击链、风险趋势、整改闭环、开放接口、流水线门禁和合规报告。", capabilities: [{ title: "风险治理", description: "管理项目组、跨项目关联、攻击链、风险趋势和整改闭环。" }, { title: "开放接口", description: "提供开放工具接口、批量任务和研发流水线安全门禁。" }, { title: "权限与配额", description: "管理模块权限、授权配额和审计日志。" }, { title: "交付报告", description: "输出诊断导出、合规报告和治理看板。" }], dependencies: [], default_config: {} },
];

const moduleIcons: Record<ModuleKey, React.ReactNode> = { sast: <Bug size={20} />, sca: <Boxes size={20} />, agent: <Network size={20} />, dast: <Activity size={20} />, sandbox: <FlaskConical size={20} />, aspm: <ShieldCheck size={20} /> };

function App() {
  const [activeView, setActiveView] = useState<ViewKey>("modules");
  const [modules, setModules] = useState<SecurityModule[]>(fallbackModules);
  const [projects, setProjects] = useState<Project[]>([]);
  const [project, setProject] = useState<Project | null>(null);
  const emptyProjectDraft: ProjectDraft = { name: "", business_owner: "", security_owner: "", repository_url: "", source_path: "", runtime_url: "", api_base_url: "", sandbox_command: "", sandbox_image: "", default_branch: "main" };
  const [projectDraft, setProjectDraft] = useState<ProjectDraft>(emptyProjectDraft);
  const [assetProbe, setAssetProbe] = useState<ProjectAssetProbe | null>(null);
  const [enabledModules, setEnabledModules] = useState<Set<ModuleKey>>(() => new Set(DEFAULT_ENABLED_MODULES));
  const [components, setComponents] = useState<Component[]>([]);
  const [dependencyGraph, setDependencyGraph] = useState<DependencyGraph | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [validations, setValidations] = useState<DastValidation[]>([]);
  const [evidence, setEvidence] = useState<SandboxEvidence[]>([]);
  const [sandboxTemplates, setSandboxTemplates] = useState<SandboxTemplate[]>([]);
  const [summary, setSummary] = useState<AspmSummary | null>(null);
  const [sourcePath, setSourcePath] = useState(DEFAULT_SOURCE_PATH);
  const [sastPath, setSastPath] = useState(DEFAULT_SAST_PATH);
  const [agentPath, setAgentPath] = useState(DEFAULT_AGENT_PATH);
  const [targetUrl, setTargetUrl] = useState("https://example.com/login");
  const [runCommand, setRunCommand] = useState("python agent_runner.py");
  const [sandboxImage, setSandboxImage] = useState("python:3.12-slim");
  const [status, setStatus] = useState("正在连接 API...");
  const [loading, setLoading] = useState(false);
  const [savingKey, setSavingKey] = useState<ModuleKey | null>(null);

  useEffect(() => { void bootstrap(); }, []);

  const optionalModules = useMemo(() => modules.filter((module) => OPTIONAL_MODULES.includes(module.key)), [modules]);
  const selectedModules = useMemo(() => optionalModules.filter((module) => enabledModules.has(module.key)), [enabledModules, optionalModules]);
  const ecosystemSummary = useMemo(() => countBy(components, "ecosystem"), [components]);
  const scaRiskSummary = useMemo(() => countBy(components, "risk_status"), [components]);
  const sastFindings = useMemo(() => findings.filter((finding) => finding.source === "SAST"), [findings]);
  const sastCategorySummary = useMemo(() => countBy(sastFindings.map((finding) => ({ category: finding.ai_review?.category ?? "unknown" })), "category"), [sastFindings]);
  const agentFindings = useMemo(() => findings.filter((finding) => finding.source === "AGENT"), [findings]);
  const agentCategorySummary = useMemo(() => countBy(agentFindings.map((finding) => ({ category: finding.ai_review?.category ?? "unknown" })), "category"), [agentFindings]);

  async function bootstrap() {
    setLoading(true);
    try {
      const moduleData = await request<SecurityModule[]>("/modules");
      setModules(moduleData);
      const projectData = await request<Project[]>("/projects");
      setProjects(projectData);
      if (projectData.length === 0) {
        clearProjectData();
        setProject(null);
        setStatus("API 已连接，请先创建项目");
        return;
      }
      const nextProject = projectData.find((item) => item.id === project?.id) ?? projectData[0];
      await selectProject(nextProject, projectData);
      setStatus("API 已连接，已加载当前项目数据");
    } catch (error) {
      console.error(error);
      setStatus("API 未连接，当前只能查看本地预览结构");
    } finally {
      setLoading(false);
    }
  }

  function clearProjectData() {
    setEnabledModules(new Set(["aspm"]));
    setComponents([]);
    setDependencyGraph(null);
    setFindings([]);
    setValidations([]);
    setEvidence([]);
    setSandboxTemplates([]);
    setSummary(null);
    setAssetProbe(null);
  }

  async function selectProject(nextProject: Project, knownProjects = projects) {
    setLoading(true);
    try {
      setProject(nextProject);
      setProjects(knownProjects.length ? knownProjects : await request<Project[]>("/projects"));
      if (nextProject.source_path) {
        setSourcePath(nextProject.source_path);
        setSastPath(nextProject.source_path);
        setAgentPath(nextProject.source_path);
      }
      if (nextProject.runtime_url || nextProject.api_base_url) {
        setTargetUrl(nextProject.runtime_url ?? nextProject.api_base_url ?? "");
      }
      if (nextProject.sandbox_command) setRunCommand(nextProject.sandbox_command);
      if (nextProject.sandbox_image) setSandboxImage(nextProject.sandbox_image);
      await refreshProjectContext(nextProject.id);
      setStatus(`已切换到项目：${nextProject.name}`);
    } catch (error) {
      console.error(error);
      setStatus("项目切换失败");
    } finally {
      setLoading(false);
    }
  }

  async function refreshProjectContext(projectId = project?.id) {
    if (!projectId) return;
    const [projectModules, probeData] = await Promise.all([
      request<ProjectModule[]>(`/modules/projects/${projectId}`),
      request<ProjectAssetProbe>(`/projects/${projectId}/asset-probe`),
    ]);
    if (!projectModules.some((item) => item.module_key === "aspm" && item.enabled)) {
      await enableProjectModule(projectId, "aspm", true);
    }
    setEnabledModules(new Set([...projectModules.filter((item) => item.enabled).map((item) => item.module_key), "aspm"]));
    setAssetProbe(probeData);
    await refreshProjectData(projectId);
  }

  async function refreshProjectData(projectId = project?.id) {
    if (!projectId) return;
    const [componentData, graphData, findingData, validationData, evidenceData, templateData, summaryData] = await Promise.all([
      request<Component[]>(`/sca/projects/${projectId}/components`),
      request<DependencyGraph>(`/sca/projects/${projectId}/dependency-graph`).catch(() => null),
      request<Finding[]>(`/findings?project_id=${projectId}`),
      request<DastValidation[]>(`/dast/projects/${projectId}/validations`),
      request<SandboxEvidence[]>(`/sandbox/projects/${projectId}/evidence`),
      request<SandboxTemplate[]>(`/sandbox/projects/${projectId}/templates`),
      request<AspmSummary>(`/aspm/projects/${projectId}/summary`),
    ]);
    setComponents(componentData);
    setDependencyGraph(graphData);
    setFindings(findingData);
    setValidations(validationData);
    setEvidence(evidenceData);
    setSandboxTemplates(templateData);
    setSummary(summaryData);
  }

  async function createProject(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!projectDraft.name.trim()) return setStatus("项目名称不能为空");
    setLoading(true);
    try {
      const created = await request<Project>("/projects", {
        method: "POST",
        body: JSON.stringify({
          name: projectDraft.name.trim(),
          business_owner: emptyToNull(projectDraft.business_owner),
          security_owner: emptyToNull(projectDraft.security_owner),
          repository_url: emptyToNull(projectDraft.repository_url),
          source_path: emptyToNull(projectDraft.source_path),
          runtime_url: emptyToNull(projectDraft.runtime_url),
          api_base_url: emptyToNull(projectDraft.api_base_url),
          sandbox_command: emptyToNull(projectDraft.sandbox_command),
          sandbox_image: emptyToNull(projectDraft.sandbox_image),
          default_branch: projectDraft.default_branch.trim() || "main",
        }),
      });
      await Promise.all(DEFAULT_ENABLED_MODULES.map((moduleKey) => enableProjectModule(created.id, moduleKey, true)));
      const projectData = await request<Project[]>("/projects");
      setProjectDraft(emptyProjectDraft);
      await selectProject(created, projectData);
      setStatus(`项目已创建，并默认启用 ${DEFAULT_ENABLED_MODULES.map((item) => item.toUpperCase()).join(" + ")}`);
    } catch (error) {
      console.error(error);
      setStatus("项目创建失败");
    } finally {
      setLoading(false);
    }
  }

  async function updateProjectAssets(draft: ProjectAssetDraft) {
    if (!project) return setStatus("请先选择项目");
    setLoading(true);
    try {
      const updated = await request<Project>(`/projects/${project.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          runtime_url: emptyToNull(draft.runtime_url),
          api_base_url: emptyToNull(draft.api_base_url),
          sandbox_command: emptyToNull(draft.sandbox_command),
          sandbox_image: emptyToNull(draft.sandbox_image),
        }),
      });
      const projectData = await request<Project[]>("/projects");
      await selectProject(updated, projectData);
      setStatus("项目资产配置已保存");
    } catch (error) {
      console.error(error);
      setStatus("项目资产配置保存失败");
    } finally {
      setLoading(false);
    }
  }

  async function deleteProject(projectId: string) {
    setLoading(true);
    try {
      await request(`/projects/${projectId}`, { method: "DELETE" });
      const projectData = await request<Project[]>("/projects");
      setProjects(projectData);
      if (project?.id === projectId) {
        if (projectData.length > 0) {
          await selectProject(projectData[0], projectData);
        } else {
          setProject(null);
          clearProjectData();
        }
      }
      setStatus("项目已删除");
    } catch (error) {
      console.error(error);
      setStatus("项目删除失败");
    } finally {
      setLoading(false);
    }
  }

  async function toggleModule(module: SecurityModule) {
    const nextEnabled = !enabledModules.has(module.key);
    const next = new Set(enabledModules);
    if (nextEnabled) { next.add(module.key); module.dependencies.forEach((dependency) => next.add(dependency)); } else { next.delete(module.key); }
    setEnabledModules(next);
    if (!project) return;
    setSavingKey(module.key);
    try {
      if (nextEnabled) {
        await enableProjectModule(project.id, module.key, true);
        await Promise.all(module.dependencies.map((dependency) => enableProjectModule(project.id, dependency, true)));
      } else {
        await updateProjectModule(project.id, module.key, false);
      }
      await refreshProjectContext(project.id);
      setStatus("模块配置已保存");
    } catch (error) { console.error(error); setStatus("模块配置保存失败"); } finally { setSavingKey(null); }
  }

  async function runScan(kind: "sca" | "sast" | "agent") {
    if (!project) return setStatus("API 未连接，无法执行任务");
    const source = kind === "sca" ? sourcePath : kind === "sast" ? sastPath : agentPath;
    setLoading(true);
    try {
      await request(`/${kind}/scan`, { method: "POST", body: JSON.stringify({ project_id: project.id, source_path: source, clear_previous: true }) });
      await refreshProjectContext(project.id);
      setStatus(`${kind.toUpperCase()} 扫描完成`);
    } catch (error) { console.error(error); setStatus(`${kind.toUpperCase()} 扫描失败：${errorMessage(error)}`); } finally { setLoading(false); }
  }

  async function runRecommendedScans() {
    if (!project || !assetProbe) return;
    const runnable = assetProbe.recommended_tasks.filter((kind) => enabledModules.has(kind));
    if (runnable.length === 0) return setStatus("没有可执行的推荐任务，请先配置源码路径并启用对应模块");
    setLoading(true);
    try {
      for (const kind of runnable) {
        await request(`/${kind}/scan`, { method: "POST", body: JSON.stringify({ project_id: project.id, source_path: project.source_path ?? sourcePath, clear_previous: true }) });
      }
      await refreshProjectContext(project.id);
      setStatus(`推荐任务已完成：${runnable.map((item) => item.toUpperCase()).join(" + ")}`);
    } catch (error) {
      console.error(error);
      setStatus("推荐任务执行失败，请确认模块已启用、路径可访问");
    } finally {
      setLoading(false);
    }
  }

  async function createDastValidation() {
    if (!project) return;
    setLoading(true);
    try {
      await request("/dast/probe", { method: "POST", body: JSON.stringify({ project_id: project.id, target_url: targetUrl, validator: "auto-dast" }) });
      await refreshProjectContext(project.id);
      setStatus("DAST 自动验证已完成");
    } catch (error) { console.error(error); setStatus("DAST 记录创建失败，请确认模块已启用"); } finally { setLoading(false); }
  }

  async function createSandboxEvidence() {
    if (!project) return;
    setLoading(true);
    try {
      await request("/sandbox/run", { method: "POST", body: JSON.stringify({ project_id: project.id, run_command: runCommand, image: sandboxImage, timeout_seconds: 10, operator: "security-user" }) });
      await refreshProjectContext(project.id);
      setStatus("SANDBOX 受控执行已完成");
    } catch (error) { console.error(error); setStatus("SANDBOX 执行失败，请确认模块已启用且命令未被安全策略阻止"); } finally { setLoading(false); }
  }

  async function updateFindingGovernance(findingId: string, patch: Partial<Pick<Finding, "status" | "remediation_owner" | "remediation_note" | "remediation_due_at">>) {
    if (!project) return;
    try {
      await request<Finding>(`/findings/${findingId}/governance`, { method: "PATCH", body: JSON.stringify(patch) });
      await refreshProjectData(project.id);
      setStatus("整改信息已更新");
    } catch (error) {
      console.error(error);
      setStatus("整改信息更新失败");
    }
  }

  async function runSastAgentReview() {
    if (!project) return;
    setLoading(true);
    try {
      await request<Finding[]>(`/sast/projects/${project.id}/agent-review`, { method: "POST" });
      await refreshProjectContext(project.id);
      setStatus("SAST Sub-agent 编排复核已完成");
    } catch (error) {
      console.error(error);
      setStatus(`SAST Sub-agent 编排失败：${errorMessage(error)}`);
    } finally {
      setLoading(false);
    }
  }

  async function exportScaSbom(format: "cyclonedx" | "spdx") {
    if (!project) return setStatus("请先选择项目");
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/sca/projects/${project.id}/sbom?format=${format}`);
      if (!response.ok) {
        let detail = `${response.status} ${response.statusText}`;
        try {
          const payload = await response.json();
          detail = typeof payload.detail === "string" ? payload.detail : detail;
        } catch { /* keep HTTP status */ }
        throw new Error(detail);
      }
      const sbom = await response.json();
      const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${project.name || "project"}-${format}-sbom.json`;
      link.click();
      URL.revokeObjectURL(url);
      setStatus(`${format === "cyclonedx" ? "CycloneDX" : "SPDX"} SBOM 已导出`);
    } catch (error) {
      console.error(error);
      setStatus(`SBOM 导出失败：${errorMessage(error)}`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="app-shell">
      <aside className="sidebar"><div className="brand"><ShieldCheck size={26} /><div><strong>AI 安全平台</strong><span>Application Security</span></div></div><nav className="nav-list">
        <NavButton active={activeView === "projects"} onClick={() => setActiveView("projects")} icon={<FolderKanban size={18} />} label="项目管理" />
        <NavButton active={activeView === "assets"} onClick={() => setActiveView("assets")} icon={<GitBranch size={18} />} label="项目资产" />
        <NavButton active={activeView === "modules"} onClick={() => setActiveView("modules")} icon={<SlidersHorizontal size={18} />} label="模块接入" />
        <NavButton active={activeView === "tasks"} onClick={() => setActiveView("tasks")} icon={<Play size={18} />} label="任务中心" />
        <NavButton active={activeView === "sca"} onClick={() => setActiveView("sca")} icon={<Boxes size={18} />} label="组件清单" />
        <NavButton active={activeView === "sast"} onClick={() => setActiveView("sast")} icon={<Bug size={18} />} label="SAST 审计" />
        <NavButton active={activeView === "agent"} onClick={() => setActiveView("agent")} icon={<Network size={18} />} label="AGENT 安全" />
        <NavButton active={activeView === "dast"} onClick={() => setActiveView("dast")} icon={<Activity size={18} />} label="DAST 验证" />
        <NavButton active={activeView === "sandbox"} onClick={() => setActiveView("sandbox")} icon={<FlaskConical size={18} />} label="SANDBOX 证据" />
        <NavButton active={activeView === "aspm"} onClick={() => setActiveView("aspm")} icon={<ShieldCheck size={18} />} label="治理总览" />
      </nav></aside>
      <section className="workspace"><header className="topbar"><div><p className="eyebrow">{viewEyebrow(activeView)}</p><h1>{viewTitle(activeView)}</h1></div><div className="topbar-actions"><div className="current-project-pill"><span>当前项目</span><strong>{project?.name ?? "未选择"}</strong></div><button className="primary-action" onClick={() => void bootstrap()} disabled={loading}>刷新数据</button></div></header>
        <div className={`api-status ${status.includes("失败") || status.includes("未连接") ? "warning" : "ok"}`}>{status}</div>
        {activeView === "projects" && <ProjectWorkspace projects={projects} project={project} draft={projectDraft} loading={loading} onDraftChange={setProjectDraft} onCreate={createProject} onSelect={(nextProject) => void selectProject(nextProject)} onDelete={deleteProject} />}
        {activeView === "assets" && <><ProjectAssetConfig project={project} loading={loading} onSave={updateProjectAssets} /><ProjectAssets project={project} assetProbe={assetProbe} enabledModules={enabledModules} components={components} findings={findings} validations={validations} evidence={evidence} summary={summary} onOpenTasks={() => setActiveView("tasks")} onOpenModules={() => setActiveView("modules")} /></>}
        {activeView === "modules" && <ModulesView modules={optionalModules} project={project} enabledModules={enabledModules} selectedModules={selectedModules} savingKey={savingKey} onToggle={toggleModule} />}
        {activeView === "tasks" && <TaskCenter project={project} assetProbe={assetProbe} enabledModules={enabledModules} sourcePath={sourcePath} sastPath={sastPath} agentPath={agentPath} targetUrl={targetUrl} runCommand={runCommand} loading={loading} onSourcePathChange={setSourcePath} onSastPathChange={setSastPath} onAgentPathChange={setAgentPath} onTargetUrlChange={setTargetUrl} onRunCommandChange={setRunCommand} onScan={runScan} onRecommended={runRecommendedScans} onDast={createDastValidation} onSandbox={createSandboxEvidence} />}
        {activeView === "sca" && <ScaView project={project} components={components} dependencyGraph={dependencyGraph} sourcePath={sourcePath} ecosystemSummary={ecosystemSummary} riskSummary={scaRiskSummary} loading={loading} onSourcePathChange={setSourcePath} onRunScan={() => runScan("sca")} onExportSbom={exportScaSbom} />}
        {activeView === "sast" && <SastView project={project} findings={sastFindings} categorySummary={sastCategorySummary} sourcePath={sastPath} loading={loading} onSourcePathChange={setSastPath} onRunScan={() => runScan("sast")} onAgentReview={runSastAgentReview} />}
        {activeView === "agent" && <AgentView project={project} findings={agentFindings} categorySummary={agentCategorySummary} sourcePath={agentPath} loading={loading} onSourcePathChange={setAgentPath} onRunScan={() => runScan("agent")} />}
        {activeView === "dast" && <DastView project={project} validations={validations} targetUrl={targetUrl} loading={loading} onTargetUrlChange={setTargetUrl} onProbe={createDastValidation} />}
        {activeView === "sandbox" && <SandboxView project={project} evidence={evidence} templates={sandboxTemplates} runCommand={runCommand} sandboxImage={sandboxImage} loading={loading} onRunCommandChange={setRunCommand} onSandboxImageChange={setSandboxImage} onRun={createSandboxEvidence} />}
        {activeView === "aspm" && <AspmView summary={summary} findings={findings} validations={validations} evidence={evidence} onUpdateFinding={updateFindingGovernance} />}
      </section>
    </main>
  );
}

function NavButton({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: React.ReactNode; label: string }) { return <button className={`nav-item ${active ? "active" : ""}`} onClick={onClick}>{icon}{label}</button>; }
function viewEyebrow(view: ViewKey) { return view === "projects" ? "项目空间" : view === "assets" ? "项目资产画像" : view === "modules" ? "项目模块配置" : view === "tasks" ? "统一模块任务" : view === "sca" ? "供应链组件清单" : view === "sast" ? "智能静态审计" : view === "agent" ? "Agent 供应链安全" : view === "dast" ? "漏洞动态验证" : view === "sandbox" ? "沙箱动态证据链" : "ASPM 治理汇总"; }
function viewTitle(view: ViewKey) { return view === "projects" ? "创建项目并切换当前项目" : view === "assets" ? "确认项目资产并查看推荐任务" : view === "modules" ? "选择接入的五个检测与验证模块" : view === "tasks" ? "按已启用模块触发检测与记录任务" : view === "sca" ? "查看项目 SBOM 与供应链组件清单" : view === "sast" ? "查看代码风险、CWE 与修复建议" : view === "agent" ? "查看 Agent 指令、工具和插件风险" : view === "dast" ? "对目标 URL 执行动态验证" : view === "sandbox" ? "运行受控命令并归档沙箱证据" : "按项目聚合模块结果与风险态势"; }

function ProjectWorkspace({ projects, project, draft, loading, onDraftChange, onCreate, onSelect, onDelete }: { projects: Project[]; project: Project | null; draft: ProjectDraft; loading: boolean; onDraftChange: (draft: ProjectDraft) => void; onCreate: (event: React.FormEvent<HTMLFormElement>) => Promise<void>; onSelect: (project: Project) => void; onDelete: (projectId: string) => Promise<void> }) {
  return <section className="project-workspace"><div className="panel project-create"><div className="panel-header"><h2>项目创建向导</h2><span>ASPM 默认内置，SCA + SAST 默认启用</span></div><form className="project-form" onSubmit={(event) => void onCreate(event)}><label>项目名称<input value={draft.name} onChange={(event) => onDraftChange({ ...draft, name: event.target.value })} placeholder="例如：政企门户应用" /></label><label>业务负责人<input value={draft.business_owner} onChange={(event) => onDraftChange({ ...draft, business_owner: event.target.value })} placeholder="业务系统部" /></label><label>安全负责人<input value={draft.security_owner} onChange={(event) => onDraftChange({ ...draft, security_owner: event.target.value })} placeholder="应用安全组" /></label><label>代码仓库<input value={draft.repository_url} onChange={(event) => onDraftChange({ ...draft, repository_url: event.target.value })} placeholder="git.example.com/team/repo" /></label><label>本地源码路径<input value={draft.source_path} onChange={(event) => onDraftChange({ ...draft, source_path: event.target.value })} placeholder="D:\\project\\demo-repo" /></label><label>运行地址<input value={draft.runtime_url} onChange={(event) => onDraftChange({ ...draft, runtime_url: event.target.value })} placeholder="http://localhost:3000" /></label><label>API 地址<input value={draft.api_base_url} onChange={(event) => onDraftChange({ ...draft, api_base_url: event.target.value })} placeholder="http://localhost:3000/api" /></label><label>沙箱命令<input value={draft.sandbox_command} onChange={(event) => onDraftChange({ ...draft, sandbox_command: event.target.value })} placeholder="npm test" /></label><label>沙箱镜像<input value={draft.sandbox_image} onChange={(event) => onDraftChange({ ...draft, sandbox_image: event.target.value })} placeholder="node:20-alpine" /></label><label>默认分支<input value={draft.default_branch} onChange={(event) => onDraftChange({ ...draft, default_branch: event.target.value })} placeholder="main" /></label><button className="primary-action" disabled={loading || !draft.name.trim()}><Plus size={16} />创建项目</button></form></div><div className="panel project-directory"><div className="panel-header"><h2>项目列表</h2><span>{projects.length} 个项目</span></div><div className="project-list">{projects.length === 0 ? <div className="empty-project">暂无项目。创建项目后，模块配置、任务中心、组件清单和 ASPM 总览会按项目隔离。</div> : projects.map((item) => <div className={`project-row ${project?.id === item.id ? "active" : ""}`} key={item.id}><button className="project-main" onClick={() => onSelect(item)} disabled={loading}><div><strong>{item.name}</strong><span>{item.repository_url ?? "未配置仓库"} · {item.default_branch}</span><span>{item.source_path ?? "未配置本地源码路径"}</span></div><span>{item.business_owner ?? "未配置业务负责人"}</span><span>{item.security_owner ?? "未配置安全负责人"}</span></button><button className="danger-action" disabled={loading} onClick={() => void onDelete(item.id)}>删除</button></div>)}</div></div><div className="panel current-project"><div className="panel-header"><h2>当前项目</h2><span>{project ? "已选择" : "未选择"}</span></div>{project ? <div className="project-detail"><strong>{project.name}</strong><span>业务：{project.business_owner ?? "未配置"}</span><span>安全：{project.security_owner ?? "未配置"}</span><span>仓库：{project.repository_url ?? "未配置"}</span><span>源码路径：{project.source_path ?? "未配置"}</span><span>运行地址：{project.runtime_url ?? "未配置"}</span><span>API 地址：{project.api_base_url ?? "未配置"}</span><span>沙箱命令：{project.sandbox_command ?? "未配置"}</span><span>沙箱镜像：{project.sandbox_image ?? "未配置"}</span><span>分支：{project.default_branch}</span></div> : <div className="empty-project">请先创建或选择一个项目。</div>}</div></section>;
}

function ProjectAssetConfig({ project, loading, onSave }: { project: Project | null; loading: boolean; onSave: (draft: ProjectAssetDraft) => Promise<void> }) {
  const [draft, setDraft] = useState<ProjectAssetDraft>({ runtime_url: "", api_base_url: "", sandbox_command: "", sandbox_image: "" });

  useEffect(() => {
    setDraft({
      runtime_url: project?.runtime_url ?? "",
      api_base_url: project?.api_base_url ?? "",
      sandbox_command: project?.sandbox_command ?? "",
      sandbox_image: project?.sandbox_image ?? "",
    });
  }, [project?.id, project?.runtime_url, project?.api_base_url, project?.sandbox_command, project?.sandbox_image]);

  return <section className="panel full asset-config"><div className="panel-header"><h2>项目资产配置</h2><span>{project ? "影响 DAST 与 SANDBOX 默认参数" : "请先选择项目"}</span></div><div className="asset-config-grid"><label>运行地址<input value={draft.runtime_url} onChange={(event) => setDraft({ ...draft, runtime_url: event.target.value })} placeholder="http://localhost:3000" disabled={!project || loading} /></label><label>API 地址<input value={draft.api_base_url} onChange={(event) => setDraft({ ...draft, api_base_url: event.target.value })} placeholder="http://localhost:3000/api" disabled={!project || loading} /></label><label>沙箱命令<input value={draft.sandbox_command} onChange={(event) => setDraft({ ...draft, sandbox_command: event.target.value })} placeholder="npm test" disabled={!project || loading} /></label><label>沙箱镜像<input value={draft.sandbox_image} onChange={(event) => setDraft({ ...draft, sandbox_image: event.target.value })} placeholder="node:20-alpine" disabled={!project || loading} /></label></div><div className="asset-config-actions"><button className="primary-action" disabled={!project || loading} onClick={() => void onSave(draft)}>保存资产配置</button></div></section>;
}

function ProjectAssets({ project, assetProbe, enabledModules, components, findings, validations, evidence, summary, onOpenTasks, onOpenModules }: { project: Project | null; assetProbe: ProjectAssetProbe | null; enabledModules: Set<ModuleKey>; components: Component[]; findings: Finding[]; validations: DastValidation[]; evidence: SandboxEvidence[]; summary: AspmSummary | null; onOpenTasks: () => void; onOpenModules: () => void }) {
  const recommended = assetProbe?.recommended_tasks ?? [];
  const runnable = recommended.filter((kind) => enabledModules.has(kind));
  const blocked = recommended.filter((kind) => !enabledModules.has(kind));
  const sourcePath = project?.source_path ?? assetProbe?.source_path ?? "未配置本地源码路径";
  const pathStatus = assetProbe ? assetProbe.path_exists ? "路径可访问" : "路径不可访问" : "未探测";
  const enabledNames = OPTIONAL_MODULES.filter((moduleKey) => enabledModules.has(moduleKey)).map((moduleKey) => moduleKey.toUpperCase());

  return <section className="asset-workspace"><section className="module-summary"><Metric label="资产路径" value={pathStatus} /><Metric label="依赖清单" value={assetProbe?.sca_files.length ?? 0} /><Metric label="源码文件" value={assetProbe?.source_files.length ?? 0} /><Metric label="推荐任务" value={recommended.length} /></section><div className="asset-grid"><div className="panel asset-hero full"><div><div className="panel-header"><h2>{project?.name ?? "未选择项目"}</h2><span>{project?.default_branch ?? "main"}</span></div><div className="asset-path">{sourcePath}</div><div className="asset-tags"><span>{project?.repository_url ?? "未配置仓库"}</span><span>业务：{project?.business_owner ?? "未配置"}</span><span>安全：{project?.security_owner ?? "未配置"}</span></div></div><div className="asset-actions"><button className="primary-action" onClick={onOpenTasks} disabled={!project || runnable.length === 0}>执行推荐任务</button><button className="secondary-action" onClick={onOpenModules}>配置模块</button></div></div><div className="panel"><div className="panel-header"><h2>识别结果</h2><span>{assetProbe?.message ?? "暂无探测结果"}</span></div><div className="output-strip"><div><span>SCA</span><strong>{assetProbe?.sca_files.length ?? 0}</strong></div><div><span>SAST</span><strong>{assetProbe?.source_files.length ?? 0}</strong></div><div><span>AGENT</span><strong>{assetProbe?.agent_files.length ?? 0}</strong></div></div><div className="asset-note">{runnable.length ? `当前可直接执行：${runnable.map((item) => item.toUpperCase()).join(" + ")}` : "暂无可直接执行的推荐任务"}</div>{blocked.length ? <div className="asset-warning">需先启用模块：{blocked.map((item) => item.toUpperCase()).join(" + ")}</div> : null}</div><div className="panel"><div className="panel-header"><h2>模块准备度</h2><span>{enabledNames.length} 个已启用</span></div><div className="readiness-list">{OPTIONAL_MODULES.map((moduleKey) => <div className="readiness-row" key={moduleKey}><span>{moduleKey.toUpperCase()}</span><strong className={enabledModules.has(moduleKey) ? "ready" : "muted"}>{enabledModules.has(moduleKey) ? "已接入" : "未接入"}</strong></div>)}</div></div><div className="panel full"><div className="panel-header"><h2>资产文件</h2><span>来自本地源码路径自动识别</span></div><div className="asset-file-grid"><AssetFileList title="依赖清单" files={assetProbe?.sca_files ?? []} /><AssetFileList title="源码文件" files={assetProbe?.source_files ?? []} /><AssetFileList title="Agent 配置" files={assetProbe?.agent_files ?? []} /></div></div><div className="panel full"><div className="panel-header"><h2>当前项目结果</h2><span>进入 ASPM 治理总览前的资产侧摘要</span></div><div className="output-strip wide"><div><span>组件</span><strong>{summary?.component_count ?? components.length}</strong></div><div><span>Findings</span><strong>{summary?.finding_count ?? findings.length}</strong></div><div><span>DAST 验证</span><strong>{summary?.dast_validation_count ?? validations.length}</strong></div><div><span>Sandbox 证据</span><strong>{summary?.sandbox_evidence_count ?? evidence.length}</strong></div></div></div></div></section>;
}

function AssetFileList({ title, files }: { title: string; files: string[] }) {
  return <div className="asset-file-list"><h3>{title}</h3>{files.length === 0 ? <span className="empty-inline">暂无文件</span> : <ul>{files.slice(0, 8).map((file) => <li key={file}>{file}</li>)}{files.length > 8 ? <li>还有 {files.length - 8} 个文件</li> : null}</ul>}</div>;
}
function ModulesView({ modules, project, enabledModules, selectedModules, savingKey, onToggle }: { modules: SecurityModule[]; project: Project | null; enabledModules: Set<ModuleKey>; selectedModules: SecurityModule[]; savingKey: ModuleKey | null; onToggle: (module: SecurityModule) => Promise<void> }) { return <><section className="module-summary"><Metric label="已选择模块" value={`${selectedModules.length} / ${modules.length}`} /><Metric label="当前项目" value={project?.name ?? "本地预览"} /><Metric label="动态验证依赖" value={enabledModules.has("dast") ? "SAST 联动" : "未接入"} /><Metric label="治理底座" value="ASPM 内置" /></section><section className="module-layout"><div className="module-grid">{modules.map((module) => { const enabled = enabledModules.has(module.key); return <article className={`module-card ${enabled ? "enabled" : ""}`} key={module.key}><div className="module-card-top"><div className="module-icon">{moduleIcons[module.key]}</div><div><span className="module-code">{module.code}</span><h2>{module.name}</h2></div><button aria-label={`${enabled ? "停用" : "启用"} ${module.code}`} className={`toggle ${enabled ? "on" : ""}`} disabled={savingKey === module.key} onClick={() => void onToggle(module)}><span /></button></div><p className="module-subtitle">{module.subtitle}</p><p className="module-description">{module.description}</p><div className="capability-list">{module.capabilities.map((capability) => <span key={capability.title} title={capability.description}><Check size={14} />{capability.title}</span>)}</div>{module.dependencies.length ? <div className="dependency-note"><Lock size={14} />启用时会自动接入依赖模块：{module.dependencies.join(", ").toUpperCase()}</div> : null}</article>; })}</div><aside className="selection-panel"><div className="panel-header"><h2>接入预览</h2><span>Project: {project?.name ?? "本地预览"}</span></div><ol className="selected-list">{selectedModules.map((module) => <li key={module.key}><b>{module.code}</b><span>{module.name}</span></li>)}<li className="builtin-module"><b>ASPM</b><span>平台内置治理底座</span></li></ol><div className="execution-flow"><h3>推荐执行顺序</h3><p>SCA -&gt; SAST -&gt; AGENT -&gt; DAST -&gt; SANDBOX，结果自动进入 ASPM 治理总览。</p></div></aside></section></>; }

function TaskCenter(props: { project: Project | null; assetProbe: ProjectAssetProbe | null; enabledModules: Set<ModuleKey>; sourcePath: string; sastPath: string; agentPath: string; targetUrl: string; runCommand: string; loading: boolean; onSourcePathChange: (value: string) => void; onSastPathChange: (value: string) => void; onAgentPathChange: (value: string) => void; onTargetUrlChange: (value: string) => void; onRunCommandChange: (value: string) => void; onScan: (kind: "sca" | "sast" | "agent") => Promise<void>; onRecommended: () => Promise<void>; onDast: () => Promise<void>; onSandbox: () => Promise<void> }) { const recommended = props.assetProbe?.recommended_tasks ?? []; const runnable = recommended.filter((kind) => props.enabledModules.has(kind)); const hasTask = OPTIONAL_MODULES.some((moduleKey) => props.enabledModules.has(moduleKey)); return <section className="task-stack"><div className="panel asset-probe"><div className="panel-header"><h2>源码自动识别</h2><span>{props.assetProbe?.message ?? "未探测"}</span></div><div className="probe-summary"><Metric label="依赖清单" value={props.assetProbe?.sca_files.length ?? 0} /><Metric label="源码文件" value={props.assetProbe?.source_files.length ?? 0} /><Metric label="Agent 配置" value={props.assetProbe?.agent_files.length ?? 0} /><Metric label="可执行推荐" value={runnable.length} /></div><div className="probe-actions"><div><strong>{props.project?.source_path ?? "未配置本地源码路径"}</strong><span>{runnable.length ? `可执行推荐：${runnable.map((item) => item.toUpperCase()).join(" + ")}` : "推荐任务会同时受源码识别和模块启用状态影响"}</span></div><button className="primary-action" disabled={props.loading || runnable.length === 0} onClick={() => void props.onRecommended()}>执行推荐任务</button></div></div>{hasTask ? <section className="task-grid">{props.enabledModules.has("sca") && <TaskCard title="SCA 组件清单" desc="解析依赖文件并写入 components。" value={props.sourcePath} onChange={props.onSourcePathChange} button="执行 SCA" disabled={props.loading} onClick={() => props.onScan("sca")} />}{props.enabledModules.has("sast") && <TaskCard title="SAST 基础扫描" desc="扫描硬编码密钥、命令执行、SQL 拼接等模式。" value={props.sastPath} onChange={props.onSastPathChange} button="执行 SAST" disabled={props.loading} onClick={() => props.onScan("sast")} />}{props.enabledModules.has("agent") && <TaskCard title="AGENT 配置扫描" desc="扫描 Agent/MCP/插件配置中的危险权限。" value={props.agentPath} onChange={props.onAgentPathChange} button="执行 AGENT" disabled={props.loading} onClick={() => props.onScan("agent")} />}{props.enabledModules.has("dast") && <TaskCard title="DAST 验证记录" desc="创建一条人工动态验证裁决。" value={props.targetUrl} onChange={props.onTargetUrlChange} button="记录 DAST" disabled={props.loading} onClick={props.onDast} />}{props.enabledModules.has("sandbox") && <TaskCard title="SANDBOX 受控执行" desc="执行受控命令并采集进程输出、耗时和策略证据。" value={props.runCommand} onChange={props.onRunCommandChange} button="执行 SANDBOX" disabled={props.loading} onClick={props.onSandbox} />}</section> : <div className="panel empty-project">当前项目未启用可执行模块。请先到模块接入启用 SCA、SAST、AGENT、DAST 或 SANDBOX。</div>}</section>; }
function TaskCard({ title, desc, value, button, disabled, onChange, onClick }: { title: string; desc: string; value: string; button: string; disabled: boolean; onChange: (value: string) => void; onClick: () => void }) { return <div className="panel task-card"><h2>{title}</h2><p>{desc}</p><div className="path-control"><input value={value} onChange={(event) => onChange(event.target.value)} /><button className="primary-action" disabled={disabled} onClick={onClick}>{button}</button></div></div>; }

function AgentView({ project, findings, categorySummary, sourcePath, loading, onSourcePathChange, onRunScan }: { project: Project | null; findings: Finding[]; categorySummary: Record<string, number>; sourcePath: string; loading: boolean; onSourcePathChange: (value: string) => void; onRunScan: () => Promise<void> }) {
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const severitySummary = countBy(findings, "severity");
  const pageCount = Math.max(1, Math.ceil(findings.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageFindings = findings.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  useEffect(() => { setPage(1); }, [findings]);

  return <section className="sca-layout"><div className="sca-toolbar panel full"><div><h2>AGENT 供应链安全</h2><p>扫描 Agent 指令、MCP 工具协议和插件配置，识别提示注入、权限过宽、工具滥用和密钥暴露风险。</p></div><div className="path-control"><input value={sourcePath} onChange={(event) => onSourcePathChange(event.target.value)} /><button className="primary-action" onClick={() => void onRunScan()} disabled={loading || !project}>{loading ? "执行中" : "执行 AGENT 扫描"}</button></div></div><section className="module-summary"><Metric label="Findings" value={findings.length} /><Metric label="Critical / High" value={(severitySummary.critical ?? 0) + (severitySummary.high ?? 0)} /><Metric label="风险分类" value={Object.keys(categorySummary).length} /><Metric label="当前项目" value={project?.name ?? "未连接"} /></section><div className="content-grid"><div className="panel"><div className="panel-header"><h2>风险分类</h2><span>Agent category</span></div><KeyValue data={categorySummary} /></div><div className="panel"><div className="panel-header"><h2>严重等级</h2><span>Severity</span></div><KeyValue data={severitySummary} /></div><div className="panel full"><div className="panel-header"><h2>Agent 风险发现</h2><span>共 {findings.length} 条</span></div><table><thead><tr><th>等级</th><th>分类</th><th>标题</th><th>位置</th><th>证据</th><th>修复建议 / 信任影响</th></tr></thead><tbody>{findings.length === 0 ? <tr><td colSpan={6} className="empty-cell">暂无 AGENT findings，执行 AGENT 扫描后显示结果。</td></tr> : pageFindings.map((finding) => <tr key={finding.id}><td><span className={`severity ${finding.severity}`}>{finding.severity}</span></td><td><span className="risk-badge review-required">{finding.ai_review?.category ?? "unknown"}</span></td><td><strong>{finding.title}</strong><span className="cell-subtext">{finding.ai_review?.description ?? finding.ai_review?.summary ?? "-"}</span></td><td>{finding.file_path ?? "-"}<span className="cell-subtext">Line {finding.line_start ?? "-"}</span></td><td>{finding.evidence ?? "-"}</td><td>{finding.ai_review?.remediation ?? "-"}<span className="cell-subtext">{finding.ai_review?.trust_impact ?? "-"}</span></td></tr>)}</tbody></table><div className="pagination"><button disabled={currentPage <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>上一页</button><span>第 {currentPage} / {pageCount} 页，每页 {pageSize} 条</span><button disabled={currentPage >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>下一页</button></div></div></div></section>;
}

function DastView({ project, validations, targetUrl, loading, onTargetUrlChange, onProbe }: { project: Project | null; validations: DastValidation[]; targetUrl: string; loading: boolean; onTargetUrlChange: (value: string) => void; onProbe: () => Promise<void> }) {
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const verdictSummary = countBy(validations, "verdict");
  const pageCount = Math.max(1, Math.ceil(validations.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageValidations = validations.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  useEffect(() => { setPage(1); }, [validations]);

  return <section className="sca-layout"><div className="sca-toolbar panel full"><div><h2>DAST 漏洞动态验证</h2><p>对目标 URL 发起 HTTP 探测，检查可达性、安全响应头、服务指纹并自动生成三色裁决和验证证据。</p></div><div className="path-control"><input value={targetUrl} onChange={(event) => onTargetUrlChange(event.target.value)} placeholder="https://example.com" /><button className="primary-action" onClick={() => void onProbe()} disabled={loading || !project}>{loading ? "验证中" : "执行 DAST 验证"}</button></div></div><section className="module-summary"><Metric label="验证记录" value={validations.length} /><Metric label="可利用" value={verdictSummary.exploitable ?? 0} /><Metric label="不确定" value={verdictSummary.uncertain ?? 0} /><Metric label="不可利用" value={verdictSummary.not_exploitable ?? 0} /></section><div className="content-grid"><div className="panel"><div className="panel-header"><h2>三色裁决</h2><span>Verdict</span></div><KeyValue data={verdictSummary} /></div><div className="panel"><div className="panel-header"><h2>当前目标</h2><span>{project?.name ?? "未连接"}</span></div><div className="kv-list"><div><span>Target</span><strong>{targetUrl}</strong></div></div></div><div className="panel full"><div className="panel-header"><h2>动态验证记录</h2><span>共 {validations.length} 条</span></div><table><thead><tr><th>裁决</th><th>目标</th><th>证据摘要</th><th>请求 / 响应</th><th>修复建议</th></tr></thead><tbody>{validations.length === 0 ? <tr><td colSpan={5} className="empty-cell">暂无 DAST 验证记录，执行 DAST 验证后显示结果。</td></tr> : pageValidations.map((validation) => <tr key={validation.id}><td><span className={`risk-badge ${validation.verdict}`}>{validation.verdict}</span><span className="cell-subtext">{validation.validator ?? "auto-dast"}</span></td><td>{validation.target_url}</td><td>{validation.evidence_summary ?? "-"}</td><td>{validation.request_summary ?? "-"}<span className="cell-subtext">{validation.response_summary ?? "-"}</span></td><td>{validation.remediation_hint ?? "-"}</td></tr>)}</tbody></table><div className="pagination"><button disabled={currentPage <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>上一页</button><span>第 {currentPage} / {pageCount} 页，每页 {pageSize} 条</span><button disabled={currentPage >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>下一页</button></div></div></div></section>;
}

function SandboxView({ project, evidence, templates, runCommand, sandboxImage, loading, onRunCommandChange, onSandboxImageChange, onRun }: { project: Project | null; evidence: SandboxEvidence[]; templates: SandboxTemplate[]; runCommand: string; sandboxImage: string; loading: boolean; onRunCommandChange: (value: string) => void; onSandboxImageChange: (value: string) => void; onRun: () => Promise<void> }) {
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const runtimeSummary = countBy(evidence.map((item) => ({ runtime: item.runtime_profile ?? "unknown" })), "runtime");
  const pageCount = Math.max(1, Math.ceil(evidence.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageEvidence = evidence.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const completed = evidence.filter((item) => item.observed_processes.some((process) => textValue(process.exit_code) !== "-")).length;
  useEffect(() => { setPage(1); }, [evidence]);

  return <section className="sca-layout"><div className="sca-toolbar panel full"><div><h2>SANDBOX 沙箱动态证据链</h2><p>识别项目可执行入口，并在 Docker 隔离容器中运行命令，源码只读挂载、默认禁用网络并限制资源。</p></div><div className="path-control"><input value={runCommand} onChange={(event) => onRunCommandChange(event.target.value)} placeholder="python app.py" /><input value={sandboxImage} onChange={(event) => onSandboxImageChange(event.target.value)} placeholder="python:3.12-slim" /><button className="primary-action" onClick={() => void onRun()} disabled={loading || !project}>{loading ? "执行中" : "执行 SANDBOX"}</button></div></div><section className="module-summary"><Metric label="证据记录" value={evidence.length} /><Metric label="推荐命令" value={templates.length} /><Metric label="进程完成" value={completed} /><Metric label="隔离策略" value="Docker / read-only" /></section><div className="content-grid"><div className="panel full"><div className="panel-header"><h2>推荐命令模板</h2><span>{templates.length ? "点击后填入执行框" : "未识别到可执行入口"}</span></div>{templates.length === 0 ? <div className="empty-project">当前项目未识别到 package.json、Python 入口、go.mod、pom.xml 或 Dockerfile。可以手动输入命令和镜像执行。</div> : <table><thead><tr><th>名称</th><th>命令</th><th>镜像</th><th>类型</th><th>说明</th></tr></thead><tbody>{templates.map((template) => <tr key={`${template.image}-${template.command}`}><td><button className="secondary-action" onClick={() => { onRunCommandChange(template.command); onSandboxImageChange(template.image); }}>{template.name}</button><span className="cell-subtext">风险：{template.risk_level}</span></td><td>{template.command}</td><td>{template.image}</td><td>{template.command_type}</td><td>{template.description}</td></tr>)}</tbody></table>}</div><div className="panel"><div className="panel-header"><h2>运行环境</h2><span>Runtime</span></div><KeyValue data={runtimeSummary} /></div><div className="panel"><div className="panel-header"><h2>执行策略</h2><span>Policy</span></div><div className="kv-list"><div><span>Network</span><strong>none</strong></div><div><span>Source</span><strong>readonly</strong></div><div><span>Memory</span><strong>512m</strong></div><div><span>CPU</span><strong>1</strong></div></div></div><div className="panel full"><div className="panel-header"><h2>沙箱证据记录</h2><span>共 {evidence.length} 条</span></div><table><thead><tr><th>命令</th><th>执行结果</th><th>输出摘要</th><th>策略 / 账本</th><th>时间线</th></tr></thead><tbody>{evidence.length === 0 ? <tr><td colSpan={5} className="empty-cell">暂无 SANDBOX 证据，执行 SANDBOX 后显示结果。</td></tr> : pageEvidence.map((item) => { const process = item.observed_processes[0] ?? {}; const execution = objectValue(process.execution); const output = objectValue(process.output); const timeline = listValue(process.timeline); const tool = item.observed_tool_calls[0] ?? {}; const limits = objectValue(tool.resource_limits); return <tr key={item.id}><td><strong>{item.run_command}</strong><span className="cell-subtext">{new Date(item.created_at).toLocaleString()}</span><span className="cell-subtext">{item.runtime_profile ?? "-"}</span></td><td>exit: {textValue(execution.exit_code ?? process.exit_code)}<span className="cell-subtext">image: {textValue(execution.image ?? process.image)}</span><span className="cell-subtext">{textValue(execution.elapsed_ms ?? process.elapsed_ms)}ms · timeout: {textValue(execution.timed_out ?? process.timed_out)}</span></td><td>{item.evidence_summary ?? "-"}<span className="cell-subtext">stdout: {textValue(output.stdout_summary)}</span><span className="cell-subtext">stderr: {textValue(output.stderr_summary ?? process.stderr)}</span><span className="cell-subtext">redacted: {textValue(output.redacted)} · truncated: {textValue(output.stdout_truncated || output.stderr_truncated)}</span></td><td>{item.network_policy}<span className="cell-subtext">{item.filesystem_policy}</span><span className="cell-subtext">cpu {textValue(limits.cpus)} · mem {textValue(limits.memory)} · pids {textValue(limits.pids_limit)}</span><span className="cell-subtext">tool: {textValue(tool.tool)} / {textValue(tool.event_type)}</span></td><td>{timeline.length === 0 ? "-" : timeline.map((event, index) => { const itemEvent = objectValue(event); return <span className="cell-subtext" key={`${item.id}-${index}`}>{textValue(itemEvent.stage)}: {textValue(itemEvent.status)} · {textValue(itemEvent.detail)}</span>; })}</td></tr>; })}</tbody></table><div className="pagination"><button disabled={currentPage <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>上一页</button><span>第 {currentPage} / {pageCount} 页，每页 {pageSize} 条</span><button disabled={currentPage >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>下一页</button></div></div></div></section>;
}

function SastView({ project, findings, categorySummary, sourcePath, loading, onSourcePathChange, onRunScan, onAgentReview }: { project: Project | null; findings: Finding[]; categorySummary: Record<string, number>; sourcePath: string; loading: boolean; onSourcePathChange: (value: string) => void; onRunScan: () => Promise<void>; onAgentReview: () => Promise<void> }) {
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const severitySummary = countBy(findings, "severity");
  const pageCount = Math.max(1, Math.ceil(findings.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageFindings = findings.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const reviewedCount = findings.filter((finding) => finding.ai_review?.agent_pipeline?.length).length;
  useEffect(() => { setPage(1); }, [findings]);

  return <section className="sca-layout"><div className="sca-toolbar panel full"><div><h2>SAST 智能静态审计</h2><p>优先调用 Semgrep 规则引擎扫描源码，并通过规则化 Sub-agent 编排完成复核、证据归档和修复建议归一化。</p></div><div className="path-control"><input value={sourcePath} onChange={(event) => onSourcePathChange(event.target.value)} /><button className="primary-action" onClick={() => void onRunScan()} disabled={loading || !project}>{loading ? "执行中" : "执行 SAST 审计"}</button><button className="secondary-action" onClick={() => void onAgentReview()} disabled={loading || !project || findings.length === 0}>执行 Agent 复核</button></div></div><section className="module-summary"><Metric label="Findings" value={findings.length} /><Metric label="Agent 已复核" value={reviewedCount} /><Metric label="Critical / High" value={(severitySummary.critical ?? 0) + (severitySummary.high ?? 0)} /><Metric label="风险分类" value={Object.keys(categorySummary).length} /></section><div className="content-grid"><div className="panel"><div className="panel-header"><h2>规则分类</h2><span>Category</span></div><KeyValue data={categorySummary} /></div><div className="panel"><div className="panel-header"><h2>严重等级</h2><span>Severity</span></div><KeyValue data={severitySummary} /></div><div className="panel full"><div className="panel-header"><h2>SAST 风险发现</h2><span>共 {findings.length} 条</span></div><table><thead><tr><th>等级</th><th>分类</th><th>标题</th><th>位置</th><th>Agent 复核</th><th>修复建议</th></tr></thead><tbody>{findings.length === 0 ? <tr><td colSpan={6} className="empty-cell">暂无 SAST findings，执行 SAST 审计后显示结果。</td></tr> : pageFindings.map((finding) => <tr key={finding.id}><td><span className={`severity ${finding.severity}`}>{finding.severity}</span><span className="cell-subtext">{finding.ai_review?.priority ?? "-"}</span></td><td><span className="risk-badge review-required">{finding.ai_review?.category ?? "unknown"}</span><span className="cell-subtext">{finding.ai_review?.language ?? "Unknown"}</span></td><td><strong>{finding.title}</strong><span className="cell-subtext">{finding.evidence ?? "-"}</span></td><td>{finding.file_path ?? "-"}<span className="cell-subtext">Line {finding.line_start ?? "-"}</span><span className="cell-subtext">{finding.ai_review?.cwe ?? "-"} · {finding.ai_review?.owasp ?? "-"}</span></td><td>{finding.ai_review?.review_verdict ?? "未复核"}<span className="cell-subtext">误报概率：{finding.ai_review?.false_positive_likelihood ?? "-"}</span><span className="cell-subtext">{finding.ai_review?.evidence_summary ?? "-"}</span></td><td>{finding.ai_review?.fix_strategy ?? finding.ai_review?.remediation ?? "-"}</td></tr>)}</tbody></table><div className="pagination"><button disabled={currentPage <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>上一页</button><span>第 {currentPage} / {pageCount} 页，每页 {pageSize} 条</span><button disabled={currentPage >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>下一页</button></div></div></div></section>;
}
function ScaView({ project, components, dependencyGraph, sourcePath, ecosystemSummary, riskSummary, loading, onSourcePathChange, onRunScan, onExportSbom }: { project: Project | null; components: Component[]; dependencyGraph: DependencyGraph | null; sourcePath: string; ecosystemSummary: Record<string, number>; riskSummary: Record<string, number>; loading: boolean; onSourcePathChange: (value: string) => void; onRunScan: () => Promise<void>; onExportSbom: (format: "cyclonedx" | "spdx") => Promise<void> }) {
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({ ecosystem: "all", dependencyType: "all", riskStatus: "all", severity: "all", licensePolicy: "all" });
  const pageSize = 10;
  const filteredComponents = components.filter((component) => matchesScaFilters(component, filters));
  const pageCount = Math.max(1, Math.ceil(filteredComponents.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageComponents = filteredComponents.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const sourceSummary = countBy(filteredComponents.map((component) => ({ source: component.risk_source ?? "unknown" })), "source");
  const filteredEcosystemSummary = countBy(filteredComponents, "ecosystem");
  const dependencyTypeSummary = countBy(filteredComponents, "dependency_type");
  const licensePolicySummary = countBy(filteredComponents.map((component) => ({ policy: component.license_risk ?? "not_declared" })), "policy");
  const directCount = filteredComponents.filter((component) => component.dependency_type !== "transitive").length;
  const riskyTransitiveCount = filteredComponents.filter((component) => component.dependency_type === "transitive" && isRiskyScaComponent(component)).length;
  const edgeSummary = dependencyEdgeSummary(filteredComponents);
  const filterOptions = useMemo(() => ({
    ecosystems: uniqueValues(components.map((component) => component.ecosystem)),
    dependencyTypes: uniqueValues(components.map((component) => component.dependency_type)),
    riskStatuses: uniqueValues(components.map((component) => component.risk_status ?? "not_checked")),
    severities: uniqueValues(components.map((component) => component.severity ?? "none")),
    licensePolicies: uniqueValues(components.map((component) => component.license_risk ?? "not_declared")),
  }), [components]);
  useEffect(() => { setPage(1); }, [components, filters]);

  return <section className="sca-layout"><div className="sca-toolbar panel full"><div><h2>SCA 供应链风险分析</h2><p>解析项目依赖生成 SBOM，结合 OSV 漏洞库、本地规则和许可证策略生成可解释的组件风险结果。</p></div><div className="path-control"><input value={sourcePath} onChange={(event) => onSourcePathChange(event.target.value)} /><button className="primary-action" onClick={() => void onRunScan()} disabled={loading || !project}>{loading ? "执行中" : "执行 SCA 风险分析"}</button><button className="secondary-action" onClick={() => void onExportSbom("cyclonedx")} disabled={loading || !project || components.length === 0}>导出 CycloneDX</button><button className="secondary-action" onClick={() => void onExportSbom("spdx")} disabled={loading || !project || components.length === 0}>导出 SPDX</button></div></div><section className="module-summary"><Metric label="筛选结果" value={`${filteredComponents.length} / ${components.length}`} /><Metric label="直接 / 传递" value={`${directCount} / ${dependencyTypeSummary.transitive ?? 0}`} /><Metric label="风险传递依赖" value={riskyTransitiveCount} /><Metric label="依赖边 / 推断" value={`${edgeSummary.total} / ${edgeSummary.lockfileInferred}`} /></section><div className="content-grid"><div className="panel full"><div className="panel-header"><h2>依赖图谱</h2><span>{dependencyGraph ? `${dependencyGraph.summary.node_count ?? 0} 节点 / ${dependencyGraph.summary.edge_count ?? 0} 边` : "Graph"}</span></div><DependencyGraphView graph={dependencyGraph} /></div><div className="panel full"><div className="panel-header"><h2>升级杠杆</h2><span>{dependencyGraph?.upgrade_levers.length ?? 0} 项</span></div><UpgradeLeverTable levers={dependencyGraph?.upgrade_levers ?? []} /></div><div className="panel full"><div className="panel-header"><h2>组件筛选</h2><span>Filter</span></div><div className="filter-grid"><FilterSelect label="生态" value={filters.ecosystem} options={filterOptions.ecosystems} onChange={(value) => setFilters((current) => ({ ...current, ecosystem: value }))} /><FilterSelect label="依赖类型" value={filters.dependencyType} options={filterOptions.dependencyTypes} formatOption={dependencyTypeLabel} onChange={(value) => setFilters((current) => ({ ...current, dependencyType: value }))} /><FilterSelect label="风险状态" value={filters.riskStatus} options={filterOptions.riskStatuses} formatOption={riskStatusLabel} onChange={(value) => setFilters((current) => ({ ...current, riskStatus: value }))} /><FilterSelect label="严重等级" value={filters.severity} options={filterOptions.severities} formatOption={severityLabel} onChange={(value) => setFilters((current) => ({ ...current, severity: value }))} /><FilterSelect label="许可证策略" value={filters.licensePolicy} options={filterOptions.licensePolicies} formatOption={licensePolicyLabel} onChange={(value) => setFilters((current) => ({ ...current, licensePolicy: value }))} /><button className="secondary-action" onClick={() => setFilters({ ecosystem: "all", dependencyType: "all", riskStatus: "all", severity: "all", licensePolicy: "all" })}>清空筛选</button></div></div><div className="panel"><div className="panel-header"><h2>生态分布</h2><span>SBOM ecosystem</span></div><KeyValue data={filteredEcosystemSummary} /></div><div className="panel"><div className="panel-header"><h2>依赖类型</h2><span>Dependency</span></div><KeyValue data={dependencyTypeSummary} formatKey={dependencyTypeLabel} /></div><div className="panel"><div className="panel-header"><h2>许可证策略</h2><span>License</span></div><KeyValue data={licensePolicySummary} formatKey={licensePolicyLabel} /></div><div className="panel full"><div className="panel-header"><h2>组件风险清单</h2><span>Project: {project?.name ?? "未连接"}</span></div><table><thead><tr><th>生态</th><th>组件</th><th>版本</th><th>类型</th><th>风险</th><th>来源 / OSV</th><th>漏洞编号</th><th>许可证</th><th>修复建议</th></tr></thead><tbody>{components.length === 0 ? <tr><td colSpan={9} className="empty-cell">暂无组件，执行 SCA 扫描后显示结果。</td></tr> : filteredComponents.length === 0 ? <tr><td colSpan={9} className="empty-cell">当前筛选条件下没有组件。</td></tr> : pageComponents.map((component) => <tr key={component.id}><td><span className="ecosystem-badge">{component.ecosystem}</span></td><td><strong>{component.name}</strong><span className="cell-subtext">{component.source_file}</span></td><td>{component.version ?? "-"}</td><td>{dependencyTypeLabel(component.dependency_type)}</td><td><RiskBadge status={component.risk_status ?? "not_checked"} severity={component.severity ?? null} /></td><td><span className="risk-badge review-required">{sourceLabel(component.risk_source)}</span><span className="cell-subtext">{component.osv_checked ? "OSV 已查询" : "OSV 未查询"}</span>{component.osv_error ? <span className="cell-subtext">{component.osv_error}</span> : null}</td><td>{component.vulnerability_ids?.length ? component.vulnerability_ids.join(", ") : "-"}</td><td>{component.license ?? "-"}{component.license_risk ? <span className="cell-subtext">策略：{licensePolicyLabel(component.license_risk)}</span> : null}</td><td>{component.remediation ?? component.risk_summary ?? "-"}</td></tr>)}</tbody></table><div className="pagination"><button disabled={currentPage <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>上一页</button><span>第 {currentPage} / {pageCount} 页，每页 {pageSize} 条，共 {filteredComponents.length} 条</span><button disabled={currentPage >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>下一页</button></div></div></div></section>;
}

function DependencyGraphView({ graph }: { graph: DependencyGraph | null }) {
  if (!graph || graph.nodes.length === 0) return <div className="empty-project">暂无依赖图谱，执行 SCA 扫描后显示结果。</div>;
  const positions = graphLayout(graph);
  return <div className="graph-shell"><svg viewBox="0 0 960 360" role="img" aria-label="SCA 依赖图谱">
    <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#8aa0b8" /></marker></defs>
    {graph.edges.map((edge) => {
      const source = positions.get(edge.source);
      const target = positions.get(edge.target);
      if (!source || !target) return null;
      return <line key={`${edge.source}-${edge.target}`} x1={source.x + 92} y1={source.y} x2={target.x - 92} y2={target.y} className={`graph-edge ${edge.quality}`} markerEnd="url(#arrow)" />;
    })}
    {graph.nodes.map((node) => {
      const position = positions.get(node.id);
      if (!position) return null;
      return <g key={node.id} transform={`translate(${position.x - 82}, ${position.y - 26})`} className={`graph-node ${nodeRiskClass(node)}`}>
        <rect width="164" height="52" rx="8" />
        <text x="12" y="21">{truncateText(node.label, 20)}</text>
        <text x="12" y="39" className="graph-node-meta">{node.kind === "project" ? "项目" : `${dependencyTypeLabel(node.dependency_type)} · ${node.ecosystem ?? "-"}`}</text>
      </g>;
    })}
  </svg><div className="graph-legend"><span><i className="legend-dot clean" />无风险</span><span><i className="legend-dot vulnerable" />漏洞/高危</span><span><i className="legend-dot license-risk" />许可证风险</span><span>实线：直接依赖 / 虚线：推断传递依赖</span></div></div>;
}

function UpgradeLeverTable({ levers }: { levers: UpgradeLever[] }) {
  if (levers.length === 0) return <div className="empty-project">暂无升级杠杆。通常表示当前没有直接依赖带入风险传递依赖。</div>;
  return <table><thead><tr><th>直接依赖</th><th>风险传递依赖</th><th>最高等级</th><th>影响组件</th><th>建议动作</th></tr></thead><tbody>{levers.map((lever) => <tr key={lever.component_id}><td><strong>{lever.component}</strong><span className="cell-subtext">{lever.ecosystem} · {lever.version ?? "-"}</span></td><td>{lever.risk_transitive_count}</td><td>{severityLabel(lever.highest_severity ?? "none")}</td><td>{lever.affected_components.slice(0, 5).join(", ") || "-"}{lever.affected_components.length > 5 ? <span className="cell-subtext">另 {lever.affected_components.length - 5} 个</span> : null}</td><td>{lever.recommendation}</td></tr>)}</tbody></table>;
}

function RiskBadge({ status, severity }: { status: string; severity: Severity | null }) {
  const label = severity ? `${riskStatusLabel(status)} / ${severityLabel(severity)}` : riskStatusLabel(status);
  return <span className={`risk-badge ${status}`}>{label}</span>;
}
function FilterSelect({ label, value, options, onChange, formatOption = (option) => option }: { label: string; value: string; options: string[]; onChange: (value: string) => void; formatOption?: (value: string) => string }) {
  return <label className="filter-control"><span>{label}</span><select value={value} onChange={(event) => onChange(event.target.value)}><option value="all">全部</option>{options.map((option) => <option key={option} value={option}>{formatOption(option)}</option>)}</select></label>;
}
function AspmView({ summary, findings, validations, evidence, onUpdateFinding }: { summary: AspmSummary | null; findings: Finding[]; validations: DastValidation[]; evidence: SandboxEvidence[]; onUpdateFinding: (findingId: string, patch: Partial<Pick<Finding, "status" | "remediation_owner" | "remediation_note" | "remediation_due_at">>) => Promise<void> }) {
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const pageCount = Math.max(1, Math.ceil(findings.length / pageSize));
  const currentPage = Math.min(page, pageCount);
  const pageFindings = findings.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const governanceSummary = countBy(findings, "status");
  const attackChains = summary?.attack_chains ?? [];
  useEffect(() => { setPage(1); }, [findings]);

  return <section className="sca-layout"><section className="module-summary"><Metric label="风险分" value={summary?.risk_score ?? 0} /><Metric label="攻击链" value={attackChains.length} /><Metric label="待处置" value={(governanceSummary.open ?? 0) + (governanceSummary.pending ?? 0) + (governanceSummary.confirmed ?? 0)} /><Metric label="验证/证据" value={`${summary?.dast_validation_count ?? validations.length}/${summary?.sandbox_evidence_count ?? evidence.length}`} /></section><div className="content-grid"><div className="panel"><div className="panel-header"><h2>模块来源统计</h2><span>Findings by source</span></div><KeyValue data={summary?.findings_by_source ?? {}} /></div><div className="panel"><div className="panel-header"><h2>整改状态</h2><span>Workflow</span></div><KeyValue data={governanceSummary} /></div><div className="panel full"><div className="panel-header"><h2>攻击链关联</h2><span>{attackChains.length ? `共 ${attackChains.length} 条` : "等待多模块证据"}</span></div>{attackChains.length === 0 ? <div className="empty-project">暂无攻击链。通常需要 SAST/AGENT/SCA 风险与 DAST 或 SANDBOX 证据同时存在后生成。</div> : <table><thead><tr><th>链路</th><th>等级</th><th>涉及模块</th><th>证据步骤</th><th>建议动作</th></tr></thead><tbody>{attackChains.map((chain) => <tr key={chain.id}><td><strong>{chain.name}</strong><span className="cell-subtext">{chain.summary}</span></td><td><span className={`severity ${chain.severity}`}>{chain.severity}</span></td><td>{chain.modules.join(" + ")}<span className="cell-subtext">{chain.evidence_count} 个证据点</span></td><td>{chain.steps.map((step) => <span className="cell-subtext" key={`${chain.id}-${step.module}-${step.title}`}>{step.module}: {step.title}</span>)}</td><td>{chain.recommended_action}</td></tr>)}</tbody></table>}</div><div className="panel full"><div className="panel-header"><h2>整改闭环清单</h2><span>共 {findings.length} 条</span></div><table><thead><tr><th>风险</th><th>位置</th><th>状态</th><th>负责人</th><th>截止时间</th><th>处置备注</th></tr></thead><tbody>{findings.length === 0 ? <tr><td colSpan={6} className="empty-cell">暂无 findings。</td></tr> : pageFindings.map((finding) => <tr key={finding.id}><td><span className={`severity ${finding.severity}`}>{finding.severity}</span><strong>{finding.title}</strong><span className="cell-subtext">{finding.source} · {finding.rule_id}</span></td><td>{finding.file_path ?? "-"}<span className="cell-subtext">Line {finding.line_start ?? "-"}</span></td><td><select defaultValue={normalizeFindingStatus(finding.status)} onChange={(event) => void onUpdateFinding(finding.id, { status: event.target.value as FindingStatus })}>{FINDING_WORKFLOW_STATUSES.map((status) => <option key={status} value={status}>{statusLabel(status)}</option>)}</select><span className="cell-subtext">更新：{formatDateTime(finding.updated_at)}</span></td><td><input defaultValue={finding.remediation_owner ?? ""} placeholder="负责人" onBlur={(event) => void onUpdateFinding(finding.id, { remediation_owner: emptyToNull(event.target.value) })} /></td><td><input type="date" defaultValue={dateInputValue(finding.remediation_due_at)} onBlur={(event) => void onUpdateFinding(finding.id, { remediation_due_at: dateToIso(event.target.value) })} /></td><td><textarea defaultValue={finding.remediation_note ?? ""} placeholder="处置备注" onBlur={(event) => void onUpdateFinding(finding.id, { remediation_note: emptyToNull(event.target.value) })} /></td></tr>)}</tbody></table><div className="pagination"><button disabled={currentPage <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>上一页</button><span>第 {currentPage} / {pageCount} 页，每页 {pageSize} 条</span><button disabled={currentPage >= pageCount} onClick={() => setPage((value) => Math.min(pageCount, value + 1))}>下一页</button></div></div></div></section>;
}
function KeyValue({ data, formatKey = (key) => key }: { data: Record<string, number>; formatKey?: (key: string) => string }) { const entries = Object.entries(data); return <div className="kv-list">{entries.length === 0 ? <span className="empty-inline">暂无数据</span> : entries.map(([key, value]) => <div key={key}><span>{formatKey(key)}</span><strong>{value}</strong></div>)}</div>; }
function Metric({ label, value }: { label: string; value: string | number }) { return <div><span>{label}</span><strong>{value}</strong></div>; }
function objectValue(value: unknown): Record<string, unknown> { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function listValue(value: unknown): unknown[] { return Array.isArray(value) ? value : []; }
function textValue(value: unknown) { return value === null || value === undefined || value === "" ? "-" : String(value); }
function sourceLabel(value?: string | null) { return value === "osv" ? "OSV" : value === "local_rule" ? "本地规则" : value === "license_rule" ? "许可证" : value === "version_missing" ? "版本缺失" : value === "osv_error" ? "OSV 失败" : value === "clean" ? "无风险" : value === "not_supported" ? "不支持" : value ?? "未知"; }
function riskStatusLabel(value?: string | null) { return value === "vulnerable" ? "存在漏洞" : value === "license-risk" ? "许可证风险" : value === "review-required" ? "需要复核" : value === "clean" ? "无风险" : value === "not_checked" ? "未检查" : value ?? "未知"; }
function severityLabel(value?: string | null) { return value === "critical" ? "严重" : value === "high" ? "高危" : value === "medium" ? "中危" : value === "low" ? "低危" : value === "info" ? "提示" : value === "none" ? "无等级" : value ?? "-"; }
function dependencyTypeLabel(value?: string | null) { return value === "runtime" ? "运行依赖" : value === "development" ? "开发依赖" : value === "optional" ? "可选依赖" : value === "peer" ? "对等依赖" : value === "test" ? "测试依赖" : value === "transitive" ? "传递依赖" : value === "compile" ? "编译依赖" : value === "provided" ? "容器提供" : value === "system" ? "系统依赖" : value === "import" ? "导入依赖" : value ?? "-"; }
function licensePolicyLabel(value?: string | null) { return value === "allowed" ? "允许" : value === "review_required" ? "需合规复核" : value === "restricted" ? "受限需审批" : value === "unknown" ? "未知需确认" : value ?? "-"; }
function normalizeFindingStatus(status: FindingStatus) { return status === "pending" ? "open" : status === "retest" ? "fixing" : status === "closed" ? "fixed" : status; }
function statusLabel(status: FindingStatus) { return status === "open" ? "待确认" : status === "confirmed" ? "已确认" : status === "fixing" ? "修复中" : status === "fixed" ? "已修复" : status === "accepted_risk" ? "接受风险" : status === "false_positive" ? "误报" : status; }
function dateInputValue(value?: string | null) { return value ? value.slice(0, 10) : ""; }
function dateToIso(value: string) { return value ? `${value}T00:00:00` : null; }
function formatDateTime(value?: string | null) { return value ? new Date(value).toLocaleString() : "-"; }
function countBy<T extends Record<string, unknown>>(items: T[], key: keyof T) { return items.reduce<Record<string, number>>((acc, item) => { const value = String(item[key] ?? "unknown"); acc[value] = (acc[value] ?? 0) + 1; return acc; }, {}); }
function uniqueValues(values: Array<string | null | undefined>) { return Array.from(new Set(values.filter((value): value is string => Boolean(value)))).sort(); }
function isRiskyScaComponent(component: Component) { return component.risk_status === "vulnerable" || component.risk_status === "license-risk" || component.severity === "critical" || component.severity === "high"; }
function dependencyEdgeSummary(components: Component[]) {
  const direct = components.filter((component) => component.dependency_type !== "transitive");
  const transitive = components.filter((component) => component.dependency_type === "transitive");
  let lockfileInferred = 0;
  for (const parent of direct) {
    for (const child of transitive) {
      if (componentsShareDependencyContext(parent, child)) lockfileInferred += 1;
    }
  }
  return { manifestDirect: direct.length, lockfileInferred, total: direct.length + lockfileInferred };
}
function graphLayout(graph: DependencyGraph) {
  const groups = {
    project: graph.nodes.filter((node) => node.kind === "project"),
    direct: graph.nodes.filter((node) => node.kind !== "project" && node.dependency_type !== "transitive"),
    transitive: graph.nodes.filter((node) => node.dependency_type === "transitive"),
  };
  const positions = new Map<string, { x: number; y: number }>();
  placeGraphNodes(groups.project, 110, positions);
  placeGraphNodes(groups.direct, 450, positions);
  placeGraphNodes(groups.transitive, 790, positions);
  return positions;
}
function placeGraphNodes(nodes: DependencyGraphNode[], x: number, positions: Map<string, { x: number; y: number }>) {
  const visible = nodes.slice(0, 8);
  const gap = visible.length <= 1 ? 0 : 280 / (visible.length - 1);
  visible.forEach((node, index) => positions.set(node.id, { x, y: visible.length <= 1 ? 180 : 40 + index * gap }));
}
function nodeRiskClass(node: DependencyGraphNode) {
  if (node.kind === "project") return "project";
  if (node.risk_status === "license-risk") return "license-risk";
  if (node.risk_status === "vulnerable" || node.severity === "critical" || node.severity === "high") return "vulnerable";
  return "clean";
}
function truncateText(value: string, maxLength: number) {
  return value.length > maxLength ? `${value.slice(0, maxLength - 1)}…` : value;
}
function componentsShareDependencyContext(parent: Component, child: Component) {
  if (parent.ecosystem !== child.ecosystem) return false;
  const parentSources = splitSources(parent.source_file);
  const childSources = splitSources(child.source_file);
  if (parentSources.some((source) => childSources.includes(source))) return true;
  return Boolean(parent.package_manager && child.package_manager && parent.package_manager === child.package_manager);
}
function splitSources(sourceFile?: string | null) {
  return (sourceFile ?? "").split(",").map((item) => item.trim()).filter(Boolean);
}
function matchesScaFilters(component: Component, filters: { ecosystem: string; dependencyType: string; riskStatus: string; severity: string; licensePolicy: string }) {
  return matchesFilter(component.ecosystem, filters.ecosystem)
    && matchesFilter(component.dependency_type, filters.dependencyType)
    && matchesFilter(component.risk_status ?? "not_checked", filters.riskStatus)
    && matchesFilter(component.severity ?? "none", filters.severity)
    && matchesFilter(component.license_risk ?? "not_declared", filters.licensePolicy);
}
function matchesFilter(value: string, selected: string) { return selected === "all" || value === selected; }
function emptyToNull(value: string) { const trimmed = value.trim(); return trimmed ? trimmed : null; }
async function enableProjectModule(projectId: string, moduleKey: ModuleKey, enabled: boolean) { return request<ProjectModule>(`/modules/projects/${projectId}`, { method: "POST", body: JSON.stringify({ module_key: moduleKey, enabled, config: {} }) }); }
async function updateProjectModule(projectId: string, moduleKey: ModuleKey, enabled: boolean) { return request<ProjectModule>(`/modules/projects/${projectId}/${moduleKey}`, { method: "PATCH", body: JSON.stringify({ enabled }) }); }
function errorMessage(error: unknown) { return error instanceof Error ? error.message : "未知错误"; }
async function request<T>(path: string, init: RequestInit = {}): Promise<T> { const response = await fetch(`${API_BASE}${path}`, { ...init, headers: { "Content-Type": "application/json", ...(init.headers ?? {}) } }); if (!response.ok) { let detail = `${response.status} ${response.statusText}`; try { const payload = await response.json(); detail = typeof payload.detail === "string" ? payload.detail : detail; } catch { /* keep HTTP status */ } throw new Error(detail); } if (response.status === 204) return undefined as T; return response.json() as Promise<T>; }

ReactDOM.createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);










