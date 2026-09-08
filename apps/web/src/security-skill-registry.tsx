import { useEffect, useState } from "react";
import { Play, Plus, ShieldCheck } from "lucide-react";
import { FeedbackButton, FeedbackForm } from "./action-feedback";
import { request } from "./api";
import "./security-skill-registry.css";

type Manifest = { action: "review_existing_findings"; selectors: { sources: string[]; rule_ids: string[]; categories: string[]; severities: string[]; statuses: string[] }; evidence_required: string[] };
type Version = { id: string; version: number; manifest: Manifest; status: string; change_note: string | null; created_by: string; created_at: string; published_at: string | null };
type Skill = { id: string; slug: string; name: string; description: string; module: string; status: string; active_version: number | null; versions: Version[] };
type SkillRun = { id: string; skill_id: string; skill_version: number; status: string; requested_by: string; started_at: string; result_summary: { current_finding_count?: number; selector_match_count?: number; matched_count?: number; evidence_excluded_count?: number; limitations?: string[] } };
type FormState = { slug: string; name: string; description: string; module: string; sources: string; ruleIds: string; categories: string; severities: string; statuses: string; evidence: string; changeNote: string };

const emptyForm: FormState = { slug: "", name: "", description: "", module: "cross", sources: "SAST", ruleIds: "", categories: "", severities: "high,critical", statuses: "open,confirmed,fixing,retest", evidence: "finding_location", changeNote: "初始声明式复核清单" };
const split = (value: string) => [...new Set(value.split(",").map((item) => item.trim()).filter(Boolean))];
const message = (error: unknown) => error instanceof Error ? error.message : String(error);

export function SecuritySkillRegistry({ project, isAdmin }: { project: { id: string; name: string }; isAdmin: boolean }) {
  const [skills, setSkills] = useState<Skill[]>([]), [runs, setRuns] = useState<SkillRun[]>([]);
  const [form, setForm] = useState<FormState>(emptyForm), [editingId, setEditingId] = useState<string | null>(null);
  const [notice, setNotice] = useState(""), [loading, setLoading] = useState(true);

  async function refresh() {
    setLoading(true);
    try {
      const [nextSkills, nextRuns] = await Promise.all([
        request<Skill[]>(`/security-skills${isAdmin ? "?include_drafts=true" : ""}`),
        request<SkillRun[]>(`/security-skills/projects/${project.id}/runs`),
      ]);
      setSkills(nextSkills); setRuns(nextRuns);
    } catch (error) { setNotice(`Skill 注册表加载失败：${message(error)}`); }
    finally { setLoading(false); }
  }
  useEffect(() => { void refresh(); }, [project.id, isAdmin]);

  function manifest(): Manifest {
    return { action: "review_existing_findings", selectors: { sources: split(form.sources).map((item) => item.toUpperCase()), rule_ids: split(form.ruleIds), categories: split(form.categories), severities: split(form.severities).map((item) => item.toLowerCase()), statuses: split(form.statuses) }, evidence_required: split(form.evidence) };
  }
  async function save(event: React.FormEvent) {
    event.preventDefault(); setNotice("");
    try {
      if (editingId) await request(`/security-skills/${editingId}/versions`, { method: "POST", body: JSON.stringify({ manifest: manifest(), change_note: form.changeNote }) });
      else await request("/security-skills", { method: "POST", body: JSON.stringify({ slug: form.slug, name: form.name, description: form.description, module: form.module, manifest: manifest(), change_note: form.changeNote }) });
      setNotice(editingId ? "新版已保存为草稿；发布前不会影响普通用户。" : "Skill 与 v1 草稿已创建；发布后普通用户才可执行。");
      setEditingId(null); setForm(emptyForm); await refresh();
    } catch (error) { setNotice(`保存失败：${message(error)}`); }
  }
  function edit(skill: Skill) {
    const version = skill.versions.find((item) => item.version === skill.active_version) ?? skill.versions[0];
    setEditingId(skill.id); setForm({ slug: skill.slug, name: skill.name, description: skill.description, module: skill.module, sources: version.manifest.selectors.sources.join(","), ruleIds: version.manifest.selectors.rule_ids.join(","), categories: version.manifest.selectors.categories.join(","), severities: version.manifest.selectors.severities.join(","), statuses: version.manifest.selectors.statuses.join(","), evidence: version.manifest.evidence_required.join(","), changeNote: "调整匹配范围或证据要求" });
  }
  async function publish(skill: Skill) {
    const draft = skill.versions.find((item) => item.status === "draft");
    if (!draft) { setNotice("没有待发布草稿；请先创建新版。"); return; }
    try { await request(`/security-skills/${skill.id}/versions/${draft.version}/publish`, { method: "POST" }); setNotice(`${skill.name} v${draft.version} 已发布。`); await refresh(); }
    catch (error) { setNotice(`发布失败：${message(error)}`); }
  }
  async function run(skill: Skill) {
    setNotice("");
    try {
      const result = await request<SkillRun>(`/security-skills/${skill.id}/projects/${project.id}/run`, { method: "POST" });
      setNotice(`Skill 执行完成：检查 ${result.result_summary.current_finding_count ?? 0} 条当前 Finding，匹配 ${result.result_summary.matched_count ?? 0} 条。此结果不是重新扫描结论。`); await refresh();
    } catch (error) { setNotice(`执行失败：${message(error)}`); }
  }

  return <section className="skill-registry">
    <div className="knowledge-section-heading"><div><span>可执行 Skill 注册表</span><h3>用受控清单复核现有 Finding，不替代专业扫描器</h3></div><strong>{skills.filter((item) => item.status === "published").length} 个已发布</strong></div>
    <p className="skill-boundary">Skill 只按来源、规则、分类、等级、状态和证据要求筛选当前有效 Finding；不运行任意代码、不修改 Finding，也不把零命中描述为“无漏洞”。</p>
    {notice ? <div className="knowledge-notice active" role="status">{notice}</div> : null}
    {isAdmin ? <details className="skill-editor" open={Boolean(editingId)}><summary><Plus size={15} />{editingId ? "保存一个不可变的新版本" : "创建声明式 Skill"}</summary><FeedbackForm onSubmit={save}>
      <div className="skill-fields"><label>标识<input disabled={Boolean(editingId)} required value={form.slug} placeholder="critical-sast-review" onChange={(e) => setForm({ ...form, slug: e.target.value })} /></label><label>名称<input disabled={Boolean(editingId)} required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label><label>模块<select disabled={Boolean(editingId)} value={form.module} onChange={(e) => setForm({ ...form, module: e.target.value })}><option value="cross">跨模块</option><option value="sca">SCA</option><option value="sast">SAST</option><option value="agent">AGENT</option></select></label><label className="wide">说明<textarea required value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></label><label>来源（逗号分隔）<input value={form.sources} onChange={(e) => setForm({ ...form, sources: e.target.value })} /></label><label>严重度<input value={form.severities} onChange={(e) => setForm({ ...form, severities: e.target.value })} /></label><label>规则 ID<input value={form.ruleIds} onChange={(e) => setForm({ ...form, ruleIds: e.target.value })} /></label><label>风险分类<input value={form.categories} onChange={(e) => setForm({ ...form, categories: e.target.value })} /></label><label>Finding 状态<input value={form.statuses} onChange={(e) => setForm({ ...form, statuses: e.target.value })} /></label><label>必需证据<input value={form.evidence} onChange={(e) => setForm({ ...form, evidence: e.target.value })} /></label><label className="wide">版本说明<input required value={form.changeNote} onChange={(e) => setForm({ ...form, changeNote: e.target.value })} /></label></div>
      <div className="skill-actions"><FeedbackButton type="submit" className="primary-action">{editingId ? "保存新版草稿" : "创建 v1 草稿"}</FeedbackButton>{editingId ? <FeedbackButton type="button" className="secondary-action" onClick={() => { setEditingId(null); setForm(emptyForm); }}>取消编辑</FeedbackButton> : null}</div>
    </FeedbackForm></details> : null}
    <div className="skill-list">{loading ? <div className="knowledge-empty">正在读取 Skill 注册表…</div> : skills.length ? skills.map((skill) => { const latest = skill.versions[0]; const lastRun = runs.find((item) => item.skill_id === skill.id); return <article key={skill.id}><header><span className={`skill-status ${skill.status}`}>{skill.status === "published" ? "已发布" : "草稿"}</span><b>{skill.module.toUpperCase()}</b></header><h4>{skill.name}</h4><p>{skill.description}</p><small>{skill.slug} · 最新 v{latest.version}（{latest.status}）{skill.active_version ? ` · 生效 v${skill.active_version}` : ""}</small>{lastRun ? <div className="skill-run-fact"><ShieldCheck size={15} /><span>最近执行 v{lastRun.skill_version}：检查 {lastRun.result_summary.current_finding_count ?? 0} 条，匹配 {lastRun.result_summary.matched_count ?? 0} 条</span></div> : null}<footer>{skill.status === "published" ? <FeedbackButton className="primary-action" onClick={() => run(skill)}><Play size={14} />在 {project.name} 执行</FeedbackButton> : null}{isAdmin ? <><FeedbackButton className="secondary-action" onClick={() => edit(skill)}>编辑新版</FeedbackButton>{skill.versions.some((item) => item.status === "draft") ? <FeedbackButton className="secondary-action" onClick={() => publish(skill)}>发布草稿</FeedbackButton> : null}</> : null}</footer></article>; }) : <div className="knowledge-empty">当前租户还没有{isAdmin ? "已创建的" : "已发布的"} Skill。</div>}</div>
  </section>;
}
