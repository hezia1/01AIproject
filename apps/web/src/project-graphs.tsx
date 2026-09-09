import { useEffect, useMemo, useState } from "react";
import { GitBranch, Network } from "lucide-react";
import { FeedbackButton } from "./action-feedback";
import { request } from "./api";
import "./project-graphs.css";

type GraphNode = { id: string; kind: string; label: string; file_path: string | null; line: number | null; attributes: Record<string, unknown> };
type GraphEdge = { id: string; source: string; target: string; relation: string; confidence: number; basis: string };
type GraphSnapshot = { id: string; graph_type: "code" | "business"; version: number; source_fingerprint: string; nodes: GraphNode[]; edges: GraphEdge[]; summary: Record<string, unknown>; limitations: string[]; created_by: string; created_at: string };

function message(error: unknown) { return error instanceof Error ? error.message : String(error); }
function typeLabel(value: string) { return ({ code: "代码图谱", business: "业务知识图谱" } as Record<string, string>)[value] ?? value; }
function relationLabel(value: string) { return ({ contains: "包含", imports: "导入", calls: "调用", exposes: "暴露路由", handled_by: "由其处理", has_risk: "关联风险", validates: "验证", validated_by: "由其验证", observed_by: "由证据观测", participates_in: "参与流程", targets: "目标路由", applies_to: "适用于" } as Record<string, string>)[value] ?? value; }

export function ProjectGraphs({ project }: { project: { id: string; name: string } }) {
  const [graphs, setGraphs] = useState<Partial<Record<"code" | "business", GraphSnapshot>>>({});
  const [active, setActive] = useState<"code" | "business">("code");
  const [busy, setBusy] = useState<"code" | "business" | null>(null);
  const [notice, setNotice] = useState("");

  async function load() {
    const entries = await Promise.all((["code", "business"] as const).map(async (kind) => {
      try { return [kind, await request<GraphSnapshot>(`/graphs/projects/${project.id}/${kind}`)] as const; }
      catch (error) {
        if (!message(error).includes("has not been built")) setNotice(`${typeLabel(kind)}读取失败：${message(error)}`);
        return [kind, undefined] as const;
      }
    }));
    setGraphs(Object.fromEntries(entries));
  }

  useEffect(() => { setNotice(""); void load(); }, [project.id]);

  async function rebuild(kind: "code" | "business") {
    setBusy(kind); setNotice(`正在构建${typeLabel(kind)}…`);
    try {
      const graph = await request<GraphSnapshot>(`/graphs/projects/${project.id}/${kind}/rebuild`, { method: "POST" });
      setGraphs((current) => ({ ...current, [kind]: graph }));
      setActive(kind);
      setNotice(`${typeLabel(kind)} v${graph.version} 已保存：${graph.nodes.length} 个节点、${graph.edges.length} 条关系。`);
    } catch (error) { setNotice(`${typeLabel(kind)}构建失败：${message(error)}`); }
    finally { setBusy(null); }
  }

  const graph = graphs[active];
  const nodeNames = useMemo(() => new Map((graph?.nodes ?? []).map((node) => [node.id, node.label])), [graph]);
  return <section className="project-graphs">
    <div className="graph-heading"><div><span>PROJECT KNOWLEDGE GRAPHS</span><h3>代码关系与业务安全上下文</h3><p>从当前项目源码和已保存事实生成版本化快照；低可信关系明确标注，不推断未观察到的业务语义。</p></div><div className="graph-actions"><FeedbackButton className="secondary-action" disabled={busy !== null} onClick={() => rebuild("code")}><GitBranch size={15} />{busy === "code" ? "构建中…" : "构建代码图谱"}</FeedbackButton><FeedbackButton className="secondary-action" disabled={busy !== null} onClick={() => rebuild("business")}><Network size={15} />{busy === "business" ? "构建中…" : "构建业务知识图谱"}</FeedbackButton></div></div>
    {notice ? <div className="graph-notice">{notice}</div> : null}
    <div className="graph-switch">{(["code", "business"] as const).map((kind) => <button key={kind} className={active === kind ? "active" : ""} onClick={() => setActive(kind)}><strong>{typeLabel(kind)}</strong><small>{graphs[kind] ? `v${graphs[kind]!.version} · ${graphs[kind]!.nodes.length} 节点` : "尚未构建"}</small></button>)}</div>
    {graph ? <>
      <div className="graph-metrics"><span><b>{graph.nodes.length}</b>节点</span><span><b>{graph.edges.length}</b>关系</span><span><b>{String(graph.summary.file_count ?? graph.summary.business_flow_count ?? 0)}</b>{active === "code" ? "源码文件" : "业务流程"}</span><span><b>v{graph.version}</b>快照版本</span></div>
      <div className="graph-data-grid"><section><h4>节点样例</h4>{graph.nodes.slice(0, 12).map((node) => <article key={node.id}><span>{node.kind}</span><strong>{node.label}</strong><small>{node.file_path ? `${node.file_path}${node.line ? `:${node.line}` : ""}` : "结构化事实"}</small></article>)}{graph.nodes.length > 12 ? <p>另有 {graph.nodes.length - 12} 个节点，可通过图谱 API 查询完整快照。</p> : null}</section><section><h4>关系样例</h4>{graph.edges.slice(0, 12).map((edge) => <article key={edge.id}><span>{relationLabel(edge.relation)} · {edge.confidence}%</span><strong>{nodeNames.get(edge.source) ?? edge.source} → {nodeNames.get(edge.target) ?? edge.target}</strong><small>{edge.basis}</small></article>)}{graph.edges.length > 12 ? <p>另有 {graph.edges.length - 12} 条关系，可通过图谱 API 查询完整快照。</p> : null}</section></div>
      <details className="graph-limitations"><summary>查看能力边界</summary><ul>{graph.limitations.map((item) => <li key={item}>{item}</li>)}</ul></details>
    </> : <div className="graph-empty">当前项目尚未生成{typeLabel(active)}。构建操作只读取项目源码和数据库已有事实，不运行项目代码。</div>}
  </section>;
}
