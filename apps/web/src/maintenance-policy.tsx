import { useEffect, useState } from "react";
import { request } from "./api";
import { FeedbackButton } from "./action-feedback";
import { PagedTable } from "./pagination";

type Config = { grype_download_allowed: boolean; sca_dependency_resolution_allowed: boolean; semgrep_download_allowed: boolean; sandbox_image_download_allowed: boolean; sandbox_dependency_download_allowed: boolean; sandbox_image_repositories: string[] };
type Snapshot = { config: Config; version: number; actor: string | null; updated_at: string | null };
const labels: [keyof Omit<Config, "sandbox_image_repositories">, string][] = [
  ["grype_download_allowed", "允许手动更新 Grype 漏洞数据库"],
  ["sca_dependency_resolution_allowed", "允许 SCA 在缺少 npm 锁文件时联网解析依赖"],
  ["semgrep_download_allowed", "允许手动下载 / 更新 Semgrep 社区规则"],
  ["sandbox_image_download_allowed", "允许 SANDBOX 下载白名单镜像"],
  ["sandbox_dependency_download_allowed", "允许 SANDBOX 准备阶段联网安装依赖"],
];

export function useDownloadPermission(field: "grype_download_allowed" | "semgrep_download_allowed") {
  const [allowed, setAllowed] = useState(false);
  const [detail, setDetail] = useState("正在读取管理员下载策略…");
  useEffect(() => {
    let active = true;
    request<Snapshot>("/admin/maintenance-policy").then(snapshot => {
      if (!active) return;
      setAllowed(snapshot.config[field]);
      setDetail(snapshot.config[field] ? "管理员允许手动下载；后端仍会检查显式离线限制。" : "管理员已禁止此类下载；已有本地资源仍可使用。");
    }).catch(error => { if (active) setDetail(`下载策略读取失败，暂不可下载：${String(error)}`); });
    return () => { active = false; };
  }, [field]);
  return { allowed, detail };
}

export function MaintenancePolicy({ sandbox = false }: { sandbox?: boolean }) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [entry, setEntry] = useState("");
  const [editing, setEditing] = useState<number | null>(null);
  async function load() {
    setBusy(true);
    try { setSnapshot(await request<Snapshot>("/admin/maintenance-policy")); setMessage(""); }
    catch (error) { setSnapshot(null); setMessage(`配置加载失败：${String(error)}`); }
    finally { setBusy(false); }
  }
  useEffect(() => { void load(); }, []);
  async function save() {
    setBusy(true);
    try { setSnapshot(await request<Snapshot>("/admin/maintenance-policy", { method: "PUT", body: JSON.stringify(snapshot) })); setMessage("已保存；后续下载与启动准备使用此配置，已运行任务不受影响。"); }
    catch (error) { setMessage(`保存失败：${String(error)}`); }
    finally { setBusy(false); }
  }
  function repositories(next: string[]) { if (snapshot) setSnapshot({ ...snapshot, config: { ...snapshot.config, sandbox_image_repositories: next } }); }
  return <section className="panel full"><h3>{sandbox ? "镜像下载白名单与联网准备" : "联网下载策略"}</h3><p>平台级配置。普通用户仍可在允许时手动更新资源；扫描不会因此自动更新数据库或规则。本页不控制 OSV 在线查询、AI API 或外部目标访问，也不放宽容器运行隔离。</p>{message && <p role="status">{message}</p>}{snapshot && <><fieldset disabled={busy}>{labels.filter(([key]) => sandbox ? key.startsWith("sandbox_") : !key.startsWith("sandbox_")).map(([key, label]) => <label className="inline-check" key={key}><input type="checkbox" checked={snapshot.config[key]} onChange={e => setSnapshot({ ...snapshot, config: { ...snapshot.config, [key]: e.target.checked } })} />{label}</label>)}{sandbox && <><h4>允许自动下载的 Docker Hub 仓库</h4><p>每项为 node 或 organization/image，不支持通配符。仅授权镜像下载与启动方案选择，不是网络域名白名单。已准备的本地镜像保持原有使用方式；启动命令仍经过独立校验。</p><PagedTable><thead><tr><th>仓库</th><th>操作</th></tr></thead><tbody>{snapshot.config.sandbox_image_repositories.map((name, index) => <tr key={name}><td>{name}</td><td><FeedbackButton onClick={() => { setEntry(name); setEditing(index); }}>编辑</FeedbackButton><FeedbackButton onClick={() => { repositories(snapshot.config.sandbox_image_repositories.filter((_, i) => i !== index)); setEditing(null); setEntry(""); }}>移除</FeedbackButton></td></tr>)}</tbody></PagedTable><label>镜像仓库<input value={entry} onChange={e => setEntry(e.target.value)} placeholder="organization/image" /></label><FeedbackButton disabled={!entry.trim()} onClick={() => { const next = [...snapshot.config.sandbox_image_repositories]; if (editing === null) next.push(entry.trim()); else next[editing] = entry.trim(); repositories(next); setEntry(""); setEditing(null); }}>{editing === null ? "添加到草稿" : "修改草稿"}</FeedbackButton></>}</fieldset><p>配置版本 {snapshot.version} · 最近保存：{snapshot.actor ?? "平台默认值"}</p><FeedbackButton disabled={busy} onClick={() => save()}>保存配置</FeedbackButton></>}<FeedbackButton disabled={busy} onClick={() => load()}>重新加载</FeedbackButton></section>;
}
