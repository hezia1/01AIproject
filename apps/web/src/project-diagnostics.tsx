import { useCallback, useEffect, useRef, useState } from "react";
import { Activity, RefreshCw } from "lucide-react";
import { FeedbackButton } from "./action-feedback";
import { request } from "./api";

type DiagnosticCheck = {
  key: string;
  name: string;
  status: string;
  required: boolean;
  detail: string;
  observed_at?: string | null;
};

type ModuleDiagnostic = {
  key: string;
  name: string;
  enabled: boolean;
  status: string;
  latest_task: { status: string; persisted_status?: string | null; age_hours?: number | null; reasons?: string[] };
  checks: DiagnosticCheck[];
};

type ProjectDiagnostic = {
  project_id: string;
  status: string;
  checked_at: string;
  state_contract: Record<string, string>;
  modules: ModuleDiagnostic[];
  limitations: string[];
};

const diagnosticRequests = new Map<string, Promise<ProjectDiagnostic>>();

function loadDiagnostic(projectId: string, force = false): Promise<ProjectDiagnostic> {
  if (!force) {
    const pending = diagnosticRequests.get(projectId);
    if (pending) return pending;
  }
  const pending = request<ProjectDiagnostic>(`/projects/${projectId}/diagnostics`)
    .finally(() => {
      if (diagnosticRequests.get(projectId) === pending) diagnosticRequests.delete(projectId);
    });
  diagnosticRequests.set(projectId, pending);
  return pending;
}

export function ProjectDiagnostics({ projectId }: { projectId: string }) {
  const [diagnostic, setDiagnostic] = useState<ProjectDiagnostic | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const requestGeneration = useRef(0);

  const refresh = useCallback(async (force = false) => {
    const generation = ++requestGeneration.current;
    setLoading(true);
    setError("");
    try {
      const result = await loadDiagnostic(projectId, force);
      if (generation === requestGeneration.current) setDiagnostic(result);
    } catch (failure) {
      if (generation === requestGeneration.current) {
        setDiagnostic(null);
        setError(failure instanceof Error ? failure.message : "模块诊断加载失败");
      }
    } finally {
      if (generation === requestGeneration.current) setLoading(false);
    }
  }, [projectId]);

  useEffect(() => { void refresh(false); }, [refresh]);

  return <section className="panel project-diagnostics" aria-label="模块真实诊断">
    <div className="panel-header">
      <div><h2><Activity size={19} /> 模块真实诊断</h2><p>任务主状态、情报时效、模型调用证据和动态目标分别展示；“成功”不表示无漏洞。</p></div>
      <FeedbackButton className="secondary-action" disabled={loading} onClick={() => void refresh(true)}><RefreshCw size={15} />{loading ? "检查中…" : "刷新诊断"}</FeedbackButton>
    </div>
    {error ? <div className="diagnostic-load-error" role="alert">诊断接口失败：{error}。当前状态未知，不能按正常处理。</div> : null}
    {diagnostic ? <>
      <div className="diagnostic-summary"><strong className={`diagnostic-state state-${diagnostic.status}`}>{diagnosticLabel(diagnostic.status)}</strong><span>检查时间：{formatTime(diagnostic.checked_at)}</span></div>
      <div className="diagnostic-modules">
        {diagnostic.modules.map((module) => <article className="diagnostic-module" key={module.key}>
          <header><div><strong>{module.name}</strong><small>{module.enabled ? `数据库任务状态：${module.latest_task.persisted_status ?? "无记录"}` : "当前项目未启用"}</small></div><span className={`diagnostic-state state-${module.status}`}>{diagnosticLabel(module.status)}</span></header>
          <div className="diagnostic-checks">{module.checks.map((check) => <div key={check.key}>
            <span>{check.name}{check.required ? "（本模块必需）" : "（可选）"}</span>
            <strong className={`diagnostic-state state-${check.status}`}>{diagnosticLabel(check.status)}</strong>
            <small>{check.detail}{check.observed_at ? ` · 观测于 ${formatTime(check.observed_at)}` : ""}</small>
          </div>)}</div>
        </article>)}
      </div>
      <details className="diagnostic-contract"><summary>状态口径与限制</summary>
        {Object.entries(diagnostic.state_contract).map(([key, value]) => <p key={key}><strong>{diagnosticLabel(key)}：</strong>{value}</p>)}
        {diagnostic.limitations.map((item) => <p key={item}>{item}</p>)}
      </details>
    </> : loading ? <p>正在读取模块任务及依赖证据…</p> : null}
  </section>;
}

function diagnosticLabel(status: string): string {
  const labels: Record<string, string> = {
    ok: "正常", succeeded: "已完成", partial: "部分完成", stale: "已过期", failed: "失败",
    unavailable: "不可用", degraded: "降级", unknown: "未知", configured_unverified: "已配置未验证",
    not_configured: "未配置", not_run: "未运行", queued: "排队中", running: "运行中",
    cancelled: "已取消", stopped: "已停止", disabled: "未启用", not_required: "非必需",
    not_applicable: "不适用", current: "时效内", ready: "可用", invalid: "无效",
  };
  return labels[status] ?? status;
}

function formatTime(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString("zh-CN", { hour12: false, timeZone: "Asia/Shanghai" });
}
