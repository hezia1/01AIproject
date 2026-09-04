/** Structured editor and JSON use the same payload, never a display-only shadow. */
export function ScaPolicyFields({ kind, value, onChange }: { kind: string; value: string; onChange: (value: string) => void }) {
  let config: Record<string, unknown>;
  try { config = value ? JSON.parse(value) : {}; if (!config || Array.isArray(config) || typeof config !== "object") return null; }
  catch { return <p>JSON 尚未有效，请先修正完整策略 JSON。</p>; }
  const fields = kind === "vulnerability" ? [["ecosystem", "生态"], ["package", "组件名"], ["affected", "受影响版本范围"], ["severity", "严重程度"], ["summary", "漏洞说明"], ["fixed_version", "修复版本"]] : kind === "license" ? [["policy", "处置策略"], ["summary", "说明"], ["remediation", "修复建议"]] : [];
  return <>{fields.map(([key, label]) => <label key={key}>{label}<input value={String(config[key] ?? "")} onChange={event => onChange(JSON.stringify({ ...config, [key]: event.target.value }, null, 2))} /></label>)}</>;
}
