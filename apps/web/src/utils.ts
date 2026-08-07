export function formatBeijing(value: unknown) {
  if (!value) return "-";
  const raw = String(value);
  const explicitZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(raw);
  const date = new Date(explicitZone ? raw : `${raw.replace(" ", "T")}Z`);
  if (Number.isNaN(date.getTime())) return raw;
  return `${new Intl.DateTimeFormat("zh-CN", { timeZone: "Asia/Shanghai", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }).format(date)}（北京时间）`;
}
