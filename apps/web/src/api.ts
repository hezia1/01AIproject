export const API_BASE = (import.meta.env.VITE_API_BASE_URL || "/api").replace(/\/$/, "");

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = String(init.method ?? "GET").toUpperCase();
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    cache: method === "GET" ? "no-store" : init.cache,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const payload = await response.json();
      detail = typeof payload.detail === "string" ? payload.detail : payload.detail?.message ? String(payload.detail.message) : JSON.stringify(payload.detail ?? payload);
    } catch { /* keep HTTP status */ }
    throw new Error(detail);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function requestWithTimeout<T>(path: string, init: RequestInit, timeoutMs: number): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await request<T>(path, { ...init, signal: controller.signal });
  } catch (error) {
    if (controller.signal.aborted) throw new Error(`扫描超过 ${Math.round(timeoutMs / 1000)} 秒客户端等待上限；服务端会保存已经完成的有界结果`);
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}
