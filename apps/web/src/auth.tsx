import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { FeedbackButton, FeedbackForm } from "./action-feedback";
import { API_BASE, ApiRequestError, request } from "./api";

export type AuthUser = { id: string; username: string; role: "user" | "admin"; enabled: boolean };

type AuthContextValue = {
  user: AuthUser;
  isAdmin: boolean;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);
const AUTH_BOOTSTRAP_TIMEOUT_MS = 8000;

type PlatformHealthCheck = { key: string; name: string; status: "ok" | "degraded" | "unavailable"; required: boolean; detail: string };
type PlatformHealth = { status: "ok" | "degraded" | "unavailable"; checks: PlatformHealthCheck[]; limitations: string[] };
type AuthLoadError = { title: string; message: string; health: PlatformHealth | null };

class AuthBootstrapTimeoutError extends Error {}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthGate");
  return value;
}

export function AuthGate({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [initialized, setInitialized] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<AuthLoadError | null>(null);
  const loadGeneration = useRef(0);

  const loadAuthentication = useCallback(async () => {
    const generation = ++loadGeneration.current;
    setLoading(true);
    setLoadError(null);
    try {
      const status = await authRequest<{ initialized: boolean }>("/auth/status");
      let nextUser: AuthUser | null = null;
      if (!status.initialized) {
        nextUser = null;
      } else {
        try {
          nextUser = await authRequest<AuthUser>("/auth/me");
        } catch (error) {
          if (!(error instanceof ApiRequestError && error.status === 401)) throw error;
        }
      }
      if (generation !== loadGeneration.current) return;
      setInitialized(status.initialized);
      setUser(nextUser);
    } catch (error) {
      const health = await loadPlatformHealth();
      if (generation !== loadGeneration.current) return;
      setInitialized(null);
      setUser(null);
      setLoadError(classifyAuthLoadError(error, health));
    } finally {
      if (generation === loadGeneration.current) setLoading(false);
    }
  }, []);

  useEffect(() => { void loadAuthentication(); }, [loadAuthentication]);

  async function logout() {
    await request("/auth/logout", { method: "POST" }).catch(() => undefined);
    setUser(null);
  }

  if (loadError) return <AuthErrorPanel error={loadError} loading={loading} onRetry={loadAuthentication} />;
  if (loading || initialized === null) return <div className="auth-shell"><div className="auth-card"><strong>正在连接安全平台…</strong></div></div>;
  if (!user) return <LoginPanel initialized={initialized} onAuthenticated={(next) => { setInitialized(true); setUser(next); }} />;

  const value = { user, isAdmin: user.role === "admin", logout };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

async function authRequest<T>(path: string): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), AUTH_BOOTSTRAP_TIMEOUT_MS);
  try {
    return await request<T>(path, { signal: controller.signal });
  } catch (error) {
    if (controller.signal.aborted) throw new AuthBootstrapTimeoutError("authentication bootstrap timed out");
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

async function loadPlatformHealth(): Promise<PlatformHealth | null> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 3000);
  try {
    const response = await fetch(`${API_BASE}/health?include_optional_tools=false`, {
      cache: "no-store",
      signal: controller.signal,
    });
    const payload = await response.json();
    return payload && Array.isArray(payload.checks) ? payload as PlatformHealth : null;
  } catch {
    return null;
  } finally {
    window.clearTimeout(timeout);
  }
}

function classifyAuthLoadError(error: unknown, health: PlatformHealth | null): AuthLoadError {
  const database = health?.checks.find((item) => item.key === "database");
  if (database?.status === "unavailable") {
    return { title: "安全平台依赖服务不可用", message: "API 可以响应，但数据库当前不可用，认证和业务数据无法加载。", health };
  }
  if (error instanceof AuthBootstrapTimeoutError) {
    return { title: "连接安全平台超时", message: "认证状态检查超过 8 秒。请确认 API 和数据库状态后重试。", health };
  }
  if (error instanceof TypeError) {
    return { title: "无法连接后端 API", message: "浏览器无法访问安全平台 API。请确认后端地址和服务进程。", health };
  }
  if (error instanceof ApiRequestError) {
    return { title: "安全平台暂时不可用", message: `认证状态请求失败（HTTP ${error.status}）：${error.message}`, health };
  }
  return { title: "安全平台加载失败", message: error instanceof Error ? error.message : "认证状态无法读取。", health };
}

function AuthErrorPanel({ error, loading, onRetry }: { error: AuthLoadError; loading: boolean; onRetry: () => Promise<void> }) {
  return <main className="auth-shell"><section className="auth-card auth-error-card" role="alert">
    <div className="auth-brand"><ShieldCheck size={32} /><div><strong>AI 安全平台</strong><span>连接诊断</span></div></div>
    <h1>{error.title}</h1>
    <p>{error.message}</p>
    {error.health ? <div className="auth-diagnostics" aria-label="平台健康诊断">{error.health.checks.map((item) => <div key={item.key}>
      <span>{item.name}{item.required ? "（必需）" : "（可选）"}</span>
      <strong className={`health-${item.status}`}>{healthStatusLabel(item.status)}</strong>
      <small>{item.detail}</small>
    </div>)}</div> : <p className="auth-message">健康接口也不可达，当前无法判断数据库和可选工具状态。</p>}
    <FeedbackButton className="primary-action" disabled={loading} onClick={() => void onRetry()}>{loading ? "正在重试…" : "重试连接"}</FeedbackButton>
    <small>诊断状态不代表任何项目扫描已经成功，也不能作为“无漏洞”结论。</small>
  </section></main>;
}

function healthStatusLabel(status: PlatformHealthCheck["status"]): string {
  return status === "ok" ? "正常" : status === "degraded" ? "降级" : "不可用";
}

function LoginPanel({ initialized, onAuthenticated }: { initialized: boolean; onAuthenticated: (user: AuthUser) => void }) {
  type Mode = "user-login" | "admin-login" | "register" | "setup";
  const [mode, setMode] = useState<Mode>(initialized ? "user-login" : "setup");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if ((mode === "setup" || mode === "register") && password !== confirmPassword) return setMessage("两次输入的密码不一致");
    setSubmitting(true);
    setMessage("");
    try {
      const endpoint = mode === "setup" ? "/auth/bootstrap" : mode === "register" ? "/auth/register" : "/auth/login";
      const next = await request<AuthUser>(endpoint, { method: "POST", body: JSON.stringify({ username: username.trim(), password }) });
      const wrongLoginType = (mode === "admin-login" && next.role !== "admin") || (mode === "user-login" && next.role !== "user");
      if (wrongLoginType) {
        await request("/auth/logout", { method: "POST" }).catch(() => undefined);
        throw new Error(mode === "admin-login" ? "该账号不是管理员账号" : "管理员请使用下方的“管理员登录”入口");
      }
      onAuthenticated(next);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "登录失败");
    } finally {
      setSubmitting(false);
    }
  }

  function switchMode(next: Mode) {
    setMode(next);
    setPassword("");
    setConfirmPassword("");
    setMessage("");
  }

  const title = mode === "setup" ? "初始化管理员" : mode === "register" ? "用户注册" : mode === "admin-login" ? "管理员登录" : "用户登录";
  const description = mode === "setup"
    ? "首次启动需要创建初始管理员。后续管理员账号只能在管理中心新增。"
    : mode === "register"
      ? "注册入口只创建普通用户账号，不能创建管理员。"
      : mode === "admin-login"
        ? "使用管理员账号进入平台管理中心。"
        : "使用普通用户账号进入项目检测与治理工作台。";

  return <main className="auth-shell"><FeedbackForm className="auth-card" onSubmit={(event) => submit(event)}>
    <div className="auth-brand"><ShieldCheck size={32} /><div><strong>AI 安全平台</strong><span>{title}</span></div></div>
    <p>{description}</p>
    <label>用户名<input autoComplete="username" minLength={3} maxLength={120} value={username} onChange={(event) => setUsername(event.target.value)} required /></label>
    <label>密码<input type="password" placeholder="至少 6 位" autoComplete={mode === "register" || mode === "setup" ? "new-password" : "current-password"} minLength={6} maxLength={200} value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
    {mode === "setup" || mode === "register" ? <label>确认密码<input type="password" autoComplete="new-password" minLength={6} maxLength={200} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required /></label> : null}
    {message ? <div className="auth-message" role="alert">{message}</div> : null}
    <FeedbackButton className="primary-action" disabled={submitting}>{submitting ? "请稍候…" : mode === "setup" ? "创建初始管理员并登录" : mode === "register" ? "注册并登录" : "登录"}</FeedbackButton>
    {mode !== "setup" ? <div className="auth-alternatives">
      {mode !== "user-login" ? <FeedbackButton type="button" onClick={() => switchMode("user-login")}>用户登录</FeedbackButton> : null}
      {mode !== "admin-login" ? <FeedbackButton type="button" onClick={() => switchMode("admin-login")}>管理员登录</FeedbackButton> : null}
      {mode !== "register" ? <FeedbackButton type="button" onClick={() => switchMode("register")}>用户注册</FeedbackButton> : null}
    </div> : null}
    <small>安全说明：浏览器脚本不能读取登录会话，数据库也不会保存你的明文密码。</small>
  </FeedbackForm></main>;
}
