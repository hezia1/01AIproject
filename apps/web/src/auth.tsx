import React, { createContext, useContext, useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { FeedbackButton, FeedbackForm } from "./action-feedback";
import { request } from "./api";

export type AuthUser = { id: string; username: string; role: "user" | "admin"; enabled: boolean };

type AuthContextValue = {
  user: AuthUser;
  isAdmin: boolean;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthGate");
  return value;
}

export function AuthGate({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [initialized, setInitialized] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void request<{ initialized: boolean }>("/auth/status")
      .then(async (status) => {
        setInitialized(status.initialized);
        if (!status.initialized) return;
        setUser(await request<AuthUser>("/auth/me").catch(() => null));
      })
      .finally(() => setLoading(false));
  }, []);

  async function logout() {
    await request("/auth/logout", { method: "POST" }).catch(() => undefined);
    setUser(null);
  }

  if (loading || initialized === null) return <div className="auth-shell"><div className="auth-card"><strong>正在连接安全平台…</strong></div></div>;
  if (!user) return <LoginPanel initialized={initialized} onAuthenticated={(next) => { setInitialized(true); setUser(next); }} />;

  const value = { user, isAdmin: user.role === "admin", logout };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
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
