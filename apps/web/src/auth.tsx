import React, { createContext, useContext, useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
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
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!initialized && password !== confirmPassword) return setMessage("两次输入的密码不一致");
    setSubmitting(true);
    setMessage("");
    try {
      const endpoint = initialized ? "/auth/login" : "/auth/bootstrap";
      onAuthenticated(await request<AuthUser>(endpoint, { method: "POST", body: JSON.stringify({ username: username.trim(), password }) }));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "登录失败");
    } finally {
      setSubmitting(false);
    }
  }

  return <main className="auth-shell"><form className="auth-card" onSubmit={(event) => void submit(event)}>
    <div className="auth-brand"><ShieldCheck size={32} /><div><strong>AI 安全平台</strong><span>{initialized ? "登录工作台" : "初始化管理员"}</span></div></div>
    <p>{initialized ? "使用管理员为你创建的账号登录。普通用户账号请由管理员在“管理中心 → 用户管理”中创建。" : "首次启动只需创建管理员。普通用户账号可在登录后进入“管理中心 → 用户管理”创建。"}</p>
    <label>用户名<input autoComplete="username" minLength={3} maxLength={120} value={username} onChange={(event) => setUsername(event.target.value)} required /></label>
    <label>密码<input type="password" placeholder="至少 6 位" autoComplete={initialized ? "current-password" : "new-password"} minLength={6} maxLength={200} value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
    {!initialized ? <label>确认密码<input type="password" autoComplete="new-password" minLength={6} maxLength={200} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required /></label> : null}
    {message ? <div className="auth-message" role="alert">{message}</div> : null}
    <button className="primary-action" disabled={submitting}>{submitting ? "请稍候…" : initialized ? "登录" : "创建管理员并登录"}</button>
    <small>安全说明：浏览器脚本不能读取登录会话，数据库也不会保存你的明文密码。</small>
  </form></main>;
}
