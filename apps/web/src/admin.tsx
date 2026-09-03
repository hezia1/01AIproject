import { useEffect, useState } from "react";
import { request } from "./api";

type ManagedUser = { id: string; username: string; role: "user" | "admin"; enabled: boolean; created_at: string };

export function UserAdministration() {
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [draft, setDraft] = useState({ username: "", password: "", role: "user" as "user" | "admin" });
  const [message, setMessage] = useState("");

  async function load() {
    setUsers(await request<ManagedUser[]>("/auth/users"));
  }
  useEffect(() => { void load().catch((error) => setMessage(String(error))); }, []);

  async function createUser() {
    try {
      await request("/auth/users", { method: "POST", body: JSON.stringify(draft) });
      setDraft({ username: "", password: "", role: "user" });
      setMessage("用户已创建");
      await load();
    } catch (error) { setMessage(error instanceof Error ? error.message : "创建失败"); }
  }

  async function toggle(user: ManagedUser) {
    try {
      await request(`/auth/users/${user.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !user.enabled }) });
      await load();
    } catch (error) { setMessage(error instanceof Error ? error.message : "更新失败"); }
  }

  return <section className="content-grid">
    <div className="panel full"><div className="panel-header"><div><h2>用户管理</h2><span>平台只区分普通用户和管理员</span></div></div>
      <div className="filter-grid"><label>用户名<input value={draft.username} onChange={(event) => setDraft({ ...draft, username: event.target.value })} /></label><label>初始密码（至少 6 位）<input type="password" minLength={6} value={draft.password} onChange={(event) => setDraft({ ...draft, password: event.target.value })} /></label><label>身份<select value={draft.role} onChange={(event) => setDraft({ ...draft, role: event.target.value as "user" | "admin" })}><option value="user">普通用户</option><option value="admin">管理员</option></select></label><button className="primary-action" disabled={draft.username.trim().length < 3 || draft.password.length < 6} onClick={() => void createUser()}>新增用户</button></div>
      {message ? <div className="empty-project">{message}</div> : null}
      {users.length ? <table><thead><tr><th>用户名</th><th>身份</th><th>状态</th><th>操作</th></tr></thead><tbody>{users.map((user) => <tr key={user.id}><td>{user.username}</td><td>{user.role === "admin" ? "管理员" : "普通用户"}</td><td>{user.enabled ? "启用" : "停用"}</td><td><button className="secondary-action" onClick={() => void toggle(user)}>{user.enabled ? "停用" : "启用"}</button></td></tr>)}</tbody></table> : <div className="empty-project">暂无用户</div>}
    </div>
  </section>;
}
