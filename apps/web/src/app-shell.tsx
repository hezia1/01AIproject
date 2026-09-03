import React from "react";
import { BookOpen, FileText, FolderKanban, Play, Settings, ShieldCheck } from "lucide-react";
import { useAuth } from "./auth";

export type PrimaryView = "projects" | "assets" | "detection" | "governance" | "knowledge" | "reports" | "admin";
type ShellProject = { id: string; name: string };

export function AppShell({ activeView, projects, project, busy, onNavigate, onSelectProject, onRefresh, children }: {
  activeView: PrimaryView;
  projects: ShellProject[];
  project: ShellProject | null;
  busy: boolean;
  onNavigate: (view: PrimaryView) => void;
  onSelectProject: (projectId: string) => void;
  onRefresh: () => void;
  children: React.ReactNode;
}) {
  const { user, isAdmin, logout } = useAuth();
  return <main className="app-shell">
    <aside className="sidebar">
      <div className="brand"><ShieldCheck size={26} /><div><strong>AI 安全平台</strong><span>Application Security</span></div></div>
      <nav className="nav-list">
        <NavButton active={activeView === "projects" || activeView === "assets"} onClick={() => onNavigate("projects")} icon={<FolderKanban size={18} />} label="项目" />
        <NavButton active={activeView === "detection"} onClick={() => onNavigate("detection")} icon={<Play size={18} />} label="检测" />
        <NavButton active={activeView === "governance"} onClick={() => onNavigate("governance")} icon={<ShieldCheck size={18} />} label="风险治理" />
        <NavButton active={activeView === "knowledge"} onClick={() => onNavigate("knowledge")} icon={<BookOpen size={18} />} label="安全知识中枢" />
        <NavButton active={activeView === "reports"} onClick={() => onNavigate("reports")} icon={<FileText size={18} />} label="报告" />
        {isAdmin ? <div className="nav-admin-divider"><span>平台管理</span><NavButton active={activeView === "admin"} onClick={() => onNavigate("admin")} icon={<Settings size={18} />} label="管理中心" /></div> : null}
      </nav>
      <div className="sidebar-account"><span>{isAdmin ? "管理员" : "普通用户"}</span><strong>{user.username}</strong><button onClick={() => void logout()}>退出登录</button></div>
    </aside>
    <section className="workspace">
      <header className="topbar"><div><p className="eyebrow">{viewEyebrow(activeView)}</p><h1>{viewTitle(activeView)}</h1></div><div className="topbar-actions"><label className="project-switcher"><span>当前项目</span><select value={project?.id ?? ""} onChange={(event) => onSelectProject(event.target.value)}><option value="">未选择</option>{projects.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label><button className="secondary-action" onClick={onRefresh} disabled={busy}>刷新</button></div></header>
      {children}
    </section>
  </main>;
}

function NavButton({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: React.ReactNode; label: string }) {
  return <button className={`nav-item ${active ? "active" : ""}`} onClick={onClick}>{icon}{label}</button>;
}

function viewEyebrow(view: PrimaryView) {
  return view === "projects" || view === "assets" ? "项目空间" : view === "detection" ? "五模块统一执行" : view === "knowledge" ? "可学习、可传递、可治理" : view === "reports" ? "集中交付" : view === "admin" ? "平台能力配置" : "ASPM 项目安全治理";
}

function viewTitle(view: PrimaryView) {
  return view === "projects" ? "项目接入与切换" : view === "assets" ? "项目资产与准备度" : view === "detection" ? "检测" : view === "knowledge" ? "安全知识中枢" : view === "reports" ? "报告" : view === "admin" ? "管理中心" : "风险治理";
}
