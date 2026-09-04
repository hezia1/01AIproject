import { useState, type ReactNode } from "react";
import "./admin-workspace.css";
import { FeedbackButton } from "./action-feedback";

export type AdminModuleGroup = {
  id: string;
  label: string;
  items: Array<{ id: string; label: string; scope: string; content: ReactNode }>;
};

export function AdminWorkspace({ projectName, users, groups, onOpenKnowledge }: {
  projectName?: string;
  users: ReactNode;
  groups: AdminModuleGroup[];
  onOpenKnowledge: () => void;
}) {
  const [section, setSection] = useState("users");
  const [moduleId, setModuleId] = useState("sca");
  const [itemId, setItemId] = useState("");
  const group = groups.find((item) => item.id === moduleId) ?? groups[0];
  const item = group?.items.find((item) => item.id === itemId) ?? group?.items[0];

  return <section className="admin-center admin-workspace">
    <nav className="admin-primary-tabs" aria-label="管理中心工作区">
      <FeedbackButton className={section === "users" ? "active" : ""} onClick={() => setSection("users")}>用户管理</FeedbackButton>
      <FeedbackButton className={section === "modules" ? "active" : ""} onClick={() => setSection("modules")}>模块配置</FeedbackButton>
      <FeedbackButton onClick={onOpenKnowledge}>知识审核</FeedbackButton>
    </nav>
    {section === "users" ? users : <>
      <section className="module-context-note"><strong>当前项目：{projectName ?? "未选择"}</strong><span>修改前请核对作用范围。项目配置不自动影响其他项目；平台公共资源会供多个项目使用。</span></section>
      <nav className="admin-module-tabs" aria-label="管理员模块选择">
        {groups.map((group) => <FeedbackButton key={group.id} className={group.id === moduleId ? "active" : ""} onClick={() => { setModuleId(group.id); setItemId(""); }}>{group.label}</FeedbackButton>)}
      </nav>
      <nav className="admin-config-tabs" aria-label="管理员配置分类">
        {group?.items.map((candidate) => <FeedbackButton key={candidate.id} className={candidate.id === item?.id ? "active" : ""} onClick={() => setItemId(candidate.id)}>{candidate.label}</FeedbackButton>)}
      </nav>
      {item ? <section className="admin-config-content" key={`${group.id}-${item.id}-${projectName}`}>
        <div className="admin-scope-label">作用范围：{item.scope}</div>
        {item.content}
      </section> : null}
    </>}
  </section>;
}
