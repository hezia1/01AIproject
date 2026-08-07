import { createRouter, createWebHistory } from "vue-router";
import WorkspaceView from "./views/WorkspaceView.vue";

export const viewRoutes = [
  ["projects", "项目空间", "创建项目并切换当前项目"],
  ["assets", "项目资产画像", "确认待检测的项目资产"],
  ["detection", "模块接入与统一执行", "选择安全模块并一键执行检测"],
  ["governance", "项目安全治理", "从风险发现到修复复测的完整闭环"],
  ["knowledge", "可学习、可传递、可治理", "安全知识中枢"],
  ["modules", "能力目录", "安全模块"],
  ["sca", "供应链风险分析", "SCA 治理工作台"],
  ["sast", "智能静态审计", "SAST 治理工作台"],
  ["agent", "Agent 供应链安全", "Agent 风险治理"],
  ["dast", "漏洞动态验证", "DAST 验证工作台"],
  ["sandbox", "沙箱动态证据链", "SANDBOX 证据工作台"],
  ["tasks", "任务执行", "安全任务中心"],
  ["aspm", "平台治理与交付", "ASPM 治理总览"],
] as const;

export default createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", redirect: "/detection" },
    ...viewRoutes.map(([name, eyebrow, title]) => ({ path: `/${name}`, name, component: WorkspaceView, meta: { eyebrow, title } })),
    { path: "/:pathMatch(.*)*", redirect: "/detection" },
  ],
});
