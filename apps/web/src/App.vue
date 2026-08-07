<script setup lang="ts">
import { computed, onMounted } from "vue";
import { useRoute } from "vue-router";
import { BookOpen, FolderKanban, GitBranch, Play, ShieldCheck } from "lucide-vue-next";
import { usePlatformStore } from "./stores/platform";

const route = useRoute();
const store = usePlatformStore();
const title = computed(() => String(route.meta.title ?? "AI 安全平台"));
const eyebrow = computed(() => String(route.meta.eyebrow ?? "Application Security"));
const nav = [
  ["projects", "项目管理", FolderKanban], ["assets", "项目资产", GitBranch], ["detection", "安全检测", Play],
  ["governance", "治理总览", ShieldCheck], ["knowledge", "安全知识中枢", BookOpen],
];
onMounted(() => store.bootstrap());
</script>

<template>
  <main class="app-shell">
    <aside class="sidebar">
      <div class="brand"><ShieldCheck :size="26" /><div><strong>AI 安全平台</strong><span>Application Security</span></div></div>
      <nav class="nav-list">
        <RouterLink v-for="[key, label, icon] in nav" :key="String(key)" class="nav-item" :to="`/${key}`"><component :is="icon" :size="18" />{{ label }}</RouterLink>
      </nav>
    </aside>
    <section class="workspace">
      <header class="topbar">
        <div><p class="eyebrow">{{ eyebrow }}</p><h1>{{ title }}</h1></div>
        <div class="topbar-actions"><div class="current-project-pill"><span>当前项目</span><strong>{{ store.project?.name ?? "未选择" }}</strong></div><button class="primary-action" :disabled="store.loading" @click="store.bootstrap">刷新数据</button></div>
      </header>
      <div class="api-status" :class="{ warning: /失败|未连接/.test(store.status), ok: !/失败|未连接/.test(store.status) }">{{ store.status }}</div>
      <RouterView />
    </section>
  </main>
</template>
