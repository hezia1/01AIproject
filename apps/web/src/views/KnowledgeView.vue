<script setup lang="ts">
import { ref } from "vue";
import { api, errorText } from "../api";
import { usePlatformStore } from "../stores/platform";
const store = usePlatformStore(); const report = ref<Record<string, any> | null>(null); const message = ref("");
async function generate() { if (!store.project) return; try { report.value = await api(`/aspm/projects/${store.project.id}/report`); message.value = "报告数据已刷新"; } catch (e) { message.value = errorText(e); } }
</script>
<template><div class="stack-layout"><section class="panel"><div class="panel-header"><h2>安全知识与交付报告</h2><span>聚合 SCA、SAST、DAST 和沙箱证据</span></div><div class="toolbar"><button class="primary-action" :disabled="!store.project" @click="generate">生成报告预览</button></div></section><section class="split-grid"><article class="panel"><h2>风险知识摘要</h2><p>当前项目沉淀 {{ store.counts.findings }} 条发现、{{ store.counts.validations }} 条验证、{{ store.counts.evidence }} 条动态证据。</p><pre class="json-preview">{{ JSON.stringify(store.summary ?? {}, null, 2) }}</pre></article><article class="panel"><h2>交付报告</h2><pre class="json-preview">{{ JSON.stringify(report ?? {}, null, 2) }}</pre></article></section><p>{{ message }}</p></div></template>
