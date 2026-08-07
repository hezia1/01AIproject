<script setup lang="ts">
import { reactive, watch } from "vue";
import { usePlatformStore } from "../stores/platform";
const store = usePlatformStore();
const draft = reactive({ runtime_url: "", api_base_url: "", sandbox_command: "", sandbox_image: "" });
watch(() => store.project, (value) => Object.assign(draft, { runtime_url: value?.runtime_url ?? "", api_base_url: value?.api_base_url ?? "", sandbox_command: value?.sandbox_command ?? "", sandbox_image: value?.sandbox_image ?? "" }), { immediate: true });
</script>
<template><div class="stack-layout">
  <section class="panel"><div class="panel-header"><h2>运行与沙箱资产</h2><span>保存后用于 DAST 与 SANDBOX</span></div><div class="project-form"><label>运行地址<input v-model="draft.runtime_url" /></label><label>API 地址<input v-model="draft.api_base_url" /></label><label>沙箱命令<input v-model="draft.sandbox_command" /></label><label>沙箱镜像<input v-model="draft.sandbox_image" /></label><button class="primary-action" :disabled="!store.project || store.loading" @click="store.updateProject(draft)">保存资产配置</button></div></section>
  <section class="metric-grid"><article class="metric-card"><span>源码文件</span><strong>{{ store.assetProbe?.files?.length ?? store.assetProbe?.source_file_count ?? 0 }}</strong></article><article class="metric-card"><span>依赖组件</span><strong>{{ store.counts.components }}</strong></article><article class="metric-card"><span>安全发现</span><strong>{{ store.counts.findings }}</strong></article><article class="metric-card"><span>动态证据</span><strong>{{ store.counts.evidence }}</strong></article></section>
  <section class="panel"><div class="panel-header"><h2>资产探测结果</h2><span>{{ store.assetProbe?.status ?? (store.project ? "已探测" : "未选择项目") }}</span></div><pre class="json-preview">{{ JSON.stringify(store.assetProbe ?? {}, null, 2) }}</pre></section>
</div></template>
