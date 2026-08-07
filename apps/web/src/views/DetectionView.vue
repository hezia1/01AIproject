<script setup lang="ts">
import { usePlatformStore, type ModuleKey } from "../stores/platform";
const store = usePlatformStore();
const labels: Record<string, string> = { detection: "检测", validation: "验证", evidence: "证据", governance: "治理" };
</script>
<template><div class="stack-layout">
  <section class="panel"><div class="panel-header"><h2>统一执行参数</h2><span>勾选的模块按安全链路顺序执行</span></div><div class="execution-config-grid"><label>源码路径<input v-model="store.sourcePath" /></label><label>运行地址<input v-model="store.targetUrl" /></label><label>沙箱命令<input v-model="store.runCommand" /></label><label>沙箱镜像<input v-model="store.sandboxImage" /></label></div><div class="toolbar"><label class="check-control"><input v-model="store.scaEnhanced" type="checkbox" /> SCA 默认使用 Syft/Grype 增强扫描</label><button class="primary-action" :disabled="!store.project || store.loading" @click="store.runUnified">一键执行已启用检测</button></div></section>
  <section class="module-catalog"><article v-for="module in store.modules" :key="module.key" class="module-card" :class="{ selected: store.enabled(module.key) }"><div class="module-card-top"><span class="module-code">{{ module.code }}</span><span class="module-category">{{ labels[module.category] ?? module.category }}</span></div><h2>{{ module.name }}</h2><p>{{ module.subtitle }}</p><div class="module-card-actions"><button v-if="module.key !== 'aspm'" class="secondary-action" @click="store.toggleModule(module.key as ModuleKey)">{{ store.enabled(module.key) ? "停用" : "启用" }}</button><RouterLink class="primary-action" :to="`/${module.key}`">进入工作台</RouterLink></div></article></section>
</div></template>
