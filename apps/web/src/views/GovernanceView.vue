<script setup lang="ts">
import { reactive } from "vue";
import { usePlatformStore } from "../stores/platform";
import DataTable from "../components/DataTable.vue";
const store = usePlatformStore(); const edits = reactive<Record<string, any>>({});
const columns = [{ key: "source", label: "来源" }, { key: "title", label: "风险" }, { key: "severity", label: "级别" }, { key: "status", label: "状态" }, { key: "remediation_owner", label: "负责人" }, { key: "remediation_due_at", label: "到期时间" }];
function edit(item: any) { edits[item.id] = { status: item.status ?? "open", remediation_owner: item.remediation_owner ?? "", remediation_note: item.remediation_note ?? "", remediation_due_at: item.remediation_due_at ?? "" }; }
</script>
<template><div class="stack-layout">
  <section class="metric-grid"><article class="metric-card"><span>组件</span><strong>{{ store.counts.components }}</strong></article><article class="metric-card"><span>风险发现</span><strong>{{ store.counts.findings }}</strong></article><article class="metric-card"><span>严重 / 高危</span><strong>{{ store.counts.severe }}</strong></article><article class="metric-card"><span>验证 / 证据</span><strong>{{ store.counts.validations }} / {{ store.counts.evidence }}</strong></article></section>
  <section class="panel"><div class="panel-header"><h2>风险治理清单</h2><span>点击问题进入整改编辑</span></div><DataTable :rows="store.findings" :columns="columns" /><div class="governance-list"><details v-for="item in store.findings" :key="item.id" @toggle="edit(item)"><summary>{{ item.source }} · {{ item.severity }} · {{ item.title }}</summary><div v-if="edits[item.id]" class="project-form"><label>状态<select v-model="edits[item.id].status"><option value="open">待处理</option><option value="in_progress">处理中</option><option value="resolved">已修复</option><option value="accepted">接受风险</option></select></label><label>负责人<input v-model="edits[item.id].remediation_owner" /></label><label>到期时间<input v-model="edits[item.id].remediation_due_at" type="datetime-local" /></label><label>整改说明<textarea v-model="edits[item.id].remediation_note" /></label><button class="primary-action" @click="store.updateFinding(item.id, edits[item.id])">保存整改</button></div></details></div></section>
  <section class="panel"><div class="panel-header"><h2>风险证据链</h2><span>发现 → 验证 → 沙箱证据</span></div><pre class="json-preview">{{ JSON.stringify(store.evidenceGraph ?? store.summary ?? {}, null, 2) }}</pre></section>
</div></template>
