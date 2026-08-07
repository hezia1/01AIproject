<script setup lang="ts">
import { computed, ref, watch } from "vue";
const props = defineProps<{ rows: Record<string, any>[]; columns: { key: string; label: string; format?: (value: any, row: Record<string, any>) => string }[]; empty?: string }>();
const page = ref(1); const pageCount = computed(() => Math.max(1, Math.ceil(props.rows.length / 10))); const items = computed(() => props.rows.slice((page.value - 1) * 10, page.value * 10)); watch(() => props.rows.length, () => { page.value = 1; });
</script>
<template>
  <div class="table-wrap"><table><thead><tr><th v-for="column in columns" :key="column.key">{{ column.label }}</th></tr></thead><tbody>
    <tr v-if="!rows.length"><td :colspan="columns.length" class="empty-row">{{ empty ?? "暂无数据" }}</td></tr>
    <tr v-for="(row, index) in items" :key="row.id ?? index"><td v-for="column in columns" :key="column.key">{{ column.format ? column.format(row[column.key], row) : (row[column.key] ?? "-") }}</td></tr>
  </tbody></table><div class="result-pagination"><span>共 {{ rows.length }} 条，每页 10 条</span><div><button :disabled="page<=1" @click="page--">上一页</button><strong>第 {{ page }} / {{ pageCount }} 页</strong><button :disabled="page>=pageCount" @click="page++">下一页</button></div></div></div>
</template>
