<script setup lang="ts">
defineProps<{ rows: Record<string, any>[]; columns: { key: string; label: string; format?: (value: any, row: Record<string, any>) => string }[]; empty?: string }>();
</script>
<template>
  <div class="table-wrap"><table><thead><tr><th v-for="column in columns" :key="column.key">{{ column.label }}</th></tr></thead><tbody>
    <tr v-if="!rows.length"><td :colspan="columns.length" class="empty-row">{{ empty ?? "暂无数据" }}</td></tr>
    <tr v-for="(row, index) in rows" :key="row.id ?? index"><td v-for="column in columns" :key="column.key">{{ column.format ? column.format(row[column.key], row) : (row[column.key] ?? "-") }}</td></tr>
  </tbody></table></div>
</template>
