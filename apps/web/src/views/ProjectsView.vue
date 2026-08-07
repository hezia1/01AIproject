<script setup lang="ts">
import { reactive } from "vue";
import { Plus } from "lucide-vue-next";
import { usePlatformStore } from "../stores/platform";
const store = usePlatformStore();
const empty = () => ({ name: "", business_owner: "", security_owner: "", repository_url: "", source_path: "", runtime_url: "", api_base_url: "", sandbox_command: "", sandbox_image: "", default_branch: "main" });
const draft = reactive(empty());
async function submit() { await store.createProject({ ...draft }); if (store.project?.name === draft.name.trim()) Object.assign(draft, empty()); }
</script>
<template><section class="project-workspace">
  <div class="panel project-create"><div class="panel-header"><h2>项目创建向导</h2><span>ASPM 内置，SCA + SAST 默认启用</span></div><form class="project-form" @submit.prevent="submit">
    <label>项目名称<input v-model="draft.name" placeholder="例如：政企门户应用" /></label><label>业务负责人<input v-model="draft.business_owner" /></label><label>安全负责人<input v-model="draft.security_owner" /></label><label>代码仓库<input v-model="draft.repository_url" /></label><label>本地源码路径<input v-model="draft.source_path" placeholder="D:\project\demo-repo" /></label><label>运行地址<input v-model="draft.runtime_url" /></label><label>API 地址<input v-model="draft.api_base_url" /></label><label>沙箱命令<input v-model="draft.sandbox_command" /></label><label>沙箱镜像<input v-model="draft.sandbox_image" /></label><label>默认分支<input v-model="draft.default_branch" /></label><button class="primary-action" :disabled="store.loading || !draft.name.trim()"><Plus :size="16" />创建项目</button>
  </form></div>
  <div class="panel project-directory"><div class="panel-header"><h2>项目列表</h2><span>{{ store.projects.length }} 个项目</span></div><div class="project-list"><div v-if="!store.projects.length" class="empty-project">暂无项目。创建项目后，数据会按项目隔离。</div><div v-for="item in store.projects" :key="item.id" class="project-row" :class="{ active: store.project?.id === item.id }"><button class="project-main" @click="store.selectProject(item)"><div><strong>{{ item.name }}</strong><span>{{ item.repository_url ?? "未配置仓库" }} · {{ item.default_branch }}</span><span>{{ item.source_path ?? "未配置源码路径" }}</span></div><span>{{ item.business_owner ?? "未配置业务负责人" }}</span><span>{{ item.security_owner ?? "未配置安全负责人" }}</span></button><button class="danger-action" @click="store.deleteProject(item.id)">删除</button></div></div></div>
  <div class="panel current-project"><div class="panel-header"><h2>当前项目</h2><span>{{ store.project ? "已选择" : "未选择" }}</span></div><div v-if="store.project" class="project-detail"><strong>{{ store.project.name }}</strong><span>业务：{{ store.project.business_owner ?? "未配置" }}</span><span>安全：{{ store.project.security_owner ?? "未配置" }}</span><span>仓库：{{ store.project.repository_url ?? "未配置" }}</span><span>源码：{{ store.project.source_path ?? "未配置" }}</span><span>运行地址：{{ store.project.runtime_url ?? "未配置" }}</span><span>分支：{{ store.project.default_branch }}</span></div><div v-else class="empty-project">请先创建或选择项目。</div></div>
</section></template>
