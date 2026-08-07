<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";
import { usePlatformStore } from "../stores/platform";
import ProjectsView from "./ProjectsView.vue";
import AssetsView from "./AssetsView.vue";
import DetectionView from "./DetectionView.vue";
import GovernanceView from "./GovernanceView.vue";
import KnowledgeView from "./KnowledgeView.vue";
import ScaView from "./ScaView.vue";
import SastView from "./SastView.vue";
import ModuleView from "./ModuleView.vue";

const route = useRoute();
const store = usePlatformStore();
const key = computed(() => String(route.name));
const component = computed(() => ({ projects: ProjectsView, assets: AssetsView, detection: DetectionView, governance: GovernanceView, knowledge: KnowledgeView, sca: ScaView, sast: SastView }[key.value] ?? ModuleView));
</script>

<template><component :is="component" :module-key="key" :key="`${key}-${store.project?.id ?? 'none'}`" /></template>
