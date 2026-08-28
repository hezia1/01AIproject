# 项目文档索引

本目录承接 `artifacts/audit-ppt-20260809/01.pptx` 的目标，并记录仓库截至 **2026-08-28** 的实际实现。根目录 [`README.md`](../README.md) 是启动、使用和安全边界的主入口；出现冲突时，以代码、数据库迁移、自动化测试和根 README 的当前说明为准。

状态词统一如下：

- **已实现**：代码、接口和持久化路径存在，并有自动化测试或本地运行证据。
- **有条件实现**：需要 Docker、固定镜像、第三方扫描器、离线情报或模型密钥；缺失时会明确降级或阻塞。
- **未实现**：不得作为现有能力宣传，包括生产级 IAM/租户隔离、跨项目治理、分布式任务、完整运行时系统观测和已量化的精确率/召回率。

建议阅读顺序：

1. [`prd.md`](prd.md)：当前产品范围、用户和能力边界。
2. [`architecture.md`](architecture.md)：实际系统结构、数据流与部署边界。
3. [`module-system.md`](module-system.md)：六模块的现状与依赖关系。
4. [`mvp-roadmap.md`](mvp-roadmap.md)：已交付里程碑和剩余工作。
5. [`acceptance-baseline.md`](acceptance-baseline.md)：P0 可机读验收状态、证据与缺口。
6. [`deferred-work.md`](deferred-work.md)：暂缓事项、重新启动条件和完成记录。
7. [`PROJECT_HANDOFF_2026-07-26.md`](PROJECT_HANDOFF_2026-07-26.md)：当前交接快照；文件名因外部引用而保留。
8. 专题文档：[`SAST_CI_INTEGRATIONS.md`](SAST_CI_INTEGRATIONS.md)、[`sca-ci-gate.md`](sca-ci-gate.md)、[`sandbox-adapter-protocol.md`](sandbox-adapter-protocol.md)。
