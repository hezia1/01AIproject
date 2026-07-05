# 技术架构设计

## 1. 架构原则

- 平台先模块化单体，后续再拆微服务。
- 扫描任务异步执行，避免阻塞 Web 请求。
- 扫描执行环境和平台控制面隔离。
- AI 能力通过统一网关封装，不绑定单一模型供应商。
- 漏洞、组件、证据、任务和知识资产使用结构化数据保存。

## 2. 推荐技术栈

MVP 推荐：

- 前端：React + TypeScript + Vite
- 后端：Python FastAPI
- 数据库：PostgreSQL
- 缓存与任务队列：Redis + RQ 或 Celery
- 扫描执行：Docker 容器或本地隔离工作目录
- 对象存储：本地文件系统起步，后续替换为 MinIO
- AI 网关：后端统一封装 LLM 调用

## 3. 系统模块

### 3.1 Web 控制台

负责：

- 登录和权限。
- 项目管理。
- 扫描任务管理。
- 漏洞列表与治理。
- 报告查看和导出。
- 平台配置。

### 3.2 API 服务

负责：

- 对外提供 REST API。
- 管理用户、项目、任务、漏洞、组件、报告。
- 创建扫描任务并投递到队列。
- 聚合扫描结果和 AI 复核结果。

### 3.3 扫描 Worker

负责：

- 拉取代码。
- 识别语言和依赖文件。
- 执行 SCA 解析。
- 执行基础 SAST 规则扫描。
- 生成结构化 findings。
- 保存原始日志和扫描证据。

### 3.4 AI 复核服务

负责：

- 对 finding 构造上下文。
- 调用 LLM 进行风险解释。
- 输出误报可能性、影响分析和修复建议。
- 将 AI 结论作为辅助字段写入漏洞记录。

### 3.5 知识中枢

MVP 先以表结构实现，后续再图谱化。

包括：

- 漏洞类型知识库。
- 规则库。
- 误报样本库。
- 组件漏洞知识。
- 修复建议模板。
- 后续扩展 Skill 库和业务知识图谱。

## 4. 数据流

1. 用户创建项目并配置 Git 仓库。
2. 用户触发扫描任务。
3. API 服务创建扫描任务，写入数据库，投递队列。
4. Worker 拉取代码到隔离目录。
5. Worker 识别依赖文件和代码文件。
6. SCA 引擎解析依赖，匹配漏洞和许可证风险。
7. SAST 引擎执行规则扫描，生成 finding。
8. API 或 Worker 将高风险 finding 投递给 AI 复核。
9. AI 复核服务生成解释、误报判断和修复建议。
10. 平台将结果归并为漏洞记录。
11. 用户在控制台确认、分派、修复、复测和关闭。
12. 平台导出报告并沉淀误报经验。

## 5. 核心数据模型

### User

- id
- username
- password_hash
- role
- created_at

### Project

- id
- name
- business_owner
- security_owner
- repository_url
- default_branch
- created_at

### ScanTask

- id
- project_id
- scan_type
- status
- commit_hash
- started_at
- finished_at
- log_path

### Component

- id
- project_id
- scan_task_id
- ecosystem
- name
- version
- dependency_type
- license

### Finding

- id
- project_id
- scan_task_id
- source
- rule_id
- title
- severity
- file_path
- line_start
- line_end
- evidence
- status

### Vulnerability

- id
- finding_id
- project_id
- severity
- category
- title
- description
- impact
- remediation
- status
- assignee
- ai_review_id

### AiReview

- id
- finding_id
- model
- summary
- false_positive_likelihood
- reasoning
- remediation
- created_at

### Report

- id
- project_id
- scan_task_id
- format
- file_path
- created_at

## 6. MVP 目录结构建议

```text
apps/
  web/
  api/
packages/
  scanner/
  rules/
  ai-gateway/
docs/
infra/
  docker-compose.yml
```

## 7. 二期扩展方向

- 将扫描 Worker 独立为可横向扩展服务。
- 引入 MinIO 保存证据、报告和代码快照。
- 引入 OpenSearch 支持全文检索。
- 引入 Neo4j 或 PostgreSQL graph 扩展承载代码/依赖/业务图谱。
- 引入沙箱执行环境支持 DAST 和 Agent 行为观测。
- 引入 CI/CD 插件和安全门禁。

