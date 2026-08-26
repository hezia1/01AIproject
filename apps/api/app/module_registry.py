from app.models import ModuleCapability, ModuleCategory, ModuleKey, SecurityModule


MODULE_REGISTRY: dict[ModuleKey, SecurityModule] = {
    ModuleKey.sast: SecurityModule(
        key=ModuleKey.sast,
        code="SAST",
        name="智能静态审计",
        subtitle="定制化安全 Skill + 多 Sub-agent 编排 + 行业历史漏洞知识库",
        category=ModuleCategory.detection,
        description="面向代码仓库执行智能静态审计，将规则扫描、AI 审计、历史漏洞经验和多 Agent 复核组合为代码风险发现能力。",
        capabilities=[
            ModuleCapability(title="定制化安全 Skill", description="按行业、框架和业务场景生成审计策略。"),
            ModuleCapability(title="多 Sub-agent 编排", description="发现、复核、证据和修复建议分工协同。"),
            ModuleCapability(title="行业历史漏洞知识库", description="沉淀通用漏洞、业务漏洞和误报经验。"),
        ],
        default_config={
            "ai_review": True,
            "scan_depth": "standard",
            "knowledge_enhancement": True,
            "rule_sets": ["secrets", "injection", "command", "ssrf"],
        },
    ),
    ModuleKey.sca: SecurityModule(
        key=ModuleKey.sca,
        code="SCA",
        name="供应链风险分析",
        subtitle="SBOM + 组件漏洞匹配 + 许可证风险归一化 + 依赖影响分析",
        category=ModuleCategory.detection,
        description="解析多语言工程依赖，生成 SBOM，识别漏洞、许可证和直接/传递依赖风险，并给出修复优先级。",
        capabilities=[
            ModuleCapability(title="SBOM 生成", description="生成项目组件清单和依赖来源。"),
            ModuleCapability(title="组件漏洞匹配", description="匹配 CVE、受影响版本和修复版本。"),
            ModuleCapability(title="许可证风险归一化", description="识别许可证类型并归一化风险等级。"),
            ModuleCapability(title="依赖影响分析", description="分析直接/传递依赖、版本归一化和修复影响。"),
        ],
        default_config={
            "ecosystems": ["node", "python", "java", "go"],
            "transitive_dependencies": True,
            "license_policy": "standard",
            "generate_sbom": True,
        },
    ),
    ModuleKey.agent: SecurityModule(
        key=ModuleKey.agent,
        code="AGENT",
        name="Agent 供应链安全",
        subtitle="统一资产模型 + 能力权限矩阵 + 语义差异",
        category=ModuleCategory.detection,
        description="结构化解析 Agent 指令、MCP、工具和插件配置，形成资产、能力、资源范围、审批边界和批次变化。",
        capabilities=[
            ModuleCapability(title="多格式资产解析", description="解析 Markdown Frontmatter、JSON、YAML 与 TOML。"),
            ModuleCapability(title="能力权限矩阵", description="归一化工具、文件、网络、命令、凭据和审批边界。"),
            ModuleCapability(title="证据脱敏", description="保存发现前遮蔽凭据和值。"),
            ModuleCapability(title="语义差异", description="比较资产新增/移除、配置变化与权限扩大/收缩。"),
        ],
        default_config={
            "scan_prompts": True,
            "scan_mcp": True,
            "scan_plugins": True,
            "rule_version": "agent-rules-2026.08.10-v3",
            "sensitive_resource_policy": "strict",
        },
    ),
    ModuleKey.dast: SecurityModule(
        key=ModuleKey.dast,
        code="DAST",
        name="漏洞动态验证",
        subtitle="SAST / AGENT 联动 + 专用策略 + 证据驱动三色裁决",
        category=ModuleCategory.validation,
        description="把当前项目的 SAST/AGENT 漏洞转换为运行时验证策略，经审批后由 DAST 有界 HTTP 执行器或 SANDBOX 隔离执行器完成验证、证据归档和报告。",
        capabilities=[
            ModuleCapability(title="运行资产发现", description="同源抓取 URL、表单、JavaScript API 和 OpenAPI 参数并持久化。"),
            ModuleCapability(title="专用验证策略", description="SQL 注入、XSS、越权、SSRF、命令注入等类型使用独立证据规则。"),
            ModuleCapability(title="隔离执行合同", description="浏览器、OAST、时延和 Agent 运行验证通过一次性 SANDBOX 合同交接。"),
            ModuleCapability(title="证据驱动裁决", description="三色结论与未验证分开统计并生成专项报告。"),
        ],
        dependencies=[ModuleKey.sast],
        default_config={
            "active_probe": True,
            "verification_strength": "evidence_driven",
            "auth_required": "strategy_dependent",
            "linked_static_findings": True,
            "sandbox_handoff_schema": "ai-security-platform.dast-sandbox-handoff/v1",
        },
    ),
    ModuleKey.sandbox: SecurityModule(
        key=ModuleKey.sandbox,
        code="SANDBOX",
        name="沙箱动态证据链",
        subtitle="隔离环境 + 行为监控 + 调用账本 + AI 驱动动态验证",
        category=ModuleCategory.evidence,
        description="在隔离环境中运行目标程序、插件或 Agent，采集文件、网络、进程、工具调用和运行时行为证据。",
        capabilities=[
            ModuleCapability(title="隔离环境", description="以容器或受控运行时隔离目标执行。"),
            ModuleCapability(title="行为监控", description="监控文件访问、网络连接、进程启动和环境变量读取。"),
            ModuleCapability(title="调用账本", description="结构化采集 Agent 工具调用和运行时覆盖。"),
            ModuleCapability(title="策略化探测", description="适配多类 Agent 运行时并支持 AI 驱动验证。"),
        ],
        dependencies=[ModuleKey.agent],
        default_config={
            "network_policy": "restricted",
            "filesystem_policy": "readonly",
            "max_runtime_seconds": 300,
            "collect_tool_calls": True,
        },
    ),
    ModuleKey.aspm: SecurityModule(
        key=ModuleKey.aspm,
        code="ASPM",
        name="平台治理与交付",
        subtitle="项目组 + 攻击链 + 风险趋势 + 整改闭环 + 安全门禁",
        category=ModuleCategory.governance,
        description="聚合各模块结果，提供跨项目关联、攻击链、风险趋势、整改闭环、开放接口、流水线门禁和合规报告。",
        capabilities=[
            ModuleCapability(title="风险治理", description="管理项目组、跨项目关联、攻击链、风险趋势和整改闭环。"),
            ModuleCapability(title="开放接口", description="提供开放工具接口、批量任务和研发流水线安全门禁。"),
            ModuleCapability(title="权限与配额", description="管理模块权限、授权配额和审计日志。"),
            ModuleCapability(title="交付报告", description="输出诊断导出、合规报告和治理看板。"),
        ],
        default_config={
            "sla_policy": "standard",
            "audit_retention_days": 180,
            "ci_gate": False,
            "compliance_report": True,
        },
    ),
}


def list_modules() -> list[SecurityModule]:
    return list(MODULE_REGISTRY.values())


def get_module(module_key: ModuleKey) -> SecurityModule | None:
    return MODULE_REGISTRY.get(module_key)
