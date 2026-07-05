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
        subtitle="指令文件 + 工具协议 + 插件扩展 + 信任评分",
        category=ModuleCategory.detection,
        description="面向 Agent、MCP、工具协议和插件扩展执行安全检查，识别提示注入、工具滥用、敏感资源访问等 AI 时代新攻击面。",
        capabilities=[
            ModuleCapability(title="三类目标扫描", description="扫描指令文件、工具协议和插件扩展。"),
            ModuleCapability(title="规则检测与 AI 审计", description="结合规则、AI 审计、覆盖矩阵和信任评分。"),
            ModuleCapability(title="私有源接入", description="接入私有 MCP、插件源和配置解析。"),
            ModuleCapability(title="复测报告", description="生成公开只读报告并支持复测。"),
        ],
        default_config={
            "scan_prompts": True,
            "scan_mcp": True,
            "scan_plugins": True,
            "trust_score": True,
            "sensitive_resource_policy": "strict",
        },
    ),
    ModuleKey.dast: SecurityModule(
        key=ModuleKey.dast,
        code="DAST",
        name="漏洞动态验证",
        subtitle="Web 业务验证 + 静态发现联动验证 + 三色裁决",
        category=ModuleCategory.validation,
        description="将静态发现、供应链风险和运行时目标联动验证，输出可利用、不确定、不可利用三态裁决和完整验证证据。",
        capabilities=[
            ModuleCapability(title="Web 业务验证", description="对目标 Web 应用执行业务化安全验证。"),
            ModuleCapability(title="静态发现联动验证", description="将 SAST/SCA/Agent 发现转为验证策略。"),
            ModuleCapability(title="三色裁决", description="输出可利用、不确定、不可利用的验证结论。"),
            ModuleCapability(title="证据归档", description="保留执行日志、请求响应、截图和验证过程。"),
        ],
        dependencies=[ModuleKey.sast],
        default_config={
            "active_probe": False,
            "verification_strength": "safe",
            "auth_required": False,
            "linked_static_findings": True,
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

