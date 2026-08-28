from app.models import ModuleCapability, ModuleCategory, ModuleKey, SecurityModule


MODULE_REGISTRY: dict[ModuleKey, SecurityModule] = {
    ModuleKey.sast: SecurityModule(
        key=ModuleKey.sast,
        code="SAST",
        name="智能静态审计",
        subtitle="项目规则治理 + 有限语义分析 + 可选七角色 AI 复核",
        category=ModuleCategory.detection,
        description="面向代码仓库执行本地与项目规则、有限数据流、Git 基线和历史密钥检查；配置模型密钥后可执行七角色 AI 辅助复核。",
        capabilities=[
            ModuleCapability(title="项目规则包", description="管理本地规则、项目规则与 Semgrep YAML 配置。"),
            ModuleCapability(title="有限语义与 Git 证据", description="执行有限数据流、扫描基线和历史密钥检查。"),
            ModuleCapability(title="可选七角色复核", description="模型可用时生成辅助解释、证据复核和修复草案。"),
            ModuleCapability(title="项目历史关联", description="关联当前项目历史 Finding；尚不提供跨项目行业知识库。"),
        ],
        default_config={
            "ai_review": False,
            "scan_depth": "standard",
            "knowledge_scope": "project_history_only",
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
        subtitle="Docker 隔离目标 + 固定探针 + 受控证据归档",
        category=ModuleCategory.evidence,
        description="在受限 Docker 网络中启动已审批目标，由固定 HTTP、浏览器、上传、时延或 Agent 合同探针采集证据；不提供完整系统行为监控。",
        capabilities=[
            ModuleCapability(title="受限 Docker 目标", description="使用内部网络、只读根文件系统、能力删除和资源上限。"),
            ModuleCapability(title="固定证据探针", description="按合同执行 HTTP、浏览器、上传、时延和 Agent 合成探针。"),
            ModuleCapability(title="目标生命周期", description="管理启动、健康检查、过期停止、事件和受管容器清理。"),
            ModuleCapability(title="结构化证据", description="归档 HAR、截图、控制台、时延和目标主动上报的合成工具事件。"),
        ],
        dependencies=[ModuleKey.agent],
        default_config={
            "network_policy": "restricted",
            "filesystem_policy": "readonly",
            "max_runtime_seconds": 300,
            "evidence_mode": "fixed_probes_and_declared_runtime_contract",
        },
    ),
    ModuleKey.aspm: SecurityModule(
        key=ModuleKey.aspm,
        code="ASPM",
        name="平台治理与交付",
        subtitle="单项目汇总 + 显式证据链 + 整改复测 + 项目报告",
        category=ModuleCategory.governance,
        description="聚合当前项目的组件、Finding、动态验证和沙箱证据，提供显式关系图、攻击链、整改复测和项目级安全报告。",
        capabilities=[
            ModuleCapability(title="项目风险汇总", description="按单项目汇总组件、Finding、验证、证据和模块状态。"),
            ModuleCapability(title="显式证据关系", description="只基于已保存关联生成证据图和攻击链。"),
            ModuleCapability(title="整改与复测", description="跟踪 Finding 状态并比较 SCA、SAST、AGENT 扫描批次。"),
            ModuleCapability(title="项目安全报告", description="导出项目级结果、证据、边界和复测快照。"),
        ],
        default_config={
            "governance_scope": "project",
            "evidence_graph": True,
            "retest_comparison": True,
            "report_type": "project_security_snapshot",
        },
    ),
}


def list_modules() -> list[SecurityModule]:
    return list(MODULE_REGISTRY.values())


def get_module(module_key: ModuleKey) -> SecurityModule | None:
    return MODULE_REGISTRY.get(module_key)
