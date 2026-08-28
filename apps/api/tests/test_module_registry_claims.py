from pathlib import Path

from app.models import ModuleKey
from app.module_registry import MODULE_REGISTRY


def _module_copy(module_key: ModuleKey) -> str:
    module = MODULE_REGISTRY[module_key]
    return " ".join(
        [
            module.subtitle,
            module.description,
            *(item.title for item in module.capabilities),
            *(item.description for item in module.capabilities),
        ]
    )


def test_sast_claims_limit_knowledge_to_current_project() -> None:
    copy = _module_copy(ModuleKey.sast)

    assert "项目历史" in copy
    assert "行业历史漏洞知识库" not in copy
    assert MODULE_REGISTRY[ModuleKey.sast].default_config["ai_review"] is False
    assert MODULE_REGISTRY[ModuleKey.sast].default_config["knowledge_scope"] == "project_history_only"


def test_sandbox_claims_describe_fixed_probes_not_full_observability() -> None:
    copy = _module_copy(ModuleKey.sandbox)

    assert "固定" in copy
    assert "不提供完整系统行为监控" in copy
    assert "AI 驱动动态验证" not in copy


def test_aspm_claims_remain_project_scoped() -> None:
    copy = _module_copy(ModuleKey.aspm)

    assert "单项目" in copy
    assert "跨项目关联" not in copy
    assert "授权配额" not in copy
    assert MODULE_REGISTRY[ModuleKey.aspm].default_config["governance_scope"] == "project"


def test_frontend_fallback_claims_match_the_calibrated_scope() -> None:
    frontend_path = Path(__file__).resolve().parents[3] / "apps" / "web" / "src" / "main.tsx"
    source = frontend_path.read_text(encoding="utf-8")
    fallback_copy = source.split("const fallbackModules", 1)[1].split("const moduleIcons", 1)[0]

    assert "项目规则治理" in fallback_copy
    assert "固定探针" in fallback_copy
    assert "单项目汇总" in fallback_copy
    assert "行业历史漏洞知识库" not in fallback_copy
    assert "AI 驱动动态验证" not in fallback_copy
    assert "提供跨项目关联" not in fallback_copy
