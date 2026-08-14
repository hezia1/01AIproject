from types import SimpleNamespace

import pytest

from app.services.agent_ai_review import build_agent_ai_input, run_agent_deepseek_review
from app.services.deepseek_client import DeepSeekCallResult, DeepSeekUnavailable


class FakeAgentReviewClient:
    def __init__(self, model: str = "deepseek-v4-flash") -> None:
        self.settings = SimpleNamespace(model=model)
        self.calls: list[dict[str, object]] = []

    def complete_json(self, **kwargs: object) -> DeepSeekCallResult:
        self.calls.append(kwargs)
        return DeepSeekCallResult(
            content={
                "summary": "Prioritize the declared shell capability for human review.",
                "reviews": [{
                    "audit_item_id": "audit-shell",
                    "review_priority": "high",
                    "rationale": "The declared capability needs a documented approval boundary.",
                    "review_questions": ["Is shell access required?"],
                    "recommended_actions": ["Restrict the command scope."],
                    "limitations": ["Static evidence only."],
                }, {
                    "audit_item_id": "unknown-id",
                    "review_priority": "critical",
                    "rationale": "Must be discarded.",
                }],
            },
            model="deepseek-v4-flash",
            prompt_tokens=120,
            completion_tokens=90,
            cache_hit_tokens=0,
            latency_ms=18,
            finish_reason="stop",
        )


def audit() -> dict[str, object]:
    return {
        "schema": "ai-security-platform.agent-offline-audit/v1",
        "items": [{
            "id": "audit-shell",
            "kind": "finding",
            "priority": "high",
            "title": "Shell access with token=super-secret-value",
            "rationale": "Review the declared shell capability.",
            "evidence_refs": ["rule:AGENT.TOOL.SHELL_EXEC", "asset:agent.json"],
        }],
    }


def test_agent_deepseek_review_uses_only_bounded_redacted_candidates_and_keeps_advisory_output() -> None:
    client = FakeAgentReviewClient()

    result = run_agent_deepseek_review(audit(), {"has_comparison": True, "summary": {"new_count": 1}}, client)

    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["role"] == "agent_security_review"
    assert call["max_retries"] == 0
    assert call["max_tokens"] == 1200
    assert call["thinking_enabled"] is False
    assert "super-secret-value" not in str(call["user_prompt"])
    assert result["external_model_invoked"] is True
    assert result["input_summary"]["source_code_included"] is False
    assert result["input_summary"]["credential_values_included"] is False
    assert result["usage"]["call_count"] == 1
    assert result["reviews"] == [{
        "audit_item_id": "audit-shell",
        "review_status": "needs_manual_review",
        "review_priority": "high",
        "rationale": "The declared capability needs a documented approval boundary.",
        "review_questions": ["Is shell access required?"],
        "recommended_actions": ["Restrict the command scope."],
        "limitations": ["Static evidence only."],
    }]
    assert "does not change findings" in " ".join(result["limitations"])


def test_agent_deepseek_review_rejects_non_flash_model_before_a_request() -> None:
    client = FakeAgentReviewClient("deepseek-v4-pro")

    with pytest.raises(DeepSeekUnavailable, match="deepseek-v4-flash"):
        run_agent_deepseek_review(audit(), client=client)

    assert client.calls == []


def test_agent_ai_input_never_contains_source_or_prompt_contents() -> None:
    payload, summary = build_agent_ai_input(audit())

    assert "candidate_items" in payload
    assert summary["source_code_included"] is False
    assert summary["prompt_content_included"] is False
    assert summary["tool_parameters_included"] is False
