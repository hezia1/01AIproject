import json

from app import main
from app.services.platform_health import check, platform_health


def test_health_is_ok_only_when_all_dependencies_are_ready() -> None:
    payload = platform_health(
        database_probe=lambda: check("database", "PostgreSQL", "ok", True, "ready"),
        redis_probe=lambda: check("redis", "Redis", "ok", False, "ready"),
        runtime_probe=lambda: [
            check("docker", "Docker Engine", "ok", False, "ready"),
            check("sca_tools", "SCA Docker 工具", "ok", False, "ready"),
            check("semgrep", "Semgrep", "ok", False, "ready"),
        ],
    )

    assert payload["status"] == "ok"
    assert [item["key"] for item in payload["checks"]] == [
        "api", "database", "redis", "docker", "sca_tools", "semgrep"
    ]


def test_optional_dependency_failure_is_degraded_not_success() -> None:
    payload = platform_health(
        database_probe=lambda: check("database", "PostgreSQL", "ok", True, "ready"),
        redis_probe=lambda: check("redis", "Redis", "unavailable", False, "down"),
        runtime_probe=lambda: [check("docker", "Docker Engine", "unavailable", False, "down")],
    )

    assert payload["status"] == "degraded"
    assert next(item for item in payload["checks"] if item["key"] == "redis")["status"] == "unavailable"


def test_required_database_failure_makes_platform_unavailable() -> None:
    payload = platform_health(
        database_probe=lambda: check("database", "PostgreSQL", "unavailable", True, "down"),
        redis_probe=lambda: check("redis", "Redis", "ok", False, "ready"),
        runtime_probe=lambda: [],
    )

    assert payload["status"] == "unavailable"
    database = next(item for item in payload["checks"] if item["key"] == "database")
    assert database["required"] is True
    assert database["status"] == "unavailable"


def test_health_limitations_do_not_claim_scanner_execution() -> None:
    payload = platform_health(
        database_probe=lambda: check("database", "PostgreSQL", "ok", True, "ready"),
        redis_probe=lambda: check("redis", "Redis", "ok", False, "ready"),
        runtime_probe=lambda: [],
    )

    assert "不代表目标扫描成功" in "".join(payload["limitations"])


def test_health_can_skip_optional_runtime_tools() -> None:
    payload = platform_health(
        database_probe=lambda: check("database", "PostgreSQL", "ok", True, "ready"),
        redis_probe=lambda: check("redis", "Redis", "ok", False, "ready"),
        runtime_probe=lambda: (_ for _ in ()).throw(AssertionError("runtime probe must be skipped")),
        include_optional_tools=False,
    )

    assert payload["status"] == "ok"
    assert [item["key"] for item in payload["checks"]] == ["api", "database", "redis"]


def test_health_route_returns_503_when_required_dependency_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(main, "platform_health", lambda **_: {"status": "unavailable", "checks": []})

    response = main.health()

    assert response.status_code == 503
    assert json.loads(response.body)["status"] == "unavailable"


def test_health_route_keeps_degraded_optional_dependencies_readable(monkeypatch) -> None:
    monkeypatch.setattr(main, "platform_health", lambda **_: {"status": "degraded", "checks": []})

    response = main.health()

    assert response.status_code == 200
    assert json.loads(response.body)["status"] == "degraded"
