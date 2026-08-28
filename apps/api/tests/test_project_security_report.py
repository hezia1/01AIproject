from app.routers.aspm import project_report_capability_boundaries


def test_project_report_capability_boundaries_cover_every_delivered_module() -> None:
    boundaries = project_report_capability_boundaries()

    assert {"SCA", "SAST", "AGENT", "DAST", "SANDBOX", "ASPM / 证据链"} <= set(boundaries)
    assert all(items for items in boundaries.values())
    assert any("证据条件" in item for item in boundaries["DAST"])
    assert any("一次性 Docker" in item for item in boundaries["AGENT"])
    assert any("不提供完整" in item for item in boundaries["SANDBOX"])
