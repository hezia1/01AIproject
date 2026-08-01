from app.services.sca_tool_scanner import offline_assets_dir


def test_default_offline_assets_directory_is_under_repository_root() -> None:
    path = offline_assets_dir()

    assert path.name == "sca-offline"
    assert path.parent.name == "artifacts"
    assert path.parent.parent.name == "AI网安项目"
