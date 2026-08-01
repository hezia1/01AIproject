from pathlib import Path
from uuid import uuid4

from app.db_models import ComponentRecord, ProjectRecord
from app.services.sca_artifacts import collect_artifact_hashes
from app.services.sca_dependency_graph import dependency_snapshot_edges
from app.services.sca_parser import ParsedComponent


def test_collects_reproducible_manifest_and_installed_package_hashes(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
    record = tmp_path / ".venv" / "Lib" / "site-packages" / "requests-2.32.0.dist-info" / "RECORD"
    record.parent.mkdir(parents=True)
    record.write_text("requests/__init__.py,,\n", encoding="utf-8")
    hashes = collect_artifact_hashes(str(tmp_path), [ParsedComponent("pypi", "requests", "2.32.0", "runtime", "requirements.txt", "pip")])

    assert hashes["status"] == "available"
    assert hashes["files"][0]["path"] == "requirements.txt"
    assert hashes["packages"][0]["name"] == "requests"
    assert len(hashes["files"][0]["sha256"]) == 64


def test_accepts_new_native_tree_snapshot_qualities() -> None:
    project = ProjectRecord(id=str(uuid4()), name="demo", default_branch="main")
    component = ComponentRecord(id=str(uuid4()), project_id=str(project.id), ecosystem="maven", name="a:b", version="1.0.0", dependency_type="runtime", source_file="pom.xml", risk_status="clean", vulnerability_ids=[])
    edges = dependency_snapshot_edges({"edges": [{"source": f"project:{project.id}", "target": f"Maven:{component.name}@1.0.0", "quality": "maven_native_tree"}, {"source": f"Maven:{component.name}@1.0.0", "target": "Go:example.com/x@v1.0.0", "quality": "go_native_tree"}]})

    assert edges is not None
    assert {edge["quality"] for edge in edges} == {"maven_native_tree", "go_native_tree"}


def test_collects_local_node_and_maven_package_evidence(tmp_path: Path) -> None:
    node_manifest = tmp_path / "node_modules" / "left-pad" / "package.json"
    node_manifest.parent.mkdir(parents=True)
    node_manifest.write_text('{"name":"left-pad","version":"1.3.0"}', encoding="utf-8")
    jar = tmp_path / ".m2" / "repository" / "org" / "example" / "demo" / "1.0.0" / "demo-1.0.0.jar"
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b"demo-jar")
    hashes = collect_artifact_hashes(
        str(tmp_path),
        [
            ParsedComponent("npm", "left-pad", "1.3.0", "runtime", "package.json", "npm"),
            ParsedComponent("maven", "org.example:demo", "1.0.0", "runtime", "pom.xml", "maven"),
        ],
    )

    assert {item["kind"] for item in hashes["packages"]} == {"npm_installed_manifest", "maven_local_jar"}
