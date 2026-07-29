from pathlib import Path
from uuid import uuid4

from app.db_models import ComponentRecord, ProjectRecord
from app.services.sca_python_environment import (
    build_python_environment_edges_from_inspection,
    parse_pip_inspect_payload,
)
from app.services.sca_dependency_graph import build_dependency_graph, dependency_snapshot_edges


def test_pip_inspect_builds_actual_python_dependency_edges() -> None:
    root = Path("C:/demo-project")
    inspection = parse_pip_inspect_payload(
        {
            "installed": [
                {
                    "metadata": {
                        "name": "requests",
                        "version": "2.32.0",
                        "requires_dist": ["urllib3>=1.21.1", "PySocks; extra == 'socks'"],
                    },
                    "requested": True,
                },
                {
                    "metadata": {"name": "urllib3", "version": "2.2.1", "requires_dist": []},
                    "requested": False,
                },
            ]
        },
        root,
        root / ".venv" / "Scripts" / "python.exe",
    )
    project = ProjectRecord(id=str(uuid4()), name="Demo", source_path=str(root), default_branch="main")
    requests = component(project, "requests", "2.32.0")
    urllib3 = component(project, "urllib3", "2.2.1")

    edges = build_python_environment_edges_from_inspection(project, [requests, urllib3], inspection)

    assert inspection.available
    assert inspection.components[0].source_file == ".venv/pip inspect"
    assert {edge["quality"] for edge in edges} == {"python_environment"}
    assert any(edge["source"] == f"project:{project.id}" and edge["target"] == "PyPI:requests@2.32.0" for edge in edges)
    assert any(edge["source"] == "PyPI:requests@2.32.0" and edge["target"] == "PyPI:urllib3@2.2.1" for edge in edges)
    assert all(not edge["target"].endswith("pysocks") for edge in edges)


def component(project: ProjectRecord, name: str, version: str) -> ComponentRecord:
    return ComponentRecord(
        id=str(uuid4()),
        project_id=str(project.id),
        ecosystem="PyPI",
        name=name,
        version=version,
        dependency_type="runtime" if name == "requests" else "transitive",
        source_file="requirements.txt",
        risk_status="not_checked",
        vulnerability_ids=[],
    )


def test_persisted_dependency_snapshot_is_used_without_rechecking_the_environment() -> None:
    project = ProjectRecord(id=str(uuid4()), name="Demo", source_path="C:/missing", default_branch="main")
    requests = component(project, "requests", "2.32.0")
    urllib3 = component(project, "urllib3", "2.2.1")
    snapshot = {
        "edges": [
            {"source": f"project:{project.id}", "target": "PyPI:requests@2.32.0", "quality": "python_environment"},
            {"source": "PyPI:requests@2.32.0", "target": "PyPI:urllib3@2.2.1", "quality": "python_environment"},
        ]
    }

    graph = build_dependency_graph(project, [requests, urllib3], dependency_edges=dependency_snapshot_edges(snapshot))

    assert graph["summary"]["python_environment_edge_count"] == 2
    assert graph["summary"]["edge_count"] == 2
