from pathlib import Path
from uuid import uuid4

from app.db_models import ComponentRecord, ProjectRecord
from app.services.sca_python_environment import (
    build_python_environment_edges_from_inspection,
    parse_pip_inspect_payload,
)


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
