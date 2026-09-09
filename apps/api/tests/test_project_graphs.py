from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.routers.project_graphs import snapshot_response
from app.services.project_graphs import build_code_graph


def test_code_graph_builds_files_symbols_routes_imports_and_calls(tmp_path):
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\nfrom helper import work\napp=FastAPI()\n@app.get('/items')\ndef items():\n    return work()\n",
        encoding="utf-8",
    )
    (tmp_path / "helper.py").write_text("def work():\n    return 1\n", encoding="utf-8")
    (tmp_path / "routes.js").write_text(
        "const express=require('express');\nconst router=express.Router();\nrouter.post('/login', controller.login);\n",
        encoding="utf-8",
    )

    result = build_code_graph(str(tmp_path))

    kinds = {item["kind"] for item in result["nodes"]}
    relations = {item["relation"] for item in result["edges"]}
    labels = {item["label"] for item in result["nodes"]}
    assert {"project", "file", "function", "route", "external_dependency"} <= kinds
    assert {"contains", "imports", "calls", "exposes", "handled_by"} <= relations
    assert {"GET /items", "POST /login"} <= labels
    assert result["summary"]["file_count"] == 3
    assert result["source_fingerprint"] == build_code_graph(str(tmp_path))["source_fingerprint"]


def test_code_graph_rejects_missing_source_directory(tmp_path):
    with pytest.raises(ValueError, match="不存在"):
        build_code_graph(str(tmp_path / "missing"))


def test_snapshot_query_filters_nodes_and_relations():
    record = SimpleNamespace(
        id=str(uuid4()), project_id=str(uuid4()), graph_type="code", version=1,
        source_fingerprint="a" * 64, generator_version="v1", status="completed",
        nodes=[
            {"id": "file:a", "kind": "file", "label": "a.py", "file_path": "a.py", "line": None, "attributes": {}},
            {"id": "route:a", "kind": "route", "label": "GET /a", "file_path": "a.py", "line": 2, "attributes": {}},
        ],
        edges=[{"id": "edge:a", "source": "file:a", "target": "route:a", "relation": "exposes", "confidence": 100, "basis": "test"}],
        summary={}, limitations=[], created_by="tester", created_at=__import__("datetime").datetime.now(),
    )

    filtered = snapshot_response(record, relation="exposes")

    assert len(filtered.nodes) == 2
    assert len(filtered.edges) == 1
    assert filtered.summary["returned_edge_count"] == 1
