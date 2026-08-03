from app.services.sast_governance import add_semgrep_rule, validate_semgrep_rule_payload
from app.services.sast_scanner import scan_source_tree


def test_python_ast_taint_detects_request_controlled_command(tmp_path):
    source = tmp_path / "handler.py"
    source.write_text('command = request.args.get("command")\nsubprocess.run(command)\n', encoding="utf-8")

    findings = scan_source_tree(str(tmp_path)).findings

    assert any(item.rule_id == "SAST.TAINT.PYTHON.COMMAND" for item in findings)


def test_semgrep_yaml_rule_pack_is_versioned_and_validated():
    payload = {
        "name": "Project dangerous evaluation",
        "content": "rules:\n  - id: project.example.dangerous-eval\n    languages: [python]\n    severity: WARNING\n    message: Review dynamic evaluation.\n    pattern: eval(...)\n",
    }

    validation = validate_semgrep_rule_payload(payload)
    profile = add_semgrep_rule({}, payload)

    assert validation["yaml"]["rule_ids"] == ["project.example.dangerous-eval"]
    assert profile["semgrep_rules"][0]["version"] == 1


def test_python_interprocedural_taint_follows_local_import(tmp_path):
    (tmp_path / "database.py").write_text(
        "def execute_query(value):\n    cursor.execute(value)\n",
        encoding="utf-8",
    )
    (tmp_path / "handler.py").write_text(
        "from database import execute_query\nvalue = request.args.get('query')\nexecute_query(value)\n",
        encoding="utf-8",
    )

    findings = scan_source_tree(str(tmp_path)).findings

    assert any(item.rule_id == "SAST.TAINT.INTERPROC.PYTHON.SQL" and item.file_path == "handler.py" for item in findings)
