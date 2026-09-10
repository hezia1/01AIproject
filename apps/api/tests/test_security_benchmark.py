import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "security_benchmark.py"
SPEC = importlib.util.spec_from_file_location("security_benchmark_script", SCRIPT)
assert SPEC and SPEC.loader
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


def test_versioned_security_benchmark_meets_declared_thresholds() -> None:
    result = benchmark.run_benchmark()

    assert result["status"] == "passed"
    assert result["threshold_failures"] == []
    assert result["sast"]["precision"] == 1.0
    assert result["sast"]["recall"] == 1.0
    assert result["sast"]["false_positive_rate"] == 0.0
    assert result["agent"]["precision"] == 1.0
    assert result["agent"]["recall"] == 1.0
    assert result["agent"]["false_positive_rate"] == 0.0
    assert result["sca"]["component_recall"] == 1.0
    assert result["sca"]["vulnerability_recall"] == 1.0
    assert result["dast"]["verdict_accuracy"] == 1.0
    assert result["dast"]["replay_consistency"] == 1.0


def test_external_benchmark_rejects_source_identity_mismatch(tmp_path) -> None:
    config = benchmark.load_json(benchmark.BENCHMARK_ROOT / "external-testproject.json")

    try:
        benchmark.verify_external_source(tmp_path, config)
    except Exception as exc:
        assert "git" in str(exc).lower() or "external" in str(exc).lower()
    else:
        raise AssertionError("unversioned source must not be accepted")


def test_dormant_benchmark_fixtures_do_not_pollute_normal_repository_scans() -> None:
    assert benchmark.scan_source_tree(str(benchmark.BENCHMARK_ROOT)).findings == []
    assert benchmark.scan_agent_tree(str(benchmark.BENCHMARK_ROOT)).findings == []
    assert benchmark.parse_dependency_tree(str(benchmark.BENCHMARK_ROOT)).components == []
