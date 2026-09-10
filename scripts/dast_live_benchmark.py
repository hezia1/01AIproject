"""Run paired live DAST probes against disposable localhost Docker fixtures."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.request import urlopen
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
API_ROOT = ROOT / "apps" / "api"
TARGET = ROOT / "benchmarks" / "security" / "v1" / "fixtures" / "dast" / "target.fixture"
IMAGE = "python:3.12-slim"
sys.path.insert(0, str(API_ROOT))

from app.models import DastSandboxResult  # noqa: E402
from app.routers.dast import _adjudicate_sandbox_result  # noqa: E402
from app.services.sandbox_http_executor import probe  # noqa: E402


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, capture_output=True, text=True, timeout=120)


def free_local_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_ready(url: str) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with urlopen(f"{url}/health", timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"DAST fixture did not become ready: {url}")


def coverage_evidence(evidence: list[dict[str, object]], request_id: str) -> dict[str, object]:
    probe_count = sum(int(item.get("probe_count") or 0) for item in evidence)
    expected = sum(int(item.get("expected_probe_count") or 0) for item in evidence)
    negative = bool(evidence) and all(bool(item.get("negative_conclusion_supported")) for item in evidence)
    return {
        "type": "coverage", "request_id": request_id, "complete": probe_count >= expected > 0,
        "probe_count": probe_count, "expected_probe_count": expected,
        "negative_conclusion_supported": negative,
    }


def execute_case(target: str, mode: str, probe_name: str, repeat: int) -> dict[str, object]:
    expected = "exploitable" if mode == "vulnerable" else "not_exploitable"
    verdicts: list[str] = []
    complete_runs = 0
    for index in range(repeat):
        request_id = f"{mode}-{probe_name}-{index + 1}"
        step = {
            "probe": probe_name, "url": f"{target}/calculate" if probe_name == "code_injection" else f"{target}/headers",
            "method": "POST" if probe_name == "code_injection" else "GET",
            "parameter": "expression", "location": "json", "request_id": request_id,
        }
        evidence, confirmed, _count, negative = probe(step, target, ["/calculate", "/headers"], [])
        signal = "exploitable" if confirmed else "not_exploitable" if negative else "uncertain"
        all_evidence = [*evidence, coverage_evidence(evidence, request_id)]
        payload = DastSandboxResult(
            task_id=uuid4(), strategy_id=uuid4(), callback_token="live-benchmark-callback-00000001",
            execution_id=request_id, status="completed", evidence=all_evidence, verdict_signal=signal,
        )
        verdicts.append(_adjudicate_sandbox_result(payload)[0])
        complete_runs += int(bool(all_evidence[-1]["complete"]))
    return {
        "id": f"{mode}-{probe_name}", "expected_verdict": expected, "observed_verdicts": verdicts,
        "correct": all(item == expected for item in verdicts), "consistent": len(set(verdicts)) == 1,
        "evidence_complete_runs": complete_runs,
    }


def benchmark(repeat: int = 3) -> dict[str, object]:
    image_id = run(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"]).stdout.strip()
    source_hash = sha256(TARGET.read_bytes()).hexdigest()
    containers: list[str] = []
    targets: dict[str, str] = {}
    try:
        for mode in ("vulnerable", "safe"):
            name = f"ai-security-dast-benchmark-{mode}-{uuid4().hex[:10]}"
            port = free_local_port()
            run([
                "docker", "run", "--rm", "-d", "--name", name,
                "--network", "bridge", "--read-only", "--cap-drop", "ALL",
                "--memory", "128m", "--cpus", "0.5", "--pids-limit", "64",
                "-p", f"127.0.0.1:{port}:8080", "-e", f"DAST_FIXTURE_MODE={mode}",
                "-v", f"{TARGET}:/fixture/target.py:ro", IMAGE, "python", "/fixture/target.py",
            ])
            containers.append(name)
            targets[mode] = f"http://127.0.0.1:{port}"
            wait_ready(targets[mode])
        cases = [
            execute_case(targets[mode], mode, probe_name, repeat)
            for mode in ("vulnerable", "safe")
            for probe_name in ("code_injection", "security_misconfiguration")
        ]
    finally:
        for name in containers:
            run(["docker", "rm", "-f", name], check=False)
    run_count = len(cases) * repeat
    return {
        "schema_version": "1.0", "benchmark_id": "dast-live-paired-v1",
        "target_source_sha256": source_hash, "base_image": IMAGE, "base_image_id": image_id,
        "localhost_only": True, "repeat_count": repeat, "cases": cases,
        "verdict_accuracy": sum(int(item["correct"]) for item in cases) / len(cases),
        "replay_consistency": sum(int(item["consistent"]) for item in cases) / len(cases),
        "evidence_completeness": sum(int(item["evidence_complete_runs"]) for item in cases) / run_count,
        "limitations": "Paired synthetic targets validate the real fixed-probe and adjudication path, not testproject exploit coverage.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Paired localhost Docker DAST replay benchmark")
    parser.add_argument("--repeat", type=int, default=3, choices=range(1, 6))
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    try:
        result = benchmark(args.repeat)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "error", "detail": f"{type(exc).__name__}: {exc}"}), file=sys.stderr)
        return 3
    result["status"] = "passed" if all(result[key] == 1.0 for key in ("verdict_accuracy", "replay_consistency", "evidence_completeness")) else "failed"
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_bytes(payload.encode("utf-8"))
        print(json.dumps({"status": result["status"], "report": str(args.json), "sha256": sha256(args.json.read_bytes()).hexdigest()}, ensure_ascii=False))
    else:
        print(payload, end="")
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
