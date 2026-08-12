from __future__ import annotations

import json
import os
import socket
from pathlib import Path


def write_is_blocked(path: Path) -> bool:
    try:
        path.write_text("probe", encoding="utf-8")
    except OSError:
        return True
    try:
        path.unlink()
    except OSError:
        pass
    return False


def network_is_blocked() -> bool:
    try:
        with socket.create_connection(("192.0.2.1", 9), timeout=0.25):
            return False
    except OSError:
        return True


def proc_status() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key] = value.strip()
    return values


def cgroup_value(name: str) -> str | None:
    path = Path("/sys/fs/cgroup") / name
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def main() -> None:
    request = json.loads((Path(__file__).parent / "request.json").read_text(encoding="utf-8"))
    status = proc_status()
    tmp_path = Path("/tmp/agent-fixture-probe.txt")
    tmp_path.write_text("temporary probe", encoding="utf-8")
    tmp_write_succeeded = tmp_path.read_text(encoding="utf-8") == "temporary probe"
    tmp_path.unlink()
    evidence = {
        "schema": "ai-security-platform.agent-fixture-probe/v1",
        "fixture": "harmless-offline-fixture",
        "received": request.get("message"),
        "checks": {
            "root_filesystem_write_blocked": write_is_blocked(Path("/agent-root-write-test")),
            "workspace_write_blocked": write_is_blocked(Path("/workspace/workspace-write-test")),
            "network_egress_blocked": network_is_blocked(),
            "host_canary_absent": "AGENT_HOST_CANARY" not in os.environ,
            "effective_capabilities_zero": int(status.get("CapEff", "1"), 16) == 0,
            "no_new_privileges_enabled": status.get("NoNewPrivs") == "1",
            "tmpfs_write_succeeded": tmp_write_succeeded,
        },
        "cgroup": {
            "cpu_max": cgroup_value("cpu.max"),
            "memory_max": cgroup_value("memory.max"),
            "pids_max": cgroup_value("pids.max"),
        },
        "secret_values_returned": False,
    }
    print(json.dumps(evidence, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
