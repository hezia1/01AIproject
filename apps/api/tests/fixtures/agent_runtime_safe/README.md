# Harmless AGENT runtime fixture

This fixture is deterministic and offline. `runner.py` only echoes bundled metadata. `policy_probe.py` is reserved for the controlled fixture acceptance: it verifies that network access and writes outside `/tmp` are blocked, checks Linux capability/cgroup state, tests only for the absence of a named host canary, writes one JSON object to standard output, and exits. It does not contact a reachable target, invoke tools, install packages, or retain file changes.
