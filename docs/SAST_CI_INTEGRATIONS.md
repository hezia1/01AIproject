# SAST CI integrations

The repository ships deterministic templates for GitHub Actions, GitLab CI,
Jenkins and Azure DevOps. Every template invokes `scripts/sast_ci.py`, retains
JSON/SARIF evidence and returns a non-zero exit code when the configured local
quality threshold is met.

No template downloads Semgrep images or remote rule packs. If an organization
enables the optional Semgrep engine, it must preload the pinned image and rules
under `D:\project\PYproject\AI网安项目\artifacts\sast-offline\` on its own runner.

For a pull request, pass the merge-base or target commit with `--baseline` and
`--changed-files-only`. Keep a full Git history for history-secret scanning.
Platform credentials, webhook secrets, branch protection and PR approval
policies are intentionally configured in the corresponding CI platform, not
stored in this repository.

## Project policy and worker

The project SAST profile exposes an auditable quality gate: severity threshold,
branch glob, exclusions, maximum blocking finding count and an optional
new-findings-only comparison. CI templates use the local CLI threshold; export
the project CI configuration from the SAST governance page when a project needs
its exact profile represented in a platform pipeline.

Queue scans with `POST /api/sast/jobs`, then run a worker in the same deployed
environment as the API and database:

```powershell
cd D:\project\PYproject\AI网安项目
.\.venv\Scripts\python.exe scripts\sast_worker.py --poll-seconds 3
```

`--once` processes at most one queued job for maintenance and tests. The worker
does not download engines, images or rules. Supervise the long-running process
with the deployment platform's service manager, and keep cancellation as a
cooperative operation before execution begins.
