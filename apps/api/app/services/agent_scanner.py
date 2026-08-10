from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.models import Severity


@dataclass(frozen=True)
class AgentRule:
    rule_id: str
    title: str
    severity: Severity
    category: str
    description: str
    remediation: str
    trust_impact: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class AgentFinding:
    rule_id: str
    title: str
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    evidence: str
    category: str
    description: str
    remediation: str
    trust_impact: str


@dataclass(frozen=True)
class AgentScanOutput:
    findings: list[AgentFinding]
    scanned_files: list[str]
    assets: list[AgentAsset]
    skipped_files: list[dict[str, str]]
    rule_version: str


@dataclass(frozen=True)
class AgentAsset:
    path: str
    asset_type: str
    format: str
    parser: str
    status: str
    checks: list[str]
    finding_count: int = 0
    detail: str | None = None


AGENT_RULES = [
    AgentRule(
        rule_id="AGENT.SECRET.READ_ENV",
        title="Agent instruction can access environment secrets",
        severity=Severity.high,
        category="secret-exposure",
        description="The instruction or tool configuration asks the agent to read environment variables, tokens, keys, or credentials.",
        remediation="Restrict access to environment variables and secret files; use scoped secret injection instead.",
        trust_impact="Trust is reduced because the agent can access sensitive runtime resources.",
        pattern=re.compile(r"(?i)(read|access|get|exfiltrate).{0,50}(env|environment|secret|token|api[_-]?key|credential|\.env)"),
    ),
    AgentRule(
        rule_id="AGENT.TOOL.SHELL_EXEC",
        title="Agent exposes shell or command execution",
        severity=Severity.critical,
        category="tool-abuse",
        description="The agent exposes shell, terminal, or command execution capabilities that can amplify prompt injection impact.",
        remediation="Disable shell tools by default; when required, enforce command allowlists, argument constraints, approval, and audit logs.",
        trust_impact="Trust is significantly reduced because the agent has high-risk system execution capability.",
        pattern=re.compile(
            r"(?i)(execute|run|invoke|use|access|expose|allow).{0,35}"
            r"(shell|bash|powershell|cmd\.exe|terminal|subprocess|os\.system|child_process)"
            r"|(shell|bash|powershell|terminal).{0,20}(tool|access|execution)"
        ),
    ),
    AgentRule(
        rule_id="AGENT.FS.WRITE_ACCESS",
        title="Agent can write or delete files",
        severity=Severity.high,
        category="permission-overreach",
        description="The agent can write, overwrite, modify, or delete files, increasing tampering risk.",
        remediation="Limit filesystem access to read-only or scoped directories; require path allowlists and human approval for writes.",
        trust_impact="Trust is reduced because write access expands supply-chain tampering risk.",
        pattern=re.compile(r"(?i)(write_file|delete_file|remove_file|filesystem\.write|fs\.write|rm -rf|overwrite|modify files?|file_write)"),
    ),
    AgentRule(
        rule_id="AGENT.NET.EXTERNAL_REQUEST",
        title="Agent can perform external network requests",
        severity=Severity.medium,
        category="network-egress",
        description="The agent can reach external network destinations, which may enable data exfiltration or SSRF-like behavior.",
        remediation="Apply network egress allowlists, block internal and metadata endpoints, and log complete request ledgers.",
        trust_impact="Trust is moderately reduced because outbound network access is available.",
        pattern=re.compile(r"(?i)(http_request|web_request|curl\b|wget\b|external network|internet access|network egress|browser tool)"),
    ),
    AgentRule(
        rule_id="AGENT.MCP.WILDCARD_PERMISSION",
        title="MCP or plugin permissions are too broad",
        severity=Severity.high,
        category="permission-overreach",
        description="The MCP/plugin configuration uses wildcard permissions or all-tool access.",
        remediation="Remove wildcard permissions and grant only task-specific, scoped capabilities.",
        trust_impact="Trust is reduced because broad permissions amplify prompt injection impact.",
        pattern=re.compile(r"(?i)(allow_all|all_tools|wildcard|\*:\*|permissions\s*[:=]\s*\[?\s*['\"]?\*|full_access|admin)"),
    ),
    AgentRule(
        rule_id="AGENT.PROMPT.INSTRUCTION_OVERRIDE",
        title="Instruction attempts to override safety policy",
        severity=Severity.high,
        category="prompt-injection",
        description="The instruction contains content that asks the agent to ignore safety, prior instructions, or guardrails.",
        remediation="Remove override instructions and treat external instruction files as untrusted input.",
        trust_impact="Trust is reduced because the instruction can weaken security boundaries.",
        pattern=re.compile(r"(?i)(ignore previous|ignore safety|bypass|override instructions|disable guardrails|jailbreak|ignore all prior)"),
    ),
    AgentRule(
        rule_id="AGENT.SECRET.INLINE_TOKEN",
        title="Agent configuration contains an inline token or API key",
        severity=Severity.high,
        category="secret-exposure",
        description="The agent, MCP, or plugin configuration appears to contain plaintext credentials.",
        remediation="Rotate exposed credentials and replace inline values with environment references or a secret manager.",
        trust_impact="Trust is reduced because usable credentials may be exposed through configuration, logs, or context.",
        pattern=re.compile(
            r"(?i)[\"']?(api[_-]?key|apiKey|secret|token|access[_-]?key|accessKey|password|credential)"
            r"[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9_./+\-]{12,}"
        ),
    ),
]

AGENT_RULE_VERSION = "agent-rules-2026.08.10-v2"
INSTRUCTION_FILE_NAMES = {
    "agents.md",
    "claude.md",
    "gemini.md",
    "copilot-instructions.md",
}
AGENT_CONFIG_NAMES = {
    "agent.json",
    "agent.yaml",
    "agent.yml",
    "agent.toml",
    "prompt.yaml",
    "prompt.yml",
}
MCP_CONFIG_NAMES = {
    "mcp.json",
    ".mcp.json",
    "mcp.config.json",
    "claude_desktop_config.json",
}
PLUGIN_CONFIG_NAMES = {"plugin.json"}
TOOL_CONFIG_NAMES = {"tools.json"}
AGENT_DIR_MARKERS = {".agents", ".agent", ".claude", ".codex", ".cursor", "agents", "skills", "prompts", "plugins", "mcp"}
IGNORED_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    "coverage",
    "__pycache__",
    ".pytest_cache",
    ".cache",
    "artifacts",
    "outputs",
}
MAX_FILE_BYTES = 512 * 1024


def scan_agent_tree(source_path: str) -> AgentScanOutput:
    root = Path(source_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("source_path must be an existing directory")

    findings: list[AgentFinding] = []
    scanned_files: list[str] = []
    assets: list[AgentAsset] = []
    skipped_files: list[dict[str, str]] = []
    for file_path, asset_type, skip_reason in iter_agent_files(root):
        relative_path = file_path.relative_to(root).as_posix()
        if skip_reason:
            skipped_files.append({"path": relative_path, "reason": skip_reason})
            continue
        file_findings, asset = scan_agent_file(file_path, relative_path, asset_type)
        scanned_files.append(relative_path)
        findings.extend(file_findings)
        assets.append(
            AgentAsset(
                path=asset.path,
                asset_type=asset.asset_type,
                format=asset.format,
                parser=asset.parser,
                status=asset.status,
                checks=asset.checks,
                finding_count=len(file_findings),
                detail=asset.detail,
            )
        )

    return AgentScanOutput(
        findings=dedupe_findings(findings),
        scanned_files=scanned_files,
        assets=assets,
        skipped_files=skipped_files,
        rule_version=AGENT_RULE_VERSION,
    )


def iter_agent_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        asset_type = classify_agent_asset(path, root)
        if asset_type is None:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                yield path, asset_type, "file exceeds 512 KiB limit"
                continue
        except OSError:
            yield path, asset_type, "file metadata is not readable"
            continue
        yield path, asset_type, None


def classify_agent_asset(path: Path, root: Path) -> str | None:
    name = path.name.lower()
    relative_parts = {part.lower() for part in path.relative_to(root).parts[:-1]}
    in_agent_directory = bool(relative_parts & AGENT_DIR_MARKERS)
    if name in MCP_CONFIG_NAMES:
        return "mcp-config"
    if name in INSTRUCTION_FILE_NAMES:
        return "instruction"
    if name in PLUGIN_CONFIG_NAMES:
        return "plugin-manifest"
    if name in TOOL_CONFIG_NAMES:
        return "tool-schema"
    if name == "skill.md" and in_agent_directory:
        return "skill"
    if name.endswith(".prompt.md") or (in_agent_directory and "prompts" in relative_parts and path.suffix.lower() == ".md"):
        return "prompt"
    if name in AGENT_CONFIG_NAMES or (in_agent_directory and path.suffix.lower() in {".md", ".yaml", ".yml", ".json", ".toml"}):
        return "agent-config"
    return None


def scan_agent_file(file_path: Path, relative_path: str, asset_type: str | None = None) -> tuple[list[AgentFinding], AgentAsset]:
    resolved_type = asset_type or classify_agent_asset(file_path, file_path.parent) or "unknown"
    try:
        content = file_path.read_text(encoding="utf-8-sig", errors="ignore")
    except OSError:
        return [], AgentAsset(
            path=relative_path,
            asset_type=resolved_type,
            format=file_path.suffix.lower().lstrip(".") or "text",
            parser="none",
            status="failed",
            checks=[],
            detail="file content is not readable",
        )

    findings: list[AgentFinding] = []
    checks: list[str] = []
    parser = "instruction-text"
    status = "parsed"
    detail = None
    is_json = file_path.suffix.lower() == ".json" or file_path.name.lower() in MCP_CONFIG_NAMES | PLUGIN_CONFIG_NAMES | TOOL_CONFIG_NAMES
    parsed_ok = False
    if resolved_type in {"instruction", "skill", "prompt"} or (resolved_type == "agent-config" and not is_json):
        checks.append("instruction-text-rules")
        findings.extend(scan_text_rules(content, relative_path))
    if is_json:
        parser = "structured-json"
        checks.append("json-permission-and-secret-rules")
        json_findings, parsed_ok = scan_json_security(content, relative_path)
        findings.extend(json_findings)
        if not parsed_ok:
            status = "failed"
            detail = "invalid JSON; structured checks were not completed"
    if resolved_type == "mcp-config" and parsed_ok:
        checks.append("mcp-server-rules")
        findings.extend(scan_mcp_config(content, relative_path))
    return dedupe_findings(findings), AgentAsset(
        path=relative_path,
        asset_type=resolved_type,
        format=file_path.suffix.lower().lstrip(".") or "text",
        parser=parser,
        status=status,
        checks=checks,
        detail=detail,
    )


def scan_text_rules(content: str, relative_path: str) -> list[AgentFinding]:
    findings: list[AgentFinding] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        for rule in AGENT_RULES:
            match = rule.pattern.search(stripped)
            if match and not is_negated_statement(stripped, match.start()):
                findings.append(
                    AgentFinding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        file_path=relative_path,
                        line_start=line_number,
                        line_end=line_number,
                        evidence=redact_evidence(stripped),
                        category=rule.category,
                        description=rule.description,
                        remediation=rule.remediation,
                        trust_impact=rule.trust_impact,
                    )
                )
    return findings


def is_negated_statement(line: str, match_start: int) -> bool:
    context = line[max(0, match_start - 80):].lower()
    return bool(re.search(r"\b(do not|don't|never|must not|should not|cannot|can't|prohibit(?:ed)?|deny|disabled?)\b|(?:不要|不得|禁止|严禁|不可|不允许)", context))


def scan_json_security(content: str, relative_path: str) -> tuple[list[AgentFinding], bool]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return [
            build_finding(
                "AGENT.CONFIG.INVALID_JSON",
                "Agent configuration is invalid JSON",
                Severity.medium,
                "configuration-integrity",
                relative_path,
                1,
                "Invalid JSON; structured permission and secret checks were skipped",
                "The configuration cannot be parsed reliably, so its security boundary is unknown.",
                "Fix the JSON syntax and rerun the AGENT scan.",
                "Trust cannot be evaluated until the asset is parsed successfully.",
            )
        ], False

    findings: list[AgentFinding] = []
    for path, key, value in walk_json(data):
        key_text = str(key)
        path_text = ".".join(path)
        line_number = find_line_number(content, key_text)
        if looks_like_secret_key(key_text) and isinstance(value, (str, int, float)) and looks_like_secret_value(str(value)):
            findings.append(build_finding(
                "AGENT.SECRET.INLINE_TOKEN",
                "Agent configuration contains an inline secret",
                Severity.high,
                "secret-exposure",
                relative_path,
                line_number,
                f"path={path_text}; key={key_text}; value=***REDACTED***",
                "A credential-like field contains an inline value rather than an environment or secret-manager reference.",
                "Rotate the exposed value and replace it with scoped secret injection.",
                "Trust is reduced because a reusable credential may be exposed through configuration or logs.",
            ))
        if key_text.lower() in {"permissions", "allowedtools", "allowed_tools", "tools", "capabilities"}:
            values = flatten_scalar_values(value)
            lowered = {item.lower() for item in values}
            if lowered & {"*", "*:*", "all", "all_tools", "allow_all", "full_access", "admin"}:
                findings.append(build_finding(
                    "AGENT.MCP.WILDCARD_PERMISSION",
                    "Agent or plugin permissions are too broad",
                    Severity.high,
                    "permission-overreach",
                    relative_path,
                    line_number,
                    f"path={path_text}; permission=<wildcard-or-all>",
                    "The configuration grants wildcard or all-capability access.",
                    "Replace broad permissions with an explicit task-scoped allowlist.",
                    "Trust is reduced because broad permissions amplify prompt-injection impact.",
                ))
            findings.extend(capability_findings(relative_path, line_number, path_text, values))
    return dedupe_findings(findings), True


def walk_json(value: Any, path: tuple[str, ...] = ()):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = (*path, str(key))
            yield child_path, key, child
            yield from walk_json(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_json(child, (*path, str(index)))


def flatten_scalar_values(value: Any) -> list[str]:
    if isinstance(value, (str, int, float)):
        return [str(value)]
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int, float))]
    if isinstance(value, dict):
        return [str(key) for key, enabled in value.items() if enabled is True]
    return []


def capability_findings(relative_path: str, line_number: int, path_text: str, values: list[str]) -> list[AgentFinding]:
    normalized = " ".join(values).lower()
    findings: list[AgentFinding] = []
    if re.search(r"\b(shell|terminal|bash|powershell|cmd(?:\.exe)?|command[_-]?execution)\b", normalized):
        findings.append(build_finding(
            "AGENT.TOOL.SHELL_EXEC", "Agent exposes shell or command execution", Severity.critical, "tool-abuse",
            relative_path, line_number, f"path={path_text}; capability=shell-execution",
            "The declared capability permits shell or command execution.",
            "Disable shell tools by default or enforce command and argument allowlists with approval and audit logs.",
            "Trust is significantly reduced because the asset declares high-impact system execution.",
        ))
    if re.search(r"filesystem[._-](write|delete)|write[_-]?file|delete[_-]?file", normalized):
        findings.append(build_finding(
            "AGENT.FS.WRITE_ACCESS", "Agent can write or delete files", Severity.high, "permission-overreach",
            relative_path, line_number, f"path={path_text}; capability=filesystem-write",
            "The declared capability permits filesystem modification.",
            "Restrict access to read-only or project-scoped paths and require approval for writes.",
            "Trust is reduced because write access expands tampering risk.",
        ))
    if re.search(r"http[_-]?request|web[_-]?request|network|internet|browser|fetch", normalized):
        findings.append(build_finding(
            "AGENT.NET.EXTERNAL_REQUEST", "Agent can perform external network requests", Severity.medium, "network-egress",
            relative_path, line_number, f"path={path_text}; capability=network-egress",
            "The declared capability permits outbound network access.",
            "Apply destination allowlists, block internal metadata endpoints, and retain request audit logs.",
            "Trust is moderately reduced because external data transfer is possible.",
        ))
    return findings


def scan_mcp_config(content: str, relative_path: str) -> list[AgentFinding]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return [
            build_finding(
                "AGENT.MCP.INVALID_JSON",
                "MCP configuration is invalid JSON",
                Severity.medium,
                "mcp-config",
                relative_path,
                1,
                "Invalid JSON in MCP configuration",
                "The MCP configuration could not be parsed, so server permissions and commands cannot be reviewed.",
                "Fix JSON syntax and rerun the AGENT scan.",
                "Trust is reduced because the MCP boundary cannot be evaluated.",
            )
        ]

    findings: list[AgentFinding] = []
    for server_name, server in extract_mcp_servers(data):
        if not isinstance(server, dict):
            continue
        if server.get("disabled") is True:
            continue
        line_number = find_line_number(content, server_name)
        command = str(server.get("command") or "")
        args = normalize_args(server.get("args"))
        env = server.get("env") if isinstance(server.get("env"), dict) else {}
        headers = server.get("headers") if isinstance(server.get("headers"), dict) else {}
        remote_url = str(server.get("url") or server.get("endpoint") or "")
        evidence = format_mcp_evidence(server_name, command, args)

        if is_dangerous_command(command, args):
            findings.append(
                build_finding(
                    "AGENT.MCP.DANGEROUS_COMMAND",
                    "MCP server launches a high-risk command",
                    Severity.critical,
                    "tool-protocol",
                    relative_path,
                    line_number,
                    evidence,
                    "The MCP server command can start shell, script, or interpreter execution.",
                    "Replace shell/interpreter commands with a scoped executable and strict argument allowlists.",
                    "Trust is significantly reduced because the MCP server can execute high-impact local commands.",
                )
            )

        if contains_dangerous_args(args):
            findings.append(
                build_finding(
                    "AGENT.MCP.DANGEROUS_ARGS",
                    "MCP server arguments enable unsafe behavior",
                    Severity.high,
                    "tool-protocol",
                    relative_path,
                    line_number,
                    evidence,
                    "The MCP server arguments include risky flags, inline code execution, or broad permissions.",
                    "Remove dangerous flags, avoid inline code execution, and document allowed argument values.",
                    "Trust is reduced because server startup arguments weaken tool boundaries.",
                )
            )

        secret_keys = [
            f"env.{key}" for key in env
            if looks_like_secret_key(str(key)) and looks_like_secret_value(str(env[key]))
        ]
        secret_keys.extend(
            f"headers.{key}" for key in headers
            if looks_like_secret_key(str(key)) and looks_like_secret_value(str(headers[key]))
        )
        if secret_keys:
            findings.append(
                build_finding(
                    "AGENT.MCP.SECRET_ENV",
                    "MCP server environment contains secrets",
                    Severity.high,
                    "secret-exposure",
                    relative_path,
                    line_number,
                    f"{server_name} env keys: {', '.join(secret_keys[:6])}",
                    "The MCP server configuration includes inline environment values that look like secrets.",
                    "Move secrets to a secret manager or scoped environment injection and rotate exposed values.",
                    "Trust is reduced because MCP server credentials may be exposed through configuration or logs.",
                )
            )

        if has_sensitive_path(args):
            findings.append(
                build_finding(
                    "AGENT.MCP.SENSITIVE_PATH",
                    "MCP server references a sensitive local path",
                    Severity.medium,
                    "permission-overreach",
                    relative_path,
                    line_number,
                    evidence,
                    "The MCP server arguments reference broad or sensitive local filesystem paths.",
                    "Restrict filesystem access to project-specific directories and avoid home, root, or system paths.",
                    "Trust is reduced because the MCP server may access files outside the intended workspace.",
                )
            )

        if remote_url or has_network_capability(command, args):
            findings.append(
                build_finding(
                    "AGENT.MCP.NETWORK_CAPABILITY",
                    "MCP server appears to use network capability",
                    Severity.medium,
                    "network-egress",
                    relative_path,
                    line_number,
                    f"server={server_name}; remote_endpoint={redact_url(remote_url) if remote_url else '-'}",
                    "The MCP server command or arguments suggest outbound network access.",
                    "Apply network allowlists and log MCP server network destinations.",
                    "Trust is moderately reduced because network egress can enable data flow to external services.",
                )
            )

    return findings


def extract_mcp_servers(data: Any) -> list[tuple[str, dict[str, Any]]]:
    candidates: list[tuple[str, dict[str, Any]]] = []
    for key in ("mcpServers", "mcp_servers", "servers"):
        node = data.get(key) if isinstance(data, dict) else None
        if isinstance(node, dict):
            candidates.extend((str(name), config) for name, config in node.items() if isinstance(config, dict))
    if isinstance(data, dict) and "command" in data:
        candidates.append(("default", data))
    return candidates


def build_finding(
    rule_id: str,
    title: str,
    severity: Severity,
    category: str,
    file_path: str,
    line_number: int,
    evidence: str,
    description: str,
    remediation: str,
    trust_impact: str,
) -> AgentFinding:
    return AgentFinding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        file_path=file_path,
        line_start=line_number,
        line_end=line_number,
        evidence=redact_evidence(evidence),
        category=category,
        description=description,
        remediation=remediation,
        trust_impact=trust_impact,
    )


def normalize_args(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []


def is_dangerous_command(command: str, args: list[str]) -> bool:
    normalized = " ".join([command, *args]).lower()
    command_name = Path(command).name.lower()
    if command_name in {"powershell", "powershell.exe", "cmd", "cmd.exe", "bash", "sh", "zsh"}:
        return True
    if command_name in {"python", "python.exe", "node", "node.exe"} and any(arg in {"-c", "-e"} for arg in args):
        return True
    return any(keyword in normalized for keyword in ["subprocess", "child_process", "os.system", "rm -rf"])


def contains_dangerous_args(args: list[str]) -> bool:
    normalized = " ".join(args).lower()
    return any(
        keyword in normalized
        for keyword in [
            "--allow-all",
            "--dangerously-skip-permissions",
            "--no-sandbox",
            "--privileged",
            "rm -rf",
            "powershell",
            "cmd.exe",
            "bash -c",
            "python -c",
            "node -e",
        ]
    )


def has_sensitive_path(args: list[str]) -> bool:
    normalized = " ".join(args).replace("\\", "/").lower()
    return any(
        marker in normalized
        for marker in [
            "c:/users/",
            "c:/windows",
            "/etc/",
            "/root",
            "/home/",
            "../",
            "--filesystem",
            "--allow-file-access",
            "--mount",
        ]
    )


def has_network_capability(command: str, args: list[str]) -> bool:
    normalized = " ".join([command, *args]).lower()
    return any(keyword in normalized for keyword in ["http://", "https://", "curl", "wget", "fetch", "requests", "axios"])


def looks_like_secret_key(value: str) -> bool:
    return bool(re.search(r"(?i)(token|secret|api[_-]?key|access[_-]?key|password|credential)", value))


def looks_like_secret_value(value: str) -> bool:
    normalized = value.strip()
    if normalized.startswith("${") or normalized.startswith("$"):
        return False
    if normalized.lower() in {"", "changeme", "example", "placeholder", "redacted", "***redacted***", "your-token", "your-api-key"}:
        return False
    return len(normalized) >= 12


def format_mcp_evidence(server_name: str, command: str, args: list[str]) -> str:
    return f"server={server_name}; command={command or '-'}; args={' '.join(args)[:240] or '-'}"


def find_line_number(content: str, needle: str) -> int:
    for index, line in enumerate(content.splitlines(), start=1):
        if needle in line:
            return index
    return 1


def redact_evidence(line: str) -> str:
    redacted = re.sub(
        r"(?i)([\"']?(?:secret|token|api[_-]?key|apiKey|access[_-]?key|accessKey|credential|password)[\"']?"
        r"\s*[:=]\s*)([\"']?)[^'\"\s,}]+",
        r"\1\2***REDACTED***",
        line,
    )
    redacted = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", "Bearer ***REDACTED***", redacted)
    redacted = re.sub(r"\b(?:sk|ghp|glpat|xox[baprs])[-_][A-Za-z0-9._-]{12,}\b", "***REDACTED***", redacted)
    return redacted[:500]


def redact_url(value: str) -> str:
    if not value:
        return ""
    return re.sub(r"(?i)(https?://)[^/@\s]+@", r"\1***REDACTED***@", value)[:240]


def dedupe_findings(findings: list[AgentFinding]) -> list[AgentFinding]:
    seen: set[tuple[str, str, int, str]] = set()
    deduped: list[AgentFinding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line_start, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
