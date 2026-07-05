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
        pattern=re.compile(r"(?i)(shell|bash|powershell|cmd\.exe|terminal|command|exec|subprocess|os\.system|child_process)"),
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
        pattern=re.compile(r"(?i)(http_request|web_request|fetch|curl|wget|external network|internet access|browser|axios|requests\.)"),
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
        pattern=re.compile(r"(?i)\b(api[_-]?key|secret|token|access[_-]?key)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}"),
    ),
]

AGENT_FILE_EXTENSIONS = {".md", ".yaml", ".yml", ".json", ".toml"}
AGENT_FILE_NAMES = {
    "Dockerfile",
    "AGENTS.md",
    "CLAUDE.md",
    "mcp.json",
    ".mcp.json",
    "mcp.config.json",
    "claude_desktop_config.json",
    "plugin.json",
    "tools.json",
}
MCP_CONFIG_NAMES = {"mcp.json", ".mcp.json", "mcp.config.json", "claude_desktop_config.json"}
IGNORED_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "target", "coverage", "__pycache__"}
MAX_FILE_BYTES = 512 * 1024


def scan_agent_tree(source_path: str) -> AgentScanOutput:
    root = Path(source_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("source_path must be an existing directory")

    findings: list[AgentFinding] = []
    scanned_files: list[str] = []
    for file_path in iter_agent_files(root):
        relative_path = file_path.relative_to(root).as_posix()
        scanned_files.append(relative_path)
        findings.extend(scan_agent_file(file_path, relative_path))

    return AgentScanOutput(findings=dedupe_findings(findings), scanned_files=scanned_files)


def iter_agent_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.suffix not in AGENT_FILE_EXTENSIONS and path.name not in AGENT_FILE_NAMES:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def scan_agent_file(file_path: Path, relative_path: str) -> list[AgentFinding]:
    try:
        content = file_path.read_text(encoding="utf-8-sig", errors="ignore")
    except OSError:
        return []

    findings = scan_text_rules(content, relative_path)
    if file_path.name in MCP_CONFIG_NAMES:
        findings.extend(scan_mcp_config(content, relative_path))
    return findings


def scan_text_rules(content: str, relative_path: str) -> list[AgentFinding]:
    findings: list[AgentFinding] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        for rule in AGENT_RULES:
            if rule.pattern.search(stripped):
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

        secret_keys = [key for key in env if looks_like_secret_key(str(key)) or looks_like_secret_value(str(env[key]))]
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

        if has_network_capability(command, args):
            findings.append(
                build_finding(
                    "AGENT.MCP.NETWORK_CAPABILITY",
                    "MCP server appears to use network capability",
                    Severity.medium,
                    "network-egress",
                    relative_path,
                    line_number,
                    evidence,
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
    if value.startswith("${") or value.startswith("$"):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_\-]{20,}", value))


def format_mcp_evidence(server_name: str, command: str, args: list[str]) -> str:
    return f"server={server_name}; command={command or '-'}; args={' '.join(args)[:240] or '-'}"


def find_line_number(content: str, needle: str) -> int:
    for index, line in enumerate(content.splitlines(), start=1):
        if needle in line:
            return index
    return 1


def redact_evidence(line: str) -> str:
    redacted = re.sub(
        r"(?i)(secret|token|api[_-]?key|credential|password)(\s*[:=]\s*)['\"]?[^'\"\s,}]+",
        r"\1\2***REDACTED***",
        line,
    )
    return redacted[:500]


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
