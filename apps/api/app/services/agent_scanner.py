from __future__ import annotations

import json
import hashlib
import re
import tomllib
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

import yaml

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
class AgentPermission:
    asset_path: str
    subject: str
    capability: str
    access: str
    resource_type: str
    scope: str
    approval: str
    risk_level: str
    source: str


@dataclass(frozen=True)
class AgentProvenance:
    subject: str
    package_name: str | None
    package_version: str | None
    source_type: str
    source_ref: str | None
    installation_method: str
    version_status: str
    publisher_claim: str | None
    publisher_status: str
    issues: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AgentScanOutput:
    findings: list[AgentFinding]
    scanned_files: list[str]
    assets: list[AgentAsset]
    permissions: list[AgentPermission]
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
    name: str | None = None
    version: str | None = None
    publisher: str | None = None
    transport: str | None = None
    entrypoint: str | None = None
    declared_tools: list[str] = field(default_factory=list)
    declared_resources: list[str] = field(default_factory=list)
    declared_prompts: list[str] = field(default_factory=list)
    permissions: list[AgentPermission] = field(default_factory=list)
    provenance: list[AgentProvenance] = field(default_factory=list)
    file_sha256: str | None = None
    directory_sha256: str | None = None
    integrity_status: str = "unavailable"
    integrity_issues: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentAssetDetails:
    name: str | None = None
    version: str | None = None
    publisher: str | None = None
    transport: str | None = None
    entrypoint: str | None = None
    declared_tools: list[str] = field(default_factory=list)
    declared_resources: list[str] = field(default_factory=list)
    declared_prompts: list[str] = field(default_factory=list)
    permissions: list[AgentPermission] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)


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

AGENT_RULE_VERSION = "agent-rules-2026.08.11-v4"
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
}
PROMPT_CONFIG_NAMES = {"prompt.yaml", "prompt.yml", "prompt.toml", "prompt.json"}
MCP_CONFIG_NAMES = {
    "mcp.json",
    "mcp.yaml",
    "mcp.yml",
    "mcp.toml",
    ".mcp.json",
    ".mcp.yaml",
    ".mcp.yml",
    "mcp.config.json",
    "mcp.config.yaml",
    "mcp.config.yml",
    "claude_desktop_config.json",
}
PLUGIN_CONFIG_NAMES = {"plugin.json", "plugin.yaml", "plugin.yml", "plugin.toml"}
TOOL_CONFIG_NAMES = {"tools.json", "tools.yaml", "tools.yml", "tools.toml"}
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
MAX_PERMISSIONS_PER_ASSET = 500
MAX_INTEGRITY_FILES = 2_000
MAX_INTEGRITY_BYTES = 32 * 1024 * 1024


def scan_agent_tree(source_path: str, excluded_paths: list[str] | None = None) -> AgentScanOutput:
    root = Path(source_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("source_path must be an existing directory")

    findings: list[AgentFinding] = []
    scanned_files: list[str] = []
    assets: list[AgentAsset] = []
    permissions: list[AgentPermission] = []
    skipped_files: list[dict[str, str]] = []
    for file_path, asset_type, skip_reason in iter_agent_files(root, excluded_paths):
        relative_path = file_path.relative_to(root).as_posix()
        if skip_reason:
            skipped_files.append({"path": relative_path, "reason": skip_reason})
            continue
        file_findings, asset = scan_agent_file(file_path, relative_path, asset_type, root)
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
                name=asset.name,
                version=asset.version,
                publisher=asset.publisher,
                transport=asset.transport,
                entrypoint=asset.entrypoint,
                declared_tools=asset.declared_tools,
                declared_resources=asset.declared_resources,
                declared_prompts=asset.declared_prompts,
                permissions=asset.permissions,
                provenance=asset.provenance,
                file_sha256=asset.file_sha256,
                directory_sha256=asset.directory_sha256,
                integrity_status=asset.integrity_status,
                integrity_issues=asset.integrity_issues,
                metadata=asset.metadata,
            )
        )
        permissions.extend(asset.permissions)

    return AgentScanOutput(
        findings=dedupe_findings(findings),
        scanned_files=scanned_files,
        assets=assets,
        permissions=dedupe_permissions(permissions),
        skipped_files=skipped_files,
        rule_version=AGENT_RULE_VERSION,
    )


def iter_agent_files(root: Path, excluded_paths: list[str] | None = None):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        relative_path = path.relative_to(root).as_posix()
        if any(agent_path_matches(relative_path, pattern) for pattern in excluded_paths or []):
            continue
        asset_type = classify_agent_asset(path, root)
        if asset_type is None:
            continue
        try:
            resolved_path = path.resolve(strict=True)
        except OSError:
            yield path, asset_type, "file target is not readable"
            continue
        if path.is_symlink() or (resolved_path != root and root not in resolved_path.parents):
            yield path, asset_type, "symbolic links and paths outside the project are not scanned"
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                yield path, asset_type, "file exceeds 512 KiB limit"
                continue
        except OSError:
            yield path, asset_type, "file metadata is not readable"
            continue
        yield path, asset_type, None


def agent_path_matches(path: str, pattern: str) -> bool:
    normalized_pattern = str(pattern).replace("\\", "/")
    return fnmatchcase(path, normalized_pattern) or PurePosixPath(path).match(normalized_pattern)


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
    if name in PROMPT_CONFIG_NAMES:
        return "prompt"
    if name == "skill.md" and in_agent_directory:
        return "skill"
    if name.endswith(".prompt.md") or (in_agent_directory and "prompts" in relative_parts and path.suffix.lower() == ".md"):
        return "prompt"
    if name in AGENT_CONFIG_NAMES or (in_agent_directory and path.suffix.lower() in {".md", ".yaml", ".yml", ".json", ".toml"}):
        return "agent-config"
    return None


def scan_agent_file(
    file_path: Path,
    relative_path: str,
    asset_type: str | None = None,
    project_root: Path | None = None,
) -> tuple[list[AgentFinding], AgentAsset]:
    resolved_type = asset_type or classify_agent_asset(file_path, file_path.parent) or "unknown"
    try:
        raw_content = file_path.read_bytes()
        content = raw_content.decode("utf-8-sig", errors="ignore")
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
    structured_data: Any = None
    suffix = file_path.suffix.lower()
    structured_format = suffix.lstrip(".") if suffix in {".json", ".yaml", ".yml", ".toml"} else None

    if resolved_type in {"instruction", "skill", "prompt"} and suffix == ".md":
        checks.append("instruction-text-rules")
        findings.extend(scan_text_rules(content, relative_path))
        frontmatter, frontmatter_error = parse_markdown_frontmatter(content)
        if frontmatter is not None:
            structured_data = frontmatter
            parser = "markdown+yaml-frontmatter"
            checks.append("frontmatter-permission-rules")
            findings.extend(scan_structured_security(frontmatter, content, relative_path))
        elif frontmatter_error:
            status = "failed"
            detail = frontmatter_error
            findings.append(invalid_config_finding(relative_path, "YAML frontmatter", frontmatter_error))
    elif structured_format:
        parser = f"structured-{structured_format}"
        checks.append("structured-permission-and-secret-rules")
        structured_data, parse_error = parse_structured_config(content, structured_format)
        if parse_error:
            status = "failed"
            detail = parse_error
            findings.append(invalid_config_finding(relative_path, structured_format.upper(), parse_error))
        else:
            findings.extend(scan_structured_security(structured_data, content, relative_path))
            if resolved_type in {"instruction", "skill", "prompt", "agent-config"}:
                checks.append("structured-instruction-rules")
                findings.extend(scan_structured_instruction_rules(structured_data, relative_path))
    else:
        checks.append("instruction-text-rules")
        findings.extend(scan_text_rules(content, relative_path))

    if resolved_type == "mcp-config" and structured_data is not None:
        checks.append("mcp-server-rules")
        findings.extend(scan_mcp_data(structured_data, content, relative_path))

    asset_details = extract_agent_asset_details(structured_data, relative_path, resolved_type, file_path.name)
    root = (project_root or file_path.parent).resolve()
    provenance = [] if status == "failed" else extract_agent_provenance(
        structured_data,
        relative_path=relative_path,
        asset_type=resolved_type,
        publisher=asset_details.publisher,
        file_path=file_path,
        project_root=root,
    )
    file_sha256 = hashlib.sha256(raw_content).hexdigest()
    directory_sha256, integrity_status, integrity_issues, integrity_file_count = hash_asset_directory(
        file_path,
        root,
        resolved_type,
    )
    checks.append("source-integrity")
    findings.extend(provenance_findings(relative_path, provenance, integrity_status, integrity_issues))
    metadata = dict(asset_details.metadata)
    metadata.update({
        "integrity_algorithm": "sha256",
        "integrity_scope": "directory" if directory_sha256 else "file",
        "integrity_file_count": integrity_file_count,
        "publisher_verification": "claim-only" if asset_details.publisher else "not-declared",
    })
    return dedupe_findings(findings), AgentAsset(
        path=relative_path,
        asset_type=resolved_type,
        format=file_path.suffix.lower().lstrip(".") or "text",
        parser=parser,
        status=status,
        checks=checks,
        detail=detail,
        name=asset_details.name,
        version=asset_details.version,
        publisher=asset_details.publisher,
        transport=asset_details.transport,
        entrypoint=asset_details.entrypoint,
        declared_tools=asset_details.declared_tools,
        declared_resources=asset_details.declared_resources,
        declared_prompts=asset_details.declared_prompts,
        permissions=asset_details.permissions,
        provenance=provenance,
        file_sha256=file_sha256,
        directory_sha256=directory_sha256,
        integrity_status=integrity_status,
        integrity_issues=integrity_issues,
        metadata=metadata,
    )


def parse_structured_config(content: str, structured_format: str) -> tuple[Any, str | None]:
    try:
        if structured_format == "json":
            return json.loads(content), None
        if structured_format in {"yaml", "yml"}:
            return yaml.safe_load(content) or {}, None
        if structured_format == "toml":
            return tomllib.loads(content), None
    except (json.JSONDecodeError, yaml.YAMLError, tomllib.TOMLDecodeError) as exc:
        return None, f"invalid {structured_format.upper()}: {str(exc).splitlines()[0][:180]}"
    return None, f"unsupported structured format: {structured_format}"


def parse_markdown_frontmatter(content: str) -> tuple[dict[str, Any] | None, str | None]:
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, None
    try:
        closing_index = next(index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---")
    except StopIteration:
        return None, "YAML frontmatter is not closed"
    try:
        parsed = yaml.safe_load("\n".join(lines[1:closing_index])) or {}
    except yaml.YAMLError as exc:
        return None, f"invalid YAML frontmatter: {str(exc).splitlines()[0][:180]}"
    if not isinstance(parsed, dict):
        return None, "YAML frontmatter must be an object"
    return parsed, None


def invalid_config_finding(relative_path: str, format_name: str, detail: str) -> AgentFinding:
    return build_finding(
        f"AGENT.CONFIG.INVALID_{format_name.upper().replace(' ', '_')}",
        f"Agent configuration is invalid {format_name}",
        Severity.medium,
        "configuration-integrity",
        relative_path,
        1,
        f"{format_name} parse failed; structured permission checks were skipped",
        f"The configuration cannot be parsed reliably: {detail}",
        f"Fix the {format_name} syntax and rerun the AGENT scan.",
        "Trust cannot be evaluated until the asset is parsed successfully.",
    )


def scan_structured_instruction_rules(data: Any, relative_path: str) -> list[AgentFinding]:
    findings: list[AgentFinding] = []
    instruction_keys = {"instruction", "instructions", "prompt", "systemprompt", "system_prompt", "systemmessage", "system_message"}
    for path, key, value in walk_json(data):
        normalized_key = normalize_key(str(key))
        is_message_content = normalized_key == "content" and any(normalize_key(item) in {"messages", "prompts"} for item in path[:-1])
        if not isinstance(value, str) or (normalized_key not in instruction_keys and not is_message_content):
            continue
        line_number = find_line_number_in_values(relative_path, value)
        for finding in scan_text_rules(value, relative_path):
            findings.append(AgentFinding(
                rule_id=finding.rule_id,
                title=finding.title,
                severity=finding.severity,
                file_path=finding.file_path,
                line_start=line_number,
                line_end=line_number,
                evidence=finding.evidence,
                category=finding.category,
                description=finding.description,
                remediation=finding.remediation,
                trust_impact=finding.trust_impact,
            ))
    return findings


def find_line_number_in_values(relative_path: str, value: str) -> int:
    # Structured parser callers do not retain a source map. A stable line 1 fallback is
    # more honest than fabricating a location; the config path remains in evidence.
    del relative_path, value
    return 1


def scan_structured_security(data: Any, content: str, relative_path: str) -> list[AgentFinding]:
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
        if normalize_key(key_text) in {"permissions", "allowedtools", "tools", "capabilities"}:
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
    return dedupe_findings(findings)


def extract_agent_asset_details(data: Any, relative_path: str, asset_type: str, fallback_name: str) -> AgentAssetDetails:
    if not isinstance(data, (dict, list)):
        return AgentAssetDetails(name=Path(fallback_name).stem)

    name = first_known_scalar(data, {"name", "displayname", "title"}) or Path(fallback_name).stem
    version = first_known_scalar(data, {"version"})
    publisher = first_known_scalar(data, {"publisher", "author", "vendor", "owner"})
    transports = extract_mcp_transports(data) if asset_type == "mcp-config" else []
    commands = [safe_command(item) for item in collect_known_scalars(data, {"command"})]
    tools = collect_declared_names(data, {"tools", "allowedtools", "allowed_tools", "functions"})
    resources = collect_declared_names(data, {"resources", "roots", "directories", "paths", "allowedpaths", "allowed_paths"})
    prompts = collect_declared_names(data, {"prompts", "prompttemplates", "prompt_templates"})
    extracted_permissions = extract_permissions(data, relative_path, str(name), asset_type)
    permissions = extracted_permissions[:MAX_PERMISSIONS_PER_ASSET]
    resources = sorted(set(resources + [item.scope for item in permissions if item.resource_type in {"filesystem", "network"}]))
    metadata: dict[str, object] = {
        "top_level_keys": sorted(str(key) for key in data.keys())[:30] if isinstance(data, dict) else [],
        "subject_count": len({permission.subject for permission in permissions}),
        "permission_limit": MAX_PERMISSIONS_PER_ASSET,
        "permissions_truncated": max(0, len(extracted_permissions) - len(permissions)),
    }
    return AgentAssetDetails(
        name=safe_metadata_value(name),
        version=safe_metadata_value(version),
        publisher=safe_metadata_value(publisher),
        transport=", ".join(sorted(set(transports)))[:200] or None,
        entrypoint=", ".join(sorted(set(commands)))[:240] or None,
        declared_tools=sorted(set(tools))[:100],
        declared_resources=resources[:100],
        declared_prompts=sorted(set(prompts))[:100],
        permissions=permissions,
        metadata=metadata,
    )


def extract_agent_provenance(
    data: Any,
    *,
    relative_path: str,
    asset_type: str,
    publisher: str | None,
    file_path: Path,
    project_root: Path,
) -> list[AgentProvenance]:
    records: list[AgentProvenance] = []
    if asset_type == "mcp-config" and isinstance(data, dict):
        servers = extract_mcp_servers(data)
        for subject, node in servers:
            records.append(provenance_from_node(
                subject=f"mcp:{subject}", node=node, publisher=publisher,
                file_path=file_path, project_root=project_root,
            ))
        if not servers:
            records.append(provenance_from_node(
                subject=f"mcp:{Path(relative_path).stem}", node=data, publisher=publisher,
                file_path=file_path, project_root=project_root,
            ))
    elif asset_type in {"plugin-manifest", "skill", "agent-config"}:
        node = data if isinstance(data, dict) else {}
        records.append(provenance_from_node(
            subject=f"{asset_type}:{Path(relative_path).stem}", node=node, publisher=publisher,
            file_path=file_path, project_root=project_root,
        ))
    return dedupe_provenance(records)


def provenance_from_node(
    *,
    subject: str,
    node: dict[str, Any],
    publisher: str | None,
    file_path: Path,
    project_root: Path,
) -> AgentProvenance:
    command = direct_scalar(node, {"command", "executable"})
    args = direct_string_list(node, {"args", "arguments"})
    image = direct_scalar(node, {"image", "containerimage", "container_image"})
    repository = direct_reference(node, {"repository", "source", "sourceurl", "source_url", "git", "giturl", "git_url"})
    endpoint = direct_reference(node, {"url", "endpoint"})
    declared_package = direct_scalar(node, {"package", "packagename", "package_name", "distribution"})
    declared_version = direct_scalar(node, {"version", "packageversion", "package_version"})
    installation_method = "configuration"
    source_type = "unknown"
    source_ref: str | None = None
    package_name: str | None = safe_metadata_value(declared_package)
    package_version: str | None = safe_metadata_value(declared_version)
    raw_source: str | None = None

    command_name = Path(str(command or "").strip('"\'')).name.lower()
    if command_name in {"npx", "npm", "pnpm", "pnpx", "yarn", "bunx"}:
        installation_method = command_name
        source_type = "registry"
        spec = first_package_argument(args)
        parsed_name, parsed_version = split_npm_spec(spec)
        package_name = safe_metadata_value(parsed_name) or package_name
        package_version = safe_metadata_value(parsed_version) or package_version
        source_ref = f"npm:{package_name}" if package_name else None
    elif command_name in {"uvx", "pipx", "pip", "python", "python.exe"}:
        installation_method = command_name
        spec = first_package_argument(args)
        if command_name in {"uvx", "pipx", "pip"} and spec:
            source_type = "registry"
            parsed_name, parsed_version = split_python_spec(spec)
            package_name = safe_metadata_value(parsed_name) or package_name
            package_version = safe_metadata_value(parsed_version) or package_version
            source_ref = f"pypi:{package_name}" if package_name else None
        else:
            source_type = "local"
            source_ref = safe_local_reference(first_non_flag_argument(args))
    elif command_name in {"docker", "podman"} or image:
        container_ref = image or first_container_image(args)
        installation_method = command_name if command_name in {"docker", "podman"} else "container"
        source_type = "container"
        raw_source = container_ref
        source_ref = safe_scope(container_ref) if container_ref else None
        package_name, package_version = split_container_ref(container_ref) if container_ref else (package_name, package_version)
    elif repository:
        installation_method = "git"
        source_type = "git"
        raw_source = repository
        source_ref = safe_scope(repository)
        package_name = package_name or repository_name(repository)
        package_version = package_version or git_reference(repository)
    elif endpoint:
        installation_method = "remote-endpoint"
        source_type = "remote-url"
        raw_source = endpoint
        source_ref = safe_scope(endpoint)
    elif command:
        installation_method = safe_command(command)
        source_type = "local"
        source_ref = safe_local_reference(first_non_flag_argument(args) or command)
    elif declared_package:
        installation_method = "declared-package"
        source_type = "registry"
        source_ref = f"registry:{safe_metadata_value(declared_package)}"

    if repository and source_type not in {"git", "container"}:
        raw_source = repository
    if endpoint and raw_source is None and source_type == "remote-url":
        raw_source = endpoint
    version_status = provenance_version_status(source_type, package_version, source_ref)
    issues: list[str] = []
    source_candidate = str(raw_source or source_ref or "")
    if re.match(r"(?i)^http://", source_candidate):
        issues.append("insecure-http-source")
    if re.match(r"(?i)^https?://[^/\s@]+@", source_candidate):
        issues.append("embedded-source-credentials")
    if version_status in {"missing", "floating"} and source_type in {"registry", "git", "container"}:
        issues.append("version-unpinned")
    if source_type == "unknown":
        issues.append("source-unknown")
    local_candidates = [item for item in [source_ref, *args] if isinstance(item, str)]
    if source_type == "local" and any(local_reference_escapes(item, file_path.parent, project_root) for item in local_candidates):
        issues.append("local-path-escape")
    return AgentProvenance(
        subject=redact_evidence(subject)[:240],
        package_name=package_name,
        package_version=package_version,
        source_type=source_type,
        source_ref=source_ref,
        installation_method=installation_method,
        version_status=version_status,
        publisher_claim=safe_metadata_value(publisher),
        publisher_status="claim-only" if publisher else "not-declared",
        issues=sorted(set(issues)),
    )


def provenance_findings(
    relative_path: str,
    provenance: list[AgentProvenance],
    integrity_status: str,
    integrity_issues: list[str],
) -> list[AgentFinding]:
    findings: list[AgentFinding] = []
    for item in provenance:
        evidence = (
            f"subject={item.subject}; package={item.package_name or 'unknown'}; "
            f"source_type={item.source_type}; version_status={item.version_status}"
        )
        if "version-unpinned" in item.issues:
            findings.append(build_finding(
                "AGENT.SUPPLY.UNPINNED_VERSION", "Agent dependency version is not immutable", Severity.medium,
                "supply-chain-integrity", relative_path, 1, evidence,
                "The Agent, MCP, or plugin dependency uses a missing or floating version reference.",
                "Pin an exact package version, immutable Git commit, or container digest and record the expected hash.",
                "Trust is reduced because the installed implementation can change without a configuration review.",
            ))
        if "insecure-http-source" in item.issues:
            findings.append(build_finding(
                "AGENT.SUPPLY.INSECURE_SOURCE", "Agent dependency uses an insecure source", Severity.high,
                "supply-chain-integrity", relative_path, 1, evidence,
                "The declared source uses unencrypted HTTP transport.",
                "Use HTTPS or an authenticated internal registry and verify the downloaded artifact hash or signature.",
                "Trust is reduced because the dependency can be modified in transit.",
            ))
        if "embedded-source-credentials" in item.issues:
            findings.append(build_finding(
                "AGENT.SUPPLY.SOURCE_CREDENTIALS", "Agent source URL embeds credentials", Severity.high,
                "supply-chain-integrity", relative_path, 1, evidence,
                "The dependency source URL contains embedded credentials; the credential value was not retained.",
                "Rotate the credential and use scoped secret injection instead of URL user information.",
                "Trust is reduced because source credentials can leak through configuration and logs.",
            ))
        if "local-path-escape" in item.issues:
            findings.append(build_finding(
                "AGENT.SUPPLY.LOCAL_PATH_ESCAPE", "Agent dependency resolves outside the project", Severity.high,
                "supply-chain-integrity", relative_path, 1, evidence,
                "A local dependency reference can resolve outside the configured project root.",
                "Move the dependency under the project root or declare a separately governed immutable package source.",
                "Trust is reduced because the scanned configuration does not cover the referenced implementation.",
            ))
        if "source-unknown" in item.issues:
            findings.append(build_finding(
                "AGENT.SUPPLY.SOURCE_UNKNOWN", "Agent dependency source is not declared", Severity.low,
                "supply-chain-integrity", relative_path, 1, evidence,
                "The asset does not declare a registry, repository, container, endpoint, or governed local source.",
                "Declare the installation source, package identity, locked version, and expected integrity value.",
                "Trust remains incomplete because the implementation origin cannot be reconstructed from the asset.",
            ))
    if integrity_status == "partial":
        findings.append(build_finding(
            "AGENT.SUPPLY.INTEGRITY_PARTIAL", "Agent directory integrity evidence is incomplete", Severity.medium,
            "supply-chain-integrity", relative_path, 1,
            f"integrity_status=partial; issues={','.join(integrity_issues) or 'unknown'}",
            "The local asset directory exceeded a safety limit or contained an unreadable or linked file.",
            "Reduce the governed directory scope or remove unsupported links, then regenerate complete SHA-256 evidence.",
            "Trust remains incomplete because not every local implementation file contributed to the directory digest.",
        ))
    return findings


def hash_asset_directory(
    file_path: Path,
    project_root: Path,
    asset_type: str,
) -> tuple[str | None, str, list[str], int]:
    if asset_type not in {"plugin-manifest", "skill"} or file_path.parent.resolve() == project_root:
        return None, "recorded", [], 1
    asset_root = file_path.parent.resolve()
    if asset_root != project_root and project_root not in asset_root.parents:
        return None, "partial", ["directory-outside-project"], 0
    digest = hashlib.sha256()
    issues: list[str] = []
    file_count = 0
    total_bytes = 0
    for candidate in sorted(asset_root.rglob("*"), key=lambda item: (item.as_posix().lower(), item.as_posix())):
        if not candidate.is_file() or any(part in IGNORED_DIRS for part in candidate.relative_to(asset_root).parts[:-1]):
            continue
        if candidate.is_symlink():
            issues.append("symbolic-link-skipped")
            continue
        try:
            resolved = candidate.resolve(strict=True)
            if resolved != project_root and project_root not in resolved.parents:
                issues.append("outside-project-file-skipped")
                continue
            size = candidate.stat().st_size
            if file_count >= MAX_INTEGRITY_FILES or total_bytes + size > MAX_INTEGRITY_BYTES:
                issues.append("directory-hash-limit-reached")
                break
            content = candidate.read_bytes()
        except OSError:
            issues.append("unreadable-file-skipped")
            continue
        relative = candidate.relative_to(asset_root).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).digest())
        file_count += 1
        total_bytes += len(content)
    if file_count == 0:
        return None, "partial", sorted(set(issues + ["no-directory-files-hashed"])), 0
    return digest.hexdigest(), "partial" if issues else "recorded", sorted(set(issues)), file_count


def direct_scalar(data: dict[str, Any], keys: set[str]) -> str | None:
    normalized = {normalize_key(item) for item in keys}
    for key, value in data.items():
        if normalize_key(str(key)) in normalized and isinstance(value, (str, int, float)):
            return str(value)
    return None


def direct_string_list(data: dict[str, Any], keys: set[str]) -> list[str]:
    normalized = {normalize_key(item) for item in keys}
    for key, value in data.items():
        if normalize_key(str(key)) not in normalized:
            continue
        if isinstance(value, list):
            return [str(item) for item in value if isinstance(item, (str, int, float))]
        if isinstance(value, str):
            return [value]
    return []


def direct_reference(data: dict[str, Any], keys: set[str]) -> str | None:
    normalized = {normalize_key(item) for item in keys}
    for key, value in data.items():
        if normalize_key(str(key)) not in normalized:
            continue
        if isinstance(value, (str, int, float)):
            return str(value)
        if isinstance(value, dict):
            nested = direct_scalar(value, {"url", "href", "path"})
            if nested:
                return nested
    return None


def first_package_argument(args: list[str]) -> str | None:
    value_options = {"--index-url", "--extra-index-url", "--registry", "--cache-dir", "--python"}
    skip_next = False
    for item in args:
        if skip_next:
            skip_next = False
            continue
        if item in {"--package", "-p"}:
            continue
        if item.startswith(("--package=", "-p=")):
            return item.split("=", 1)[1]
        if item in value_options:
            skip_next = True
            continue
        if item.lower() in {"install", "add", "exec", "run", "dlx"}:
            continue
        if item.startswith("-"):
            continue
        return item
    return None


def first_non_flag_argument(args: list[str]) -> str | None:
    return next((item for item in args if item and not item.startswith("-")), None)


def first_container_image(args: list[str]) -> str | None:
    value_options = {"--name", "--network", "--volume", "-v", "--env", "-e", "--workdir", "-w", "--user", "-u"}
    skip_next = False
    for item in args:
        if skip_next:
            skip_next = False
            continue
        if item in {"run", "create", "pull"}:
            continue
        if item in value_options:
            skip_next = True
            continue
        if item.startswith("-"):
            continue
        return item
    return None


def split_npm_spec(spec: str | None) -> tuple[str | None, str | None]:
    if not spec:
        return None, None
    value = spec.strip()
    if value.startswith("@"):
        separator = value.rfind("@")
        return (value[:separator], value[separator + 1:] or None) if separator > 0 else (value, None)
    if "@" in value:
        name, version = value.rsplit("@", 1)
        return name or None, version or None
    return value, None


def split_python_spec(spec: str | None) -> tuple[str | None, str | None]:
    if not spec:
        return None, None
    for separator in ("===", "==", "@"):
        if separator in spec:
            name, version = spec.split(separator, 1)
            return name.strip() or None, version.strip() or None
    match = re.match(r"^([A-Za-z0-9_.-]+)\s*([<>=!~].+)$", spec)
    return (match.group(1), match.group(2)) if match else (spec, None)


def split_container_ref(value: str) -> tuple[str | None, str | None]:
    clean = value.strip()
    if "@sha256:" in clean:
        name, digest = clean.split("@", 1)
        return safe_metadata_value(name), safe_metadata_value(digest)
    last_segment = clean.rsplit("/", 1)[-1]
    if ":" in last_segment:
        name, tag = clean.rsplit(":", 1)
        return safe_metadata_value(name), safe_metadata_value(tag)
    return safe_metadata_value(clean), None


def provenance_version_status(source_type: str, version: str | None, source_ref: str | None) -> str:
    if source_type in {"local", "remote-url", "unknown"}:
        return "not-applicable" if source_type != "unknown" else "missing"
    candidate = str(version or "").strip()
    if not candidate:
        return "missing"
    if source_type == "git":
        return "locked" if (
            re.fullmatch(r"[0-9a-fA-F]{12,64}", candidate)
            or (source_ref is not None and re.search(r"#[0-9a-fA-F]{12,64}$", source_ref))
        ) else "floating"
    if candidate.startswith("sha256:") or re.fullmatch(r"[0-9a-fA-F]{12,64}", candidate):
        return "locked"
    if re.fullmatch(r"v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?", candidate):
        return "locked"
    if source_type == "container" and candidate.lower() not in {"latest", "main", "master", "stable", "edge"}:
        return "tagged"
    return "floating"


def repository_name(value: str) -> str | None:
    clean = value.split("#", 1)[0].rstrip("/")
    name = clean.rsplit("/", 1)[-1]
    return safe_metadata_value(name[:-4] if name.endswith(".git") else name)


def git_reference(value: str) -> str | None:
    return safe_metadata_value(value.split("#", 1)[1]) if "#" in value else None


def safe_local_reference(value: str | None) -> str | None:
    if not value:
        return None
    return redact_evidence(str(value).strip())[:300] or None


def local_reference_escapes(value: str, base: Path, project_root: Path) -> bool:
    normalized = value.strip().replace("\\", "/")
    if not normalized or normalized.startswith(("http://", "https://", "npm:", "pypi:")):
        return False
    if not looks_like_resource_path(normalized):
        return False
    try:
        candidate = Path(normalized)
        resolved = (candidate if candidate.is_absolute() else base / candidate).resolve()
    except OSError:
        return True
    return resolved != project_root and project_root not in resolved.parents


def dedupe_provenance(items: list[AgentProvenance]) -> list[AgentProvenance]:
    seen: set[tuple[str, str | None, str | None, str | None]] = set()
    result: list[AgentProvenance] = []
    for item in items:
        key = (item.subject, item.package_name, item.package_version, item.source_ref)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def extract_permissions(data: Any, relative_path: str, default_subject: str, asset_type: str) -> list[AgentPermission]:
    permissions: list[AgentPermission] = []
    for path, key, value in walk_json(data):
        key_text = str(key)
        normalized_key = normalize_key(key_text)
        source = ".".join(path)
        subject = permission_subject(path, default_subject)
        approval = approval_for_path(data, path)

        if normalized_key in {"permissions", "capabilities", "allowedtools", "allowed_tools"}:
            for token in flatten_permission_values(value):
                permissions.append(permission_from_token(relative_path, subject, token, approval, source))
        elif normalized_key in {"tools", "functions"}:
            for tool_name in collect_names_from_value(value):
                permissions.append(make_permission(
                    relative_path, subject, "tool-invocation", "use", "tool", tool_name, approval, "low", source
                ))
        elif normalized_key in {"roots", "directories", "paths", "allowedpaths", "allowed_paths", "filesystem"}:
            for scope in flatten_resource_values(value):
                permissions.append(make_permission(
                    relative_path, subject, "filesystem-access", infer_filesystem_access(path, data), "filesystem",
                    scope, approval, "high" if infer_filesystem_access(path, data) != "read" else "medium", source
                ))
        elif normalized_key in {"url", "endpoint", "baseurl", "base_url", "alloweddomains", "allowed_domains", "domains"}:
            for scope in flatten_resource_values(value):
                permissions.append(make_permission(
                    relative_path, subject, "network-egress", "connect", "network", redact_url(scope), approval, "medium", source
                ))
        elif normalized_key in {"env", "environment", "headers"} and isinstance(value, dict):
            secret_keys = sorted(str(item) for item in value if looks_like_secret_key(str(item)))
            if secret_keys:
                permissions.append(make_permission(
                    relative_path, subject, "secret-access", "inject", "environment" if normalized_key != "headers" else "header",
                    ", ".join(secret_keys[:30]), approval, "high", source
                ))
        elif normalized_key == "command" and isinstance(value, str):
            permissions.append(make_permission(
                relative_path, subject, "server-process", "execute", "command", safe_command(value), approval,
                "high" if is_dangerous_command(value, []) else "medium", source
            ))
        elif normalized_key == "args" and isinstance(value, list):
            argument_flags = safe_argument_flags(value)
            if argument_flags:
                permissions.append(make_permission(
                    relative_path, subject, "server-process", "execute", "command-arguments",
                    ", ".join(argument_flags), approval, "medium", source
                ))
            for item in value:
                if not isinstance(item, str):
                    continue
                if looks_like_resource_path(item):
                    permissions.append(make_permission(
                        relative_path, subject, "filesystem-access", "read-write", "filesystem", item,
                        approval, "high", source
                    ))
                elif item.startswith(("http://", "https://")):
                    permissions.append(make_permission(
                        relative_path, subject, "network-egress", "connect", "network", redact_url(item),
                        approval, "medium", source
                    ))

    if asset_type in {"instruction", "skill", "prompt"} and not permissions:
        return []
    return dedupe_permissions(permissions)


def permission_from_token(asset_path: str, subject: str, token: str, approval: str, source: str) -> AgentPermission:
    normalized = token.strip().lower().replace(" ", "_")
    if normalized in {"*", "*:*", "all", "all_tools", "allow_all", "full_access", "admin"}:
        return make_permission(asset_path, subject, "all-capabilities", "admin", "wildcard", "*", approval, "critical", source)
    if re.search(r"shell|terminal|bash|powershell|cmd(?:\.exe)?|command[_-]?(?:exec|execution)|\bbash\b", normalized):
        return make_permission(asset_path, subject, "shell-execution", "execute", "command", token, approval, "critical", source)
    if re.search(r"filesystem[._-]?(?:write|delete)|write[_-]?file|delete[_-]?file|^(?:write|edit)$", normalized):
        return make_permission(asset_path, subject, "filesystem-write", "write", "filesystem", token, approval, "high", source)
    if re.search(r"filesystem[._-]?read|read[_-]?file|^read$|grep|glob", normalized):
        return make_permission(asset_path, subject, "filesystem-read", "read", "filesystem", token, approval, "medium", source)
    if re.search(r"http|network|internet|browser|fetch|web[_-]?(?:request|fetch|search)", normalized):
        return make_permission(asset_path, subject, "network-egress", "connect", "network", token, approval, "medium", source)
    if re.search(r"secret|token|credential|environment|\benv\b", normalized):
        return make_permission(asset_path, subject, "secret-access", "read", "secret", token, approval, "high", source)
    return make_permission(asset_path, subject, "tool-invocation", "use", "tool", token, approval, "low", source)


def make_permission(
    asset_path: str,
    subject: str,
    capability: str,
    access: str,
    resource_type: str,
    scope: str,
    approval: str,
    risk_level: str,
    source: str,
) -> AgentPermission:
    return AgentPermission(
        asset_path=asset_path,
        subject=safe_metadata_value(subject) or "asset",
        capability=capability,
        access=access,
        resource_type=resource_type,
        scope=safe_scope(scope),
        approval=approval,
        risk_level=risk_level,
        source=source[:300],
    )


def permission_subject(path: tuple[str, ...], fallback: str) -> str:
    normalized = [normalize_key(item) for item in path]
    for marker in ("mcpservers", "mcp_servers", "servers", "plugins", "tools"):
        if marker in normalized:
            index = normalized.index(marker)
            if len(path) > index + 1:
                return f"{marker}:{path[index + 1]}"
    return fallback


def extract_approval_requirement(data: Any) -> str:
    if not isinstance(data, dict):
        return "unknown"
    for key, value in data.items():
        if normalize_key(str(key)) not in {"approval", "requireapproval", "requiresapproval", "humanapproval", "confirm"}:
            continue
        if value is True or str(value).lower() in {"required", "always", "true", "manual"}:
            return "required"
        if value is False or str(value).lower() in {"none", "never", "false", "disabled"}:
            return "not-required"
    return "unknown"


def approval_for_path(data: Any, path: tuple[str, ...]) -> str:
    for length in range(len(path) - 1, -1, -1):
        node = value_at_path(data, path[:length])
        approval = extract_approval_requirement(node)
        if approval != "unknown":
            return approval
    return "unknown"


def value_at_path(data: Any, path: tuple[str, ...]) -> Any:
    node = data
    for part in path:
        if isinstance(node, dict):
            node = node.get(part)
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return None
    return node


def infer_filesystem_access(path: tuple[str, ...], data: Any) -> str:
    normalized_path = ".".join(normalize_key(item) for item in path)
    if "readonly" in normalized_path or has_boolean_key(data, {"readonly", "read_only"}, True):
        return "read"
    if "write" in normalized_path or "delete" in normalized_path:
        return "write"
    return "read-write"


def has_boolean_key(data: Any, keys: set[str], expected: bool) -> bool:
    normalized_keys = {normalize_key(item) for item in keys}
    return any(normalize_key(str(key)) in normalized_keys and value is expected for _, key, value in walk_json(data))


def first_known_scalar(data: Any, keys: set[str]) -> str | None:
    normalized_keys = {normalize_key(item) for item in keys}
    if isinstance(data, dict):
        for key, value in data.items():
            if normalize_key(str(key)) in normalized_keys and isinstance(value, (str, int, float)):
                return str(value)
    return None


def collect_known_scalars(data: Any, keys: set[str]) -> list[str]:
    normalized_keys = {normalize_key(item) for item in keys}
    values: list[str] = []
    for _, key, value in walk_json(data):
        if normalize_key(str(key)) in normalized_keys and isinstance(value, (str, int, float)):
            values.append(safe_scope(str(value)))
    return values


def extract_mcp_transports(data: Any) -> list[str]:
    transports: list[str] = []
    for _, server in extract_mcp_servers(data):
        explicit = server.get("transport") or server.get("type")
        if isinstance(explicit, str):
            transports.append(safe_scope(explicit))
        elif server.get("url") or server.get("endpoint"):
            transports.append("http")
        elif server.get("command"):
            transports.append("stdio")
    return transports


def collect_declared_names(data: Any, keys: set[str]) -> list[str]:
    normalized_keys = {normalize_key(item) for item in keys}
    names: list[str] = []
    for _, key, value in walk_json(data):
        if normalize_key(str(key)) in normalized_keys:
            names.extend(collect_names_from_value(value))
    return [safe_scope(name) for name in names if name]


def collect_names_from_value(value: Any) -> list[str]:
    if isinstance(value, str):
        return split_compound_values(value)
    if isinstance(value, list):
        names: list[str] = []
        for item in value:
            if isinstance(item, dict):
                name = first_known_scalar(item, {"name", "id", "title"})
                if name:
                    names.append(name)
            elif isinstance(item, (str, int, float)):
                names.append(str(item))
        return names
    if isinstance(value, dict):
        return [str(key) for key in value]
    return []


def flatten_permission_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return split_compound_values(value)
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, (str, int, float))]
    if isinstance(value, dict):
        return [str(key) for key, enabled in value.items() if enabled is True or isinstance(enabled, dict)]
    return []


def flatten_resource_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return split_compound_values(value)
    if isinstance(value, list):
        return [safe_scope(str(item)) for item in value if isinstance(item, (str, int, float))]
    if isinstance(value, dict):
        return [safe_scope(str(key)) for key in value]
    return []


def split_compound_values(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"\s*,\s*|\s+", value.strip()) if item.strip()]


def normalize_key(value: str) -> str:
    return re.sub(r"[-_\s]", "", value).lower()


def safe_metadata_value(value: Any) -> str | None:
    if value is None:
        return None
    text = redact_evidence(str(value).strip())
    return text[:240] or None


def safe_scope(value: str) -> str:
    text = redact_evidence(str(value).strip())
    if text.startswith(("http://", "https://")):
        text = redact_url(text)
    return text[:300] or "unspecified"


def safe_command(value: str) -> str:
    executable = re.split(r"\s+", value.strip(), maxsplit=1)[0].strip("\"'")
    command_name = Path(executable).name
    return redact_evidence(command_name)[:160] or "unknown"


def looks_like_resource_path(value: str) -> bool:
    normalized = value.strip().replace("\\", "/")
    if not normalized or normalized.startswith("-") or normalized.startswith(("http://", "https://")):
        return False
    return bool(re.match(r"^(?:[A-Za-z]:/|/|\.{1,2}/)", normalized))


def safe_argument_flags(value: list[Any]) -> list[str]:
    flags: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.startswith("-"):
            continue
        flag = item.split("=", maxsplit=1)[0]
        if re.search(r"(?i)(token|secret|password|credential|api[_-]?key)", flag):
            flags.append(f"{flag}=***REDACTED***")
        else:
            flags.append(flag[:120])
    return flags[:50]


def dedupe_permissions(permissions: list[AgentPermission]) -> list[AgentPermission]:
    seen: set[tuple[str, str, str, str, str, str, str, str]] = set()
    result: list[AgentPermission] = []
    for permission in permissions:
        key = (
            permission.asset_path,
            permission.subject,
            permission.capability,
            permission.access,
            permission.resource_type,
            permission.scope,
            permission.approval,
            permission.source,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(permission)
    return result


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
        return [invalid_config_finding(relative_path, "JSON", "invalid JSON")], False

    return scan_structured_security(data, content, relative_path), True


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

    return scan_mcp_data(data, content, relative_path)


def scan_mcp_data(data: Any, content: str, relative_path: str) -> list[AgentFinding]:
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
    redacted = re.sub(
        r"(?i)(--(?:api[_-]?key|token|password|secret|credential)(?:=|\s+))[^\s,]+",
        r"\1***REDACTED***",
        redacted,
    )
    redacted = re.sub(r"(?i)(https?://)[^/@\s]+@", r"\1***REDACTED***@", redacted)
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
