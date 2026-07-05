from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

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
        title="Agent 指令允许读取环境变量或密钥",
        severity=Severity.high,
        category="secret-exposure",
        description="Agent 指令或工具配置要求读取环境变量、密钥、Token 或凭据，可能导致敏感信息泄露。",
        remediation="限制 Agent 对环境变量和密钥文件的访问，改为最小权限的密钥代理或受控 Secret 注入。",
        trust_impact="降低信任评分：Agent 具备敏感资源访问能力，需要人工复核。",
        pattern=re.compile(r"(?i)(read|access|get|exfiltrate).{0,50}(env|environment|secret|token|api[_-]?key|credential|\.env)"),
    ),
    AgentRule(
        rule_id="AGENT.TOOL.SHELL_EXEC",
        title="Agent 工具暴露 Shell 或命令执行能力",
        severity=Severity.critical,
        category="tool-abuse",
        description="Agent 可调用 shell、终端或命令执行工具，若指令被注入可能直接执行系统命令。",
        remediation="默认禁用 shell 工具；必须启用时使用命令白名单、参数约束、审批流和审计日志。",
        trust_impact="显著降低信任评分：具备高危系统执行能力。",
        pattern=re.compile(r"(?i)(shell|bash|powershell|cmd\.exe|terminal|command|exec|subprocess|os\.system|child_process)"),
    ),
    AgentRule(
        rule_id="AGENT.FS.WRITE_ACCESS",
        title="Agent 工具具备文件写入或删除能力",
        severity=Severity.high,
        category="permission-overreach",
        description="Agent 工具可以写入、覆盖或删除文件，可能被用于篡改源码、配置或安全策略。",
        remediation="将文件系统能力限制为只读或限定目录；写入操作必须经过路径白名单和人工审批。",
        trust_impact="降低信任评分：文件写权限扩大了供应链篡改风险。",
        pattern=re.compile(r"(?i)(write_file|delete_file|remove_file|filesystem\.write|fs\.write|rm -rf|overwrite|modify files?|file_write)"),
    ),
    AgentRule(
        rule_id="AGENT.NET.EXTERNAL_REQUEST",
        title="Agent 工具允许外部网络请求",
        severity=Severity.medium,
        category="network-egress",
        description="Agent 可以向外部网络发起请求，可能造成数据外传、SSRF 或调用未授权第三方服务。",
        remediation="设置网络出口白名单，禁止访问内网、云元数据地址和未知域名，并记录完整请求账本。",
        trust_impact="中度降低信任评分：存在外联和数据流出风险。",
        pattern=re.compile(r"(?i)(http_request|web_request|fetch|curl|wget|external network|internet access|browser|axios|requests\.)"),
    ),
    AgentRule(
        rule_id="AGENT.MCP.WILDCARD_PERMISSION",
        title="MCP 或插件权限范围过宽",
        severity=Severity.high,
        category="permission-overreach",
        description="MCP/插件配置出现通配权限或全量工具访问，违背最小权限原则。",
        remediation="移除通配权限，按任务拆分工具范围，只授予必要的只读或受限能力。",
        trust_impact="降低信任评分：权限边界不清晰，容易被提示注入放大影响。",
        pattern=re.compile(r"(?i)(allow_all|all_tools|wildcard|\*:\*|permissions\s*[:=]\s*\[?\s*['\"]?\*|full_access|admin)"),
    ),
    AgentRule(
        rule_id="AGENT.PROMPT.INSTRUCTION_OVERRIDE",
        title="提示词包含忽略安全策略或覆盖指令风险",
        severity=Severity.high,
        category="prompt-injection",
        description="Agent 指令中出现忽略历史指令、绕过安全策略或禁用防护的内容，可能形成提示注入载荷。",
        remediation="删除绕过类指令，建立系统提示词优先级校验，并对外部文档指令做不可信隔离。",
        trust_impact="降低信任评分：指令文件可能主动破坏安全边界。",
        pattern=re.compile(r"(?i)(ignore previous|ignore safety|bypass|override instructions|disable guardrails|jailbreak|ignore all prior)"),
    ),
    AgentRule(
        rule_id="AGENT.SECRET.INLINE_TOKEN",
        title="Agent 配置包含疑似明文 Token 或 API Key",
        severity=Severity.high,
        category="secret-exposure",
        description="Agent、MCP 或插件配置中出现明文密钥，可能被模型上下文、日志或工具调用泄露。",
        remediation="立即轮换密钥，改为环境变量引用或 Secret Manager，禁止将密钥写入 Agent 配置。",
        trust_impact="降低信任评分：配置中存在可直接滥用的敏感凭据。",
        pattern=re.compile(r"(?i)\b(api[_-]?key|secret|token|access[_-]?key)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}"),
    ),
]

AGENT_FILE_EXTENSIONS = {".md", ".yaml", ".yml", ".json", ".toml"}
AGENT_FILE_NAMES = {"Dockerfile", "AGENTS.md", "CLAUDE.md", "mcp.json", "plugin.json", "tools.json"}
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
        lines = file_path.read_text(encoding="utf-8-sig", errors="ignore").splitlines()
    except OSError:
        return []

    findings: list[AgentFinding] = []
    for line_number, line in enumerate(lines, start=1):
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
