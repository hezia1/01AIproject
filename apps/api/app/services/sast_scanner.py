from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from app.models import Severity
from app.services.sast_noise import IGNORED_DIRS, is_noise_path


@dataclass(frozen=True)
class SastRule:
    rule_id: str
    title: str
    severity: Severity
    category: str
    cwe: str
    owasp: str
    description: str
    remediation: str
    pattern: re.Pattern[str]
    file_extensions: set[str] | None = None


@dataclass(frozen=True)
class ParsedFinding:
    rule_id: str
    title: str
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    evidence: str
    category: str
    cwe: str
    owasp: str
    description: str
    remediation: str
    language: str


@dataclass(frozen=True)
class SastScanOutput:
    findings: list[ParsedFinding]
    scanned_files: list[str]


SAST_RULES = [
    SastRule(
        rule_id="SAST.SECRET.HARDCODED_PASSWORD",
        title="疑似硬编码密码",
        severity=Severity.high,
        category="secret",
        cwe="CWE-798",
        owasp="A02:2021 Cryptographic Failures",
        description="源码中出现硬编码密码，泄露后会导致账号、数据库或第三方服务被直接访问。",
        remediation="删除硬编码密码，改用环境变量、密钥管理服务或运行时安全配置注入。",
        pattern=re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
    ),
    SastRule(
        rule_id="SAST.SECRET.API_KEY",
        title="疑似硬编码 API Key 或 Secret",
        severity=Severity.high,
        category="secret",
        cwe="CWE-798",
        owasp="A02:2021 Cryptographic Failures",
        description="源码中出现疑似 API Key、Token 或 Secret，可能造成接口滥用或供应链凭据泄露。",
        remediation="立即轮换已暴露密钥，并使用 Secret Manager、环境变量或 CI/CD 密钥变量管理。",
        pattern=re.compile(r"(?i)\b(api[_-]?key|secret|token|access[_-]?key)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]"),
    ),
    SastRule(
        rule_id="SAST.CMD.OS_SYSTEM",
        title="危险命令执行调用",
        severity=Severity.critical,
        category="rce",
        cwe="CWE-78",
        owasp="A03:2021 Injection",
        description="代码调用系统命令执行接口，如果参数可被用户控制，可能导致远程命令执行。",
        remediation="避免拼接系统命令；必须执行时使用参数数组、白名单命令和严格输入校验。",
        pattern=re.compile(r"\b(os\.system|subprocess\.(Popen|call|run)|child_process\.(exec|spawn))\s*\("),
    ),
    SastRule(
        rule_id="SAST.CODE.EVAL_EXEC",
        title="危险动态代码执行",
        severity=Severity.critical,
        category="rce",
        cwe="CWE-95",
        owasp="A03:2021 Injection",
        description="动态执行字符串代码会扩大攻击面，用户可控输入进入后可能造成任意代码执行。",
        remediation="移除 eval/exec，改为白名单解析、固定表达式解释器或安全 DSL。",
        pattern=re.compile(r"\b(eval|exec)\s*\("),
    ),
    SastRule(
        rule_id="SAST.SQL.STRING_CONCAT",
        title="疑似 SQL 字符串拼接",
        severity=Severity.high,
        category="injection",
        cwe="CWE-89",
        owasp="A03:2021 Injection",
        description="SQL 语句通过字符串拼接或格式化生成，用户输入进入后可能造成 SQL 注入。",
        remediation="使用参数化查询、ORM 查询参数绑定或预编译语句，禁止拼接用户输入。",
        pattern=re.compile(r"(?i)(select|insert|update|delete)\s+.+(\+|%|\.format\(|f['\"])")
    ),
    SastRule(
        rule_id="SAST.SSRF.USER_CONTROLLED_REQUEST",
        title="疑似用户可控 SSRF 请求",
        severity=Severity.high,
        category="ssrf",
        cwe="CWE-918",
        owasp="A10:2021 Server-Side Request Forgery",
        description="请求目标可能来自用户输入，攻击者可借服务端访问内网或云元数据地址。",
        remediation="对目标 URL 做协议、域名、IP 段白名单校验，并禁止访问内网和元数据地址。",
        pattern=re.compile(r"\b(requests\.(get|post|put|delete)|axios\.(get|post)|fetch)\s*\(\s*(url|target|input|request|req\.)"),
    ),
    SastRule(
        rule_id="SAST.PATH.TRAVERSAL_JOIN",
        title="疑似路径穿越风险",
        severity=Severity.medium,
        category="path-traversal",
        cwe="CWE-22",
        owasp="A01:2021 Broken Access Control",
        description="文件路径可能由用户输入控制，未规范化校验时可能访问越权文件。",
        remediation="使用固定根目录、路径规范化和白名单文件名校验，拒绝包含 .. 或绝对路径的输入。",
        pattern=re.compile(r"\b(open|readFile|writeFile|send_file)\s*\(.+(filename|filepath|path|req\.|request\.)"),
    ),
    SastRule(
        rule_id="SAST.CRYPTO.WEAK_HASH",
        title="弱加密或弱哈希算法使用",
        severity=Severity.medium,
        category="crypto",
        cwe="CWE-327",
        owasp="A02:2021 Cryptographic Failures",
        description="MD5、SHA1、DES、RC4 等算法已不适合安全场景，可能被碰撞或破解。",
        remediation="密码存储使用 bcrypt/argon2；完整性校验使用 SHA-256/HMAC；加密使用 AES-GCM 等现代算法。",
        pattern=re.compile(r"\b(md5|sha1|DES|RC4)\b", re.IGNORECASE),
    ),
    SastRule(
        rule_id="SAST.CONFIG.DEBUG_ENABLED",
        title="疑似调试模式开启",
        severity=Severity.medium,
        category="config",
        cwe="CWE-489",
        owasp="A05:2021 Security Misconfiguration",
        description="生产环境开启调试模式可能暴露堆栈、环境变量和内部路径。",
        remediation="区分开发和生产配置，生产环境关闭 debug/dev mode 并限制错误详情输出。",
        pattern=re.compile(r"(?i)\b(debug|dev_mode)\b\s*[:=]\s*(true|1|yes)")
    ),
]

SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".php", ".rb", ".cs",
    ".yaml", ".yml", ".json", ".env", ".properties", ".xml",
}

MAX_FILE_BYTES = 512 * 1024


def scan_source_tree(source_path: str) -> SastScanOutput:
    root = Path(source_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("source_path must be an existing directory")

    findings: list[ParsedFinding] = []
    scanned_files: list[str] = []
    for file_path in iter_source_files(root):
        relative_path = file_path.relative_to(root).as_posix()
        scanned_files.append(relative_path)
        findings.extend(scan_file(file_path, relative_path))

    return SastScanOutput(findings=dedupe_findings(findings), scanned_files=scanned_files)


def iter_source_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if is_noise_path(path.relative_to(root).as_posix()):
            continue
        if path.suffix not in SOURCE_EXTENSIONS and path.name != ".env":
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def scan_file(file_path: Path, relative_path: str) -> list[ParsedFinding]:
    try:
        lines = file_path.read_text(encoding="utf-8-sig", errors="ignore").splitlines()
    except OSError:
        return []

    language = detect_language(file_path)
    findings: list[ParsedFinding] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        for rule in SAST_RULES:
            if rule.file_extensions and file_path.suffix not in rule.file_extensions:
                continue
            if rule.pattern.search(stripped):
                findings.append(
                    ParsedFinding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        file_path=relative_path,
                        line_start=line_number,
                        line_end=line_number,
                        evidence=redact_evidence(stripped),
                        category=rule.category,
                        cwe=rule.cwe,
                        owasp=rule.owasp,
                        description=rule.description,
                        remediation=rule.remediation,
                        language=language,
                    )
                )
    return findings


def detect_language(file_path: Path) -> str:
    suffix = file_path.suffix.lower()
    if suffix == ".py":
        return "Python"
    if suffix in {".js", ".jsx"}:
        return "JavaScript"
    if suffix in {".ts", ".tsx"}:
        return "TypeScript"
    if suffix == ".java":
        return "Java"
    if suffix == ".go":
        return "Go"
    if suffix in {".yaml", ".yml", ".json", ".env", ".properties", ".xml"} or file_path.name == ".env":
        return "Config"
    return suffix.removeprefix(".").upper() or "Unknown"


def redact_evidence(line: str) -> str:
    redacted = re.sub(
        r"(?i)(password|passwd|pwd|api[_-]?key|secret|token|access[_-]?key)(\s*[:=]\s*)['\"][^'\"]+['\"]",
        r"\1\2\"***REDACTED***\"",
        line,
    )
    return redacted[:500]


def dedupe_findings(findings: list[ParsedFinding]) -> list[ParsedFinding]:
    seen: set[tuple[str, str, int, str]] = set()
    deduped: list[ParsedFinding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line_start, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
