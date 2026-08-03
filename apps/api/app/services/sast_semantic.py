"""Small, transparent semantic checks for source-to-sink paths.

This is deliberately a bounded intraprocedural analysis: Python is parsed with
the standard-library AST and JavaScript/TypeScript receives a conservative
line-level data-flow pass. It complements Semgrep; it does not claim whole
program taint reachability.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from app.models import Severity
from app.services.sast_scanner import ParsedFinding, detect_language, redact_evidence


SINKS = {
    "sql": ("SQL query receives request-controlled data", "CWE-89", "A03:2021 Injection", Severity.high, "Use parameter binding or an ORM query API; never concatenate request input into SQL."),
    "command": ("Command execution receives request-controlled data", "CWE-78", "A03:2021 Injection", Severity.critical, "Use a fixed command with argument arrays and a strict allow-list."),
    "ssrf": ("Outbound request receives request-controlled URL", "CWE-918", "A10:2021 Server-Side Request Forgery", Severity.high, "Allow-list schemes, hosts and resolved IP ranges before making the request."),
    "path": ("File operation receives request-controlled path", "CWE-22", "A01:2021 Broken Access Control", Severity.high, "Resolve against a fixed root and reject traversal or absolute paths."),
    "deserialize": ("Unsafe deserialization receives request-controlled data", "CWE-502", "A08:2021 Software and Data Integrity Failures", Severity.high, "Use a safe data format and a restricted loader; never deserialize untrusted objects."),
}

SOURCE_MARKERS = ("request.", "request[", "req.", "ctx.request", "input(", "argv", "query.", "params.", "body.", "form.", "cookies.")
SANITIZER_MARKERS = ("safe_join", "secure_filename", "shlex.quote", "validate_url", "is_safe_url", "urlparse", "quote_plus", "parameterized", "sanitize")


def scan_semantic_file(file_path: Path, relative_path: str) -> list[ParsedFinding]:
    if file_path.suffix.lower() == ".py":
        return _scan_python(file_path, relative_path)
    if file_path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx"}:
        return _scan_javascript(file_path, relative_path)
    return []


def _scan_python(file_path: Path, relative_path: str) -> list[ParsedFinding]:
    try:
        source = file_path.read_text(encoding="utf-8-sig", errors="ignore")
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return []
    visitor = _PythonTaintVisitor(source, relative_path)
    visitor.visit(tree)
    return visitor.findings


class _PythonTaintVisitor(ast.NodeVisitor):
    def __init__(self, source: str, relative_path: str) -> None:
        self.source = source
        self.relative_path = relative_path
        self.tainted: set[str] = set()
        self.findings: list[ParsedFinding] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        tainted = self._is_tainted(node.value) and not self._is_sanitized(node.value)
        for target in node.targets:
            for name in _assigned_names(target):
                if tainted:
                    self.tainted.add(name)
                else:
                    self.tainted.discard(name)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            tainted = self._is_tainted(node.value) and not self._is_sanitized(node.value)
            for name in _assigned_names(node.target):
                if tainted:
                    self.tainted.add(name)
                else:
                    self.tainted.discard(name)

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        kind = _python_sink_kind(_dotted_name(node.func))
        if kind is None or not node.args:
            return
        relevant = node.args if kind != "command" else node.args[:1]
        if any(self._is_tainted(argument) and not self._is_sanitized(argument) for argument in relevant):
            self._add(kind, node)

    def _is_tainted(self, node: ast.AST) -> bool:
        rendered = _dotted_name(node).lower()
        if any(marker in rendered for marker in SOURCE_MARKERS):
            return True
        return any(isinstance(child, ast.Name) and child.id in self.tainted for child in ast.walk(node))

    def _is_sanitized(self, node: ast.AST) -> bool:
        return any(marker in _dotted_name(child).lower() for child in ast.walk(node) if isinstance(child, ast.Call) for marker in SANITIZER_MARKERS)

    def _add(self, kind: str, node: ast.Call) -> None:
        title, cwe, owasp, severity, remediation = SINKS[kind]
        snippet = ast.get_source_segment(self.source, node) or _dotted_name(node.func)
        self.findings.append(ParsedFinding(
            rule_id=f"SAST.TAINT.PYTHON.{kind.upper()}", title=title, severity=severity,
            file_path=self.relative_path, line_start=node.lineno, line_end=getattr(node, "end_lineno", node.lineno),
            evidence=redact_evidence(snippet), category=kind, cwe=cwe, owasp=owasp,
            description="A request-controlled source reaches a sensitive sink in the same Python scope. The result is a bounded AST/data-flow finding and needs contextual review.",
            remediation=remediation, language="Python",
        ))


def _scan_javascript(file_path: Path, relative_path: str) -> list[ParsedFinding]:
    try:
        lines = file_path.read_text(encoding="utf-8-sig", errors="ignore").splitlines()
    except OSError:
        return []
    tainted: set[str] = set()
    findings: list[ParsedFinding] = []
    for line_number, line in enumerate(lines, start=1):
        lowered = line.lower()
        assignment = re.search(r"(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*(.+)", line)
        if assignment:
            name, value = assignment.groups()
            if any(marker in value.lower() for marker in SOURCE_MARKERS) or any(re.search(rf"\b{re.escape(item)}\b", value) for item in tainted):
                if not any(marker in value.lower() for marker in SANITIZER_MARKERS):
                    tainted.add(name)
        sink = _javascript_sink_kind(lowered)
        if sink is None:
            continue
        if any(re.search(rf"\b{re.escape(name)}\b", line) for name in tainted) and not any(marker in lowered for marker in SANITIZER_MARKERS):
            title, cwe, owasp, severity, remediation = SINKS[sink]
            findings.append(ParsedFinding(
                rule_id=f"SAST.TAINT.JAVASCRIPT.{sink.upper()}", title=title, severity=severity,
                file_path=relative_path, line_start=line_number, line_end=line_number, evidence=redact_evidence(line.strip()),
                category=sink, cwe=cwe, owasp=owasp,
                description="A request-controlled source reaches a sensitive JavaScript/TypeScript sink in the same file. This is conservative data-flow evidence, not whole-program proof.",
                remediation=remediation, language=detect_language(file_path),
            ))
    return findings


def _assigned_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for element in node.elts for name in _assigned_names(element)]
    return []


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Subscript):
        return f"{_dotted_name(node.value)}[...]"
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return ""


def _python_sink_kind(name: str) -> str | None:
    normalized = name.lower()
    if normalized.endswith((".execute", ".executemany", ".raw")):
        return "sql"
    if normalized in {"os.system", "os.popen"} or normalized.startswith("subprocess."):
        return "command"
    if normalized.startswith(("requests.", "httpx.", "urllib.request.")):
        return "ssrf"
    if normalized in {"open", "send_file", "send_from_directory"} or normalized.endswith((".read_text", ".write_text", ".open")):
        return "path"
    if normalized.startswith(("pickle.", "marshal.")) or normalized == "yaml.load":
        return "deserialize"
    return None


def _javascript_sink_kind(line: str) -> str | None:
    if re.search(r"\b(query|execute)\s*\(", line):
        return "sql"
    if re.search(r"\b(exec|execsync|spawn|spawnSync)\s*\(", line):
        return "command"
    if re.search(r"\b(fetch|axios\.(get|post|request)|got)\s*\(", line):
        return "ssrf"
    if re.search(r"\b(readfile|writefile|createReadStream|sendfile)\s*\(", line):
        return "path"
    if re.search(r"\b(yaml\.load|deserialize|unserialize)\s*\(", line):
        return "deserialize"
    return None
