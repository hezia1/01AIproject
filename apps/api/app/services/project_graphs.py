from __future__ import annotations

import ast
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Iterable
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db_models import (
    DastBusinessFlowRecord,
    DastValidationRecord,
    KnowledgeEntryRecord,
    ProjectGraphSnapshotRecord,
    ProjectRecord,
    SandboxEvidenceRecord,
)
from app.services.finding_retest import current_finding_records


GENERATOR_VERSION = "project-graph-v1"
SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
IGNORED_DIRECTORIES = {".git", ".venv", "venv", "node_modules", "dist", "build", "coverage", "vendor", "__pycache__"}
MAX_FILES = 1200
MAX_TOTAL_BYTES = 60 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_NODES = 5000
MAX_EDGES = 10000
ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "route", "use"}


def graph_key(prefix: str, *parts: object) -> str:
    raw = "|".join(str(part) for part in parts)
    return f"{prefix}:{sha256(raw.encode('utf-8')).hexdigest()[:24]}"


class GraphBuilder:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, object]] = {}
        self.edges: dict[tuple[str, str, str], dict[str, object]] = {}
        self.truncated = False

    def node(self, node_id: str, kind: str, label: str, *, file_path: str | None = None,
             line: int | None = None, attributes: dict[str, object] | None = None) -> str:
        if node_id not in self.nodes:
            if len(self.nodes) >= MAX_NODES:
                self.truncated = True
                return node_id
            self.nodes[node_id] = {"id": node_id, "kind": kind, "label": label,
                                   "file_path": file_path, "line": line,
                                   "attributes": attributes or {}}
        return node_id

    def edge(self, source: str, target: str, relation: str, confidence: int, basis: str) -> None:
        if source not in self.nodes or target not in self.nodes:
            return
        key = (source, target, relation)
        if key in self.edges:
            return
        if len(self.edges) >= MAX_EDGES:
            self.truncated = True
            return
        self.edges[key] = {"id": graph_key("edge", *key), "source": source, "target": target,
                           "relation": relation, "confidence": confidence, "basis": basis}

    def result(self) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        return (sorted(self.nodes.values(), key=lambda item: (str(item["kind"]), str(item["label"]), str(item["id"]))),
                sorted(self.edges.values(), key=lambda item: (str(item["relation"]), str(item["source"]), str(item["target"]))))


def build_code_graph(source_path: str | None) -> dict[str, object]:
    if not source_path:
        raise ValueError("项目没有配置源码路径")
    root = Path(source_path).resolve()
    if not root.is_dir():
        raise ValueError("项目源码目录不存在或不可读取")
    builder = GraphBuilder()
    project_id = "code:project"
    builder.node(project_id, "project", root.name, attributes={"source_root": str(root)})
    files, skipped, total_bytes = collect_source_files(root)
    digest = sha256()
    file_ids: dict[str, str] = {}
    contents: dict[str, str] = {}
    for path in files:
        relative = path.relative_to(root).as_posix()
        raw = path.read_bytes()
        digest.update(relative.encode("utf-8")); digest.update(b"\0"); digest.update(raw); digest.update(b"\0")
        contents[relative] = raw.decode("utf-8", errors="replace")
        file_id = graph_key("file", relative)
        file_ids[relative] = file_id
        builder.node(file_id, "file", relative, file_path=relative,
                     attributes={"language": language_for(path.suffix.lower()), "size_bytes": len(raw)})
        builder.edge(project_id, file_id, "contains", 100, "source tree")

    for relative, content in contents.items():
        suffix = Path(relative).suffix.lower()
        if suffix == ".py":
            parse_python(relative, content, builder, file_ids)
        else:
            parse_javascript(relative, content, builder, file_ids)

    nodes, edges = builder.result()
    kinds = Counter(str(item["kind"]) for item in nodes)
    relations = Counter(str(item["relation"]) for item in edges)
    limitations = [
        "代码图谱是静态、启发式关系快照，不证明运行时真实调用。",
        "Python 使用标准 AST；JavaScript/TypeScript 使用保守语法模式，动态导入、反射、框架注入和生成代码可能无法解析。",
        "调用目标无法唯一解析时保留为外部/未解析符号，并降低关系可信度。",
    ]
    if skipped or builder.truncated:
        limitations.append(f"达到读取或图规模上限：跳过 {skipped} 个文件；图截断={builder.truncated}。")
    return {"source_fingerprint": digest.hexdigest(), "nodes": nodes, "edges": edges,
            "summary": {"file_count": len(files), "inspected_bytes": total_bytes,
                        "node_count": len(nodes), "edge_count": len(edges),
                        "node_kinds": dict(kinds), "relations": dict(relations),
                        "skipped_file_count": skipped, "truncated": bool(skipped or builder.truncated)},
            "limitations": limitations}


def collect_source_files(root: Path) -> tuple[list[Path], int, int]:
    selected: list[Path] = []
    skipped = 0
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().lower()):
        try:
            relative_parts = path.relative_to(root).parts
            if any(part.casefold() in IGNORED_DIRECTORIES for part in relative_parts) or path.is_symlink() or not path.is_file():
                continue
            if path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            size = path.stat().st_size
        except OSError:
            skipped += 1
            continue
        if size > MAX_FILE_BYTES or len(selected) >= MAX_FILES or total + size > MAX_TOTAL_BYTES:
            skipped += 1
            continue
        selected.append(path); total += size
    return selected, skipped, total


def language_for(suffix: str) -> str:
    return "python" if suffix == ".py" else "typescript" if suffix in {".ts", ".tsx"} else "javascript"


def parse_python(relative: str, content: str, builder: GraphBuilder, file_ids: dict[str, str]) -> None:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        builder.nodes[file_ids[relative]]["attributes"] = {**builder.nodes[file_ids[relative]]["attributes"], "parse_status": "syntax_error"}
        return
    module_name = relative[:-3].replace("/", ".")
    symbol_ids: dict[str, str] = {}

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.stack: list[tuple[str, str]] = [(module_name, file_ids[relative])]

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self._visit_symbol(node, "class")

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_symbol(node, "function")

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_symbol(node, "function")

        def _visit_symbol(self, node: ast.AST, kind: str) -> None:
            name = getattr(node, "name")
            qualified = f"{self.stack[-1][0]}.{name}"
            symbol_id = graph_key("symbol", relative, qualified)
            symbol_ids[name] = symbol_id
            builder.node(symbol_id, kind, qualified, file_path=relative, line=getattr(node, "lineno", None),
                         attributes={"language": "python"})
            builder.edge(self.stack[-1][1], symbol_id, "contains", 100, "Python AST")
            for decorator in getattr(node, "decorator_list", []):
                route = python_route(decorator)
                if route:
                    method, path = route
                    route_id = graph_key("route", method, path, relative, qualified)
                    builder.node(route_id, "route", f"{method} {path}", file_path=relative,
                                 line=getattr(decorator, "lineno", None),
                                 attributes={"method": method, "path": path, "handler": qualified})
                    builder.edge(route_id, symbol_id, "handled_by", 100, "Python route decorator")
                    builder.edge(file_ids[relative], route_id, "exposes", 100, "Python route decorator")
            self.stack.append((qualified, symbol_id)); self.generic_visit(node); self.stack.pop()

        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                add_import(builder, file_ids[relative], relative, alias.name, file_ids, node.lineno)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            if node.module:
                add_import(builder, file_ids[relative], relative, node.module, file_ids, node.lineno)

        def visit_Call(self, node: ast.Call) -> None:
            if len(self.stack) > 1:
                name = call_name(node.func)
                if name:
                    target = symbol_ids.get(name.split(".")[-1])
                    if target is None:
                        target = graph_key("call", name)
                        builder.node(target, "external_symbol", name, attributes={"resolution": "unresolved"})
                    builder.edge(self.stack[-1][1], target, "calls", 75 if target in symbol_ids.values() else 45, "Python AST call")
            self.generic_visit(node)

    Visitor().visit(tree)


def python_route(decorator: ast.AST) -> tuple[str, str] | None:
    if not isinstance(decorator, ast.Call) or not decorator.args or not isinstance(decorator.args[0], ast.Constant):
        return None
    name = call_name(decorator.func).lower()
    method = name.split(".")[-1]
    if method not in ROUTE_METHODS or not isinstance(decorator.args[0].value, str):
        return None
    if method == "route":
        method = "ANY"
        for keyword in decorator.keywords:
            if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)) and keyword.value.elts:
                value = keyword.value.elts[0]
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    method = value.value.upper()
    return method.upper(), decorator.args[0].value


def call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def add_import(builder: GraphBuilder, source_id: str, relative: str, module: str,
               file_ids: dict[str, str], line: int) -> None:
    candidates = [module.replace(".", "/") + ".py", module.replace(".", "/") + "/__init__.py"]
    local = next((file_ids[item] for item in candidates if item in file_ids), None)
    if local:
        builder.edge(source_id, local, "imports", 90, f"Python import line {line}")
    else:
        dependency = module.split(".")[0]
        target = graph_key("dependency", "python", dependency)
        builder.node(target, "external_dependency", dependency, attributes={"ecosystem": "PyPI"})
        builder.edge(source_id, target, "imports", 70, f"Python import line {line}")


JS_IMPORT = re.compile(r"(?m)(?:import\s+(?:[^;]+?\s+from\s+)?|require\s*\()\s*['\"]([^'\"]+)['\"]")
JS_SYMBOL = re.compile(r"(?m)^\s*(?:export\s+)?(?:async\s+)?(?:function\s+([A-Za-z_$][\w$]*)|class\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)")
JS_ROUTE = re.compile(r"(?m)\b(?:app|router|server)\s*\.\s*(get|post|put|patch|delete|options|head|use)\s*\(\s*['\"]([^'\"]+)['\"]\s*,([^\n)]*)")
JS_CALL = re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\(")


def parse_javascript(relative: str, content: str, builder: GraphBuilder, file_ids: dict[str, str]) -> None:
    file_id = file_ids[relative]
    symbols: dict[str, str] = {}
    for match in JS_SYMBOL.finditer(content):
        name = next(value for value in match.groups() if value)
        kind = "class" if match.group(2) else "function"
        symbol_id = graph_key("symbol", relative, name)
        symbols[name] = symbol_id
        builder.node(symbol_id, kind, name, file_path=relative, line=line_number(content, match.start()),
                     attributes={"language": language_for(Path(relative).suffix.lower())})
        builder.edge(file_id, symbol_id, "contains", 90, "JavaScript/TypeScript syntax pattern")
    for match in JS_IMPORT.finditer(content):
        imported = match.group(1)
        local = resolve_js_import(relative, imported, file_ids)
        if local:
            builder.edge(file_id, local, "imports", 85, "JavaScript/TypeScript import")
        else:
            package = imported.split("/")[0] if not imported.startswith("@") else "/".join(imported.split("/")[:2])
            target = graph_key("dependency", "npm", package)
            builder.node(target, "external_dependency", package, attributes={"ecosystem": "npm"})
            builder.edge(file_id, target, "imports", 65, "JavaScript/TypeScript import")
    for match in JS_ROUTE.finditer(content):
        method, path, arguments = match.groups()
        handler_candidates = re.findall(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+|[A-Za-z_$][\w$]*", arguments)
        handler = handler_candidates[-1] if handler_candidates and "=>" not in arguments else None
        route_id = graph_key("route", method, path, relative, handler or match.start())
        builder.node(route_id, "route", f"{method.upper()} {path}", file_path=relative,
                     line=line_number(content, match.start()),
                     attributes={"method": method.upper(), "path": path, "handler": handler})
        builder.edge(file_id, route_id, "exposes", 90, "Express-compatible route syntax")
        if handler:
            handler_id = symbols.get(handler)
            if handler_id is None:
                handler_id = graph_key("call", relative, handler)
                builder.node(handler_id, "external_symbol", handler,
                             attributes={"resolution": "cross-file-or-unresolved"})
            builder.edge(route_id, handler_id, "handled_by", 85 if handler in symbols else 55,
                         "Explicit route handler argument")
    for name in set(match.group(1) for match in JS_CALL.finditer(content)):
        if name in {"if", "for", "while", "switch", "catch", "function", "require"}:
            continue
        target = symbols.get(name.split(".")[-1])
        if target is None:
            target = graph_key("call", name)
            builder.node(target, "external_symbol", name, attributes={"resolution": "unresolved"})
        builder.edge(file_id, target, "calls", 55 if target in symbols.values() else 35, "JavaScript/TypeScript call pattern")


def resolve_js_import(relative: str, imported: str, file_ids: dict[str, str]) -> str | None:
    if not imported.startswith("."):
        return None
    base = (Path(relative).parent / imported).as_posix()
    candidates = [base, *(base + suffix for suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")),
                  *(base + "/index" + suffix for suffix in (".js", ".jsx", ".ts", ".tsx"))]
    return next((file_ids[item] for item in candidates if item in file_ids), None)


def line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


def build_business_graph(db: Session, project: ProjectRecord, code_snapshot: ProjectGraphSnapshotRecord | None) -> dict[str, object]:
    builder = GraphBuilder()
    project_id = graph_key("business-project", project.id)
    builder.node(project_id, "project", project.name, attributes={"business_owner": project.business_owner, "security_owner": project.security_owner})
    code_routes = [node for node in (code_snapshot.nodes if code_snapshot else []) if node.get("kind") == "route"]
    for route in code_routes:
        node_id = f"business-{route['id']}"
        builder.node(node_id, "route", str(route.get("label")), file_path=route.get("file_path"), line=route.get("line"),
                     attributes={**dict(route.get("attributes") or {}), "code_node_id": route["id"]})
        builder.edge(project_id, node_id, "exposes", 100, f"code graph v{code_snapshot.version}")

    findings = current_finding_records(db, project.id)
    finding_nodes: dict[str, str] = {}
    for finding in findings:
        node_id = graph_key("finding", finding.id); finding_nodes[str(finding.id)] = node_id
        builder.node(node_id, "finding", finding.title, file_path=finding.file_path, line=finding.line_start,
                     attributes={"source": finding.source, "rule_id": finding.rule_id, "severity": finding.severity, "status": finding.status})
        builder.edge(project_id, node_id, "has_risk", 100, "current Finding")
        for route in code_routes:
            if finding.file_path and normalize_path(finding.file_path) == normalize_path(str(route.get("file_path") or "")):
                builder.edge(f"business-{route['id']}", node_id, "has_risk", 70, "same source file; review required")

    flows = list(db.scalars(select(DastBusinessFlowRecord).where(DastBusinessFlowRecord.project_id == project.id)).all())
    for flow in flows:
        flow_id = graph_key("flow", flow.id)
        path = urlparse(flow.target_url).path or "/"
        builder.node(flow_id, "business_flow", flow.name, attributes={"status": flow.status, "target_url": flow.target_url,
                     "flow_mode": flow.flow_mode, "allowed_paths": flow.allowed_paths or []})
        builder.edge(project_id, flow_id, "contains", 100, "project business flow")
        if flow.finding_id and str(flow.finding_id) in finding_nodes:
            builder.edge(flow_id, finding_nodes[str(flow.finding_id)], "validates", 100, "flow.finding_id")
        for role in flow.roles or []:
            if not isinstance(role, dict):
                continue
            alias = str(role.get("alias") or role.get("name") or "").strip()
            if not alias:
                continue
            role_id = graph_key("role", flow.id, alias)
            builder.node(role_id, "role", alias, attributes={"source": "DAST business flow"})
            builder.edge(role_id, flow_id, "participates_in", 100, "flow.roles")
        candidate_paths = {path, *(str(item) for item in (flow.allowed_paths or []))}
        for route in code_routes:
            route_path = str((route.get("attributes") or {}).get("path") or "")
            if route_path and route_path in candidate_paths:
                builder.edge(flow_id, f"business-{route['id']}", "targets", 90, "configured target/allowed path")

    validations = list(db.scalars(select(DastValidationRecord).where(DastValidationRecord.project_id == project.id)).all())
    validation_nodes: dict[str, str] = {}
    for validation in validations:
        node_id = graph_key("validation", validation.id); validation_nodes[str(validation.id)] = node_id
        builder.node(node_id, "validation", validation.strategy_name or validation.strategy_id,
                     attributes={"verdict": validation.verdict, "target_url": validation.target_url})
        builder.edge(project_id, node_id, "contains", 100, "project validation")
        if validation.finding_id and str(validation.finding_id) in finding_nodes:
            builder.edge(finding_nodes[str(validation.finding_id)], node_id, "validated_by",
                         int(validation.link_confidence or 0), validation.link_source or "finding_id")

    evidence_records = list(db.scalars(select(SandboxEvidenceRecord).where(SandboxEvidenceRecord.project_id == project.id)).all())
    for evidence in evidence_records:
        node_id = graph_key("evidence", evidence.id)
        builder.node(node_id, "evidence", evidence.strategy_name or "SANDBOX 运行证据",
                     attributes={"link_source": evidence.link_source, "confidence": evidence.link_confidence})
        builder.edge(project_id, node_id, "contains", 100, "project evidence")
        if evidence.validation_id and str(evidence.validation_id) in validation_nodes:
            builder.edge(validation_nodes[str(evidence.validation_id)], node_id, "observed_by",
                         int(evidence.link_confidence or 0), evidence.link_source or "validation_id")
        elif evidence.finding_id and str(evidence.finding_id) in finding_nodes:
            builder.edge(finding_nodes[str(evidence.finding_id)], node_id, "observed_by",
                         int(evidence.link_confidence or 0), evidence.link_source or "finding_id")

    entries = list(db.scalars(select(KnowledgeEntryRecord).where(
        KnowledgeEntryRecord.tenant_id == project.tenant_id, KnowledgeEntryRecord.status == "published")).all())
    for entry in entries:
        matches = [finding for finding in findings if str(finding.id) == str(entry.source_finding_id) or finding.rule_id == entry.rule_id]
        if not matches:
            continue
        node_id = graph_key("knowledge", entry.id)
        builder.node(node_id, "knowledge", entry.title,
                     attributes={"knowledge_type": entry.knowledge_type, "rule_id": entry.rule_id,
                                 "source_project_id": str(entry.source_project_id), "version": entry.version})
        for finding in matches:
            confidence = 100 if str(finding.id) == str(entry.source_finding_id) else 80
            basis = "source_finding_id" if confidence == 100 else "same published rule_id"
            builder.edge(node_id, finding_nodes[str(finding.id)], "applies_to", confidence, basis)

    nodes, edges = builder.result()
    fingerprint_payload = {"code": code_snapshot.source_fingerprint if code_snapshot else None,
                           "flows": [str(item.id) + ":" + str(item.updated_at) for item in flows],
                           "findings": [str(item.id) + ":" + str(item.updated_at) for item in findings],
                           "validations": [str(item.id) + ":" + str(item.updated_at) for item in validations],
                           "evidence": [str(item.id) + ":" + str(item.created_at) for item in evidence_records],
                           "knowledge": [str(item.id) + ":" + str(item.version) for item in entries]}
    kinds = Counter(str(item["kind"]) for item in nodes); relations = Counter(str(item["relation"]) for item in edges)
    limitations = [
        "业务知识图谱只连接数据库中的显式关系；同源码文件和同规则关系会标明较低可信度，必须人工复核。",
        "没有 DAST 业务流程、角色、验证或已发布知识时，对应节点保持为空，不根据名称猜测业务语义。",
        "该快照是单项目视图，不等于组织级跨项目风险图谱。",
    ]
    if code_snapshot is None:
        limitations.append("尚无代码图谱快照，因此无法关联业务流程与源码路由。")
    return {"source_fingerprint": sha256(json.dumps(fingerprint_payload, sort_keys=True).encode()).hexdigest(),
            "nodes": nodes, "edges": edges,
            "summary": {"node_count": len(nodes), "edge_count": len(edges), "node_kinds": dict(kinds),
                        "relations": dict(relations), "code_graph_version": code_snapshot.version if code_snapshot else None,
                        "current_finding_count": len(findings), "business_flow_count": len(flows)},
            "limitations": limitations}


def normalize_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./").casefold()
