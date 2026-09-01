from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urljoin, urlparse

from app.services.sandbox_identity import automatic_ref, roles_ready


URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
PATH_PATTERN = re.compile(r"(?<![\w.])(/(?:api|v\d+|graphql|admin|auth|login|user|order|agent)[\w./{}:-]*)", re.IGNORECASE)
METHOD_PATTERN = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", re.IGNORECASE)
PARAMETER_PATTERNS = (
    re.compile(r"(?:param(?:eter)?|参数|字段)\s*[:=]\s*['\"]?([A-Za-z_][\w.-]{0,80})", re.IGNORECASE),
    re.compile(r"[?&]([A-Za-z_][\w.-]{0,80})="),
)
LOCATED_PARAMETER_PATTERN = re.compile(r"(?:param(?:eter)?|参数|字段)?\s*(query|url|path|body|json|header|cookie|form)\s*[:=]\s*['\"]?([A-Za-z_][\w.-]{0,80})", re.IGNORECASE)
REQUEST_MEMBER_PATTERN = re.compile(
    r"\breq(?:uest)?\s*\.\s*(query|body|params|headers|cookies|files)\s*(?:\.\s*([A-Za-z_]\w{0,80})|\[\s*['\"]([^'\"]{1,80})['\"]\s*\])",
    re.IGNORECASE,
)
GET_PARAMETER_PATTERN = re.compile(r"\b(?:request|req)\s*\.\s*getParameter\s*\(\s*['\"]([^'\"]{1,80})['\"]\s*\)", re.IGNORECASE)
STATIC_ONLY_RULE_TOKENS = (
    "history_secret", "hardcoded", "api_key", "credential material", "weak_hash", "weak hash", "weak crypto",
    "auth_events_not_audited", "insufficient_logging", "cwe-778",
    "cwe-798", "cwe-259", "cwe-321", "cwe-327",
)
DAST_FLOW_NAME_MAX_LENGTH = 200


def bounded_strategy_name(title: object, suffix: str, fallback: str) -> str:
    """Build a readable strategy name that always fits the database column."""
    normalized_title = re.sub(r"\s+", " ", str(title or fallback)).strip() or fallback
    normalized_suffix = re.sub(r"\s+", " ", str(suffix)).strip()
    tail = f" · {normalized_suffix}" if normalized_suffix else ""
    title_budget = DAST_FLOW_NAME_MAX_LENGTH - len(tail)
    if len(normalized_title) > title_budget:
        normalized_title = normalized_title[:max(1, title_budget - 1)].rstrip(" ·:;-") + "…"
    return f"{normalized_title}{tail}"[:DAST_FLOW_NAME_MAX_LENGTH]


@lru_cache(maxsize=32)
def _request_body_location(source_root: str) -> str:
    """Infer the web application's request-body transport from local setup.

    ``req.body`` identifies a logical body field, not whether the route accepts
    JSON or an HTML form.  Treating every Express body as JSON made otherwise
    correct cross-project probes miss form-only applications.
    """
    if not source_root:
        return "json"
    try:
        root = Path(source_root).resolve(strict=True)
    except (OSError, ValueError):
        return "json"
    urlencoded = False
    json_body = False
    try:
        for candidate in root.rglob("*.js"):
            if any(part in {"node_modules", ".git", "dist", "build"} for part in candidate.parts) or candidate.stat().st_size > 1_000_000:
                continue
            text = candidate.read_text(encoding="utf-8", errors="replace")
            urlencoded = urlencoded or bool(re.search(r"(?:bodyParser|express)\s*\.\s*urlencoded\s*\(", text))
            json_body = json_body or bool(re.search(r"(?:bodyParser|express)\s*\.\s*json\s*\(", text))
            if urlencoded and json_body:
                return "body"
    except OSError:
        return "json"
    return "form_field" if urlencoded and not json_body else "json"


@dataclass(frozen=True)
class CandidateTemplate:
    id: str
    name: str
    description: str
    vulnerability_types: tuple[str, ...]
    flow_mode: str
    methods: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    required_capabilities: tuple[str, ...] = ()


TEMPLATES = (
    CandidateTemplate("access-control-read", "业务越权双身份验证", "用隔离的资源所属者与普通用户会话访问同一只读资源，比较授权结果。", ("access_control",), "api", ("GET",), ("双身份响应", "资源归属标记", "授权拒绝或越权读取证据")),
    CandidateTemplate("sql-injection-differential", "SQL 注入差分验证", "对已识别参数执行基线、真条件与假条件的只读差分请求，只有稳定差异才进入裁决。", ("sql_injection",), "api", ("GET",), ("三组请求/响应", "状态码与内容长度差异", "数据库错误或稳定布尔差分")),
    CandidateTemplate("xss-browser-evidence", "XSS 浏览器证据验证", "向已识别输入点注入唯一标记，由隔离浏览器捕获 DOM、脚本执行和截图证据。", ("xss",), "hybrid", ("GET",), ("反射上下文", "浏览器截图或录屏", "唯一标记"), ("browser",)),
    CandidateTemplate("ssrf-callback", "SSRF 外带回调验证", "使用一次性 DNS/HTTP 回调标记验证服务端出网行为。", ("ssrf",), "api", ("GET",), ("一次性回调地址", "DNS/HTTP 回调日志", "请求时间关联"), ("oast",)),
    CandidateTemplate("command-injection-timing", "命令注入时延验证", "在隔离执行环境中完成多轮基线与时延差分，并要求统计结果可重复。", ("command_injection",), "api", ("GET",), ("多轮时延数据", "基线分布", "目标环境信息"), ("timing_probe",)),
    CandidateTemplate("path-traversal-boundary", "路径穿越边界验证", "在隔离环境中围绕已识别文件参数验证路径规范化与访问边界。", ("path_traversal",), "api", ("GET",), ("边界请求", "拒绝响应", "规范化行为"), ("isolated_http",)),
    CandidateTemplate("template-injection-isolated", "模板注入隔离验证", "使用无副作用表达式和对照输入验证模板求值行为。", ("template_injection",), "api", ("GET",), ("表达式结果", "对照响应", "模板引擎特征"), ("isolated_http",)),
    CandidateTemplate("xxe-oast", "XXE 外带验证", "由隔离执行器提交受控 XML，并通过一次性回调确认外部实体解析。", ("xxe",), "api", ("POST",), ("XML 请求", "DNS/HTTP 回调", "解析器响应"), ("oast", "isolated_http")),
    CandidateTemplate("open-redirect-boundary", "开放重定向边界验证", "验证跳转参数是否允许离开批准来源站点，执行器禁止跟随跨域跳转。", ("open_redirect",), "api", ("GET",), ("Location 响应头", "跨域边界", "对照请求"), ("isolated_http",)),
    CandidateTemplate("cors-origin-differential", "CORS 来源差分验证", "使用受控 Origin 执行预检和普通请求差分，分析凭据与来源策略。", ("cors",), "api", ("GET", "OPTIONS"), ("预检响应", "ACAO/ACAC 响应头", "来源差分"), ("isolated_http",)),
    CandidateTemplate("file-upload-isolated", "文件上传隔离验证", "仅在一次性目标环境上传无害标记文件并检查存储、类型和执行边界。", ("file_upload",), "hybrid", ("POST",), ("上传响应", "存储位置", "内容类型与执行边界"), ("isolated_http",)),
    CandidateTemplate("account-recovery-boundary", "密码重置边界验证", "使用隔离测试账号验证重置令牌是否可由公开身份字段预测，不提交密码变更。", ("broken_authentication",), "api", ("GET",), ("重置页面响应", "预测令牌与随机对照", "测试账号绑定证据"), ("isolated_http",)),
    CandidateTemplate("csrf-isolated-session", "CSRF 隔离会话验证", "在一次性隔离实例中比较缺少、错误和有效 CSRF 令牌的状态变更请求，并在执行后回滚测试数据。", ("csrf",), "hybrid", ("POST",), ("三组请求/响应", "状态变更前后快照", "回滚记录"), ("isolated_http", "browser")),
    CandidateTemplate("sensitive-api-response", "敏感接口响应验证", "使用最低权限测试会话访问已识别接口，检查响应是否包含密码哈希、令牌或超出业务所需的用户字段。", ("sensitive_data_exposure",), "api", ("GET",), ("脱敏响应结构", "敏感字段命中", "最低权限身份"), ("isolated_http",)),
    CandidateTemplate("runtime-security-configuration", "运行时安全配置验证", "检查响应头、Cookie 属性和错误处理是否泄露框架或内部环境信息。", ("security_misconfiguration",), "api", ("GET", "HEAD"), ("响应头", "Cookie 属性", "错误响应摘要"), ("isolated_http",)),
    CandidateTemplate("deserialization-isolated", "不安全反序列化隔离验证", "在一次性隔离实例中提交无副作用的结构标记，验证服务端是否执行不安全反序列化路径。", ("unsafe_deserialization",), "api", ("POST",), ("请求与响应", "反序列化路径证据", "隔离环境轨迹"), ("isolated_http",)),
    CandidateTemplate("code-evaluation-isolated", "动态代码求值隔离验证", "使用无副作用表达式和对照输入，验证输入是否到达动态求值器。", ("code_injection",), "api", ("POST",), ("对照请求", "受控表达式结果", "隔离执行轨迹"), ("isolated_http",)),
    CandidateTemplate("agent-capability-boundary", "Agent 能力边界验证", "把 Agent 静态能力链映射到已上线运行入口，在隔离环境中验证不可信上下文能否到达敏感能力。", ("agent_capability", "prompt_injection"), "hybrid", ("GET", "POST"), ("运行入口", "测试会话", "工具调用账本或阻断证据"), ("agent_runtime",)),
    CandidateTemplate("component-exposure", "组件运行暴露验证", "结合组件风险和运行资产确认受影响功能是否真实暴露。", ("dependency_risk",), "api", ("GET",), ("组件版本", "运行端点", "功能可达证据")),
    CandidateTemplate("web-baseline", "Web 暴露面基线", "确认目标可达性、响应头、服务指纹和基础安全配置。", ("unclassified",), "api", ("GET", "HEAD"), ("请求/响应摘要", "服务指纹", "安全响应头")),
)


def classify_vulnerability(source: str, rule_id: str, title: str, review: dict[str, object]) -> str:
    authoritative_text = " ".join(str(value) for value in (rule_id, title, review.get("cwe"), review.get("owasp")) if value).lower()
    review_text = str(review.get("category") or "").lower()
    if source == "SCA":
        return "dependency_risk"
    if source == "SAST" and any(token in authoritative_text for token in STATIC_ONLY_RULE_TOKENS):
        return "static_only"
    text = f"{authoritative_text} {review_text}"
    if source == "AGENT" and any(token in text for token in ("prompt", "agent", "mcp", "tool", "capability")):
        return "prompt_injection" if "prompt" in text else "agent_capability"
    checks = (
        ("sql_injection", ("sql", "cwe-89", "sqli")),
        # Check the complete CSRF phrase before XSS.  The previous generic
        # ``cross-site`` token classified "cross-site request forgery" as XSS.
        ("csrf", ("csrf", "cross-site request forgery", "cwe-352")),
        ("xss", ("xss", "cross-site scripting", "cwe-79")),
        ("ssrf", ("ssrf", "cwe-918")),
        ("command_injection", ("command injection", "os command", "cwe-78", "命令注入")),
        ("path_traversal", ("path traversal", "directory traversal", "cwe-22", "路径穿越")),
        ("template_injection", ("template injection", "ssti", "cwe-1336", "模板注入")),
        ("xxe", ("xxe", "external entity", "cwe-611")),
        ("open_redirect", ("open redirect", "unvalidated redirect", "cwe-601", "开放重定向")),
        ("cors", ("cors", "cross-origin resource sharing", "跨域资源共享")),
        ("file_upload", ("file upload", "unrestricted upload", "cwe-434", "文件上传")),
        ("broken_authentication", ("predictable reset", "reset token", "cwe-640", "密码重置令牌")),
        ("sensitive_data_exposure", ("full user object", "sensitive data exposure", "cwe-200", "完整用户对象")),
        ("security_misconfiguration", ("insecure cookie", "cwe-614", "security misconfiguration", "安全配置")),
        ("access_control", ("idor", "access", "authorization", "authz", "越权", "cwe-639", "cwe-862")),
        ("unsafe_deserialization", ("deserial", "unserialize", "cwe-502", "反序列化")),
        ("code_injection", ("code eval", "eval_exec", "dynamic code", "cwe-94", "动态代码")),
        ("prompt_injection", ("prompt injection", "提示词注入")),
    )
    authoritative_match = next((kind for kind, tokens in checks if any(token in authoritative_text for token in tokens)), None)
    return authoritative_match or next((kind for kind, tokens in checks if any(token in review_text for token in tokens)), "unclassified")


def is_runtime_verifiable_finding(record: object) -> bool:
    if str(getattr(record, "source", "")) == "AGENT":
        return True
    review = getattr(record, "ai_review", None)
    review_data = review if isinstance(review, dict) else {}
    vulnerability_type = classify_vulnerability(str(getattr(record, "source", "")), str(getattr(record, "rule_id", "")), str(getattr(record, "title", "")), review_data)
    if vulnerability_type == "static_only":
        return False
    file_path = str(getattr(record, "file_path", "") or "").replace("\\", "/").lower()
    evidence = str(getattr(record, "evidence", "") or "")
    if file_path.startswith("views/vulnerabilities/") or re.search(r"<%-\s*include\s*\(", evidence, re.IGNORECASE):
        return False
    if vulnerability_type == "open_redirect" and re.search(r"\bres\.redirect\s*\(\s*['\"][^'\"]+['\"]\s*\)", evidence) and not REQUEST_MEMBER_PATTERN.search(evidence):
        return False
    # A generated database identifier rendered into a DOM cell is not a
    # user-controlled XSS injection point.  Keep it in SAST for review, but do
    # not manufacture an unfillable DAST parameter for it.
    if vulnerability_type == "xss" and re.search(r"\.innerHTML\s*=\s*[^;\n]*\.id\s*;?\s*$", evidence, re.IGNORECASE):
        return False
    return True


def template_for(vulnerability_type: str) -> CandidateTemplate:
    return next((item for item in TEMPLATES if vulnerability_type in item.vulnerability_types), TEMPLATES[-1])


def normalize_candidate(record: object, project: object, component: object | None = None, discovery: dict[str, object] | None = None) -> dict[str, object]:
    review = record.ai_review if isinstance(record.ai_review, dict) else {}
    vulnerability_type = classify_vulnerability(str(record.source), str(record.rule_id), str(record.title), review)
    template = template_for(vulnerability_type)
    review_text = " ".join(str(value) for value in review.values() if isinstance(value, (str, int, float)))
    source_context = _source_context(str(getattr(project, "source_path", "") or ""), str(record.file_path or ""), int(getattr(record, "line_start", 0) or 0))
    evidence_text = f"{record.evidence or ''} {source_context['text']} {review_text} {record.file_path or ''}"
    configured_targets = [value for value in (getattr(project, "api_base_url", None), getattr(project, "runtime_url", None)) if value]
    configured_origin = _origin(configured_targets[0]) if configured_targets else None
    urls = _unique(URL_PATTERN.findall(evidence_text))
    if configured_origin:
        urls = [url for url in urls if _origin(url) == configured_origin]
    else:
        urls = [url for url in urls if _origin(url) is not None]
    paths = _unique(PATH_PATTERN.findall(evidence_text))
    base = configured_targets[0] if configured_targets else ""
    urls.extend(urljoin(base, path) for path in paths if base)
    if not urls and base:
        urls.append(base)
    methods = _unique(item.upper() for item in METHOD_PATTERN.findall(evidence_text))
    if not methods:
        methods = list(template.methods[:1])
    parameters: list[str] = []
    injection_points: list[dict[str, str]] = []
    body_location = _request_body_location(str(getattr(project, "source_path", "") or ""))
    location_map = {"url": "query", "params": "path", "headers": "header", "cookies": "cookie", "body": body_location, "files": "form", "form": "form"}
    for location, dot_name, bracket_name in REQUEST_MEMBER_PATTERN.findall(evidence_text):
        name = dot_name or bracket_name
        parameters.append(name)
        injection_points.append({"name": name, "location": location_map.get(location.lower(), location.lower())})
    for name in GET_PARAMETER_PATTERN.findall(evidence_text):
        parameters.append(name)
        injection_points.append({"name": name, "location": "query"})
    for pattern in PARAMETER_PATTERNS:
        parameters.extend(pattern.findall(evidence_text))
    parameters = _unique(parameters)
    for location, name in LOCATED_PARAMETER_PATTERN.findall(evidence_text):
        # Avoid treating the first SQL keyword in assignments such as
        # `query = "SELECT ..."` as a user-controlled request parameter.
        if name.upper() in {"SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "CREATE", "ALTER", "DROP"}:
            continue
        normalized_location = location_map.get(location.lower(), location.lower())
        injection_points.append({"name": name, "location": normalized_location})
    for url in urls:
        for pair in urlparse(url).query.split("&") if urlparse(url).query else []:
            name = pair.partition("=")[0]
            if name:
                injection_points.append({"name": name, "location": "query"})
    for name in parameters:
        if not any(item["name"] == name for item in injection_points):
            injection_points.append({"name": name, "location": "query"})
    injection_points = _dedupe_points(injection_points)
    discovery_parameters = discovery.get("parameters") if isinstance(discovery, dict) and isinstance(discovery.get("parameters"), list) else []
    for point in injection_points:
        matches = [item for item in discovery_parameters if isinstance(item, dict) and str(item.get("name") or "").casefold() == point["name"].casefold() and item.get("source_url")]
        matched_urls = _unique(str(item["source_url"]) for item in matches)
        if len(matched_urls) == 1:
            urls = matched_urls
            discovered_location = str(matches[0].get("location") or point["location"])
            point["location"] = location_map.get(discovered_location.lower(), discovered_location.lower())
            forms = discovery.get("forms") if isinstance(discovery, dict) and isinstance(discovery.get("forms"), list) else []
            matched_form = next((item for item in forms if isinstance(item, dict) and str(item.get("action") or "") == matched_urls[0]), None)
            if matched_form and matched_form.get("method"):
                methods = [str(matched_form["method"]).upper()]
            break
    if not METHOD_PATTERN.findall(evidence_text) and any(item["location"] in {"json", "form"} for item in injection_points):
        methods = ["POST"]
    if source_context["route_path"] and base:
        urls = [urljoin(base.rstrip("/") + "/", str(source_context["route_path"]).lstrip("/"))]
        methods = [str(source_context["route_method"] or methods[0]).upper()]
    persistent_mapping: dict[str, object] = {}
    if vulnerability_type == "xss" and base:
        persistent_mapping = _persistent_template_mapping(
            str(getattr(project, "source_path", "") or ""),
            str(record.file_path or ""),
            int(getattr(record, "line_start", 0) or 0),
        )
        writer_path = str(persistent_mapping.get("writer_path") or "")
        field = str(persistent_mapping.get("parameter") or "")
        observer_path = str(persistent_mapping.get("observer_path") or source_context["route_path"] or "")
        if writer_path and field:
            urls = _unique([
                urljoin(base.rstrip("/") + "/", writer_path.lstrip("/")),
                *([urljoin(base.rstrip("/") + "/", observer_path.lstrip("/"))] if observer_path else []),
            ])
            methods = [str(persistent_mapping.get("writer_method") or "POST").upper()]
            parameters = [field]
            injection_points = [{"name": field, "location": "form_field"}]
    privileged_route = vulnerability_type == "access_control" and (
        "ADMIN_ROUTE_ROLE_MISSING" in str(record.rule_id).upper()
        or "/admin" in str(source_context.get("route_path") or "").lower()
    )
    required_roles = (
        ["authenticated_user"] if privileged_route
        else ["resource_owner", "peer_user"] if vulnerability_type == "access_control"
        else ["authenticated_user"] if source_context["requires_auth"] == "true" else []
    )
    if vulnerability_type == "xss" and persistent_mapping.get("requires_auth"):
        required_roles = ["authenticated_user"]
    required_fixtures = []
    if vulnerability_type == "access_control" and not privileged_route:
        required_fixtures.append("归属于 resource_owner 的脱敏测试资源")
    if vulnerability_type == "ssrf":
        required_fixtures.append("一次性 DNS/HTTP 回调地址")
    if vulnerability_type == "broken_authentication":
        required_roles = ["reset_test_account"]
        required_fixtures.append("仅用于隔离验证的密码重置测试账号")
    if vulnerability_type in {"sql_injection", "xss", "ssrf", "command_injection", "path_traversal", "template_injection", "open_redirect", "file_upload", "xxe", "unsafe_deserialization", "code_injection", "broken_authentication", "csrf"} and not parameters:
        parameter_missing = True
    else:
        parameter_missing = False
    missing: list[str] = []
    if not configured_targets:
        missing.append("项目运行地址或 API 地址")
    if parameter_missing:
        missing.append("可映射的运行时参数")
    identity_aliases = [str(value) for value in required_roles]
    if identity_aliases and not roles_ready(getattr(project, "id", ""), identity_aliases):
        missing.append("项目测试身份")
    # Runtime capabilities are fulfilled by the SANDBOX contract. They are not
    # human-authored vulnerability fields, so keep them separate from the
    # source-to-runtime mapping blockers shown to the operator.
    runtime_requirements = list(template.required_capabilities)
    if any(method not in {"GET", "HEAD", "OPTIONS"} for method in methods) and "isolated_http" not in runtime_requirements:
        runtime_requirements.append("isolated_http")
    auto_filled = ["漏洞类型", "策略模板", "HTTP 方法"]
    if configured_targets:
        auto_filled.append("目标地址")
    if paths:
        auto_filled.append("接口路径")
    if parameters:
        auto_filled.append("参数位置")
    if discovery_parameters and parameters:
        auto_filled.append("运行资产映射")
    if source_context["route_path"]:
        auto_filled.append("源码路由映射")
    if persistent_mapping.get("writer_path"):
        auto_filled.append("持久化数据流映射")
    notes = [f"来源模块：{record.source}", f"本地模板：{template.name}"]
    if component is not None:
        notes.append(f"受影响组件：{component.name} {component.version or 'unknown'}")
    return {
        "vulnerability_type": vulnerability_type,
        "cwe": str(review.get("cwe")) if review.get("cwe") else None,
        "attack_surface": {
            "urls": _unique(urls),
            "methods": methods,
            "parameters": parameters,
            "injection_points": injection_points,
            "observer_urls": [urls[1]] if persistent_mapping.get("writer_path") and len(urls) > 1 else [],
            "persistence": persistent_mapping,
            "access_model": "privileged_route" if privileged_route else "resource_mutation" if vulnerability_type == "access_control" and any(method not in {"GET", "HEAD", "OPTIONS"} for method in methods) else "resource_read",
        },
        "preconditions": {"required_roles": required_roles, "required_fixtures": required_fixtures, "business_notes": notes},
        "missing": missing,
        "requires_human_input": bool(missing),
        "readiness": "blocked" if not configured_targets else "needs_context" if missing else "ready",
        "target_status": "configured" if configured_targets else "not_configured",
        "recommended_strategy_id": template.id,
        "recommended_strategy_name": template.name,
        "strategy_description": template.description,
        "strategy_match": "ai_required" if vulnerability_type == "unclassified" else "builtin",
        "evidence_requirements": list(template.evidence_requirements),
        "required_capabilities": runtime_requirements,
        "auto_filled": auto_filled,
    }


def build_flow_blueprint(candidate: dict[str, object], *, finding_id: str) -> dict[str, object]:
    attack_surface = candidate["attack_surface"] if isinstance(candidate.get("attack_surface"), dict) else {}
    urls = attack_surface.get("urls") if isinstance(attack_surface.get("urls"), list) else []
    parameters = attack_surface.get("parameters") if isinstance(attack_surface.get("parameters"), list) else []
    injection_points = attack_surface.get("injection_points") if isinstance(attack_surface.get("injection_points"), list) else []
    if not urls:
        raise ValueError("项目尚未配置可用于 DAST 的运行地址")
    target_url = str(urls[0])
    parsed = urlparse(target_url)
    allowed_paths = _unique([urlparse(str(url)).path or "/" for url in urls])
    vulnerability_type = str(candidate.get("vulnerability_type") or "unclassified")
    parameter_required_types = {"sql_injection", "xss", "ssrf", "command_injection", "path_traversal", "template_injection", "open_redirect", "file_upload", "xxe", "unsafe_deserialization", "code_injection", "broken_authentication"}
    if vulnerability_type in parameter_required_types and not parameters:
        raise ValueError("尚未从 SAST 数据流或运行资产中唯一定位输入点；系统不会生成可能误伤目标的空参数策略。")
    strategy_id = str(candidate.get("recommended_strategy_id") or "web-baseline")
    roles: list[dict[str, object]] = [{"alias": "anonymous", "description": "匿名只读会话"}]
    preconditions = candidate.get("preconditions") if isinstance(candidate.get("preconditions"), dict) else {}
    required_roles = preconditions.get("required_roles") if isinstance(preconditions.get("required_roles"), list) else []
    if "authenticated_user" in required_roles:
        roles = [{"alias": "authenticated_user", "credential_ref": automatic_ref("authenticated_user"), "description": "由 SANDBOX 自动初始化并保存在后端的项目测试会话"}]
    elif "reset_test_account" in required_roles:
        roles = [{"alias": "reset_test_account", "credential_ref": automatic_ref("reset_test_account"), "description": "由 SANDBOX 自动初始化的一次性密码重置测试账号"}]
    default_role = str(roles[0]["alias"])
    steps: list[dict[str, object]] = []
    parameter = str(parameters[0]) if parameters else ""
    point = next((item for item in injection_points if isinstance(item, dict) and str(item.get("name") or "") == parameter), {"name": parameter, "location": "query"})
    parameter_location = str(point.get("location") or "query")
    candidate_methods = [str(value).upper() for value in (attack_surface.get("methods") or ["GET"])]
    requested_method = candidate_methods[0]
    if vulnerability_type == "csrf":
        requested_method = next((method for method in candidate_methods if method in {"POST", "PUT", "PATCH", "DELETE"}), "POST")
    if vulnerability_type == "access_control":
        access_model = str(attack_surface.get("access_model") or "resource_read")
        if access_model == "privileged_route":
            roles = [
                {"alias": "anonymous", "description": "匿名会话"},
                {"alias": "authenticated_user", "credential_ref": automatic_ref("authenticated_user"), "description": "SANDBOX 自动创建的已认证普通用户"},
            ]
            steps = [
                {"id": "anonymous-read", "kind": "http_request", "role": "anonymous", "method": "GET", "url": target_url},
                {"id": "ordinary-user-read", "kind": "http_request", "role": "authenticated_user", "method": "GET", "url": target_url},
                {"id": "authorization-differential", "kind": "assert_compare", "mode": "privileged_route", "left": "anonymous-read", "right": "ordinary-user-read"},
            ]
        elif requested_method in {"GET", "HEAD", "OPTIONS"}:
            roles = [
                {"alias": "resource_owner", "credential_ref": automatic_ref("resource_owner"), "description": "SANDBOX 自动创建的测试资源所属者"},
                {"alias": "peer_user", "credential_ref": automatic_ref("peer_user"), "description": "SANDBOX 自动创建的另一普通测试用户"},
            ]
            steps = [
                {"id": "owner-read", "kind": "http_request", "role": "resource_owner", "method": requested_method, "url": target_url},
                {"id": "peer-read", "kind": "http_request", "role": "peer_user", "method": requested_method, "url": target_url},
                {"id": "authorization-differential", "kind": "assert_compare", "mode": "access_control", "left": "owner-read", "right": "peer-read"},
            ]
        else:
            roles = [
                {"alias": "resource_owner", "credential_ref": automatic_ref("resource_owner"), "description": "SANDBOX 自动创建的测试资源所属者"},
                {"alias": "peer_user", "credential_ref": automatic_ref("peer_user"), "description": "SANDBOX 自动创建的另一普通测试用户"},
            ]
            steps = [{
                "id": "authorization-mutation-proof", "kind": "sandbox_probe", "capability": "browser",
                "probe": "access_control_mutation", "role": "peer_user", "owner_role": "resource_owner",
                "method": requested_method, "url": target_url, "parameters": list(parameters),
                "location": parameter_location, "evidence": list(candidate.get("evidence_requirements") or []),
            }]
    elif vulnerability_type == "sql_injection":
        if requested_method in {"GET", "HEAD", "OPTIONS"} and parameter_location in {"query", "header", "cookie"}:
            steps = [
                {"id": "baseline-1", "kind": "http_request", "role": default_role, "method": requested_method, "url": target_url, **_injection_payload(parameter, parameter_location, "DAST_BASELINE_A_{{run.id}}")},
                {"id": "baseline-2", "kind": "http_request", "role": default_role, "method": requested_method, "url": target_url, **_injection_payload(parameter, parameter_location, "DAST_BASELINE_B_{{run.id}}")},
                {"id": "boolean-true", "kind": "http_request", "role": default_role, "method": requested_method, "url": target_url, **_injection_payload(parameter, parameter_location, "DAST' OR '1'='1")},
                {"id": "boolean-false", "kind": "http_request", "role": default_role, "method": requested_method, "url": target_url, **_injection_payload(parameter, parameter_location, "DAST' AND '1'='2")},
                {"id": "sql-differential", "kind": "assert_compare", "mode": "sql_injection", "baseline": ["baseline-1", "baseline-2"], "true": "boolean-true", "false": "boolean-false"},
            ]
        else:
            steps = [{"id": "sql-isolated-proof", "kind": "sandbox_probe", "capability": "isolated_http", "probe": "sql_injection", "role": default_role, "method": requested_method, "url": target_url, "parameter": parameter, "location": parameter_location, "evidence": list(candidate.get("evidence_requirements") or [])}]
    elif vulnerability_type == "xss":
        observer_urls = attack_surface.get("observer_urls") if isinstance(attack_surface.get("observer_urls"), list) else []
        observer_url = str(observer_urls[0]) if observer_urls else target_url
        if observer_urls:
            steps = [{"id": "xss-browser-proof", "kind": "sandbox_probe", "capability": "browser", "probe": "xss", "role": default_role, "method": "GET", "url": observer_url, "setup_url": target_url, "setup_method": requested_method, "parameter": parameter, "location": parameter_location, "evidence": ["setup_exchange", "dom", "console", "screenshot", "har"]}]
        else:
            steps = [{"id": "xss-browser-proof", "kind": "sandbox_probe", "capability": "browser", "probe": "xss", "role": default_role, "method": requested_method, "url": target_url, "parameter": parameter, "location": parameter_location, "evidence": ["dom", "console", "screenshot", "har"]}]
    elif vulnerability_type == "ssrf":
        steps = [{"id": "ssrf-oast-proof", "kind": "sandbox_probe", "capability": "oast", "probe": "ssrf", "role": default_role, "method": requested_method, "url": target_url, "parameter": parameter, "location": parameter_location, "evidence": ["dns_callback", "http_callback", "correlation_token"]}]
    elif vulnerability_type == "command_injection":
        steps = [{"id": "command-timing-proof", "kind": "sandbox_probe", "capability": "timing_probe", "probe": "command_injection", "role": default_role, "method": requested_method, "url": target_url, "parameter": parameter, "location": parameter_location, "samples": 5, "evidence": ["baseline_timings", "probe_timings", "environment"]}]
    elif vulnerability_type == "path_traversal":
        steps = [{"id": "path-boundary-proof", "kind": "sandbox_probe", "capability": "isolated_http", "probe": "path_traversal", "role": default_role, "method": requested_method, "url": target_url, "parameter": parameter, "location": parameter_location, "evidence": ["baseline_response", "boundary_responses", "normalization"]}]
    elif vulnerability_type in {"template_injection", "xxe", "open_redirect", "cors", "file_upload", "unsafe_deserialization", "code_injection"}:
        capability = "oast" if vulnerability_type == "xxe" else "isolated_http"
        method = "POST" if vulnerability_type in {"xxe", "file_upload", "unsafe_deserialization", "code_injection"} else "OPTIONS" if vulnerability_type == "cors" else "GET"
        steps = [{"id": f"{vulnerability_type}-proof", "kind": "sandbox_probe", "capability": capability, "probe": vulnerability_type, "role": default_role, "method": method, "url": target_url, "parameter": parameter, "location": parameter_location, "evidence": list(candidate.get("evidence_requirements") or [])}]
    elif vulnerability_type == "broken_authentication":
        steps = [{"id": "account-recovery-proof", "kind": "sandbox_probe", "capability": "isolated_http", "probe": "account_recovery", "role": default_role, "method": requested_method, "url": target_url, "parameters": list(parameters), "location": parameter_location, "evidence": list(candidate.get("evidence_requirements") or [])}]
    elif vulnerability_type == "csrf":
        steps = [{"id": "csrf-session-proof", "kind": "sandbox_probe", "capability": "browser", "probe": "csrf", "role": default_role, "method": requested_method, "url": target_url, "parameters": list(parameters), "location": parameter_location, "evidence": list(candidate.get("evidence_requirements") or [])}]
    elif vulnerability_type == "sensitive_data_exposure":
        steps = [{"id": "sensitive-response-proof", "kind": "sandbox_probe", "capability": "isolated_http", "probe": "sensitive_data_exposure", "role": default_role, "method": requested_method, "url": target_url, "evidence": list(candidate.get("evidence_requirements") or [])}]
    elif vulnerability_type == "security_misconfiguration":
        steps = [{"id": "security-configuration-proof", "kind": "sandbox_probe", "capability": "isolated_http", "probe": "security_misconfiguration", "role": default_role, "method": "GET", "url": target_url, "evidence": list(candidate.get("evidence_requirements") or [])}]
    elif vulnerability_type in {"agent_capability", "prompt_injection"}:
        steps = [{
            "id": "agent-runtime-proof", "kind": "sandbox_probe", "capability": "agent_runtime",
            "probe": vulnerability_type, "role": default_role, "method": "POST", "url": target_url,
            "parameter": parameter or "prompt", "location": "json",
            "runtime_protocol": "ai-security-platform.agent-runtime-evidence/v1",
            "evidence": ["tool_call_ledger", "policy_decision", "runtime_trace"],
        }]
    else:
        request_input = _injection_payload(parameter, parameter_location, "DAST_SAFE_MARKER_{{run.id}}") if parameter else {}
        steps = [
            {"id": "baseline-request", "kind": "http_request", "role": default_role, "method": "GET", "url": target_url, **request_input},
            {"id": "baseline-observation", "kind": "assert", "status_in": [200, 204, 301, 302, 400, 401, 403, 404, 405, 500, 502, 503], "verdict_on_pass": "uncertain"},
        ]
    mapping_fingerprint = hashlib.sha256(
        json.dumps(
            {
                "vulnerability_type": vulnerability_type,
                "target_url": target_url,
                "allowed_paths": allowed_paths,
                "roles": roles,
                "steps": steps,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "name": bounded_strategy_name(candidate.get("title"), "自动动态验证", finding_id),
        "target_url": f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}",
        "flow_mode": "hybrid" if vulnerability_type in {"xss", "csrf", "agent_capability", "prompt_injection"} else "api",
        "strategy_source": "template",
        "authorized_scope": f"仅限项目已配置同源目标 {parsed.scheme}://{parsed.netloc}；默认只读、限速、禁止删除/支付/上传/发信和真实数据修改。",
        "allowed_paths": allowed_paths,
        "roles": roles,
        "steps": steps,
        "sufficiency_criteria": {
            "verdict_rule": "有明确触发和实际影响证据才可判定可利用；异常但证据不足为不确定；多组验证均未触发且确认修复或防护有效才可判定不可利用。",
            "evidence_requirements": candidate.get("evidence_requirements") or [],
            "blocking_items": candidate.get("missing") or [],
            "strategy_id": strategy_id,
            "vulnerability_type": vulnerability_type,
            "required_capabilities": list(candidate.get("required_capabilities") or template_for(vulnerability_type).required_capabilities),
            "adapter_version": 5,
            "mapping_fingerprint": mapping_fingerprint,
        },
        "requester": "automatic-dast-adapter",
    }


@lru_cache(maxsize=512)
def _source_context(source_root: str, file_path: str, line_start: int) -> dict[str, str]:
    empty = {"text": "", "route_path": "", "route_method": "", "requires_auth": "false"}
    if not source_root or not file_path:
        return empty
    try:
        root = Path(source_root).resolve(strict=True)
        source_file = (root / file_path).resolve(strict=True)
        if not source_file.is_file() or not source_file.is_relative_to(root) or source_file.stat().st_size > 2_000_000:
            return empty
        source = source_file.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return empty
    if source_file.suffix.lower() == ".ejs":
        return _template_source_context(root, source_file, source, line_start)
    if source_file.suffix.lower() not in {".js", ".cjs", ".mjs", ".ts"}:
        return empty
    direct_route = _direct_route_source_context(root, source_file, source, line_start)
    if direct_route is not None:
        return direct_route
    offset = sum(len(value) for value in source.splitlines(keepends=True)[:max(0, line_start - 1)])
    handlers = list(re.finditer(r"module\.exports\.([A-Za-z_$][\w$]*)\s*=\s*function\b", source))
    current = next((item for item in reversed(handlers) if item.start() <= offset), None)
    if current is None:
        return {**empty, "text": source}
    next_handler = next((item for item in handlers if item.start() > current.start()), None)
    function_text = source[current.start():next_handler.start() if next_handler else len(source)]
    handler_name = current.group(1)
    route_pattern = re.compile(
        rf"\brouter\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*['\"]([^'\"]+)['\"][^\n;]*\b[A-Za-z_$][\w$]*\s*\.\s*{re.escape(handler_name)}\b",
        re.IGNORECASE,
    )
    route_file: Path | None = None
    route_match: re.Match[str] | None = None
    inspected = 0
    try:
        candidates = root.rglob("*.js")
        for candidate in candidates:
            if inspected >= 500 or any(part in {"node_modules", ".git", "dist", "build"} for part in candidate.parts):
                continue
            inspected += 1
            if candidate.stat().st_size > 1_000_000:
                continue
            match = route_pattern.search(candidate.read_text(encoding="utf-8", errors="replace"))
            if match:
                route_file, route_match = candidate, match
                break
    except OSError:
        return {"text": function_text, "route_path": "", "route_method": "", "requires_auth": "false"}
    if route_file is None or route_match is None:
        return {"text": function_text, "route_path": "", "route_method": "", "requires_auth": "false"}
    route_path = route_match.group(2)
    prefix = ""
    try:
        route_module = route_file.relative_to(root).with_suffix("").as_posix()
        mount_pattern = re.compile(
            rf"\bapp\s*\.\s*use\s*\(\s*['\"]([^'\"]*)['\"]\s*,\s*require\s*\(\s*['\"]\.?/?{re.escape(route_module)}['\"]",
            re.IGNORECASE,
        )
        for candidate in root.glob("*.js"):
            if candidate.stat().st_size <= 1_000_000 and (mount := mount_pattern.search(candidate.read_text(encoding="utf-8", errors="replace"))):
                prefix = mount.group(1)
                break
    except (OSError, ValueError):
        prefix = ""
    combined_path = "/" + "/".join(value.strip("/") for value in (prefix, route_path) if value.strip("/"))
    requires_auth = bool(re.search(r"\b(?:isAuthenticated|requireAuth|authenticated|ensureLoggedIn)\b", route_match.group(0), re.IGNORECASE))
    return {"text": function_text, "route_path": combined_path or "/", "route_method": route_match.group(1).upper(), "requires_auth": "true" if requires_auth else "false"}


def _direct_route_source_context(root: Path, route_file: Path, source: str, line_start: int) -> dict[str, str] | None:
    lines = source.splitlines()
    if line_start < 1 or line_start > len(lines):
        return None
    route_line = lines[line_start - 1]
    match = re.search(r"\brouter\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*['\"]([^'\"]+)['\"]([^\n;]*)", route_line, re.IGNORECASE)
    if match is None:
        return None
    references = re.findall(r"\b[A-Za-z_$][\w$]*\s*\.\s*([A-Za-z_$][\w$]*)\b", match.group(3))
    handler_name = next((name for name in reversed(references) if name.lower() not in {"isauthenticated", "isnotauthenticated", "admincheck"}), "")
    handler_text = _exported_handler_text(root, handler_name) if handler_name else ""
    return {
        "text": f"{route_line}\n{handler_text}",
        "route_path": _mounted_route_path(root, route_file, match.group(2)),
        "route_method": match.group(1).upper(),
        "requires_auth": "true" if re.search(r"\b(?:isAuthenticated|requireAuth|authenticated|ensureLoggedIn)\b", match.group(0), re.IGNORECASE) else "false",
    }


def _template_source_context(root: Path, template_file: Path, source: str, line_start: int) -> dict[str, str]:
    empty = {"text": "", "route_path": "", "route_method": "", "requires_auth": "false"}
    try:
        view_name = template_file.relative_to(root / "views").with_suffix("").as_posix()
    except ValueError:
        return empty
    target_line = source.splitlines()[line_start - 1] if 0 < line_start <= len(source.splitlines()) else ""
    identifiers = {item for item in re.findall(r"\b[A-Za-z_$][\w$]*\b", target_line) if item not in {"output", "strong", "script", "innerHTML"}}
    choices: list[tuple[int, str, str]] = []
    direct_routes: list[tuple[Path, re.Match[str]]] = []
    render_pattern = re.compile(rf"res\s*\.\s*render\s*\(\s*['\"]{re.escape(view_name)}['\"]", re.IGNORECASE)
    try:
        for candidate in root.rglob("*.js"):
            if any(part in {"node_modules", ".git", "dist", "build"} for part in candidate.parts) or candidate.stat().st_size > 1_000_000:
                continue
            text = candidate.read_text(encoding="utf-8", errors="replace")
            handlers = list(re.finditer(r"module\.exports\.([A-Za-z_$][\w$]*)\s*=\s*function\b", text))
            for index, handler in enumerate(handlers):
                function_text = text[handler.start():handlers[index + 1].start() if index + 1 < len(handlers) else len(text)]
                if render_pattern.search(function_text):
                    score = sum(3 for item in identifiers if re.search(rf"\b{re.escape(item)}\b", function_text)) + int("req." in function_text)
                    choices.append((score, handler.group(1), function_text))
            route_pattern = re.compile(r"\brouter\s*\.\s*(get|post)\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
            for render_match in render_pattern.finditer(text):
                preceding_routes = [item for item in route_pattern.finditer(text, 0, render_match.start())]
                if preceding_routes:
                    direct_routes.append((candidate, preceding_routes[-1]))
    except OSError:
        return empty
    if choices:
        _, handler_name, function_text = max(choices, key=lambda item: item[0])
        return _route_for_handler(root, handler_name, function_text)
    if direct_routes:
        route_file, match = direct_routes[0]
        return {"text": target_line, "route_path": _mounted_route_path(root, route_file, match.group(2)), "route_method": match.group(1).upper(), "requires_auth": "true" if "isAuthenticated" in match.group(0) else "false"}
    return empty


def _exported_handler_text(root: Path, handler_name: str) -> str:
    pattern = re.compile(rf"module\.exports\.{re.escape(handler_name)}\s*=\s*function\b", re.IGNORECASE)
    try:
        for candidate in root.rglob("*.js"):
            if any(part in {"node_modules", ".git", "dist", "build"} for part in candidate.parts) or candidate.stat().st_size > 1_000_000:
                continue
            text = candidate.read_text(encoding="utf-8", errors="replace")
            if match := pattern.search(text):
                next_handler = re.search(r"\n\s*module\.exports\.[A-Za-z_$][\w$]*\s*=\s*function\b", text[match.end():])
                end = match.end() + next_handler.start() if next_handler else len(text)
                return text[match.start():end]
    except OSError:
        return ""
    return ""


def _route_for_handler(root: Path, handler_name: str, function_text: str) -> dict[str, str]:
    pattern = re.compile(rf"\brouter\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*['\"]([^'\"]+)['\"][^\n;]*\b[A-Za-z_$][\w$]*\s*\.\s*{re.escape(handler_name)}\b", re.IGNORECASE)
    try:
        for candidate in root.rglob("*.js"):
            if any(part in {"node_modules", ".git", "dist", "build"} for part in candidate.parts) or candidate.stat().st_size > 1_000_000:
                continue
            if match := pattern.search(candidate.read_text(encoding="utf-8", errors="replace")):
                return {"text": function_text, "route_path": _mounted_route_path(root, candidate, match.group(2)), "route_method": match.group(1).upper(), "requires_auth": "true" if re.search(r"\b(?:isAuthenticated|requireAuth|authenticated|ensureLoggedIn)\b", match.group(0), re.IGNORECASE) else "false"}
    except OSError:
        pass
    return {"text": function_text, "route_path": "", "route_method": "", "requires_auth": "false"}


def _persistent_template_mapping(source_root: str, file_path: str, line_start: int) -> dict[str, object]:
    """Map a stored DOM sink back to its HTTP writer without guessing a parameter.

    This intentionally requires a same-name request field assignment (for example
    ``user.email = req.body.email``) and an exported handler with a concrete
    router binding.  Ambiguous matches are rejected and remain visible as a
    context blocker instead of producing an unsafe strategy.
    """
    if not source_root or not file_path:
        return {}
    try:
        root = Path(source_root).resolve(strict=True)
        template = (root / file_path).resolve(strict=True)
        if not template.is_file() or not template.is_relative_to(root) or template.suffix.lower() != ".ejs":
            return {}
        source = template.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return {}
    lines = source.splitlines()
    target_line = lines[line_start - 1] if 0 < line_start <= len(lines) else ""
    right_side = target_line.partition("=")[2]
    member_matches = re.findall(r"\.\s*([A-Za-z_$][\w$]*)", right_side)
    if not member_matches:
        return {}
    field = member_matches[-1]
    source_object_match = re.search(r"\b([A-Za-z_$][\w$]*)\s*(?:\[[^\]]+\])?\s*\.\s*" + re.escape(field) + r"\b", right_side)
    source_object = str(source_object_match.group(1) if source_object_match else "").casefold()
    singular_source_object = source_object[:-1] if source_object.endswith("s") else source_object
    assignment = re.compile(
        rf"\b(?P<object>[A-Za-z_$][\w$]*)(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*\.\s*{re.escape(field)}\s*=\s*req\s*\.\s*body\s*(?:\.\s*{re.escape(field)}|\[\s*['\"]{re.escape(field)}['\"]\s*\])",
        re.IGNORECASE,
    )
    matches: list[tuple[int, str, str, dict[str, str]]] = []
    try:
        for candidate in root.rglob("*.js"):
            if any(part in {"node_modules", ".git", "dist", "build"} for part in candidate.parts) or candidate.stat().st_size > 1_000_000:
                continue
            text = candidate.read_text(encoding="utf-8", errors="replace")
            handlers = list(re.finditer(r"module\.exports\.([A-Za-z_$][\w$]*)\s*=\s*function\b", text))
            for index, handler in enumerate(handlers):
                function_text = text[handler.start():handlers[index + 1].start() if index + 1 < len(handlers) else len(text)]
                assignment_match = assignment.search(function_text)
                if assignment_match is None:
                    continue
                route = _route_for_handler(root, handler.group(1), function_text)
                if route.get("route_path") and route.get("route_method") in {"POST", "PUT", "PATCH"}:
                    object_name = assignment_match.group("object").casefold()
                    score = 2 if singular_source_object and object_name == singular_source_object else 0
                    matches.append((score, handler.group(1), function_text, route))
    except OSError:
        return {}
    if not matches:
        return {}
    best_score = max(item[0] for item in matches)
    matches = [item for item in matches if item[0] == best_score]
    unique_routes = {(item[3]["route_method"], item[3]["route_path"]) for item in matches}
    if len(unique_routes) != 1:
        return {}
    _, _, function_text, route = matches[0]
    return {
        "kind": "stored_input_to_dom",
        "parameter": field,
        "location": "form_field",
        "writer_path": route["route_path"],
        "writer_method": route["route_method"],
        "observer_path": str(_source_context(source_root, file_path, line_start).get("route_path") or ""),
        "requires_auth": route.get("requires_auth") == "true",
        "evidence": re.sub(r"\s+", " ", function_text)[:500],
    }


def _mounted_route_path(root: Path, route_file: Path, route_path: str) -> str:
    prefix = ""
    try:
        route_module = route_file.relative_to(root).with_suffix("").as_posix()
        mount_pattern = re.compile(rf"\bapp\s*\.\s*use\s*\(\s*['\"]([^'\"]*)['\"]\s*,\s*require\s*\(\s*['\"]\.?/?{re.escape(route_module)}['\"]", re.IGNORECASE)
        for candidate in root.glob("*.js"):
            if candidate.stat().st_size <= 1_000_000 and (mount := mount_pattern.search(candidate.read_text(encoding="utf-8", errors="replace"))):
                prefix = mount.group(1)
                break
    except (OSError, ValueError):
        prefix = ""
    return "/" + "/".join(value.strip("/") for value in (prefix, route_path) if value.strip("/"))


def _origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        # Source evidence commonly contains runtime templates such as
        # ``http://localhost:${PORT}``.  They are useful code evidence but are
        # not concrete DAST targets and must not abort the whole candidate list.
        return None
    if parsed.scheme not in {"http", "https"} or not hostname:
        return None
    return parsed.scheme.lower(), hostname.lower(), port or (443 if parsed.scheme == "https" else 80)


def _injection_payload(name: str, location: str, value: str) -> dict[str, object]:
    if not name:
        return {}
    if location == "header":
        return {"headers": {name: value}}
    if location == "cookie":
        return {"headers": {"Cookie": f"{name}={value}"}}
    if location in {"json", "body"}:
        return {"body": {name: value}}
    if location == "form_field":
        return {"form": {name: value}}
    return {"query": {name: value}}


def _unique(values: object) -> list[str]:
    result: list[str] = []
    for value in values if isinstance(values, (list, tuple, set)) or hasattr(values, "__iter__") else []:
        normalized = str(value).strip().rstrip(".,;)")
        if normalized and normalized not in result:
            result.append(normalized)
    return result


def _dedupe_points(values: list[dict[str, str]]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in values:
        key = (item.get("name", "").casefold(), item.get("location", "").casefold())
        if key not in seen and key[0]:
            seen.add(key)
            result.append(item)
    return result
