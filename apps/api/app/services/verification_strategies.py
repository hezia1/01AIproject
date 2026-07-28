from __future__ import annotations

from app.db_models import FindingRecord
from app.models import DastVerificationStrategy


WEB_BASELINE = DastVerificationStrategy(
    id="web-baseline",
    name="Web 基础暴露检查",
    description="安全地读取一个 URL 的响应，确认连通性、传输协议、状态码、服务指纹和基础安全响应头。",
    scope_summary="仅发起一次无认证 GET 请求；不提交表单、不修改数据、不发送攻击 payload。",
    check_items=["HTTP/HTTPS", "响应状态与耗时", "Server Header", "基础安全响应头"],
    limitations=["不能证明 SQL 注入、越权或业务逻辑漏洞可被利用。", "不包含登录态、爬虫、接口枚举或攻击 payload。"],
)

RUNTIME_EXPOSURE = DastVerificationStrategy(
    id="runtime-exposure",
    name="运行暴露面确认",
    description="面向已发现的代码或 Agent 风险，确认对应运行地址是否可访问，以及是否暴露基础 Web 配置风险。",
    scope_summary="仅检查目标地址的公开响应与基础 Web 配置，不会对上游代码问题进行攻击复现。",
    check_items=["运行地址可达性", "传输协议", "安全响应头", "服务指纹"],
    limitations=["上游风险是否可触发仍需业务测试、登录态和专用验证策略。", "结果属于运行环境佐证，不是漏洞利用证明。"],
)

COMPONENT_EXPOSURE = DastVerificationStrategy(
    id="component-exposure",
    name="组件运行暴露确认",
    description="面向 SCA 组件风险，确认项目运行地址的基础暴露面，为组件升级和运行环境复核提供上下文。",
    scope_summary="仅执行非侵入式 Web 基础检查；不会扫描组件版本、下载依赖或利用已知 CVE。",
    check_items=["运行地址可达性", "HTTPS", "响应头", "服务指纹"],
    limitations=["不能判断易受影响组件是否实际可达或可利用。", "组件漏洞仍需结合版本、调用路径和专用验证确认。"],
)


def recommended_dast_strategies(finding: FindingRecord | None = None) -> list[DastVerificationStrategy]:
    if finding and finding.source == "SCA":
        return [COMPONENT_EXPOSURE, WEB_BASELINE, RUNTIME_EXPOSURE]
    if finding:
        return [RUNTIME_EXPOSURE, WEB_BASELINE, COMPONENT_EXPOSURE]
    return [WEB_BASELINE, RUNTIME_EXPOSURE, COMPONENT_EXPOSURE]


def resolve_dast_strategy(strategy_id: str, finding: FindingRecord | None = None) -> DastVerificationStrategy:
    strategies = {item.id: item for item in recommended_dast_strategies(finding)}
    if strategy_id not in strategies:
        raise ValueError("Unknown DAST verification strategy")
    return strategies[strategy_id]
