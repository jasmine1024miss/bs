from backend.app.config import get_settings
from backend.app.llm.deepseek_client import DeepSeekClient


def critique_diagnosis(knowledge_state: dict, hypotheses: list[dict], tool_trace: list[dict]) -> dict:
    settings = get_settings()
    if settings.deepseek_enabled and settings.deepseek_api_key:
        return DeepSeekClient(settings).critique(knowledge_state, hypotheses, tool_trace)

    return _fallback_critic(knowledge_state, hypotheses, tool_trace)


def _fallback_critic(knowledge_state: dict, hypotheses: list[dict], tool_trace: list[dict]) -> dict:
    missing = []
    trace_tools = {item.get("tool") for item in tool_trace if item.get("ok")}
    if "systemctl_status" not in trace_tools:
        missing.append("缺少服务状态证据")
    if "journalctl_unit" not in trace_tools:
        missing.append("缺少错误日志证据")
    if "ss_listen" not in trace_tools:
        missing.append("缺少端口占用证据")
    if "ps_process" not in trace_tools:
        missing.append("缺少进程归属证据")

    best = max(hypotheses, key=lambda item: item["score"]) if hypotheses else {"name": "unknown", "score": 0}
    if missing:
        conclusion = "当前证据不足，建议继续补充取证。"
    else:
        conclusion = "证据链完整，候选根因可以进入验证阶段。"

    return {
        "provider": "rule-fallback",
        "enabled": False,
        "conclusion": conclusion,
        "best_hypothesis": best,
        "evidence_gaps": missing,
        "suggested_next_tools": [],
    }
