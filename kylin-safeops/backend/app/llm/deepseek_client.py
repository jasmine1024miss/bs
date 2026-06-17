import json

import httpx


class DeepSeekClient:
    def __init__(self, settings):
        self.settings = settings

    def critique(self, knowledge_state: dict, hypotheses: list[dict], tool_trace: list[dict]) -> dict:
        prompt = (
            "你是运维 Agent 的认知审查器。只检查证据缺口，不要输出 Shell 命令。"
            "未经工具验证的信息必须保持 assumed。请返回 JSON。"
        )
        payload = {
            "model": self.settings.deepseek_model,
            "messages": [
                {"role": "system", "content": prompt},
                {
                    "role": "user",
                    "content": json.dumps({
                        "knowledge_state": knowledge_state,
                        "hypotheses": hypotheses,
                        "tool_trace": [
                            {"tool": item.get("tool"), "ok": item.get("ok"), "summary": item.get("summary")}
                            for item in tool_trace
                        ],
                    }, ensure_ascii=False),
                },
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
        }
        try:
            response = httpx.post(
                f"{self.settings.deepseek_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {self.settings.deepseek_api_key}"},
                json=payload,
                timeout=httpx.Timeout(4.0, connect=2.0),
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            return {
                "provider": "deepseek",
                "enabled": True,
                "conclusion": content,
                "evidence_gaps": [],
                "suggested_next_tools": [],
            }
        except Exception as exc:
            return {
                "provider": "deepseek",
                "enabled": False,
                "conclusion": "DeepSeek 增强审查暂不可用，已切换规则兜底，诊断主链路不受影响。",
                "error": str(exc),
                "evidence_gaps": [],
                "suggested_next_tools": [],
            }
