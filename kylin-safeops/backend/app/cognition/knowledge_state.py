def build_initial_knowledge_state() -> dict:
    return {
        "known": [],
        "unknown": [
            {"key": "service_state", "question": "nginx.service 当前状态是什么"},
            {"key": "error_log", "question": "nginx 最近错误日志是什么"},
            {"key": "port_owner", "question": "80 端口是否被占用"},
            {"key": "process_owner", "question": "占用端口的进程是谁"},
        ],
        "assumed": [
            {"hypothesis": "port_conflict", "reason": "服务启动失败常见原因"},
            {"hypothesis": "config_error", "reason": "配置错误可能导致启动失败"},
            {"hypothesis": "permission_denied", "reason": "权限不足可能导致绑定失败"},
        ],
        "verified": [],
    }

