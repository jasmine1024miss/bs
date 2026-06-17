from fastapi import APIRouter

from backend.app.execution.environment import probe_environment

router = APIRouter()


@router.get("/summary")
def dashboard_summary() -> dict:
    env = probe_environment()
    return {
        "health_score": 86,
        "services": [
            {"name": "nginx", "state": "failed", "risk": "medium"},
            {"name": "sshd", "state": "running", "risk": "medium"},
        ],
        "ports": [
            {"port": 22, "process": "sshd", "risk": "medium"},
            {"port": 80, "process": "httpd", "risk": "high"},
        ],
        "mode": env["effective_mode"],
        "environment": env,
    }
