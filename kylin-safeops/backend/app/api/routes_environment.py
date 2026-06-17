from fastapi import APIRouter

from backend.app.execution.environment import probe_environment

router = APIRouter()


@router.get("/probe")
def environment_probe() -> dict:
    return probe_environment()

