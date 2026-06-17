from fastapi import APIRouter

from backend.app.security.redteam import run_redteam_suite

router = APIRouter()


@router.post("/run")
def run_redteam() -> dict:
    return run_redteam_suite()

