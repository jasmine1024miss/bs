from fastapi import APIRouter
from pydantic import BaseModel

from backend.app.execution.shadow import preview_restart_service

router = APIRouter()


class ShadowPreviewRequest(BaseModel):
    service: str = "nginx"


@router.post("/preview")
def shadow_preview(request: ShadowPreviewRequest) -> dict:
    return preview_restart_service(request.service)

