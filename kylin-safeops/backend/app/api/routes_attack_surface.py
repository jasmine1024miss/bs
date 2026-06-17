from fastapi import APIRouter

from backend.app.security.attack_surface import get_attack_surface

router = APIRouter()


@router.get("")
def attack_surface() -> dict:
    return get_attack_surface()

