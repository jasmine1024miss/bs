from fastapi import APIRouter, HTTPException

from backend.app.storage.records import load_replay

router = APIRouter()


@router.get("/{replay_id}")
def get_replay(replay_id: str) -> dict:
    replay = load_replay(replay_id)
    if replay is None:
        raise HTTPException(status_code=404, detail="replay not found")
    return replay

