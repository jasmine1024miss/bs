from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.routes_agent import router as agent_router
from backend.app.api.routes_attack_surface import router as attack_surface_router
from backend.app.api.routes_audit import router as audit_router
from backend.app.api.routes_dashboard import router as dashboard_router
from backend.app.api.routes_environment import router as environment_router
from backend.app.api.routes_redteam import router as redteam_router
from backend.app.api.routes_replay import router as replay_router
from backend.app.api.routes_runtime import router as runtime_router
from backend.app.api.routes_shadow import router as shadow_router
from backend.app.runtime.alerts import start_runtime_scheduler, stop_runtime_scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    start_runtime_scheduler()
    try:
        yield
    finally:
        await stop_runtime_scheduler()


app = FastAPI(title="KylinSafeOps", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard_router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(agent_router, prefix="/api/agent", tags=["agent"])
app.include_router(environment_router, prefix="/api/environment", tags=["environment"])
app.include_router(audit_router, prefix="/api/audit", tags=["audit"])
app.include_router(replay_router, prefix="/api/replay", tags=["replay"])
app.include_router(shadow_router, prefix="/api/shadow", tags=["shadow"])
app.include_router(redteam_router, prefix="/api/redteam", tags=["redteam"])
app.include_router(attack_surface_router, prefix="/api/attack-surface", tags=["attack-surface"])
app.include_router(runtime_router, prefix="/api/runtime", tags=["runtime"])


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
