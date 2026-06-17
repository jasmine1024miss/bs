from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class RuntimeEvidence:
    tool: str
    signal: str
    value: str
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeAlert:
    event_id: str
    source: str
    title: str
    risk_level: str
    service: str
    port: int | None
    process: str
    bind: str
    summary: str
    evidence_hint: str
    detected_at: str
    target: str
    mode: str
    adapter: str
    category: str = "runtime"
    status: str = "new"
    suggested_action: str = ""
    evidence: list[RuntimeEvidence] = field(default_factory=list)
    plan_hint: str = "生成 PlanSpec 后进入受控诊断"
    first_seen_at: str | None = None
    last_seen_at: str | None = None
    occurrence_count: int = 1
    linked_audit_id: str | None = None
    handled_at: str | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["evidence"] = [item.to_dict() for item in self.evidence]
        return data
