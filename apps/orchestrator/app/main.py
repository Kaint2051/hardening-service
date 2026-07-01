from typing import Any, Optional

from fastapi import Depends, FastAPI
from pydantic import BaseModel

from app.audit import verify_chain, write_audit_event
from app.auth import CurrentUser, get_current_user, require_roles
from app.controls import router as controls_router

app = FastAPI(title="Hardening Console — Orchestrator (Giai đoạn 1)")
app.include_router(controls_router)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/me")
def whoami(user: CurrentUser = Depends(get_current_user)) -> dict:
    return {"username": user.username, "roles": sorted(user.roles)}


class AuditEventIn(BaseModel):
    action: str
    resource: Optional[str] = None
    payload: dict[str, Any] = {}


# Endpoint ghi audit log thủ công — giới hạn cho admin. "actor" LẤY TỪ TOKEN đã
# xác thực (KHÔNG nhận từ request body) để tránh giả mạo actor trong audit log;
# đây là gap bảo mật thật đã sửa so với bản demo Giai đoạn 0.
@app.post("/internal/audit-events")
def create_audit_event(
    event: AuditEventIn, user: CurrentUser = Depends(require_roles("admin"))
) -> dict:
    entry = write_audit_event(
        actor=user.username,
        action=event.action,
        resource=event.resource,
        payload=event.payload,
    )
    return {
        "id": entry.id,
        "prev_hash": entry.prev_hash,
        "record_hash": entry.record_hash,
    }


@app.get("/internal/audit-events/verify")
def verify_audit_chain(
    _user: CurrentUser = Depends(require_roles("auditor", "admin"))
) -> dict:
    return {"chain_intact": verify_chain()}
