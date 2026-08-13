import logging
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.agents import router as agents_router
from app.audit import verify_chain, write_audit_event
from app.auth import CurrentUser, get_current_user
from app.canary import reconcile_orphaned_rollouts
from app.canary import router as canary_router
from app.config import settings
from app.control_templates import router as control_templates_router
from app.controls import router as controls_router
from app.hosts import router as hosts_router
from app.jobs import reconcile_orphaned_remediate_jobs
from app.jobs import router as jobs_router
from app.permissions import AUDIT_VERIFY, AUDIT_WRITE
from app.rbac import require_permission
from app.remediation_requests import router as remediation_requests_router
from app.roles import router as roles_router
from app.users import router as users_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Dọn rollout mồ côi TRƯỚC KHI nhận request đầu tiên — xem docstring
    # app/canary.py:reconcile_orphaned_rollouts (gap: BackgroundTasks không
    # sống sót qua restart process, để lại rollout kẹt "running" mãi mãi và
    # khoá cứng control đó khỏi canary rollout kế tiếp).
    reconciled = reconcile_orphaned_rollouts()
    if reconciled:
        logger.warning(
            "khởi động: đã abort %d canary rollout mồ côi (running) sót lại từ lần chạy trước",
            reconciled,
        )
    # Cùng lý do reconcile_orphaned_rollouts ở trên, áp cho Job remediate qua
    # đường Agent (poll sống trong process) và cả đường SSH (dispatch đồng
    # bộ trong request) — xem docstring app/jobs.py:reconcile_orphaned_remediate_jobs.
    reconciled_jobs = reconcile_orphaned_remediate_jobs()
    if reconciled_jobs:
        logger.warning(
            "khởi động: đã đánh failed %d remediate job mồ côi (pending/running) sót lại từ lần chạy trước",
            reconciled_jobs,
        )
    yield


app = FastAPI(title="Hardening Console — Orchestrator (Giai đoạn 1)", lifespan=lifespan)

# SPA (apps/web) chạy khác origin với API này -> cần CORS. Chỉ allowlist đúng
# 1 origin của Web UI (settings.web_origin), không dùng "*" vì request có gửi
# Authorization header (credentials thật, không phải request công khai).
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.web_origin],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(controls_router)
app.include_router(control_templates_router)
app.include_router(hosts_router)
app.include_router(jobs_router)
app.include_router(agents_router)
app.include_router(canary_router)
app.include_router(remediation_requests_router)
app.include_router(users_router)
app.include_router(roles_router)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/me")
def whoami(user: CurrentUser = Depends(get_current_user)) -> dict:
    return {"username": user.username, "roles": sorted(user.roles)}


@app.get("/runtime-config")
def runtime_config(_user: CurrentUser = Depends(get_current_user)) -> dict:
    """Cờ cấu hình phía server mà UI PHẢI biết mới hiển thị đúng sự thật —
    hiện chỉ có kill-switch TOÀN CỤC Active Response (app/config.py).

    Lý do tồn tại: cột "Kết nối" ở trang Hosts suy kênh remediate (SSH hay
    Agent) từ 3 cờ trên chính Host, nhưng app/jobs.py:_agent_ineligible_reason
    còn kiểm tra ĐIỀU KIỆN THỨ 4 này. Thiếu nó, UI sẽ báo "Agent" cho 1 host
    đã bật active_response_enabled trong khi thực tế mọi remediate vẫn đi
    đường SSH — đúng loại "UI nói dối" mà dự án này tránh (không tin UI để
    enforce, nhưng UI cũng không được mô tả sai trạng thái thật).

    CHỈ ĐỌC, không có gì nhạy cảm (1 boolean đã ghi rõ trong .env.example) —
    mở cho mọi role đã đăng nhập, cùng mức GET /hosts.
    """
    return {"active_response_enabled": settings.active_response_enabled}


class AuditEventIn(BaseModel):
    action: str
    resource: Optional[str] = None
    payload: dict[str, Any] = {}


# Endpoint ghi audit log thủ công — giới hạn cho admin. "actor" LẤY TỪ TOKEN đã
# xác thực (KHÔNG nhận từ request body) để tránh giả mạo actor trong audit log;
# đây là gap bảo mật thật đã sửa so với bản demo Giai đoạn 0.
@app.post("/internal/audit-events")
def create_audit_event(
    event: AuditEventIn, user: CurrentUser = Depends(require_permission(AUDIT_WRITE))
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
    _user: CurrentUser = Depends(require_permission(AUDIT_VERIFY))
) -> dict:
    return {"chain_intact": verify_chain()}
