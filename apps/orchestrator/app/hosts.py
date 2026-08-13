"""Host Registry API (Giai đoạn 1, mục 7 architecture-proposal.md).

Vai trò:
  - operator/admin: đăng ký máy mới, cập nhật ca_migration_status (phản ánh
    tiến độ chạy ansible/playbooks/zero-to-ca-migration.yml +
    revoke-old-credential.yml — xem ansible/README.md), decommission/
    recommission (ngừng/khôi phục quản lý, xem update_decommission bên dưới).
  - Mọi role đã đăng nhập: đọc (list/get) — dùng để biết máy nào đang
    "migrate dở dang" (ca_migration_status="trust_deployed" nhưng chưa
    "migrated") mà không phải tự query DB thủ công như trước.

`DELETE /hosts/{hostname}` (admin-only, xem delete_host bên dưới) — theo yêu
cầu người dùng, xoá THẬT TOÀN BỘ dữ liệu liên quan tới host này (Job,
RemediationRequest, và AgentEnrollmentToken/AgentFimEvent qua cascade), kể cả
lịch sử job đã có — KHÁC HẲN thiết kế gốc (chỉ xoá được host chưa từng chạy
job nào, giữ nguyên lịch sử audit/job). Cố tình đánh đổi mất lịch sử job để
lấy "xoá dứt điểm 1 lần bấm", có ghi 1 audit_event RIÊNG (bảng audit_events
không bị xoá theo) làm dấu vết cuối cùng. Trước khi xoá DB, cố gắng gỡ Agent
khỏi máy thật qua SSH (best-effort, KHÔNG chặn xoá nếu thất bại/máy không
còn online — xem _run_agent_uninstall_best_effort). Muốn GIỮ lịch sử (khuyến
nghị cho host đã vận hành thật) thì dùng decommission thay vào đó.
"""
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.audit import write_audit_event
from app.auth import CurrentUser
from app.config import settings
from app.db import SessionLocal
from app.jobs import _call_job_dispatcher, _get_ssh_dispatch_environment
from app.models import Host, Job, RemediationRequest
from app.permissions import HOSTS_DELETE, HOSTS_MANAGE, HOSTS_MANAGE_TIER, HOSTS_VIEW, HOSTS_VIEW_SSH_CREDENTIAL
from app.rbac import _get_db as _rbac_get_db
from app.rbac import require_permission, resolve_permissions
from app.risk import compute_attention_level, compute_compliance_score, ATTENTION_SORT_RANK
from app.secrets_crypto import decrypt_host_secret, encrypt_host_secret
from app.schemas import (
    CA_MIGRATION_STATUSES,
    EXPOSURE_LEVELS,
    HostActiveResponseUpdate,
    HostAgentRenewalUpdate,
    HostCreate,
    HostDecommissionUpdate,
    HostMigrationStatusUpdate,
    HostOut,
    HostRiskOverviewItem,
    HostSshCredentialOut,
    HostUpdate,
)

router = APIRouter(prefix="/hosts", tags=["host-registry"])

# Tier 0/1 = "production/Tier cao" theo mục 1.3 architecture-proposal.md —
# dùng làm ngưỡng tính attention_level cho risk overview (compute_attention_level).
_HIGH_TIER_MAX = 1


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("", response_model=HostOut, status_code=status.HTTP_201_CREATED)
def register_host(
    body: HostCreate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(HOSTS_MANAGE)),
) -> Host:
    if db.get(Host, body.hostname) is not None:
        raise HTTPException(status_code=409, detail="host đã được đăng ký")
    if body.ssh_user not in settings.allowed_ssh_users_set:
        raise HTTPException(
            status_code=422,
            detail=f"ssh_user không hợp lệ, các giá trị hỗ trợ: {sorted(settings.allowed_ssh_users_set)}",
        )
    if body.exposure not in EXPOSURE_LEVELS:
        raise HTTPException(status_code=422, detail=f"exposure phải là 1 trong {EXPOSURE_LEVELS}")
    host = Host(
        hostname=body.hostname,
        ip_address=body.ip_address,
        tier=body.tier,
        ssh_user=body.ssh_user,
        ssh_port=body.ssh_port,
        ssh_password_encrypted=encrypt_host_secret(body.ssh_password) if body.ssh_password else None,
        ca_migration_status="not_started",
        exposure=body.exposure,
        added_by=user.username,
    )
    db.add(host)
    db.commit()
    db.refresh(host)

    write_audit_event(
        actor=user.username,
        action="host_registered",
        resource=host.hostname,
        payload={"ip_address": host.ip_address, "tier": host.tier, "os_family": host.os_family},
    )
    return host


@router.get("", response_model=list[HostOut])
def list_hosts(
    ca_migration_status: str | None = None,
    include_decommissioned: bool = False,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_permission(HOSTS_VIEW)),
) -> list[Host]:
    query = db.query(Host)
    if ca_migration_status is not None:
        query = query.filter(Host.ca_migration_status == ca_migration_status)
    # Mặc định ẩn host đã decommission khỏi danh sách quản lý hàng ngày —
    # vẫn tra cứu được đầy đủ (lịch sử job/audit không mất) qua
    # include_decommissioned=true hoặc GET /hosts/{hostname} trực tiếp.
    if not include_decommissioned:
        query = query.filter(Host.decommissioned_at.is_(None))
    return query.order_by(Host.hostname.asc()).all()


@router.get("/risk-overview", response_model=list[HostRiskOverviewItem])
def get_risk_overview(
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_permission(HOSTS_VIEW)),
) -> list[HostRiskOverviewItem]:
    """Tổng hợp "cần chú ý" cho toàn fleet — xem app/risk.py để biết cách
    tính điểm/mức ưu tiên. PHẢI khai TRƯỚC route "/{hostname}" bên dưới,
    nếu không FastAPI sẽ khớp "risk-overview" như 1 hostname (path param
    literal luôn phải đứng trước path param động cùng cấp).

    1 query/host để lấy job quét gần nhất (N+1, KHÔNG tối ưu thành 1 query
    lớn) — chấp nhận được ở quy mô ≤50 máy mục tiêu ban đầu (mục 7 roadmap),
    xem docs/architecture-proposal.md.
    """
    hosts = (
        db.query(Host)
        .filter(Host.decommissioned_at.is_(None))
        .order_by(Host.hostname.asc())
        .all()
    )

    items: list[HostRiskOverviewItem] = []
    for host in hosts:
        latest_job = (
            db.query(Job)
            .filter(
                Job.hostname == host.hostname,
                Job.job_type.in_(("scan", "agent-scan")),
                Job.status == "succeeded",
            )
            .order_by(Job.finished_at.desc())
            .first()
        )
        findings = []
        if latest_job is not None and latest_job.result_summary:
            findings = latest_job.result_summary.get("findings") or []
        score = compute_compliance_score(findings)
        items.append(
            HostRiskOverviewItem(
                hostname=host.hostname,
                tier=host.tier,
                exposure=host.exposure,
                ca_migration_status=host.ca_migration_status,
                compliance_score=score,
                attention_level=compute_attention_level(
                    tier=host.tier,
                    compliance_score=score,
                    exposure=host.exposure,
                    ca_migration_status=host.ca_migration_status,
                    high_tier_max=_HIGH_TIER_MAX,
                ),
                latest_scan_job_id=latest_job.id if latest_job is not None else None,
                latest_scan_at=latest_job.finished_at if latest_job is not None else None,
            )
        )

    items.sort(key=lambda it: (ATTENTION_SORT_RANK[it.attention_level], it.tier, it.hostname))
    return items


@router.get("/{hostname}", response_model=HostOut)
def get_host(
    hostname: str,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_permission(HOSTS_VIEW)),
) -> Host:
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    return host


@router.patch("/{hostname}", response_model=HostOut)
def update_host(
    hostname: str,
    body: HostUpdate,
    db: Session = Depends(_get_db),
    rbac_db: Session = Depends(_rbac_get_db),
    user: CurrentUser = Depends(require_permission(HOSTS_MANAGE)),
) -> Host:
    """Sửa thông tin host đã đăng ký — partial update (chỉ field có mặt
    trong request mới đổi), xem docstring HostUpdate (app/schemas.py) để
    biết lý do `tier` cần permission riêng (hosts.manage_tier) và vì sao đổi
    `ip_address` tự động reset `ca_migration_status`.

    `rbac_db` (KHÁC `db` — bảng domain hosts/jobs/... của router này) dùng
    riêng cho check permission qua `resolve_permissions`, cùng session mà
    `require_permission(...)` ở trên đã dùng (FastAPI dedupe theo cùng
    `Depends(app.rbac._get_db)`, không mở thêm connection) — tách biệt vì
    `role_permissions` là bảng RBAC dùng chung toàn hệ thống, không phải
    bảng domain riêng của app/hosts.py (production cùng 1 DB Postgres nên
    không khác gì, nhưng test mỗi router tự có SQLite riêng — xem
    tests/_rbac_test_engine.py).
    """
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    if host.decommissioned_at is not None:
        raise HTTPException(status_code=422, detail="host đang tạm ngưng quản lý — khôi phục quản lý trước khi sửa")

    if body.tier is not None and HOSTS_MANAGE_TIER not in resolve_permissions(rbac_db, user.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cần quyền hosts.manage_tier để đổi tier (mức độ quan trọng của host)",
        )

    if body.ssh_user is not None and body.ssh_user not in settings.allowed_ssh_users_set:
        raise HTTPException(
            status_code=422,
            detail=f"ssh_user không hợp lệ, các giá trị hỗ trợ: {sorted(settings.allowed_ssh_users_set)}",
        )

    if body.exposure is not None and body.exposure not in EXPOSURE_LEVELS:
        raise HTTPException(status_code=422, detail=f"exposure phải là 1 trong {EXPOSURE_LEVELS}")

    changes: dict = {}
    ca_status_reset = False

    if body.ip_address is not None and body.ip_address != host.ip_address:
        changes["ip_address"] = {"from": host.ip_address, "to": body.ip_address}
        host.ip_address = body.ip_address
        # Trust CA đã deploy (ca_migration_status) là cho địa chỉ CŨ — giữ
        # nguyên "trust_deployed"/"migrated" cho địa chỉ MỚI sẽ là thông tin
        # sai, có thể khiến operator tưởng nhầm host mới đã sẵn sàng nhận SSH
        # cert trong khi chưa hề chạy Zero-to-CA Migration cho địa chỉ đó.
        if host.ca_migration_status != "not_started":
            changes["ca_migration_status"] = {"from": host.ca_migration_status, "to": "not_started"}
            host.ca_migration_status = "not_started"
            host.ca_migration_updated_by = None
            ca_status_reset = True

    if body.os_family is not None and body.os_family != host.os_family:
        changes["os_family"] = {"from": host.os_family, "to": body.os_family}
        host.os_family = body.os_family

    if body.os_version is not None and body.os_version != host.os_version:
        changes["os_version"] = {"from": host.os_version, "to": body.os_version}
        host.os_version = body.os_version

    if body.tier is not None and body.tier != host.tier:
        changes["tier"] = {"from": host.tier, "to": body.tier}
        host.tier = body.tier

    if body.ssh_user is not None and body.ssh_user != host.ssh_user:
        changes["ssh_user"] = {"from": host.ssh_user, "to": body.ssh_user}
        host.ssh_user = body.ssh_user

    if body.ssh_port is not None and body.ssh_port != host.ssh_port:
        # Chỉ KHAI LẠI — không tự đổi gì trên host thật. Đổi cổng an toàn có
        # xác minh kết nối cho host đang quản lý phải qua
        # POST /hosts/{hostname}/ssh-port-change (app/jobs.py).
        changes["ssh_port"] = {"from": host.ssh_port, "to": body.ssh_port}
        host.ssh_port = body.ssh_port

    if body.exposure is not None and body.exposure != host.exposure:
        changes["exposure"] = {"from": host.exposure, "to": body.exposure}
        host.exposure = body.exposure

    if body.ssh_password is not None:
        # "" xoá password đã lưu, chuỗi khác rỗng mã hoá + ghi đè — KHÔNG bao
        # giờ đưa giá trị thật (cũ lẫn mới) vào changes/audit, chỉ ghi lại
        # SỰ KIỆN đã đổi.
        if body.ssh_password == "":
            if host.ssh_password_encrypted is not None:
                changes["ssh_password"] = "cleared"
                host.ssh_password_encrypted = None
        else:
            changes["ssh_password"] = "updated"
            host.ssh_password_encrypted = encrypt_host_secret(body.ssh_password)

    if body.clear_static_ssh_key and host.static_ssh_private_key_encrypted is not None:
        # KHÔNG có "ghi đè bằng giá trị mới" ở đây (khác ssh_password) — key
        # mới chỉ tạo được qua POST .../bootstrap-static-ssh-key (cần chạy
        # thật trên host, không phải field text nhập tay). PATCH này CHỈ xoá.
        changes["static_ssh_private_key"] = "cleared"
        host.static_ssh_private_key_encrypted = None

    if not changes:
        return host

    db.commit()
    db.refresh(host)

    write_audit_event(
        actor=user.username,
        action="host_updated",
        resource=hostname,
        payload={"changes": changes, "ca_migration_status_reset": ca_status_reset},
    )
    return host


@router.patch("/{hostname}/ca-migration-status", response_model=HostOut)
def update_ca_migration_status(
    hostname: str,
    body: HostMigrationStatusUpdate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(HOSTS_MANAGE)),
) -> Host:
    if body.ca_migration_status not in CA_MIGRATION_STATUSES:
        raise HTTPException(
            status_code=422, detail=f"ca_migration_status phải là 1 trong {CA_MIGRATION_STATUSES}"
        )
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    if host.decommissioned_at is not None:
        raise HTTPException(status_code=422, detail="host đang tạm ngưng quản lý — khôi phục quản lý trước khi đổi ca_migration_status")

    if body.ca_migration_status == "migrated":
        # Bắt buộc phải qua "trust_deployed" trước — không cho nhảy thẳng
        # not_started -> migrated (đúng thứ tự Zero-to-CA Migration thật:
        # đẩy trust trước, xác nhận migrate xong sau). Four-eyes cho bước
        # này đã bị bỏ theo yêu cầu người dùng — 1 người có thể tự đặt
        # trust_deployed rồi tự xác nhận migrated, kể cả host Tier cao.
        if host.ca_migration_status != "trust_deployed":
            raise HTTPException(
                status_code=422,
                detail="chỉ được xác nhận 'migrated' từ trạng thái 'trust_deployed'",
            )

    previous_status = host.ca_migration_status
    host.ca_migration_status = body.ca_migration_status
    host.ca_migration_updated_by = user.username
    db.commit()
    db.refresh(host)

    write_audit_event(
        actor=user.username,
        action="host_ca_migration_status_updated",
        resource=hostname,
        payload={"from": previous_status, "to": body.ca_migration_status, "tier": host.tier},
    )
    return host


@router.patch("/{hostname}/agent-renewal", response_model=HostOut)
def update_agent_renewal(
    hostname: str,
    body: HostAgentRenewalUpdate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(HOSTS_MANAGE)),
) -> Host:
    # Khoá/mở renew cert mTLS định kỳ của Agent trên 1 host cụ thể (vd host
    # nghi ngờ bị chiếm, chờ điều tra) — enforce thật ở
    # POST /internal/agent/renew-cert (xem app/agents.py), endpoint này chỉ
    # đặt cờ + ghi audit.
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    host.agent_renewal_blocked = body.blocked
    db.commit()
    db.refresh(host)

    write_audit_event(
        actor=user.username,
        action="agent_renewal_blocked_updated",
        resource=hostname,
        payload={"blocked": body.blocked},
    )
    return host


@router.patch("/{hostname}/active-response", response_model=HostOut)
def update_active_response(
    hostname: str,
    body: HostActiveResponseUpdate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(HOSTS_MANAGE)),
) -> Host:
    # Bật/tắt Active Response RIÊNG cho 1 host (mục 4.3/4.4 — Agent thực thi
    # remediation thật) — vẫn cần kill-switch TOÀN CỤC
    # settings.active_response_enabled bật thì host mới thật sự dùng đường
    # Agent, enforce thật ở app/jobs.py:_dispatch_remediate_job. Endpoint này
    # chỉ đặt cờ + ghi audit, cùng cấu trúc update_agent_renewal ở trên.
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    host.active_response_enabled = body.enabled
    db.commit()
    db.refresh(host)

    write_audit_event(
        actor=user.username,
        action="active_response_enabled_updated",
        resource=hostname,
        payload={"enabled": body.enabled},
    )
    return host


@router.patch("/{hostname}/decommission", response_model=HostOut)
def update_decommission(
    hostname: str,
    body: HostDecommissionUpdate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(HOSTS_MANAGE)),
) -> Host:
    """Ngừng/khôi phục quản lý 1 host — KHÔNG xoá record (xem docstring đầu
    file để biết lý do không có hard-delete). Host đã decommission bị chặn ở
    mọi endpoint tạo job/enrollment mới (trigger_scan/trigger_ssh_check/
    remediate/restore trong app/jobs.py, create_enrollment_token/
    create_agent_install_script trong app/agents.py, canary rollout trong
    app/canary.py) — enforce riêng ở từng nơi vì mỗi luồng có cách lấy Host
    khác nhau (`_lock_host_for_remediate` cho remediate, `db.get` cho scan/
    ssh-check/agent, query riêng cho canary), không có 1 điểm chặn tập trung
    duy nhất khả thi.

    KHÔNG có four-eyes (khác ca_migration_status="migrated") — đây là 1
    hành động đơn (không phải quy trình 2 bước đề xuất/duyệt), cùng mức đơn
    giản với update_agent_renewal/update_active_response ở trên.
    """
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    if body.decommissioned:
        if host.decommissioned_at is not None:
            raise HTTPException(status_code=409, detail="host đang tạm ngưng quản lý rồi")
        host.decommissioned_at = datetime.now(timezone.utc)
        host.decommissioned_by = user.username
        action = "host_decommissioned"
    else:
        if host.decommissioned_at is None:
            raise HTTPException(status_code=409, detail="host đang được quản lý bình thường, không cần khôi phục")
        host.decommissioned_at = None
        host.decommissioned_by = None
        action = "host_recommissioned"

    db.commit()
    db.refresh(host)

    write_audit_event(actor=user.username, action=action, resource=hostname, payload={})
    return host


@router.get("/{hostname}/ssh-credential", response_model=HostSshCredentialOut)
def get_ssh_credential(
    hostname: str,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(HOSTS_VIEW_SSH_CREDENTIAL)),
) -> HostSshCredentialOut:
    """Xem password SSH đã lưu (nếu có, xem HostCreate/HostUpdate.ssh_password)
    — tự ghi 1 audit event MỖI LẦN gọi, coi việc XEM lại credential đã lưu là
    hành động nhạy cảm ngang việc ghi (khác các field khác chỉ audit lúc
    sửa)."""
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    password = None
    if host.ssh_password_encrypted is not None:
        try:
            password = decrypt_host_secret(host.ssh_password_encrypted, "ssh_password")
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    write_audit_event(
        actor=user.username, action="host_ssh_credential_viewed", resource=hostname, payload={}
    )
    return HostSshCredentialOut(hostname=hostname, ssh_user=host.ssh_user, ssh_password=password)


def _run_agent_uninstall_best_effort(host: Host) -> dict:
    """Cố gắng gỡ Agent (Reporter + Executor) khỏi máy thật TRƯỚC khi hard-
    delete Host — BEST-EFFORT, KHÔNG chặn xoá nếu bước này thất bại (xem
    docstring delete_host: máy có thể đã tắt/đổi IP/mất mạng, không có lý do
    giữ record console mãi chỉ để chờ máy đó online lại).

    Cố tình KHÔNG tạo `Job` row cho bước này (khác mọi hành động SSH khác
    trong app này) — Job của host này sắp bị xoá cứng ngay sau lời gọi này
    (xem delete_host), ghi 1 Job rồi xoá ngay sau không còn giá trị audit gì.
    Outcome trả về từ đây được ghi vào `audit_events` (bảng riêng, hash-chain,
    KHÔNG bị xoá theo Host) bởi delete_host, không phải ở đây.

    Trả `{"outcome": ...}` — "skipped_no_agent" (chưa từng enroll Agent),
    "skipped_unreachable" (chưa có CA trust nên không cấp được SSH cert),
    "succeeded", hoặc "failed" (kèm "reason").
    """
    if host.agent_enrolled_at is None:
        return {"outcome": "skipped_no_agent"}
    if host.ca_migration_status not in ("trust_deployed", "migrated"):
        return {
            "outcome": "skipped_unreachable",
            "reason": "host chưa deploy CA trust (ca_migration_status='not_started') — không cấp được SSH cert",
        }

    try:
        ssh_auth_env = _get_ssh_dispatch_environment(host, principal=host.ssh_user)
    except RuntimeError as exc:
        return {"outcome": "failed", "reason": f"không cấp được SSH cert: {exc}"}

    dispatch_body = {
        "job_id": f"delete-{host.hostname}",
        "image": settings.allowed_execution_image,
        "command": ["agent-uninstall"],
        "environment": {
            "TARGET_HOST": host.ip_address,
            "TARGET_PORT": str(host.ssh_port),
            "SSH_USER": host.ssh_user,
            **ssh_auth_env,
        },
        "timeout_seconds": 60,
    }
    try:
        result = _call_job_dispatcher(dispatch_body, timeout=90)
    except httpx.HTTPError as exc:
        return {"outcome": "failed", "reason": f"job-dispatcher lỗi: {exc}"}

    if result.get("exit_code") == 0:
        return {"outcome": "succeeded"}
    return {"outcome": "failed", "reason": f"exit_code={result.get('exit_code')}"}


@router.delete("/{hostname}", status_code=status.HTTP_204_NO_CONTENT)
def delete_host(
    hostname: str,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(HOSTS_DELETE)),
) -> None:
    """Xoá THẬT (hard-delete) Host record — CHỈ admin (ngưỡng cao hơn các
    thao tác khác trong file này vì đây là hành động KHÔNG thể hoàn tác,
    khác decommission có thể recommission lại).

    Theo yêu cầu người dùng: xoá TOÀN BỘ dữ liệu liên quan, kể cả lịch sử job
    đã có — khác thiết kế gốc (chỉ xoá host chưa từng chạy job). Thứ tự XOÁ
    THỦ CÔNG bắt buộc vì `jobs.hostname`/`remediation_requests.hostname` +
    `remediation_requests.dry_run_job_id`/`apply_job_id` là FK RESTRICT
    (KHÔNG có ondelete=CASCADE, khác agent_enrollment_tokens/agent_fim_events
    — 2 bảng đó tự cascade): xoá RemediationRequest (tham chiếu cả hostname
    lẫn Job.id) TRƯỚC, rồi Job, rồi mới tới Host.
    """
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    uninstall_result = _run_agent_uninstall_best_effort(host)

    deleted_request_count = (
        db.query(RemediationRequest).filter(RemediationRequest.hostname == hostname).delete()
    )
    deleted_job_count = db.query(Job).filter(Job.hostname == hostname).delete()

    audit_payload = {
        "ip_address": host.ip_address,
        "tier": host.tier,
        "os_family": host.os_family,
        "agent_uninstall": uninstall_result,
        "deleted_job_count": deleted_job_count,
        "deleted_remediation_request_count": deleted_request_count,
    }
    db.delete(host)
    db.commit()

    write_audit_event(actor=user.username, action="host_force_deleted", resource=hostname, payload=audit_payload)
