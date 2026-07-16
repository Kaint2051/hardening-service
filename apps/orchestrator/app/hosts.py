"""Host Registry API (Giai đoạn 1, mục 7 architecture-proposal.md).

Vai trò:
  - operator/admin: đăng ký máy mới, cập nhật ca_migration_status (phản ánh
    tiến độ chạy ansible/playbooks/zero-to-ca-migration.yml +
    revoke-old-credential.yml — xem ansible/README.md), decommission/
    recommission (ngừng/khôi phục quản lý, xem update_decommission bên dưới).
  - Mọi role đã đăng nhập: đọc (list/get) — dùng để biết máy nào đang
    "migrate dở dang" (ca_migration_status="trust_deployed" nhưng chưa
    "migrated") mà không phải tự query DB thủ công như trước.

`DELETE /hosts/{hostname}` (admin-only, xem delete_host bên dưới) CHỈ xoá
được host CHƯA từng chạy job nào — `jobs.hostname` là foreign key KHÔNG có
`ondelete=CASCADE` (khác agent_enrollment_tokens/agent_fim_events), nên DB sẽ
từ chối (409, không phải lỗi 500 khó hiểu) nếu host đã có job history, để
không phá mất lịch sử audit/job — đi ngược triết lý audit-trail xuyên suốt dự
án. Với host đã có lịch sử, dùng decommission (đổi trạng thái, giữ nguyên
lịch sử) — cùng tinh thần Control.maturity/ca_migration_status: chuyển trạng
thái, không xoá record.
"""
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.audit import write_audit_event
from app.auth import CurrentUser, require_roles
from app.config import settings
from app.db import SessionLocal
from app.models import Host, Job
from app.schemas import (
    CA_MIGRATION_STATUSES,
    HostActiveResponseUpdate,
    HostAgentRenewalUpdate,
    HostCreate,
    HostDecommissionUpdate,
    HostMigrationStatusUpdate,
    HostOut,
    HostSshCredentialOut,
    HostUpdate,
)

router = APIRouter(prefix="/hosts", tags=["host-registry"])

_ALL_ROLES = ("viewer", "auditor", "rule-editor", "approver", "operator", "admin")
_OPERATOR_ROLES = ("operator", "admin")

# Tier 0/1 = "production/Tier cao" theo mục 1.3 architecture-proposal.md.
# Tier 2 (mặc định) chưa cần four-eyes ở bước này.
_HIGH_TIER_MAX = 1


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _encrypt_ssh_password(plaintext: str) -> str:
    # Fernet (AES-CBC + HMAC, xử lý nonce/xác thực nội bộ) — khoá lấy từ
    # settings.host_credential_encryption_key (chỉ ở .env, KHÔNG lưu DB).
    # LƯU Ý đã ghi rõ ở app/config.py: không chặn được kịch bản Orchestrator
    # tự nó bị chiếm, chỉ chặn được lộ riêng bản backup DB.
    return Fernet(settings.host_credential_encryption_key.encode()).encrypt(plaintext.encode()).decode()


def _decrypt_ssh_password(ciphertext: str) -> str:
    try:
        return Fernet(settings.host_credential_encryption_key.encode()).decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        # Xảy ra nếu host_credential_encryption_key bị đổi SAU khi đã mã hoá
        # dữ liệu cũ (vd xoay khoá không di trú lại dữ liệu) — báo lỗi rõ
        # ràng thay vì để lộ traceback thô qua API.
        raise RuntimeError(
            "không giải mã được ssh_password đã lưu — host_credential_encryption_key "
            "có thể đã đổi kể từ lúc lưu"
        ) from exc


@router.post("", response_model=HostOut, status_code=status.HTTP_201_CREATED)
def register_host(
    body: HostCreate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> Host:
    if db.get(Host, body.hostname) is not None:
        raise HTTPException(status_code=409, detail="host đã được đăng ký")
    if body.ssh_user not in settings.allowed_ssh_users_set:
        raise HTTPException(
            status_code=422,
            detail=f"ssh_user không hợp lệ, các giá trị hỗ trợ: {sorted(settings.allowed_ssh_users_set)}",
        )
    host = Host(
        hostname=body.hostname,
        ip_address=body.ip_address,
        os_family=body.os_family,
        os_version=body.os_version,
        tier=body.tier,
        ssh_user=body.ssh_user,
        ssh_password_encrypted=_encrypt_ssh_password(body.ssh_password) if body.ssh_password else None,
        ca_migration_status="not_started",
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
    _user: CurrentUser = Depends(require_roles(*_ALL_ROLES)),
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


@router.get("/{hostname}", response_model=HostOut)
def get_host(
    hostname: str,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_roles(*_ALL_ROLES)),
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
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> Host:
    """Sửa thông tin host đã đăng ký — partial update (chỉ field có mặt
    trong request mới đổi), xem docstring HostUpdate (app/schemas.py) để
    biết lý do `tier` chỉ admin sửa được và vì sao đổi `ip_address` tự động
    reset `ca_migration_status`.
    """
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    if host.decommissioned_at is not None:
        raise HTTPException(status_code=422, detail="host đã decommission — recommission trước khi sửa")

    if body.tier is not None and "admin" not in user.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="chỉ admin được đổi tier (ngưỡng four-eyes CA migration/remediate-apply)",
        )

    if body.ssh_user is not None and body.ssh_user not in settings.allowed_ssh_users_set:
        raise HTTPException(
            status_code=422,
            detail=f"ssh_user không hợp lệ, các giá trị hỗ trợ: {sorted(settings.allowed_ssh_users_set)}",
        )

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
            host.ssh_password_encrypted = _encrypt_ssh_password(body.ssh_password)

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
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> Host:
    if body.ca_migration_status not in CA_MIGRATION_STATUSES:
        raise HTTPException(
            status_code=422, detail=f"ca_migration_status phải là 1 trong {CA_MIGRATION_STATUSES}"
        )
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    if host.decommissioned_at is not None:
        raise HTTPException(status_code=422, detail="host đã decommission — recommission trước khi đổi ca_migration_status")

    if body.ca_migration_status == "migrated":
        # Bắt buộc phải qua "trust_deployed" trước — thiếu ràng buộc này thì
        # 1 operator có thể tự đăng ký host rồi nhảy thẳng
        # not_started -> migrated 1 mình, khiến check four-eyes bên dưới bị
        # bỏ qua hoàn toàn (ca_migration_updated_by khi đó vẫn là None, guard
        # "is not None" tự tắt cả điều kiện) — phát hiện qua test thật gọi
        # API trực tiếp, không phải chỉ đọc code.
        if host.ca_migration_status != "trust_deployed":
            raise HTTPException(
                status_code=422,
                detail="chỉ được xác nhận 'migrated' từ trạng thái 'trust_deployed'",
            )
        # Four-eyes: xác nhận "migrated" (khẳng định credential cũ đã bị thu
        # hồi) cho host Tier 0/1 không được do đúng người vừa đặt
        # "trust_deployed" tự xác nhận nốt — cần người thứ 2 (xem mô tả cột
        # trong app/models.py). Nhờ ràng buộc ngay trên, tới đây
        # ca_migration_updated_by chắc chắn không còn None.
        if host.tier <= _HIGH_TIER_MAX and host.ca_migration_updated_by == user.username:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="host Tier cao: không được tự xác nhận 'migrated' cho thay đổi trust_deployed của chính mình (four-eyes)",
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
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
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
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
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
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
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
            raise HTTPException(status_code=409, detail="host đã decommission rồi")
        host.decommissioned_at = datetime.now(timezone.utc)
        host.decommissioned_by = user.username
        action = "host_decommissioned"
    else:
        if host.decommissioned_at is None:
            raise HTTPException(status_code=409, detail="host chưa decommission, không cần recommission")
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
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
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
            password = _decrypt_ssh_password(host.ssh_password_encrypted)
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    write_audit_event(
        actor=user.username, action="host_ssh_credential_viewed", resource=hostname, payload={}
    )
    return HostSshCredentialOut(hostname=hostname, ssh_user=host.ssh_user, ssh_password=password)


@router.delete("/{hostname}", status_code=status.HTTP_204_NO_CONTENT)
def delete_host(
    hostname: str,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles("admin")),
) -> None:
    """Xoá THẬT (hard-delete) Host record — CHỈ admin (ngưỡng cao hơn các
    thao tác khác trong file này vì đây là hành động KHÔNG thể hoàn tác,
    khác decommission có thể recommission lại). CHỈ khả thi cho host CHƯA
    từng chạy job nào — xem docstring đầu file. Host đã có job history dùng
    decommission thay vào đó.
    """
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    has_job = db.query(Job).filter(Job.hostname == hostname).first() is not None
    if has_job:
        raise HTTPException(
            status_code=409,
            detail=(
                "host đã có lịch sử job — xoá thật sẽ phá vỡ liên kết audit/job, "
                "dùng PATCH .../decommission thay vào đó"
            ),
        )

    audit_payload = {"ip_address": host.ip_address, "tier": host.tier, "os_family": host.os_family}
    db.delete(host)
    db.commit()

    write_audit_event(actor=user.username, action="host_deleted", resource=hostname, payload=audit_payload)
