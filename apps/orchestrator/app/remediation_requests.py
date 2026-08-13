"""Hàng đợi chờ duyệt cho remediate-apply thật ("Gửi duyệt" -> "Duyệt") —
mục "Kiểm tra & Khắc phục" trên giao diện.

Vai trò:
  - operator/admin: "Gửi duyệt" sau khi đã dry-run xong
    (POST .../submit-for-approval) — chỉ tạo 1 dòng "pending", KHÔNG apply
    ngay.
  - approver/admin: xem toàn bộ hàng đợi + "Duyệt"/"Từ chối"
    (GET /remediation-requests, POST .../approve|reject). Four-eyes (yêu cầu
    người duyệt khác người gửi) đã bị bỏ hoàn toàn theo yêu cầu người dùng —
    approver/admin có thể tự duyệt/từ chối yêu cầu do chính mình gửi.
  - Mọi role đã đăng nhập: xem lại yêu cầu CHÍNH MÌNH đã gửi
    (GET /remediation-requests?mine_only=true) — không có "hố đen im lặng"
    sau khi bấm Gửi duyệt.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.audit import write_audit_event
from app.auth import CurrentUser
from app.db import SessionLocal
from app.jobs import DRY_RUN_MAX_AGE, _agent_ineligible_reason, run_remediate_apply
from app.models import Control, Host, Job, RemediationRequest
from app.permissions import REMEDIATION_REQUESTS_APPROVE, REMEDIATION_REQUESTS_SUBMIT, REMEDIATION_REQUESTS_VIEW
from app.rbac import _get_db as _rbac_get_db
from app.rbac import require_permission, resolve_permissions
from app.schemas import (
    RemediationRejectRequest,
    RemediationRequestOut,
    RemediationSubmitRequest,
)

router = APIRouter(tags=["remediation-requests"])


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post(
    "/hosts/{hostname}/controls/{control_id}/remediate/submit-for-approval",
    response_model=RemediationRequestOut,
    status_code=status.HTTP_201_CREATED,
)
def submit_remediation_request(
    hostname: str,
    control_id: str,
    body: RemediationSubmitRequest,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(REMEDIATION_REQUESTS_SUBMIT)),
) -> RemediationRequest:
    """Validate Y HỆT các bước đầu của app/jobs.py:run_remediate_apply
    (control không draft, dry-run job đúng host/control/succeeded/chưa hết
    hạn DRY_RUN_MAX_AGE) NHƯNG DỪNG LẠI Ở ĐÂY — tạo 1 RemediationRequest
    "pending", KHÔNG tạo Job apply nào. Job apply thật chỉ được tạo lúc
    approve (xem approve_remediation_request bên dưới), lúc đó mới gọi
    run_remediate_apply và re-validate lại toàn bộ 1 lần nữa (phòng trường
    hợp dry-run kịp hết hạn trong lúc chờ duyệt).

    `body.connection_method` (None/"ssh"/"agent") lưu NGUYÊN vào
    RemediationRequest, dùng lại y hệt lúc approve — CỐ Ý kiểm tra sớm ngay
    ở đây nếu là "agent" (dù dispatch thật chỉ xảy ra lúc approve) để người
    gửi biết ngay lựa chọn không khả thi, thay vì phải chờ 1 approver khác
    bấm "Duyệt" rồi mới thấy request chuyển "failed".
    """
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    if host.decommissioned_at is not None:
        raise HTTPException(
            status_code=422, detail="host đang tạm ngưng quản lý — khôi phục quản lý trước khi gửi duyệt"
        )
    if body.connection_method == "agent":
        reason = _agent_ineligible_reason(host)
        if reason is not None:
            raise HTTPException(
                status_code=422,
                detail=f"không thể dùng đường Agent cho host '{hostname}': {reason}",
            )

    control = db.get(Control, control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="control không tồn tại")
    if control.maturity == "draft":
        raise HTTPException(
            status_code=422,
            detail="control còn ở maturity 'draft' — chỉ cho phép dry-run, chưa cho gửi duyệt áp dụng thật",
        )

    dry_run_job = db.get(Job, body.dry_run_job_id)
    if dry_run_job is None:
        raise HTTPException(status_code=422, detail="dry_run_job_id không tồn tại")
    if dry_run_job.job_type != "remediate-dry-run":
        raise HTTPException(status_code=422, detail="dry_run_job_id không phải job dry-run")
    if dry_run_job.hostname != hostname or dry_run_job.control_id != control_id:
        raise HTTPException(
            status_code=422, detail="dry_run_job_id không khớp đúng host/control đang gửi duyệt"
        )
    if dry_run_job.status != "succeeded":
        raise HTTPException(status_code=422, detail="dry_run_job_id chưa succeeded")

    dry_run_finished = dry_run_job.finished_at
    if dry_run_finished is None:
        raise HTTPException(status_code=422, detail="dry_run_job_id chưa có finished_at")
    # SQLite (test) trả DateTime(timezone=True) dạng naive, Postgres (thật)
    # trả dạng aware — chuẩn hoá trước khi so sánh, cùng bug đã gặp ở
    # app/jobs.py:run_remediate_apply.
    if dry_run_finished.tzinfo is None:
        dry_run_finished = dry_run_finished.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - dry_run_finished > DRY_RUN_MAX_AGE:
        raise HTTPException(
            status_code=422,
            detail=f"dry_run_job_id đã quá hạn (giới hạn {DRY_RUN_MAX_AGE}) — chạy dry-run lại trước khi gửi duyệt",
        )

    request = RemediationRequest(
        hostname=hostname,
        control_id=control_id,
        dry_run_job_id=body.dry_run_job_id,
        connection_method=body.connection_method,
        status="pending",
        requested_by=user.username,
    )
    db.add(request)
    db.commit()
    db.refresh(request)

    write_audit_event(
        actor=user.username,
        action="remediation_request_submitted",
        resource=hostname,
        payload={
            "request_id": request.id, "control_id": control_id, "dry_run_job_id": body.dry_run_job_id,
            "connection_method": body.connection_method,
        },
    )
    return request


@router.get("/remediation-requests", response_model=list[RemediationRequestOut])
def list_remediation_requests(
    status_filter: str | None = None,
    mine_only: bool = False,
    db: Session = Depends(_get_db),
    rbac_db: Session = Depends(_rbac_get_db),
    user: CurrentUser = Depends(require_permission(REMEDIATION_REQUESTS_VIEW)),
) -> list[RemediationRequest]:
    """`mine_only=true` — mọi role xem được đúng yêu cầu CHÍNH MÌNH đã gửi
    (không có "hố đen im lặng" sau khi bấm Gửi duyệt). KHÔNG có
    `mine_only`, chỉ ai có quyền remediation_requests.approve mới xem được
    TOÀN BỘ hàng đợi — operator thường không cần (và không nên) thấy yêu cầu
    của người khác.

    `rbac_db` (KHÁC `db` — bảng domain remediation_requests của router này)
    cùng lý do app/hosts.py:update_host — bảng role_permissions là RBAC dùng
    chung toàn hệ thống, tách session khỏi domain của router này (production
    cùng 1 Postgres nên không khác gì, test mỗi router tự có SQLite riêng).
    """
    query = db.query(RemediationRequest)
    if mine_only:
        query = query.filter(RemediationRequest.requested_by == user.username)
    elif REMEDIATION_REQUESTS_APPROVE not in resolve_permissions(rbac_db, user.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="chỉ approver/admin xem được toàn bộ hàng đợi — dùng mine_only=true để xem yêu cầu của chính bạn",
        )
    # status bất kỳ, không khớp gì trả rỗng chứ không 422 — cùng quy ước
    # GET /jobs (app/jobs.py:list_jobs).
    if status_filter is not None:
        query = query.filter(RemediationRequest.status == status_filter)
    return query.order_by(RemediationRequest.id.desc()).all()


@router.post("/remediation-requests/{request_id}/approve", response_model=RemediationRequestOut)
def approve_remediation_request(
    request_id: int,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(REMEDIATION_REQUESTS_APPROVE)),
) -> RemediationRequest:
    """Duyệt 1 yêu cầu đang "pending" — gọi THẲNG
    app/jobs.py:run_remediate_apply (tái dùng 100% logic maturity/
    staleness/backup trong đó), CHỈ set status="approved" nếu hàm đó KHÔNG
    raise. Four-eyes đã bị bỏ hoàn toàn theo yêu cầu người dùng — approver có
    thể tự duyệt yêu cầu do chính mình gửi.

    Nếu run_remediate_apply raise (vd dry-run kịp hết hạn trong lúc chờ
    duyệt) — request chuyển "failed" (KHÔNG PHẢI "rejected", ý nghĩa khác
    hẳn: đây là lỗi hệ thống/dữ liệu cũ, không phải approver không đồng ý
    nội dung) rồi RE-RAISE nguyên lỗi đó để approver thấy ngay, không phải
    chỉ biết qua việc tự vào xem lại hàng đợi sau.
    """
    req = db.get(RemediationRequest, request_id)
    if req is None:
        raise HTTPException(status_code=404, detail="yêu cầu không tồn tại")
    if req.status != "pending":
        raise HTTPException(
            status_code=409, detail=f"yêu cầu đã ở trạng thái '{req.status}', không còn 'pending'"
        )

    try:
        apply_job = run_remediate_apply(
            db, req.hostname, req.control_id, req.dry_run_job_id, user,
            connection_method=req.connection_method,
        )
    except HTTPException as exc:
        req.status = "failed"
        req.decided_by = user.username
        req.decided_at = datetime.now(timezone.utc)
        req.decision_note = str(exc.detail)
        db.commit()
        write_audit_event(
            actor=user.username,
            action="remediation_request_approve_failed",
            resource=req.hostname,
            payload={"request_id": req.id, "error": str(exc.detail)},
        )
        raise

    req.status = "approved"
    req.decided_by = user.username
    req.decided_at = datetime.now(timezone.utc)
    req.apply_job_id = apply_job.id
    db.commit()
    db.refresh(req)

    write_audit_event(
        actor=user.username,
        action="remediation_request_approved",
        resource=req.hostname,
        payload={"request_id": req.id, "apply_job_id": apply_job.id},
    )
    return req


@router.post("/remediation-requests/{request_id}/reject", response_model=RemediationRequestOut)
def reject_remediation_request(
    request_id: int,
    body: RemediationRejectRequest,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(REMEDIATION_REQUESTS_APPROVE)),
) -> RemediationRequest:
    """Từ chối — cùng quyền hạn với approve, không còn ràng buộc four-eyes
    (đã bị bỏ theo yêu cầu người dùng): approver có thể tự từ chối yêu cầu do
    chính mình gửi."""
    req = db.get(RemediationRequest, request_id)
    if req is None:
        raise HTTPException(status_code=404, detail="yêu cầu không tồn tại")
    if req.status != "pending":
        raise HTTPException(
            status_code=409, detail=f"yêu cầu đã ở trạng thái '{req.status}', không còn 'pending'"
        )

    req.status = "rejected"
    req.decided_by = user.username
    req.decided_at = datetime.now(timezone.utc)
    req.decision_note = body.reason
    db.commit()
    db.refresh(req)

    write_audit_event(
        actor=user.username,
        action="remediation_request_rejected",
        resource=req.hostname,
        payload={"request_id": req.id, "reason": body.reason},
    )
    return req
