"""Canary Rollout API (mục 7 roadmap architecture-proposal.md: "canary/rollout
theo Tier" cho control đã kiểm định).

Chỉ cho phép canary rollout TỰ ĐỘNG (nhiều host Tier 2, lần lượt dry-run rồi
apply NGAY, dừng ngay khi có 1 host lỗi) cho control risk_group="A" +
maturity="production" (xem app/controls.py: risk_group chỉ được gán "A" khi
maturity đã "production", và tự reset về "B" ngay khi control rời khỏi
"production" — nên 2 điều kiện này luôn nhất quán với nhau). Control
risk_group="B" (mặc định) hoặc chưa "production" PHẢI dùng luồng remediate
thủ công từng host (app/jobs.py `trigger_remediate_dry_run`/
`trigger_remediate_apply`) — canary ở đây KHÔNG thay thế luồng đó, chỉ dành
cho control đã đủ tin cậy để tự động hoá trên diện rộng.

`_run_rollout` chạy trong background task (FastAPI `BackgroundTasks`) — mở
SESSION RIÊNG vì session request-scoped của route đã đóng (`db.close()` trong
`_get_db`) lúc task này thực sự chạy. Lần lượt dry-run RỒI apply NGAY trên
CÙNG 1 host trước khi sang host kế tiếp (không dry-run hết mọi host rồi mới
apply hết) — xem comment tại `_run_rollout` để biết vì sao thứ tự này
load-bearing.
"""
import logging
from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit import write_audit_event
from app.auth import CurrentUser, require_roles
from app.db import SessionLocal
from app.jobs import _find_remediation_variant, run_remediate_apply, run_remediate_dry_run
from app.models import CanaryRollout, Control, Host, Job
from app.schemas import CanaryRolloutDetailOut, CanaryRolloutHostOutcome, CanaryRolloutOut

router = APIRouter(tags=["canary-rollout"])

logger = logging.getLogger(__name__)

# Trùng đúng giá trị _OPERATOR_ROLES ở app/jobs.py và app/hosts.py — duplicate
# có chủ đích (không import), cùng lý do jobs.py tự duplicate
# _REMEDIATE_HIGH_TIER_MAX từ hosts.py thay vì import: giữ policy "ai được
# trigger remediate/canary" độc lập theo từng router, dễ tách rời sau này nếu
# 1 router cần siết chặt hơn router kia mà không ảnh hưởng router còn lại.
_OPERATOR_ROLES = ("operator", "admin")
_ALL_ROLES = ("viewer", "auditor", "rule-editor", "approver", "operator", "admin")

# Canary CHỈ chạy trên host Tier 2 — Tier 0/1 ("production/Tier cao", xem
# app/hosts.py) luôn bắt buộc remediate thủ công từng host qua app/jobs.py,
# không bao giờ tự động hoá hàng loạt qua canary.
_CANARY_HOST_TIER = 2


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _run_rollout(rollout_id: int, hostnames: list[str], control_id: str, triggered_by: str) -> None:
    """Chạy NGOÀI request (FastAPI BackgroundTasks). Session request-scoped
    của route `start_canary_rollout` đã đóng lúc hàm này thực thi -> PHẢI mở
    session riêng qua `SessionLocal` (giống app/jobs.py/app/canary.py
    `_get_db`, chỉ khác không có request nào để inject qua `Depends`).

    `run_remediate_dry_run`/`run_remediate_apply` (app/jobs.py) chỉ đọc thuộc
    tính `.username` của tham số `user` (đã đọc lại app/jobs.py để xác nhận,
    không đoán) — background task này không có request/token thật nên dùng 1
    object rỗng (`SimpleNamespace`) chỉ mang đúng `.username`, KHÔNG dựng lại
    `CurrentUser` đầy đủ (vốn cần `subject`/`roles` không có ý nghĩa ở đây).

    THỨ TỰ dry-run rồi apply NGAY trên CÙNG 1 host (không dry-run hết mọi host
    rồi mới apply hết) LÀ LOAD-BEARING: `DRY_RUN_MAX_AGE` (app/jobs.py, hiện
    30 phút) giả định khoảng cách dry-run -> apply ngắn; nếu dry-run hết N
    host trước rồi mới quay lại apply lần lượt, các host xử lý sau có thể
    apply dựa trên dry-run đã quá hạn hoặc lệch trạng thái thật (drift) nếu N
    đủ lớn hoặc 1 host giữa chừng chạy lâu.
    """
    db = SessionLocal()
    fake_user = SimpleNamespace(username=triggered_by)

    def _abort(reason: str, hostname: str | None) -> None:
        rollout = db.get(CanaryRollout, rollout_id)
        if rollout is None or rollout.status != "running":
            # rollout.status != "running": process KHÁC (vd
            # reconcile_orphaned_rollouts) đã ghi lý do abort của CHÍNH nó
            # trong lúc dry-run/apply của host này còn dở dang — lỗi của
            # host này (dry_run_failed/apply_failed/internal_error) tới SAU,
            # không được ghi đè lên lý do đã có, đúng bất biến "process nào
            # đưa rollout ra khỏi 'running' trước thì lý do của process đó
            # được giữ" (khớp check tương tự ở đầu vòng lặp phía trên).
            return
        rollout.status = "aborted"
        rollout.aborted_hostname = hostname
        rollout.abort_reason = reason
        rollout.finished_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_event(
            actor=triggered_by,
            action="canary_rollout_aborted",
            resource=control_id,
            payload={
                "rollout_id": rollout_id,
                "control_id": control_id,
                "hostname": hostname,
                "abort_reason": reason,
            },
        )

    try:
        for hostname in hostnames:
            rollout = db.get(CanaryRollout, rollout_id)
            if rollout is None:
                return
            if rollout.status != "running":
                # Rollout đã bị đưa ra khỏi "running" bởi CODE KHÁC — không
                # phải cancel_requested (nhánh đó xử lý riêng ngay dưới), mà
                # ví dụ `reconcile_orphaned_rollouts()` (app/main.py lifespan)
                # chạy ở 1 process Orchestrator KHÁC đang khởi động cùng lúc.
                # Deploy hiện tại chỉ 1 process/1 replica nên tình huống này
                # chưa xảy ra thật, nhưng nếu sau này chạy nhiều worker/replica
                # mà thiếu check này, process này sẽ tiếp tục dry-run/apply
                # trên các host còn lại của 1 rollout mà process khác vừa coi
                # là mồ côi và abort — 2 rollout uncoordinated cùng đụng 1 tập
                # host, đúng cái mà ux_canary_rollouts_running sinh ra để
                # ngăn. Dừng ngay, KHÔNG ghi đè lại status (process kia đã ghi
                # lý do abort của riêng nó).
                return
            if rollout.cancel_requested:
                rollout.status = "aborted"
                rollout.abort_reason = "cancelled"
                rollout.finished_at = datetime.now(timezone.utc)
                db.commit()
                write_audit_event(
                    actor=triggered_by,
                    action="canary_rollout_aborted",
                    resource=control_id,
                    payload={"rollout_id": rollout_id, "control_id": control_id, "abort_reason": "cancelled"},
                )
                return

            try:
                dry_run_job = run_remediate_dry_run(
                    db, hostname, control_id, fake_user, canary_rollout_id=rollout_id
                )

                if dry_run_job.status != "succeeded":
                    _abort("dry_run_failed", hostname)
                    return

                # Re-check NGAY TRƯỚC bước có thể đổi thật cấu hình host
                # (apply) — thu hẹp cửa sổ TOCTOU giữa lần kiểm tra đầu vòng
                # lặp (trước dry-run) và đây: dry-run (`--check --diff`,
                # không đổi gì trên host) đủ chậm để 1 process khác kịp abort
                # rollout này giữa chừng; apply thì KHÔNG được phép chạy sau
                # khi rollout đã bị coi là mồ côi/huỷ bởi process khác. Không
                # cần re-check thêm sau dry-run xong nhưng trước bước này vì
                # không có I/O nào chen giữa 2 dòng đó.
                rollout = db.get(CanaryRollout, rollout_id)
                if rollout is None or rollout.status != "running":
                    return

                # Apply NGAY sau dry-run của CÙNG host này — xem docstring
                # hàm này, thứ tự không được đảo (load-bearing).
                apply_job = run_remediate_apply(
                    db, hostname, control_id, dry_run_job.id, fake_user, canary_rollout_id=rollout_id
                )

                if apply_job.status != "succeeded":
                    _abort("apply_failed", hostname)
                    return
            except Exception:
                # Bất kỳ lỗi nào ở 1 host (gating HTTPException từ
                # run_remediate_*, lỗi hạ tầng...) KHÔNG được để rollout kẹt
                # mãi ở "running" — luôn đưa về "aborted" trước khi dừng task
                # (xem docstring app/models.py:CanaryRollout). Job (nếu đã
                # tạo được trước khi raise) đã tự mang đúng canary_rollout_id
                # vì run_remediate_dry_run/apply gán ngay lúc tạo Job, không
                # phải gán ở đây sau khi return — nên GET /canary-rollouts/{id}
                # vẫn thấy đúng job gây lỗi kể cả khi hàm raise thay vì trả về.
                logger.exception(
                    "canary rollout %s: lỗi khi xử lý host %s", rollout_id, hostname
                )
                _abort("internal_error", hostname)
                return

        rollout = db.get(CanaryRollout, rollout_id)
        if rollout is not None and rollout.status == "running":
            rollout.status = "completed"
            rollout.finished_at = datetime.now(timezone.utc)
            db.commit()
            write_audit_event(
                actor=triggered_by,
                action="canary_rollout_completed",
                resource=control_id,
                payload={"rollout_id": rollout_id, "control_id": control_id},
            )
    except Exception:
        # Lưới an toàn cuối: phần code NGOÀI try/except theo từng host ở trên
        # (đọc cancel_requested đầu mỗi vòng lặp, commit/audit ở nhánh cancel,
        # đọc+commit/audit sau khi hết vòng lặp) vẫn có thể văng lỗi (vd DB
        # hiccup tạm thời) mà không được bắt — nếu để lọt, rollout kẹt mãi ở
        # "running" (không có cơ chế tự hồi phục), trái với mục đích đã nêu ở
        # docstring app/models.py:CanaryRollout. rollback() trước vì session
        # có thể đang ở trạng thái "pending rollback" sau 1 commit lỗi.
        logger.exception("canary rollout %s: lỗi ngoài dự kiến ngoài phạm vi try/except từng host", rollout_id)
        try:
            db.rollback()
            _abort("internal_error", None)
        except Exception:
            logger.exception(
                "canary rollout %s: KHÔNG THỂ đánh dấu 'aborted' sau lỗi ngoài dự kiến — "
                "rollout kẹt ở 'running' cho tới lần Orchestrator khởi động lại kế tiếp "
                "(reconcile_orphaned_rollouts() tự dọn lúc đó, xem app/main.py lifespan) "
                "hoặc can thiệp thủ công (UPDATE trực tiếp) nếu cần dọn ngay",
                rollout_id,
            )
    finally:
        db.close()


def reconcile_orphaned_rollouts() -> int:
    """Gọi 1 lần lúc Orchestrator khởi động (xem app/main.py `lifespan`).

    `_run_rollout` chạy trong `BackgroundTasks` — SỐNG TRONG process, không
    phải job/task độc lập nào có thể tự resume sau khi process chết. Nếu
    Orchestrator crash/bị restart (deploy, OOM-kill, `docker compose
    restart`...) đúng lúc 1 rollout đang "running", không có gì còn chạy để
    đưa rollout đó về "completed"/"aborted" nữa — nó kẹt ở "running" MÃI MÃI
    (khác các nhánh lỗi trong-process ở `_run_rollout`, vốn đã có try/except
    bao ngoài để luôn tự đưa về "aborted", xem docstring hàm đó). Vì
    `ux_canary_rollouts_running` (migration 0009) chỉ cho phép tối đa 1
    rollout "running" mỗi control, 1 rollout mồ côi còn khoá CỨNG luôn control
    đó khỏi mọi canary rollout kế tiếp cho tới khi có người sửa DB tay.

    Luôn đưa về "aborted", KHÔNG thử tự resume dry-run/apply dở dang — trạng
    thái thật trên host tại đúng thời điểm restart không xác định chắc chắn
    (job cuối có thể đã apply xong trên host nhưng chưa kịp commit DB), resume
    mù rủi ro áp lại nhầm hoặc bỏ sót bước, trong khi "aborted" (đúng tinh
    thần an toàn mặc định đã áp dụng xuyên suốt dự án) chỉ đơn thuần mở khoá
    lại control để operator tự trigger lại rollout mới sau khi đã xác minh
    tình trạng host thật.
    """
    db = SessionLocal()
    try:
        orphaned = db.query(CanaryRollout).filter(CanaryRollout.status == "running").all()
        for rollout in orphaned:
            rollout.status = "aborted"
            rollout.abort_reason = "orchestrator_restarted"
            rollout.finished_at = datetime.now(timezone.utc)
        db.commit()
        for rollout in orphaned:
            # State chính (status="aborted", đã commit ở trên) là phần BẮT
            # BUỘC đúng — audit chỉ là bản ghi phụ. write_audit_event() dùng
            # session/engine RIÊNG (audit_database_url, xem app/audit.py) nên
            # có thể lỗi độc lập với DB chính (advisory lock timeout, audit
            # role tạm mất kết nối...) mà không liên quan gì tới việc rollout
            # đã được abort đúng hay chưa. Hàm này chạy trong `lifespan` của
            # main.py — để lỗi ở đây văng ra ngoài sẽ làm CẢ Orchestrator
            # không khởi động được (0 request nào được phục vụ) chỉ vì thiếu
            # đúng 1 dòng audit, trái tinh thần "không để lỗi ngoài dự kiến
            # sập cả app" đã áp dụng cho _run_rollout ở trên.
            try:
                write_audit_event(
                    actor="system",
                    action="canary_rollout_aborted",
                    resource=rollout.control_id,
                    payload={
                        "rollout_id": rollout.id,
                        "control_id": rollout.control_id,
                        "abort_reason": "orchestrator_restarted",
                    },
                )
            except Exception:
                logger.exception(
                    "reconcile_orphaned_rollouts: rollout %s đã abort đúng trong DB nhưng "
                    "KHÔNG ghi được audit event — chỉ thiếu dòng audit, không ảnh hưởng state",
                    rollout.id,
                )
        return len(orphaned)
    finally:
        db.close()


@router.post("/controls/{control_id}/canary-rollout", response_model=CanaryRolloutOut)
def start_canary_rollout(
    control_id: str,
    background_tasks: BackgroundTasks,
    response: Response,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> CanaryRollout:
    control = db.get(Control, control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="control không tồn tại")

    if control.maturity != "production" or control.risk_group != "A":
        raise HTTPException(
            status_code=422,
            detail=(
                "control phải ở maturity 'production' và risk_group 'A' mới được canary "
                "rollout tự động — control Nhóm B hoặc chưa production phải dùng luồng "
                "remediate thủ công từng host (POST .../remediate/dry-run rồi .../apply)"
            ),
        )

    hosts = (
        db.query(Host)
        .filter(Host.tier == _CANARY_HOST_TIER)
        .order_by(Host.hostname.asc())
        .all()
    )
    eligible = [h.hostname for h in hosts if _find_remediation_variant(db, control_id, h) is not None]

    rollout = CanaryRollout(
        control_id=control_id,
        status="running",
        triggered_by=user.username,
        eligible_host_count=len(eligible),
    )
    db.add(rollout)
    try:
        db.commit()
    except IntegrityError:
        # ux_canary_rollouts_running (migration 0009) — chỉ 1 rollout
        # "running" tại 1 thời điểm cho mỗi control (chặn ở tầng DB, tránh
        # race condition 2 request đồng thời).
        db.rollback()
        raise HTTPException(status_code=409, detail="đã có canary rollout đang chạy cho control này")
    db.refresh(rollout)

    if len(eligible) == 0:
        # Không có host nào để chạy -> hoàn tất ngay, không cần background
        # task (không có gì để dry-run/apply).
        rollout.status = "completed"
        rollout.finished_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(rollout)
        write_audit_event(
            actor=user.username,
            action="canary_rollout_started",
            resource=control_id,
            payload={"rollout_id": rollout.id, "control_id": control_id, "eligible_host_count": 0},
        )
        write_audit_event(
            actor=user.username,
            action="canary_rollout_completed",
            resource=control_id,
            payload={"rollout_id": rollout.id, "control_id": control_id},
        )
        return rollout

    write_audit_event(
        actor=user.username,
        action="canary_rollout_started",
        resource=control_id,
        payload={"rollout_id": rollout.id, "control_id": control_id, "eligible_host_count": len(eligible)},
    )
    background_tasks.add_task(_run_rollout, rollout.id, eligible, control_id, user.username)
    response.status_code = status.HTTP_202_ACCEPTED
    return rollout


@router.get("/canary-rollouts/{rollout_id}", response_model=CanaryRolloutDetailOut)
def get_canary_rollout(
    rollout_id: int,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_roles(*_ALL_ROLES)),
) -> CanaryRolloutDetailOut:
    rollout = db.get(CanaryRollout, rollout_id)
    if rollout is None:
        raise HTTPException(status_code=404, detail="canary rollout không tồn tại")

    jobs = (
        db.query(Job)
        .filter(Job.canary_rollout_id == rollout_id)
        .order_by(Job.id.asc())
        .all()
    )
    hosts_by_name: dict[str, CanaryRolloutHostOutcome] = {}
    for job in jobs:
        outcome = hosts_by_name.get(job.hostname)
        if outcome is None:
            outcome = CanaryRolloutHostOutcome(
                hostname=job.hostname, dry_run_job_id=None, apply_job_id=None, status=job.status
            )
            hosts_by_name[job.hostname] = outcome
        if job.job_type == "remediate-dry-run":
            outcome.dry_run_job_id = job.id
        elif job.job_type == "remediate-apply":
            outcome.apply_job_id = job.id
        # Job sau (id lớn hơn, do query order_by id.asc()) luôn phản ánh
        # trạng thái mới nhất của host đó trong rollout — dry-run rồi apply
        # cùng 1 host nên apply's status (nếu có) luôn ghi đè dry-run's.
        outcome.status = job.status

    return CanaryRolloutDetailOut(
        id=rollout.id,
        control_id=rollout.control_id,
        status=rollout.status,
        triggered_by=rollout.triggered_by,
        eligible_host_count=rollout.eligible_host_count,
        aborted_hostname=rollout.aborted_hostname,
        abort_reason=rollout.abort_reason,
        created_at=rollout.created_at,
        finished_at=rollout.finished_at,
        hosts=sorted(hosts_by_name.values(), key=lambda o: o.hostname),
    )


@router.patch("/canary-rollouts/{rollout_id}/cancel", response_model=CanaryRolloutOut)
def cancel_canary_rollout(
    rollout_id: int,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> CanaryRollout:
    rollout = db.get(CanaryRollout, rollout_id)
    if rollout is None:
        raise HTTPException(status_code=404, detail="canary rollout không tồn tại")
    if rollout.status != "running":
        raise HTTPException(status_code=409, detail="canary rollout không còn ở trạng thái 'running'")

    # Chỉ đặt cờ — `_run_rollout` tự kiểm tra ở đầu MỖI vòng lặp host, không
    # ngắt ngang 1 host đang dry-run/apply dở dang (xem docstring
    # app/models.py:CanaryRollout.cancel_requested).
    rollout.cancel_requested = True
    db.commit()
    db.refresh(rollout)
    return rollout
