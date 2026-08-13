"""Integration test cho hàng đợi chờ duyệt remediate-apply
(app/remediation_requests.py) — SQLite in-memory RIÊNG cho file này (KHÔNG
override jobs_module._get_db ở mức module — cùng lý do đã ghi ở
test_jobs.py: override đó là side effect TOÀN CỤC trên app.main.app dùng
chung giữa mọi file test, đè lên override của file khác cùng key). Job
dry-run "succeeded" cần cho mỗi test được CHÈN THẲNG vào DB test của CHÍNH
file này thay vì gọi thật POST .../remediate/dry-run (route đó thuộc
jobs_router, dùng jobs_module._get_db — không phải _get_db của file này).
`run_remediate_apply` (app/jobs.py) được approve_remediation_request GỌI
TRỰC TIẾP với session db của CHÍNH request đang xử lý (truyền tham số, không
qua Depends()) nên vẫn chạy đúng trên engine test của file này."""
import httpx
import pytest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import jobs as jobs_module
from app import remediation_requests as rr_module
from app.auth import CurrentUser, get_current_user
from app.db import Base
from app.main import app
from app.models import Control, Host, Job, RemediationRequest, RemediationVariant

_engine = create_engine(
    "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
)
_TestSessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)


@pytest.fixture(autouse=True)
def _fresh_schema():
    Base.metadata.create_all(
        bind=_engine,
        tables=[
            Base.metadata.tables["hosts"],
            Base.metadata.tables["jobs"],
            Base.metadata.tables["controls"],
            Base.metadata.tables["remediation_variants"],
            Base.metadata.tables["remediation_requests"],
        ],
    )
    yield
    Base.metadata.drop_all(bind=_engine)


def _override_db():
    db = _TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


def _as(username: str, *roles: str):
    def _fake_user():
        return CurrentUser(subject=username, username=username, roles=frozenset(roles))

    return _fake_user


# CHỈ override rr_module._get_db — KHÔNG đụng jobs_module._get_db (xem
# docstring đầu file, cùng nguyên tắc đã ghi trong test_jobs.py).
app.dependency_overrides[rr_module._get_db] = _override_db
client = TestClient(app)


def _clear_user_override():
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture(autouse=True)
def _mock_cert_and_dispatcher(monkeypatch):
    # approve_remediation_request gọi THẲNG run_remediate_apply (app/jobs.py)
    # — hàm đó cần mint_ssh_certificate/mint_agent_manager_server_cert/
    # httpx.post hoạt động được, mock giống hệt test_jobs.py::_mock_cert +
    # _mock_dispatcher_success (KHÔNG override _get_db của jobs_module, chỉ
    # các hàm khác — an toàn, monkeypatch tự phục hồi sau mỗi test, không
    # phải side effect toàn cục như dependency_overrides).
    monkeypatch.setattr(
        jobs_module, "mint_ssh_certificate", lambda principal: ("FAKE-KEY", "FAKE-CERT")
    )
    monkeypatch.setattr(
        jobs_module, "mint_agent_manager_server_cert",
        lambda subject="agent-manager": ("FAKE-CLIENT-CERT-PEM", "FAKE-CLIENT-KEY-PEM"),
    )
    calls = []
    monkeypatch.setattr(jobs_module, "write_audit_event", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr(rr_module, "write_audit_event", lambda **kwargs: calls.append(kwargs))

    class _FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"job_id": "1", "exit_code": 0, "logs": "SCAN_JOB_STATUS=completed\n"}

    monkeypatch.setattr(httpx, "post", lambda *a, **kw: _FakeResponse())
    return calls


def _register_host(hostname="target.internal", tier=2, decommissioned=False):
    db = _TestSessionLocal()
    db.add(Host(
        hostname=hostname,
        ip_address="10.0.0.30",
        os_family="Ubuntu",
        os_version="22.04",
        tier=tier,
        ca_migration_status="trust_deployed",
        decommissioned_at=datetime.now(timezone.utc) if decommissioned else None,
        decommissioned_by="opuser" if decommissioned else None,
        added_by="opuser",
    ))
    db.commit()
    db.close()


def _register_control(control_id="ctrl-1", maturity="production"):
    db = _TestSessionLocal()
    db.add(Control(id=control_id, title="Test control", category="ssh", maturity=maturity, created_by="ruleuser"))
    db.commit()
    db.close()


def _register_remediation_variant(control_id="ctrl-1", os_family="Ubuntu", os_version="22.04"):
    db = _TestSessionLocal()
    db.add(RemediationVariant(
        control_id=control_id, os_family=os_family, os_version=os_version,
        check_method="ansible-check", remediation_ref="test-bundle-1",
    ))
    db.commit()
    db.close()


def _register_agent_ready_host(hostname="agent-target.internal", tier=2):
    """Host đủ MỌI điều kiện để _agent_ineligible_reason(host) trả None —
    cùng vai trò _register_agent_ready_host trong test_jobs.py, viết riêng
    ở đây vì file này KHÔNG import monkeypatch-fixture của file kia (2 DB
    SQLite độc lập, xem docstring đầu file)."""
    db = _TestSessionLocal()
    db.add(Host(
        hostname=hostname, ip_address="10.0.0.31", os_family="Ubuntu", os_version="22.04",
        tier=tier, added_by="opuser",
        agent_enrolled_at=datetime.now(timezone.utc),
        active_response_enabled=True, agent_renewal_blocked=False,
        ca_migration_status="trust_deployed",
    ))
    db.commit()
    db.close()


def _insert_succeeded_dry_run(
    hostname="target.internal", control_id="ctrl-1", triggered_by="opuser", finished_at=None
):
    db = _TestSessionLocal()
    job = Job(
        hostname=hostname, job_type="remediate-dry-run", control_id=control_id,
        status="succeeded", triggered_by=triggered_by,
        finished_at=finished_at or datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    job_id = job.id
    db.close()
    return job_id


def _submit(hostname, control_id, dry_run_job_id, username="opuser", role="operator", connection_method=None):
    app.dependency_overrides[get_current_user] = _as(username, role)
    resp = client.post(
        f"/hosts/{hostname}/controls/{control_id}/remediate/submit-for-approval",
        json={"dry_run_job_id": dry_run_job_id, "connection_method": connection_method},
    )
    _clear_user_override()
    return resp


# ---- submit-for-approval ----


def test_viewer_cannot_submit():
    _register_host()
    _register_control()
    dry_run_id = _insert_succeeded_dry_run()
    resp = _submit("target.internal", "ctrl-1", dry_run_id, username="alice", role="viewer")
    assert resp.status_code == 403


def test_operator_submits_creates_pending_request():
    _register_host()
    _register_control()
    dry_run_id = _insert_succeeded_dry_run()
    resp = _submit("target.internal", "ctrl-1", dry_run_id)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "pending"
    assert body["requested_by"] == "opuser"
    assert body["dry_run_job_id"] == dry_run_id
    assert body["decided_by"] is None


def test_submit_rejects_draft_control():
    _register_host()
    _register_control(maturity="draft")
    dry_run_id = _insert_succeeded_dry_run()
    resp = _submit("target.internal", "ctrl-1", dry_run_id)
    assert resp.status_code == 422
    assert "draft" in resp.json()["detail"]


def test_submit_rejects_stale_dry_run():
    _register_host()
    _register_control()
    stale = datetime.now(timezone.utc) - jobs_module.DRY_RUN_MAX_AGE - timedelta(minutes=1)
    dry_run_id = _insert_succeeded_dry_run(finished_at=stale)
    resp = _submit("target.internal", "ctrl-1", dry_run_id)
    assert resp.status_code == 422
    assert "quá hạn" in resp.json()["detail"]


def test_submit_rejects_dry_run_for_different_control():
    _register_host()
    _register_control(control_id="ctrl-1")
    _register_control(control_id="ctrl-2")
    dry_run_id = _insert_succeeded_dry_run(control_id="ctrl-1")
    resp = _submit("target.internal", "ctrl-2", dry_run_id)
    assert resp.status_code == 422


def test_submit_unknown_host_404():
    resp = _submit("does-not-exist", "ctrl-1", 1)
    assert resp.status_code == 404


def test_submit_stores_chosen_connection_method():
    _register_host()
    _register_control()
    dry_run_id = _insert_succeeded_dry_run()
    resp = _submit("target.internal", "ctrl-1", dry_run_id, connection_method="ssh")
    assert resp.status_code == 201, resp.text
    assert resp.json()["connection_method"] == "ssh"


def test_submit_connection_method_defaults_to_null():
    _register_host()
    _register_control()
    dry_run_id = _insert_succeeded_dry_run()
    resp = _submit("target.internal", "ctrl-1", dry_run_id)
    assert resp.status_code == 201, resp.text
    assert resp.json()["connection_method"] is None


def test_submit_rejects_agent_when_host_not_eligible():
    # Host thường (chưa enroll Agent) — chọn tay "agent" phải báo 422 NGAY
    # lúc gửi duyệt, KHÔNG chờ tới lúc approver bấm "Duyệt" mới biết.
    _register_host()
    _register_control()
    dry_run_id = _insert_succeeded_dry_run()
    resp = _submit("target.internal", "ctrl-1", dry_run_id, connection_method="agent")
    assert resp.status_code == 422
    assert "Agent" in resp.json()["detail"]

    app.dependency_overrides[get_current_user] = _as("carol", "approver")
    queue = client.get("/remediation-requests", params={"status_filter": "pending"})
    _clear_user_override()
    assert queue.json() == []


# ---- list ----


def test_operator_cannot_list_full_queue_without_mine_only():
    _register_host()
    _register_control()
    dry_run_id = _insert_succeeded_dry_run()
    _submit("target.internal", "ctrl-1", dry_run_id)

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.get("/remediation-requests")
    _clear_user_override()
    assert resp.status_code == 403


def test_operator_sees_own_requests_via_mine_only():
    _register_host()
    _register_control()
    dry_run_id = _insert_succeeded_dry_run()
    _submit("target.internal", "ctrl-1", dry_run_id, username="opuser")

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.get("/remediation-requests", params={"mine_only": "true"})
    _clear_user_override()
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["requested_by"] == "opuser"


def test_approver_sees_full_pending_queue():
    _register_host()
    _register_control()
    dry_run_id = _insert_succeeded_dry_run()
    _submit("target.internal", "ctrl-1", dry_run_id, username="opuser")

    app.dependency_overrides[get_current_user] = _as("carol", "approver")
    resp = client.get("/remediation-requests", params={"status_filter": "pending"})
    _clear_user_override()
    assert resp.status_code == 200
    assert len(resp.json()) == 1


# ---- approve ----


def test_approve_requires_approver_role():
    _register_host()
    _register_control()
    _register_remediation_variant()
    dry_run_id = _insert_succeeded_dry_run()
    req_id = _submit("target.internal", "ctrl-1", dry_run_id).json()["id"]

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(f"/remediation-requests/{req_id}/approve")
    _clear_user_override()
    assert resp.status_code == 403


def test_approve_allows_same_user_after_four_eyes_removed(_mock_cert_and_dispatcher):
    """Four-eyes (approver != requested_by) đã bị bỏ theo yêu cầu người
    dùng, áp dụng cho MỌI host kể cả Tier 2 mặc định."""
    _register_host(tier=2)
    _register_control()
    _register_remediation_variant()
    dry_run_id = _insert_succeeded_dry_run(triggered_by="opuser")
    req_id = _submit("target.internal", "ctrl-1", dry_run_id, username="opuser").json()["id"]

    app.dependency_overrides[get_current_user] = _as("opuser", "operator", "approver")
    resp = client.post(f"/remediation-requests/{req_id}/approve")
    _clear_user_override()
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "approved"
    assert resp.json()["decided_by"] == "opuser"


def test_approve_success_creates_apply_job_and_updates_status(_mock_cert_and_dispatcher):
    _register_host()
    _register_control()
    _register_remediation_variant()
    dry_run_id = _insert_succeeded_dry_run(triggered_by="opuser")
    req_id = _submit("target.internal", "ctrl-1", dry_run_id, username="opuser").json()["id"]

    app.dependency_overrides[get_current_user] = _as("carol", "approver")
    resp = client.post(f"/remediation-requests/{req_id}/approve")
    _clear_user_override()

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "approved"
    assert body["decided_by"] == "carol"
    assert body["apply_job_id"] is not None

    db = _TestSessionLocal()
    apply_job = db.get(Job, body["apply_job_id"])
    db.close()
    assert apply_job.job_type == "remediate-apply"
    assert apply_job.status == "succeeded"


def test_approve_uses_connection_method_stored_at_submit_time(_mock_cert_and_dispatcher, monkeypatch):
    # Host ĐỦ điều kiện Agent (mặc định sẽ tự chọn Agent) — nhưng operator
    # đã chọn tay "ssh" lúc gửi duyệt, approve PHẢI dùng lại đúng giá trị đó
    # (KHÔNG cho approver chọn lại, xem docstring RemediationSubmitRequest).
    monkeypatch.setattr(jobs_module.settings, "active_response_enabled", True)
    _register_agent_ready_host()
    _register_control()
    _register_remediation_variant()
    dry_run_id = _insert_succeeded_dry_run(hostname="agent-target.internal", triggered_by="opuser")
    req_id = _submit(
        "agent-target.internal", "ctrl-1", dry_run_id, username="opuser", connection_method="ssh"
    ).json()["id"]

    app.dependency_overrides[get_current_user] = _as("carol", "approver")
    resp = client.post(f"/remediation-requests/{req_id}/approve")
    _clear_user_override()

    assert resp.status_code == 200, resp.text
    apply_job_id = resp.json()["apply_job_id"]
    db = _TestSessionLocal()
    apply_job = db.get(Job, apply_job_id)
    db.close()
    assert apply_job.result_summary["dispatch_via"] == "ssh"


def test_approve_marks_failed_not_rejected_when_dry_run_stale():
    _register_host()
    _register_control()
    _register_remediation_variant()
    stale = datetime.now(timezone.utc) - jobs_module.DRY_RUN_MAX_AGE - timedelta(minutes=1)
    # Chèn job dry-run CÒN HẠN lúc submit, rồi "làm cũ đi" sau khi đã gửi
    # duyệt -- mô phỏng đúng kịch bản thật: dry-run kịp hết hạn TRONG LÚC
    # đang chờ duyệt.
    dry_run_id = _insert_succeeded_dry_run(triggered_by="opuser")
    req_id = _submit("target.internal", "ctrl-1", dry_run_id, username="opuser").json()["id"]

    db = _TestSessionLocal()
    job = db.get(Job, dry_run_id)
    job.finished_at = stale
    db.commit()
    db.close()

    app.dependency_overrides[get_current_user] = _as("carol", "approver")
    resp = client.post(f"/remediation-requests/{req_id}/approve")
    _clear_user_override()

    assert resp.status_code == 422
    db = _TestSessionLocal()
    req = db.get(RemediationRequest, req_id)
    db.close()
    assert req.status == "failed"
    assert req.decided_by == "carol"
    assert "quá hạn" in req.decision_note


def test_approve_unknown_request_404():
    app.dependency_overrides[get_current_user] = _as("carol", "approver")
    resp = client.post("/remediation-requests/999999/approve")
    _clear_user_override()
    assert resp.status_code == 404


def test_approve_twice_returns_409():
    _register_host()
    _register_control()
    _register_remediation_variant()
    dry_run_id = _insert_succeeded_dry_run(triggered_by="opuser")
    req_id = _submit("target.internal", "ctrl-1", dry_run_id, username="opuser").json()["id"]

    app.dependency_overrides[get_current_user] = _as("carol", "approver")
    client.post(f"/remediation-requests/{req_id}/approve")
    resp = client.post(f"/remediation-requests/{req_id}/approve")
    _clear_user_override()
    assert resp.status_code == 409


# ---- reject ----


def test_reject_requires_approver_role():
    _register_host()
    _register_control()
    dry_run_id = _insert_succeeded_dry_run()
    req_id = _submit("target.internal", "ctrl-1", dry_run_id).json()["id"]

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(f"/remediation-requests/{req_id}/reject", json={})
    _clear_user_override()
    assert resp.status_code == 403


def test_reject_allows_same_user_after_four_eyes_removed():
    _register_host()
    _register_control()
    dry_run_id = _insert_succeeded_dry_run(triggered_by="opuser")
    req_id = _submit("target.internal", "ctrl-1", dry_run_id, username="opuser").json()["id"]

    app.dependency_overrides[get_current_user] = _as("opuser", "operator", "approver")
    resp = client.post(f"/remediation-requests/{req_id}/reject", json={})
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected"
    assert resp.json()["decided_by"] == "opuser"


def test_reject_success_with_reason():
    _register_host()
    _register_control()
    dry_run_id = _insert_succeeded_dry_run(triggered_by="opuser")
    req_id = _submit("target.internal", "ctrl-1", dry_run_id, username="opuser").json()["id"]

    app.dependency_overrides[get_current_user] = _as("carol", "approver")
    resp = client.post(f"/remediation-requests/{req_id}/reject", json={"reason": "chưa đúng giờ bảo trì"})
    _clear_user_override()

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "rejected"
    assert body["decided_by"] == "carol"
    assert body["decision_note"] == "chưa đúng giờ bảo trì"
    assert body["apply_job_id"] is None
