"""Integration test cho trigger scan (app/jobs.py) — mock mint_ssh_certificate
và lệnh gọi job-dispatcher (httpx.post) để test logic RBAC/luồng job mà
không cần step-ca/job-dispatcher thật chạy. Việc dispatcher/scan.sh có chạy
đúng thật hay không được verify riêng trên lab server (không phải ở unit test)."""
import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from datetime import datetime, timedelta, timezone

from app import jobs as jobs_module
from app.auth import CurrentUser, get_current_user
from app.db import Base
from app.main import app
from app.models import Control, Host, Job, RemediationVariant

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


# CHỈ override jobs_module._get_db (không đụng hosts_module._get_db) — nếu
# override cả hai, module-level assignment này (chạy lúc pytest COLLECT, tức
# TRƯỚC khi bất kỳ test nào thật sự chạy) sẽ đè lên override riêng của
# test_hosts.py cho CÙNG key hosts_module._get_db (2 file cùng import
# app.main.app — instance dùng chung), khiến test_hosts.py chạy nhầm sang
# engine SQLite của file này (bảng chưa tạo) — phát hiện qua test thật khi
# thêm file này làm cả bộ test_hosts.py gãy theo. Vì route trigger_scan tự
# dùng jobs_module._get_db để đọc Host (không qua hosts_module._get_db), chỉ
# cần insert Host thẳng vào DB test của chính file này, không cần gọi API /hosts.
app.dependency_overrides[jobs_module._get_db] = _override_db
client = TestClient(app)


def _clear_user_override():
    app.dependency_overrides.pop(get_current_user, None)


def _register_host(hostname="scan-target.internal", tier=2, os_family="Ubuntu", os_version="22.04"):
    db = _TestSessionLocal()
    db.add(Host(
        hostname=hostname,
        ip_address="10.0.0.20",
        os_family=os_family,
        os_version=os_version,
        tier=tier,
        added_by="opuser",
    ))
    db.commit()
    db.close()


def _register_control(control_id="ctrl-1", maturity="production"):
    db = _TestSessionLocal()
    db.add(Control(
        id=control_id, title="Test control", category="ssh", maturity=maturity, created_by="ruleuser",
    ))
    db.commit()
    db.close()


def _register_remediation_variant(
    control_id="ctrl-1", os_family="Ubuntu", os_version="22.04", remediation_ref="test-bundle-1",
):
    db = _TestSessionLocal()
    db.add(RemediationVariant(
        control_id=control_id, os_family=os_family, os_version=os_version,
        check_method="ansible-check", remediation_ref=remediation_ref,
    ))
    db.commit()
    db.close()


@pytest.fixture(autouse=True)
def _mock_cert(monkeypatch):
    monkeypatch.setattr(
        jobs_module, "mint_ssh_certificate", lambda principal: ("FAKE-PRIVATE-KEY", "FAKE-CERT-PUB")
    )
    # _call_job_dispatcher (mTLS Giai đoạn 2) tự mint 1 cert CLIENT MỖI LẦN
    # gọi job-dispatcher — mock để test không cần step-ca thật. Cert PEM giả
    # (không phải PEM hợp lệ) không sao vì test chỉ mock luôn httpx.post
    # ngay sau đó (xem _mock_dispatcher_success), không có TLS handshake
    # thật nào thực sự dùng tới nội dung file này trong test.
    monkeypatch.setattr(
        jobs_module, "mint_agent_manager_server_cert",
        lambda subject="agent-manager": ("FAKE-CLIENT-CERT-PEM", "FAKE-CLIENT-KEY-PEM"),
    )
    # write_audit_event dùng Postgres thật (audit role) — không có trong test
    # SQLite in-memory, mock để test không phụ thuộc Postgres. Trả về list
    # các lần gọi để test kiểm tra được nội dung audit event khi cần.
    calls = []
    monkeypatch.setattr(jobs_module, "write_audit_event", lambda **kwargs: calls.append(kwargs))
    return calls


def _mock_dispatcher_success(monkeypatch, exit_code=0, logs="SCAN_JOB_STATUS=completed\nSCAN_RESULT_PASS=80\nSCAN_RESULT_FAIL=5\n"):
    class _FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"job_id": "1", "exit_code": exit_code, "logs": logs}

    monkeypatch.setattr(httpx, "post", lambda *a, **kw: _FakeResponse())


def test_viewer_cannot_trigger_scan():
    _register_host()
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.post(
        "/hosts/scan-target.internal/scan", json={"scap_profile_key": "ubuntu2204-standard"}
    )
    _clear_user_override()
    assert resp.status_code == 403


def test_unknown_host_404():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts/does-not-exist/scan", json={"scap_profile_key": "ubuntu2204-standard"}
    )
    _clear_user_override()
    assert resp.status_code == 404


def test_invalid_profile_key_422():
    _register_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/scan", json={"scap_profile_key": "not-a-real-profile"}
    )
    _clear_user_override()
    assert resp.status_code == 422


def test_invalid_ssh_user_rejected():
    _register_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/scan",
        json={"scap_profile_key": "ubuntu2204-standard", "ssh_user": "attacker-chosen-user"},
    )
    _clear_user_override()
    assert resp.status_code == 422


def test_cert_mint_failure_marks_job_failed(monkeypatch, _mock_cert):
    # Trước đây trigger_scan chỉ bắt RuntimeError từ mint_ssh_certificate —
    # nhánh này chưa từng có test riêng (phát hiện qua workflow review: nếu
    # ca_client.mint_ssh_certificate ném lỗi khác RuntimeError, ví dụ
    # subprocess timeout, Job sẽ kẹt vĩnh viễn ở "running"). ca_client.py đã
    # sửa để mọi lỗi cấp cert đều raise RuntimeError — test này verify nhánh
    # except RuntimeError trong jobs.py hoạt động đúng.
    _register_host()

    def _raise(principal):
        raise RuntimeError("step-ca từ chối cấp: provisioner password sai")

    monkeypatch.setattr(jobs_module, "mint_ssh_certificate", _raise)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/scan", json={"scap_profile_key": "ubuntu2204-standard"}
    )
    _clear_user_override()
    assert resp.status_code == 502

    assert len(_mock_cert) == 1
    assert _mock_cert[0]["action"] == "scan_failed"
    assert _mock_cert[0]["payload"]["error"] == "ca_mint_failed"

    # Job vẫn được ghi lại (status=failed) dù request trả 502 — kiểm tra qua
    # GET /jobs/{id} bằng job_id lấy từ DB trực tiếp vì response body của
    # HTTPException không trả JobOut.
    db = _TestSessionLocal()
    job = db.query(Job).order_by(Job.id.desc()).first()
    db.close()
    assert job.status == "failed"
    assert job.finished_at is not None


def test_get_unknown_job_404():
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/jobs/999999")
    _clear_user_override()
    assert resp.status_code == 404


def test_successful_scan_updates_job(monkeypatch):
    _register_host()
    _mock_dispatcher_success(monkeypatch, exit_code=0)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/scan", json={"scap_profile_key": "ubuntu2204-standard"}
    )
    _clear_user_override()
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "succeeded"
    assert body["result_summary"]["scan_result_pass"] == "80"
    assert body["triggered_by"] == "opuser"


def test_successful_scan_accepts_debian_profile_key(monkeypatch):
    # Hồi quy cho SCAP_PROFILES thêm entry Debian (ssg-debian, KHÔNG phải
    # ssg-debderived — tên gói đó chỉ chứa nội dung Ubuntu dù tên gây hiểu
    # nhầm, xem comment tại app/jobs.py:SCAP_PROFILES) — chỉ cần xác nhận key
    # mới không bị 422 do gõ sai chuỗi profile id, cơ chế dispatch giống hệt
    # test_successful_scan_updates_job.
    _register_host()
    _mock_dispatcher_success(monkeypatch, exit_code=0)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/scan", json={"scap_profile_key": "debian11-standard"}
    )
    _clear_user_override()
    assert resp.status_code == 202
    assert resp.json()["status"] == "succeeded"


def test_scan_parses_per_rule_findings(monkeypatch):
    _register_host()
    logs = (
        "SCAN_JOB_STATUS=completed\nSCAN_RESULT_PASS=1\nSCAN_RESULT_FAIL=1\n"
        "oscap exit code: 0\n"
        "FINDINGS_JSON_BEGIN\n"
        '[{"rule_id": "xccdf_org.ssgproject.content_rule_sshd_disable_root_login", '
        '"title": "Disable SSH Root Login", "result": "fail", "severity": "medium"}, '
        '{"rule_id": "xccdf_org.ssgproject.content_rule_package_aide_installed", '
        '"title": "Install AIDE", "result": "pass", "severity": "medium"}]\n'
        "FINDINGS_JSON_END\n"
    )
    _mock_dispatcher_success(monkeypatch, exit_code=0, logs=logs)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/scan", json={"scap_profile_key": "ubuntu2204-standard"}
    )
    _clear_user_override()
    assert resp.status_code == 202
    findings = resp.json()["result_summary"]["findings"]
    assert resp.json()["result_summary"]["findings_count"] == 2
    assert {f["result"] for f in findings} == {"pass", "fail"}
    failed = next(f for f in findings if f["result"] == "fail")
    assert failed["rule_id"] == "xccdf_org.ssgproject.content_rule_sshd_disable_root_login"
    assert failed["title"] == "Disable SSH Root Login"
    # findings JSON (có thể dài) không được lấn hết raw_log_tail
    assert "FINDINGS_JSON" not in resp.json()["result_summary"]["raw_log_tail"]


def test_failed_scan_marks_job_failed(monkeypatch):
    _register_host()
    _mock_dispatcher_success(monkeypatch, exit_code=1, logs="SCAN_JOB_STATUS=error\n")
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/scan", json={"scap_profile_key": "ubuntu2204-standard"}
    )
    _clear_user_override()
    assert resp.status_code == 202
    assert resp.json()["status"] == "failed"


def test_dispatcher_unreachable_returns_502(monkeypatch):
    _register_host()

    def _raise(*a, **kw):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", _raise)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/scan", json={"scap_profile_key": "ubuntu2204-standard"}
    )
    _clear_user_override()
    assert resp.status_code == 502


def test_get_job_any_role(monkeypatch):
    _register_host()
    _mock_dispatcher_success(monkeypatch)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    job_id = client.post(
        "/hosts/scan-target.internal/scan", json={"scap_profile_key": "ubuntu2204-standard"}
    ).json()["id"]

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get(f"/jobs/{job_id}")
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["id"] == job_id


# ---- job_type="remediate-dry-run"/"remediate-apply" (app/jobs.py) ----

_REMEDIATE_LOGS = (
    "SCAN_JOB_STATUS=completed\n"
    "DIFF_OUTPUT_BEGIN\n--- before\n+++ after\n-PermitRootLogin yes\n+PermitRootLogin no\nDIFF_OUTPUT_END\n"
)
_REMEDIATE_APPLY_LOGS_WITH_BACKUP = (
    "SCAN_JOB_STATUS=completed\n"
    "BACKUP_TAR_B64_BEGIN\nZmFrZS1iYWNrdXAtdGFyLWNvbnRlbnQ=\nBACKUP_TAR_B64_END\n"
)


def _do_dry_run(monkeypatch, hostname="scan-target.internal", control_id="ctrl-1", username="opuser"):
    _mock_dispatcher_success(monkeypatch, exit_code=0, logs=_REMEDIATE_LOGS)
    app.dependency_overrides[get_current_user] = _as(username, "operator")
    resp = client.post(f"/hosts/{hostname}/controls/{control_id}/remediate/dry-run")
    _clear_user_override()
    return resp


def test_viewer_cannot_trigger_remediate_dry_run():
    _register_host()
    _register_control()
    _register_remediation_variant()
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.post("/hosts/scan-target.internal/controls/ctrl-1/remediate/dry-run")
    _clear_user_override()
    assert resp.status_code == 403


def test_remediate_dry_run_unknown_host_404():
    _register_control()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/does-not-exist/controls/ctrl-1/remediate/dry-run")
    _clear_user_override()
    assert resp.status_code == 404


def test_remediate_dry_run_unknown_control_404():
    _register_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/scan-target.internal/controls/does-not-exist/remediate/dry-run")
    _clear_user_override()
    assert resp.status_code == 404


def test_remediate_dry_run_no_matching_variant_404():
    # Host Ubuntu 22.04 nhưng variant chỉ có cho Debian — đúng nguyên tắc
    # "từ chối job nếu không tìm thấy RemediationVariant khớp đúng distro".
    _register_host(os_family="Ubuntu", os_version="22.04")
    _register_control()
    _register_remediation_variant(os_family="Debian", os_version="12")
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/scan-target.internal/controls/ctrl-1/remediate/dry-run")
    _clear_user_override()
    assert resp.status_code == 404


def test_remediate_dry_run_matches_wildcard_os_version_variant(monkeypatch):
    # RemediationVariant.os_version=None nghĩa là "mọi version của os_family
    # này" — vẫn phải khớp được dù host có os_version cụ thể.
    _register_host(os_family="Ubuntu", os_version="24.04")
    _register_control()
    _register_remediation_variant(os_family="Ubuntu", os_version=None)
    resp = _do_dry_run(monkeypatch)
    assert resp.status_code == 202


# ---- Mở rộng RemediationVariant cho Debian (mục 7 roadmap Giai đoạn 2) ----
# _find_remediation_variant lọc theo os_family/os_version hoàn toàn generic
# (app/jobs.py), remediate.sh cũng generic (chỉ gọi ansible-playbook/ssh/gpg,
# không phân biệt distro) — về kỹ thuật đã sẵn sàng từ trước, nhưng MỌI test
# "thành công" trước giờ đều dùng Ubuntu; Debian chỉ xuất hiện ở test 404
# (mismatch). 2 test dưới đây verify BẰNG THỰC NGHIỆM (không chỉ suy luận từ
# code) rằng pipeline dry-run/apply thật sự chạy được cho host Debian.


def test_remediate_dry_run_and_apply_succeeds_for_debian_host(monkeypatch):
    _register_host(hostname="debian-target.internal", os_family="Debian", os_version="11")
    _register_control()
    _register_remediation_variant(os_family="Debian", os_version="11", remediation_ref="debian-bundle-1")

    dry_run_resp = _do_dry_run(monkeypatch, hostname="debian-target.internal")
    assert dry_run_resp.status_code == 202
    dry_run_body = dry_run_resp.json()
    assert dry_run_body["status"] == "succeeded"
    assert dry_run_body["remediation_variant_id"] is not None

    _mock_dispatcher_success(monkeypatch, exit_code=0, logs=_REMEDIATE_APPLY_LOGS_WITH_BACKUP)
    app.dependency_overrides[get_current_user] = _as("second-operator", "operator")
    apply_resp = client.post(
        "/hosts/debian-target.internal/controls/ctrl-1/remediate/apply",
        json={"dry_run_job_id": dry_run_body["id"]},
    )
    _clear_user_override()

    assert apply_resp.status_code == 202, apply_resp.text
    apply_body = apply_resp.json()
    assert apply_body["status"] == "succeeded"
    assert apply_body["result_summary"]["backup_tar_b64"] == "ZmFrZS1iYWNrdXAtdGFyLWNvbnRlbnQ="


def test_remediate_dry_run_picks_debian_variant_not_ubuntu_when_both_registered(monkeypatch):
    # Cùng 1 control có variant cho CẢ Ubuntu lẫn Debian — host Debian phải
    # dùng đúng bundle Debian, không lẫn sang bundle Ubuntu (khác remediation_ref).
    _register_host(hostname="debian-target.internal", os_family="Debian", os_version="11")
    _register_control()
    _register_remediation_variant(os_family="Ubuntu", os_version="22.04", remediation_ref="ubuntu-bundle")
    _register_remediation_variant(os_family="Debian", os_version="11", remediation_ref="debian-bundle-1")

    captured = {}

    def _fake_post(*args, **kwargs):
        captured["json"] = kwargs["json"]

        class _FakeResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {"job_id": "1", "exit_code": 0, "logs": _REMEDIATE_LOGS}

        return _FakeResponse()

    monkeypatch.setattr(httpx, "post", _fake_post)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/debian-target.internal/controls/ctrl-1/remediate/dry-run")
    _clear_user_override()

    assert resp.status_code == 202
    assert captured["json"]["environment"]["REMEDIATION_REF"] == "debian-bundle-1"


def test_remediate_dry_run_success_sets_control_and_variant(monkeypatch):
    _register_host()
    _register_control()
    _register_remediation_variant()
    resp = _do_dry_run(monkeypatch)
    assert resp.status_code == 202
    body = resp.json()
    assert body["job_type"] == "remediate-dry-run"
    assert body["control_id"] == "ctrl-1"
    assert body["remediation_variant_id"] is not None
    assert body["status"] == "succeeded"
    assert "PermitRootLogin" in body["result_summary"]["diff_output"]


def _succeeded_dry_run_job_id(monkeypatch, hostname="scan-target.internal", control_id="ctrl-1", username="opuser"):
    resp = _do_dry_run(monkeypatch, hostname=hostname, control_id=control_id, username=username)
    assert resp.status_code == 202
    return resp.json()["id"]


def test_remediate_apply_requires_dry_run_job_id_exists():
    _register_host()
    _register_control()
    _register_remediation_variant()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/controls/ctrl-1/remediate/apply", json={"dry_run_job_id": 999999}
    )
    _clear_user_override()
    assert resp.status_code == 422


def test_remediate_apply_rejects_scan_job_as_dry_run_reference(monkeypatch):
    # dry_run_job_id trỏ tới 1 job job_type="scan" thật (không phải
    # remediate-dry-run) — phải bị từ chối, không được coi là "đã dry-run".
    _register_host()
    _register_control()
    _register_remediation_variant()
    _mock_dispatcher_success(monkeypatch, exit_code=0)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    scan_job_id = client.post(
        "/hosts/scan-target.internal/scan", json={"scap_profile_key": "ubuntu2204-standard"}
    ).json()["id"]
    resp = client.post(
        "/hosts/scan-target.internal/controls/ctrl-1/remediate/apply",
        json={"dry_run_job_id": scan_job_id},
    )
    _clear_user_override()
    assert resp.status_code == 422


def test_remediate_apply_rejects_dry_run_for_different_control(monkeypatch):
    _register_host()
    _register_control("ctrl-1")
    _register_control("ctrl-2")
    _register_remediation_variant(control_id="ctrl-1")
    _register_remediation_variant(control_id="ctrl-2", remediation_ref="test-bundle-2")
    dry_run_id = _succeeded_dry_run_job_id(monkeypatch, control_id="ctrl-1")

    app.dependency_overrides[get_current_user] = _as("someone-else", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/controls/ctrl-2/remediate/apply",
        json={"dry_run_job_id": dry_run_id},
    )
    _clear_user_override()
    assert resp.status_code == 422


def test_remediate_apply_blocks_draft_control(monkeypatch):
    _register_host()
    _register_control(maturity="draft")
    _register_remediation_variant()
    dry_run_id = _succeeded_dry_run_job_id(monkeypatch)

    app.dependency_overrides[get_current_user] = _as("someone-else", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/controls/ctrl-1/remediate/apply",
        json={"dry_run_job_id": dry_run_id},
    )
    _clear_user_override()
    assert resp.status_code == 422


def test_remediate_apply_blocks_stale_dry_run(monkeypatch):
    _register_host()
    _register_control()
    _register_remediation_variant()
    dry_run_id = _succeeded_dry_run_job_id(monkeypatch)

    # Giả lập dry-run đã cũ (quá DRY_RUN_MAX_AGE) — chỉnh finished_at thẳng
    # trong DB, mô phỏng thời gian trôi qua giữa lúc dry-run và lúc apply.
    db = _TestSessionLocal()
    job = db.get(Job, dry_run_id)
    job.finished_at = datetime.now(timezone.utc) - jobs_module.DRY_RUN_MAX_AGE - timedelta(minutes=1)
    db.commit()
    db.close()

    app.dependency_overrides[get_current_user] = _as("someone-else", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/controls/ctrl-1/remediate/apply",
        json={"dry_run_job_id": dry_run_id},
    )
    _clear_user_override()
    assert resp.status_code == 422
    assert "quá hạn" in resp.json()["detail"]


def test_remediate_apply_four_eyes_blocks_same_user_on_tier0(monkeypatch):
    _register_host(tier=0)
    _register_control()
    _register_remediation_variant()
    dry_run_id = _succeeded_dry_run_job_id(monkeypatch, username="opuser")

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/controls/ctrl-1/remediate/apply",
        json={"dry_run_job_id": dry_run_id},
    )
    _clear_user_override()
    assert resp.status_code == 403


def test_remediate_apply_four_eyes_allows_different_user_on_tier0(monkeypatch):
    _register_host(tier=0)
    _register_control()
    _register_remediation_variant()
    dry_run_id = _succeeded_dry_run_job_id(monkeypatch, username="opuser")

    _mock_dispatcher_success(monkeypatch, exit_code=0, logs=_REMEDIATE_APPLY_LOGS_WITH_BACKUP)
    app.dependency_overrides[get_current_user] = _as("second-operator", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/controls/ctrl-1/remediate/apply",
        json={"dry_run_job_id": dry_run_id},
    )
    _clear_user_override()
    assert resp.status_code == 202
    body = resp.json()
    assert body["job_type"] == "remediate-apply"
    assert body["status"] == "succeeded"
    assert body["result_summary"]["backup_tar_b64"] == "ZmFrZS1iYWNrdXAtdGFyLWNvbnRlbnQ="
    assert body["result_summary"]["backup_truncated"] is False


def test_remediate_apply_no_four_eyes_required_on_tier2_same_user(monkeypatch):
    # Tier 2 (mặc định) — người dry-run được tự apply, KHÔNG cần người thứ 2.
    _register_host(tier=2)
    _register_control()
    _register_remediation_variant()
    dry_run_id = _succeeded_dry_run_job_id(monkeypatch, username="opuser")

    _mock_dispatcher_success(monkeypatch, exit_code=0, logs=_REMEDIATE_APPLY_LOGS_WITH_BACKUP)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/controls/ctrl-1/remediate/apply",
        json={"dry_run_job_id": dry_run_id},
    )
    _clear_user_override()
    assert resp.status_code == 202


def test_remediate_apply_audit_event_references_dry_run(monkeypatch, _mock_cert):
    _register_host(tier=2)
    _register_control()
    _register_remediation_variant()
    dry_run_id = _succeeded_dry_run_job_id(monkeypatch, username="opuser")

    _mock_dispatcher_success(monkeypatch, exit_code=0, logs=_REMEDIATE_APPLY_LOGS_WITH_BACKUP)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.post(
        "/hosts/scan-target.internal/controls/ctrl-1/remediate/apply",
        json={"dry_run_job_id": dry_run_id},
    )
    _clear_user_override()

    apply_events = [c for c in _mock_cert if c["action"] == "remediate_apply_completed"]
    assert len(apply_events) == 1
    assert apply_events[0]["payload"]["dry_run_job_id"] == dry_run_id


# ---- job_type="restore" / "1-click restore" (app/jobs.py:run_restore) ----


def _succeeded_apply_job_id(
    monkeypatch, hostname="scan-target.internal", control_id="ctrl-1", username="opuser",
    logs=_REMEDIATE_APPLY_LOGS_WITH_BACKUP,
):
    dry_run_id = _succeeded_dry_run_job_id(monkeypatch, hostname=hostname, control_id=control_id, username=username)
    _mock_dispatcher_success(monkeypatch, exit_code=0, logs=logs)
    app.dependency_overrides[get_current_user] = _as(username, "operator")
    resp = client.post(
        f"/hosts/{hostname}/controls/{control_id}/remediate/apply", json={"dry_run_job_id": dry_run_id}
    )
    _clear_user_override()
    assert resp.status_code == 202, resp.text
    return resp.json()["id"]


def test_chunk_backup_env_reassembles_to_original():
    # Đơn vị thuần cho _chunk_backup_env — backup dài hơn nhiều lần
    # RESTORE_CHUNK_SIZE để chắc chắn thật sự chia thành >1 biến, không chỉ
    # đúng trong trường hợp vừa vặn 1 biến.
    original = "ab" * (jobs_module.RESTORE_CHUNK_SIZE * 3 + 7)
    env = jobs_module._chunk_backup_env(original)
    n = int(env["BACKUP_TAR_B64_CHUNKS"])
    assert n > 1
    reassembled = "".join(env[f"BACKUP_TAR_B64_{i}"] for i in range(n))
    assert reassembled == original
    assert all(len(env[f"BACKUP_TAR_B64_{i}"]) <= jobs_module.RESTORE_CHUNK_SIZE for i in range(n))


def test_viewer_cannot_trigger_restore(monkeypatch):
    _register_host()
    _register_control()
    _register_remediation_variant()
    apply_job_id = _succeeded_apply_job_id(monkeypatch)
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.post("/hosts/scan-target.internal/restore", json={"source_job_id": apply_job_id})
    _clear_user_override()
    assert resp.status_code == 403


def test_restore_unknown_host_404():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/does-not-exist/restore", json={"source_job_id": 1})
    _clear_user_override()
    assert resp.status_code == 404


def test_restore_requires_source_job_id_exists():
    _register_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/scan-target.internal/restore", json={"source_job_id": 999999})
    _clear_user_override()
    assert resp.status_code == 422


def test_restore_rejects_non_apply_job_as_source(monkeypatch):
    # Job dry-run (kể cả succeeded) KHÔNG có backup — chỉ remediate-apply mới
    # chụp backup thật, phải từ chối rõ ràng thay vì cố restore từ 1 job sai
    # loại.
    _register_host()
    _register_control()
    _register_remediation_variant()
    dry_run_id = _succeeded_dry_run_job_id(monkeypatch)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/scan-target.internal/restore", json={"source_job_id": dry_run_id})
    _clear_user_override()
    assert resp.status_code == 422
    assert "remediate-apply" in resp.json()["detail"]


def test_restore_rejects_hostname_mismatch(monkeypatch):
    # apply job của host A không được dùng để restore host B, dù backup vẫn
    # còn hợp lệ về mặt kỹ thuật — tránh restore nhầm cấu hình chéo host.
    _register_host(hostname="host-a")
    _register_host(hostname="host-b")
    _register_control()
    _register_remediation_variant()
    apply_job_id = _succeeded_apply_job_id(monkeypatch, hostname="host-a")
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/host-b/restore", json={"source_job_id": apply_job_id})
    _clear_user_override()
    assert resp.status_code == 422
    assert "không khớp" in resp.json()["detail"]


def test_restore_rejects_truncated_backup(monkeypatch):
    # backup_truncated=True nghĩa là backup gốc đã bị cắt bớt lúc chụp (vượt
    # BACKUP_MAX_BYTES) — restore tự động có thể thiếu file, phải từ chối rõ
    # ràng thay vì âm thầm khôi phục 1 phần.
    _register_host()
    _register_control()
    _register_remediation_variant()
    huge_backup = "A" * (jobs_module.BACKUP_MAX_BYTES + 1000)
    logs = f"SCAN_JOB_STATUS=completed\nBACKUP_TAR_B64_BEGIN\n{huge_backup}\nBACKUP_TAR_B64_END\n"
    apply_job_id = _succeeded_apply_job_id(monkeypatch, logs=logs)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/scan-target.internal/restore", json={"source_job_id": apply_job_id})
    _clear_user_override()
    assert resp.status_code == 422
    assert "cắt bớt" in resp.json()["detail"]


def test_restore_success_dispatches_chunked_backup(monkeypatch):
    _register_host()
    _register_control()
    _register_remediation_variant()
    apply_job_id = _succeeded_apply_job_id(monkeypatch)

    captured = {}

    class _FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"job_id": "restore-1", "exit_code": 0, "logs": "SCAN_JOB_STATUS=completed\n"}

    def _fake_post(url, json, **kwargs):
        captured["url"] = url
        captured["json"] = json
        return _FakeResponse()

    monkeypatch.setattr(httpx, "post", _fake_post)

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/scan-target.internal/restore", json={"source_job_id": apply_job_id})
    _clear_user_override()

    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["job_type"] == "restore"
    assert body["status"] == "succeeded"

    env = captured["json"]["environment"]
    assert captured["json"]["command"] == ["restore"]
    assert env["BACKUP_TAR_B64_CHUNKS"] == "1"
    assert env["BACKUP_TAR_B64_0"] == "ZmFrZS1iYWNrdXAtdGFyLWNvbnRlbnQ="


def _insert_job(hostname, job_type="scan", status="succeeded", triggered_by="opuser", result_summary=None):
    db = _TestSessionLocal()
    job = Job(
        hostname=hostname, job_type=job_type, status=status, triggered_by=triggered_by,
        result_summary=result_summary,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    job_id = job.id
    db.close()
    return job_id


# ---- GET /jobs (list_jobs) ----


def test_list_jobs_viewer_can_read():
    _register_host("host-a.internal")
    _insert_job("host-a.internal")

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/jobs")
    _clear_user_override()

    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_list_jobs_excludes_result_summary_but_get_job_includes_it():
    # GET /jobs (list) CỐ Ý bỏ result_summary — có thể chứa backup base64 tới
    # 2 MiB/job (remediate-apply), trả cho MỖI job trong 1 trang tới 200 job
    # sẽ ép response lên hàng trăm MB, gọi được bởi role viewer. Chỉ
    # GET /jobs/{id} (đúng 1 job/request) mới trả field này.
    _register_host("host-a.internal")
    job_id = _insert_job("host-a.internal", result_summary={"backup_tar_b64": "huge-fake-blob"})

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    list_resp = client.get("/jobs")
    detail_resp = client.get(f"/jobs/{job_id}")
    _clear_user_override()

    assert "result_summary" not in list_resp.json()[0]
    assert detail_resp.json()["result_summary"] == {"backup_tar_b64": "huge-fake-blob"}


def test_list_jobs_orders_newest_first():
    _register_host("host-a.internal")
    first_id = _insert_job("host-a.internal")
    second_id = _insert_job("host-a.internal")

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/jobs")
    _clear_user_override()

    ids = [j["id"] for j in resp.json()]
    assert ids == [second_id, first_id]


def test_list_jobs_filters_by_hostname():
    _register_host("host-a.internal")
    _register_host("host-b.internal")
    _insert_job("host-a.internal")
    _insert_job("host-b.internal")

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/jobs", params={"hostname": "host-a.internal"})
    _clear_user_override()

    jobs = resp.json()
    assert len(jobs) == 1
    assert jobs[0]["hostname"] == "host-a.internal"


def test_list_jobs_filters_by_job_type_and_status():
    _register_host("host-a.internal")
    _insert_job("host-a.internal", job_type="scan", status="succeeded")
    _insert_job("host-a.internal", job_type="remediate-apply", status="failed")

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/jobs", params={"job_type": "remediate-apply"})
    assert [j["job_type"] for j in resp.json()] == ["remediate-apply"]

    resp = client.get("/jobs", params={"status": "failed"})
    _clear_user_override()
    assert [j["status"] for j in resp.json()] == ["failed"]


def test_list_jobs_pagination_limit_and_offset():
    _register_host("host-a.internal")
    ids = [_insert_job("host-a.internal") for _ in range(5)]

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    page1 = client.get("/jobs", params={"limit": 2, "offset": 0}).json()
    page2 = client.get("/jobs", params={"limit": 2, "offset": 2}).json()
    _clear_user_override()

    assert [j["id"] for j in page1] == list(reversed(ids))[0:2]
    assert [j["id"] for j in page2] == list(reversed(ids))[2:4]


def test_list_jobs_rejects_invalid_limit():
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp_zero = client.get("/jobs", params={"limit": 0})
    resp_too_big = client.get("/jobs", params={"limit": 500})
    resp_negative_offset = client.get("/jobs", params={"offset": -1})
    _clear_user_override()

    assert resp_zero.status_code == 422
    assert resp_too_big.status_code == 422
    assert resp_negative_offset.status_code == 422


def test_restore_failed_dispatch_marks_job_failed(monkeypatch):
    _register_host()
    _register_control()
    _register_remediation_variant()
    apply_job_id = _succeeded_apply_job_id(monkeypatch)

    def _raise(*a, **kw):
        raise httpx.ConnectError("job-dispatcher không phản hồi")

    monkeypatch.setattr(httpx, "post", _raise)

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/scan-target.internal/restore", json={"source_job_id": apply_job_id})
    _clear_user_override()
    assert resp.status_code == 502


# ---- POST /internal/job-dispatcher/server-cert (mTLS Giai đoạn 2) ----


def test_job_dispatcher_server_cert_requires_shared_secret():
    resp = client.post("/internal/job-dispatcher/server-cert")
    assert resp.status_code == 401


def test_job_dispatcher_server_cert_wrong_secret_401(monkeypatch):
    monkeypatch.setattr(jobs_module.settings, "job_dispatcher_shared_secret", "correct-secret")
    resp = client.post(
        "/internal/job-dispatcher/server-cert", headers={"Authorization": "Bearer wrong-secret"}
    )
    assert resp.status_code == 401


def test_job_dispatcher_server_cert_success(monkeypatch):
    monkeypatch.setattr(jobs_module.settings, "job_dispatcher_shared_secret", "correct-secret")
    monkeypatch.setattr(
        jobs_module, "mint_agent_manager_server_cert",
        lambda subject: ("FAKE-JD-CERT-PEM", "FAKE-JD-KEY-PEM"),
    )
    resp = client.post(
        "/internal/job-dispatcher/server-cert", headers={"Authorization": "Bearer correct-secret"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["cert_pem"] == "FAKE-JD-CERT-PEM"
    assert body["key_pem"] == "FAKE-JD-KEY-PEM"
    assert len(body["ca_root_pem"]) > 0


def test_job_dispatcher_server_cert_upstream_failure_502(monkeypatch):
    monkeypatch.setattr(jobs_module.settings, "job_dispatcher_shared_secret", "correct-secret")

    def _boom(subject):
        raise RuntimeError("step-ca không phản hồi")

    monkeypatch.setattr(jobs_module, "mint_agent_manager_server_cert", _boom)
    resp = client.post(
        "/internal/job-dispatcher/server-cert", headers={"Authorization": "Bearer correct-secret"}
    )
    assert resp.status_code == 502


# ---- _call_job_dispatcher tự mint client cert (mTLS Giai đoạn 2) ----


def test_scan_fails_gracefully_when_client_cert_mint_fails(monkeypatch):
    _register_host()

    def _boom(subject="agent-manager"):
        raise RuntimeError("step-ca không phản hồi")

    monkeypatch.setattr(jobs_module, "mint_agent_manager_server_cert", _boom)

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts/scan-target.internal/scan", json={"scap_profile_key": "ubuntu2204-standard"}
    )
    _clear_user_override()

    # Lỗi mint client cert phải rơi vào ĐÚNG nhánh xử lý lỗi dispatcher hiện
    # có (502, job đánh "failed") — không phải 500 không rõ nguyên nhân.
    assert resp.status_code == 502


# ---- Active Response (Agent thực thi remediation thật — app/jobs.py:
# _dispatch_remediate_job / _dispatch_remediate_job_via_agent) ----


def test_with_for_update_and_skip_locked_do_not_raise_on_sqlite():
    # Mục F cảnh báo kỹ thuật: with_for_update()/with_for_update(skip_locked=True)
    # là tính năng POSTGRES — PHẢI xác nhận qua chạy test thật (không suy
    # đoán) rằng gọi 2 hàm này trên SQLite (dùng cho toàn bộ pytest ở đây)
    # không raise lỗi TRƯỚC KHI dùng chúng ở _lock_host_for_remediate/
    # claim_remediate_job. Xác nhận: dialect KHÔNG hỗ trợ FOR UPDATE/SKIP
    # LOCKED tự bỏ qua mệnh đề này lúc compile SQL thay vì raise — SQLite chỉ
    # đơn giản KHÔNG khoá gì (chấp nhận được cho test, không có concurrent
    # writers thật), Postgres (thật) mới thực sự khoá/bỏ qua dòng đã khoá.
    _register_host()
    db = _TestSessionLocal()
    try:
        host = (
            db.query(Host)
            .filter(Host.hostname == "scan-target.internal")
            .with_for_update()
            .first()
        )
        assert host is not None

        no_job = db.query(Job).filter(Job.status == "pending").with_for_update(skip_locked=True).first()
        assert no_job is None  # không có job nào — mục đích chỉ là không raise lỗi
    finally:
        db.close()


def _register_agent_ready_host(
    monkeypatch,
    hostname="agent-target.internal",
    tier=2,
    os_family="Ubuntu",
    os_version="22.04",
    agent_renewal_blocked=False,
    host_active_response=True,
    global_active_response=True,
):
    """Host đủ MỌI điều kiện để _dispatch_remediate_job chọn đường Agent
    (trừ khi 1 tham số bị lệch cố ý để test hồi quy "vẫn rơi về SSH")."""
    db = _TestSessionLocal()
    db.add(
        Host(
            hostname=hostname,
            ip_address="10.0.0.30",
            os_family=os_family,
            os_version=os_version,
            tier=tier,
            added_by="opuser",
            agent_enrolled_at=datetime.now(timezone.utc),
            active_response_enabled=host_active_response,
            agent_renewal_blocked=agent_renewal_blocked,
        )
    )
    db.commit()
    db.close()
    monkeypatch.setattr(jobs_module.settings, "active_response_enabled", global_active_response)


def _make_agent_report_on_sleep(
    monkeypatch, hostname, job_type, exit_code=0, log_tail="ok qua agent",
    diff_output=None, backup_tar_b64=None, error=None,
):
    """Mô phỏng Agent claim + report kết quả "giữa 2 lần poll" — cập nhật
    TRỰC TIẾP qua ORM (không qua HTTP claim/result) để test không cần
    threading thật: monkeypatch time.sleep (gọi bên trong vòng lặp poll của
    _dispatch_remediate_job_via_agent) để, ngay lần gọi đầu tiên, tự ghi kết
    quả vào ĐÚNG job "pending"/"running" mới nhất của host+job_type này."""

    def _fake_sleep(_seconds):
        db = _TestSessionLocal()
        job = (
            db.query(Job)
            .filter(
                Job.hostname == hostname,
                Job.job_type == job_type,
                Job.status.in_(("pending", "running")),
            )
            .order_by(Job.id.desc())
            .first()
        )
        if job is not None:
            summary = {"exit_code": exit_code, "dispatch_via": "agent", "log_tail": log_tail}
            if diff_output is not None:
                summary["diff_output"] = diff_output
            if backup_tar_b64 is not None:
                summary["backup_tar_b64"] = backup_tar_b64
                summary["backup_truncated"] = False
            if error is not None:
                summary["error"] = error
            job.status = "succeeded" if exit_code == 0 else "failed"
            job.result_summary = summary
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
        db.close()

    monkeypatch.setattr(jobs_module.time, "sleep", _fake_sleep)


def _fail_if_dispatcher_called(*_a, **_kw):
    raise AssertionError("_call_job_dispatcher (httpx.post) không được gọi khi dùng Agent Active Response")


# ---- (a) hồi quy: host CHƯA đủ điều kiện agent -> vẫn đi SSH ----


def test_remediate_dry_run_uses_ssh_when_global_kill_switch_off(monkeypatch):
    _register_agent_ready_host(monkeypatch, global_active_response=False)
    _register_control()
    _register_remediation_variant(os_family="Ubuntu", os_version="22.04")
    resp = _do_dry_run(monkeypatch, hostname="agent-target.internal")
    assert resp.status_code == 202
    assert resp.json()["result_summary"]["dispatch_via"] == "ssh"


def test_remediate_dry_run_uses_ssh_when_host_active_response_disabled(monkeypatch):
    _register_agent_ready_host(monkeypatch, host_active_response=False)
    _register_control()
    _register_remediation_variant(os_family="Ubuntu", os_version="22.04")
    resp = _do_dry_run(monkeypatch, hostname="agent-target.internal")
    assert resp.status_code == 202
    assert resp.json()["result_summary"]["dispatch_via"] == "ssh"


def test_remediate_dry_run_uses_ssh_when_agent_not_enrolled(monkeypatch):
    # Host thường (agent_enrolled_at=None) dù kill-switch toàn cục đã bật.
    _register_host(hostname="not-enrolled.internal")
    monkeypatch.setattr(jobs_module.settings, "active_response_enabled", True)
    _register_control()
    _register_remediation_variant(os_family="Ubuntu", os_version="22.04")
    resp = _do_dry_run(monkeypatch, hostname="not-enrolled.internal")
    assert resp.status_code == 202
    assert resp.json()["result_summary"]["dispatch_via"] == "ssh"


def test_remediate_dry_run_uses_ssh_when_agent_renewal_blocked(monkeypatch):
    _register_agent_ready_host(monkeypatch, agent_renewal_blocked=True)
    _register_control()
    _register_remediation_variant(os_family="Ubuntu", os_version="22.04")
    resp = _do_dry_run(monkeypatch, hostname="agent-target.internal")
    assert resp.status_code == 202
    assert resp.json()["result_summary"]["dispatch_via"] == "ssh"


# ---- (b) đủ điều kiện -> đi Agent, KHÔNG gọi job-dispatcher ----


def test_remediate_dry_run_dispatches_via_agent_when_eligible(monkeypatch):
    _register_agent_ready_host(monkeypatch)
    _register_control()
    _register_remediation_variant(os_family="Ubuntu", os_version="22.04")
    monkeypatch.setattr(httpx, "post", _fail_if_dispatcher_called)
    _make_agent_report_on_sleep(monkeypatch, "agent-target.internal", "remediate-dry-run")

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-target.internal/controls/ctrl-1/remediate/dry-run")
    _clear_user_override()

    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "succeeded"
    assert body["result_summary"]["dispatch_via"] == "agent"


def test_remediate_apply_dispatches_via_agent_with_backup(monkeypatch):
    _register_agent_ready_host(monkeypatch)
    _register_control()
    _register_remediation_variant(os_family="Ubuntu", os_version="22.04")
    monkeypatch.setattr(httpx, "post", _fail_if_dispatcher_called)
    _make_agent_report_on_sleep(monkeypatch, "agent-target.internal", "remediate-dry-run")

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    dry_run_id = client.post(
        "/hosts/agent-target.internal/controls/ctrl-1/remediate/dry-run"
    ).json()["id"]
    _clear_user_override()

    _make_agent_report_on_sleep(
        monkeypatch, "agent-target.internal", "remediate-apply",
        backup_tar_b64="ZmFrZS1iYWNrdXAtdGFyLWNvbnRlbnQ=",
    )
    app.dependency_overrides[get_current_user] = _as("second-operator", "operator")
    resp = client.post(
        "/hosts/agent-target.internal/controls/ctrl-1/remediate/apply",
        json={"dry_run_job_id": dry_run_id},
    )
    _clear_user_override()

    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "succeeded"
    assert body["result_summary"]["dispatch_via"] == "agent"
    assert body["result_summary"]["backup_tar_b64"] == "ZmFrZS1iYWNrdXAtdGFyLWNvbnRlbnQ="
    assert body["result_summary"]["backup_truncated"] is False


# ---- (c) timeout khi Agent không bao giờ report ----


def test_remediate_dry_run_via_agent_times_out_if_never_reported(monkeypatch, _mock_cert):
    _register_agent_ready_host(monkeypatch)
    _register_control()
    _register_remediation_variant(os_family="Ubuntu", os_version="22.04")
    monkeypatch.setattr(jobs_module, "AGENT_REMEDIATE_DISPATCH_TIMEOUT", -1)
    monkeypatch.setattr(jobs_module.time, "sleep", lambda _s: None)

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-target.internal/controls/ctrl-1/remediate/dry-run")
    _clear_user_override()

    assert resp.status_code == 504

    db = _TestSessionLocal()
    job = (
        db.query(Job)
        .filter(Job.hostname == "agent-target.internal", Job.job_type == "remediate-dry-run")
        .order_by(Job.id.desc())
        .first()
    )
    db.close()
    assert job.status == "failed"
    assert job.result_summary["error"] == "agent_remediate_timeout"

    timeout_events = [c for c in _mock_cert if c["action"] == "remediate_dry_run_failed"]
    assert len(timeout_events) == 1
    # actor="system" (KHÔNG phải user.username) — xem docstring
    # _dispatch_remediate_job_via_agent.
    assert timeout_events[0]["actor"] == "system"
    assert timeout_events[0]["payload"]["error"] == "agent_remediate_timeout"


# ---- (d) four-eyes / draft-control / dry-run-max-age vẫn đúng cho Agent ----


def test_remediate_apply_via_agent_still_enforces_four_eyes_on_high_tier(monkeypatch):
    _register_agent_ready_host(monkeypatch, tier=0)
    _register_control()
    _register_remediation_variant(os_family="Ubuntu", os_version="22.04")
    monkeypatch.setattr(httpx, "post", _fail_if_dispatcher_called)
    _make_agent_report_on_sleep(monkeypatch, "agent-target.internal", "remediate-dry-run")

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    dry_run_id = client.post(
        "/hosts/agent-target.internal/controls/ctrl-1/remediate/dry-run"
    ).json()["id"]

    resp = client.post(
        "/hosts/agent-target.internal/controls/ctrl-1/remediate/apply",
        json={"dry_run_job_id": dry_run_id},
    )
    _clear_user_override()
    assert resp.status_code == 403


def test_remediate_apply_via_agent_still_blocks_draft_control(monkeypatch):
    _register_agent_ready_host(monkeypatch)
    _register_control(maturity="draft")
    _register_remediation_variant(os_family="Ubuntu", os_version="22.04")
    monkeypatch.setattr(httpx, "post", _fail_if_dispatcher_called)
    _make_agent_report_on_sleep(monkeypatch, "agent-target.internal", "remediate-dry-run")

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    dry_run_id = client.post(
        "/hosts/agent-target.internal/controls/ctrl-1/remediate/dry-run"
    ).json()["id"]

    resp = client.post(
        "/hosts/agent-target.internal/controls/ctrl-1/remediate/apply",
        json={"dry_run_job_id": dry_run_id},
    )
    _clear_user_override()
    assert resp.status_code == 422
    assert "draft" in resp.json()["detail"]


def test_remediate_apply_via_agent_still_blocks_stale_dry_run(monkeypatch):
    _register_agent_ready_host(monkeypatch)
    _register_control()
    _register_remediation_variant(os_family="Ubuntu", os_version="22.04")
    monkeypatch.setattr(httpx, "post", _fail_if_dispatcher_called)
    _make_agent_report_on_sleep(monkeypatch, "agent-target.internal", "remediate-dry-run")

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    dry_run_id = client.post(
        "/hosts/agent-target.internal/controls/ctrl-1/remediate/dry-run"
    ).json()["id"]
    _clear_user_override()

    db = _TestSessionLocal()
    job = db.get(Job, dry_run_id)
    job.finished_at = datetime.now(timezone.utc) - jobs_module.DRY_RUN_MAX_AGE - timedelta(minutes=1)
    db.commit()
    db.close()

    app.dependency_overrides[get_current_user] = _as("second-operator", "operator")
    resp = client.post(
        "/hosts/agent-target.internal/controls/ctrl-1/remediate/apply",
        json={"dry_run_job_id": dry_run_id},
    )
    _clear_user_override()
    assert resp.status_code == 422
    assert "quá hạn" in resp.json()["detail"]


# ---- (e) 409 khi có job remediate khác đang chạy dở trên CÙNG host ----


def test_remediate_dry_run_conflict_409_when_job_already_running_ssh_path(monkeypatch):
    _register_host()
    _register_control()
    _register_remediation_variant()
    db = _TestSessionLocal()
    db.add(Job(hostname="scan-target.internal", job_type="remediate-apply", status="running", triggered_by="opuser"))
    db.commit()
    db.close()

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/scan-target.internal/controls/ctrl-1/remediate/dry-run")
    _clear_user_override()
    assert resp.status_code == 409


def test_remediate_dry_run_conflict_409_when_job_already_pending_agent_path(monkeypatch):
    # "pending" chỉ tồn tại thoáng qua trong đường Agent (chờ claim) — vẫn
    # phải bị 409 chặn giống hệt "running" (đường SSH không bao giờ dùng
    # "pending", nhưng _lock_host_for_remediate không phân biệt đường nào).
    _register_agent_ready_host(monkeypatch)
    _register_control()
    _register_remediation_variant(os_family="Ubuntu", os_version="22.04")
    db = _TestSessionLocal()
    db.add(Job(hostname="agent-target.internal", job_type="remediate-dry-run", status="pending", triggered_by="opuser"))
    db.commit()
    db.close()

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-target.internal/controls/ctrl-1/remediate/dry-run")
    _clear_user_override()
    assert resp.status_code == 409
