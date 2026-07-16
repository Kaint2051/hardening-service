"""Integration test cho Agent enrollment/heartbeat/scan-result/FIM API —
SQLite in-memory + override get_current_user, mock ca_client (step-ca thật
không có trong test, giống cách test_jobs.py mock mint_ssh_certificate)."""
import base64
import os
from datetime import datetime, timedelta, timezone

import httpx
import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import agents as agents_module
from app import jobs as jobs_module
from app.auth import CurrentUser, get_current_user
from app.db import Base
from app.models import Control, Host, Job, RemediationVariant
from app.main import app

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
            Base.metadata.tables["agent_enrollment_tokens"],
            Base.metadata.tables["agent_fim_events"],
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


app.dependency_overrides[agents_module._get_db] = _override_db
client = TestClient(app)

SHARED_SECRET = "test-agent-manager-secret"
AUTH_HEADER = {"Authorization": f"Bearer {SHARED_SECRET}"}


@pytest.fixture(autouse=True)
def _mock_settings(monkeypatch):
    monkeypatch.setattr(agents_module.settings, "agent_manager_shared_secret", SHARED_SECRET)
    # Kill-switch toàn cục mặc định True cho CẢ file test này — hầu hết test
    # ở đây tồn tại để kiểm tra hành vi claim/bundle/result đường Agent, cần
    # kill-switch mở làm baseline "happy path". Các test riêng cho hành vi
    # kill-switch TẮT (test_claim_remediate_job_killswitch_*) tự monkeypatch
    # lại False/host.active_response_enabled=False khi cần.
    monkeypatch.setattr(agents_module.settings, "active_response_enabled", True)


@pytest.fixture(autouse=True)
def _mock_audit(monkeypatch):
    calls = []
    monkeypatch.setattr(agents_module, "write_audit_event", lambda **kwargs: calls.append(kwargs))
    return calls


def _clear_user_override():
    app.dependency_overrides.pop(get_current_user, None)


def _register_host(
    hostname="agent-test.internal", blocked=False, active_response_enabled=True,
    ca_migration_status="not_started", ssh_user="root", decommissioned=False,
):
    db = _TestSessionLocal()
    db.add(Host(
        hostname=hostname, ip_address="10.0.0.50", os_family="Ubuntu",
        os_version="24.04", added_by="opuser", agent_renewal_blocked=blocked,
        active_response_enabled=active_response_enabled,
        ca_migration_status=ca_migration_status, ssh_user=ssh_user,
        decommissioned_at=datetime.now(timezone.utc) if decommissioned else None,
        decommissioned_by="opuser" if decommissioned else None,
    ))
    db.commit()
    db.close()


def _mock_agent_install_dispatch(monkeypatch, exit_code=0, logs="AGENT_INSTALL_STATUS=ok\n"):
    # Mirror test_jobs.py's _mock_cert/_mock_dispatcher_success — nhưng
    # trigger_agent_install gọi mint_ssh_certificate qua namespace agents_module
    # (import trực tiếp vào app/agents.py), còn mint_agent_manager_server_cert
    # + httpx.post là 2 lời gọi NỘI BỘ của _call_job_dispatcher (định nghĩa
    # trong app/jobs.py) nên phải mock trên jobs_module/httpx global, KHÔNG
    # phải agents_module — patch nhầm namespace sẽ không có tác dụng gì.
    monkeypatch.setattr(
        agents_module, "mint_ssh_certificate", lambda principal: ("FAKE-PRIVATE-KEY", "FAKE-CERT-PUB")
    )
    monkeypatch.setattr(
        jobs_module, "mint_agent_manager_server_cert",
        lambda subject="agent-manager": ("FAKE-CLIENT-CERT-PEM", "FAKE-CLIENT-KEY-PEM"),
    )

    class _FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"job_id": "1", "exit_code": exit_code, "logs": logs}

    monkeypatch.setattr(httpx, "post", lambda *a, **kw: _FakeResponse())


def _fake_ott(hostname="agent-test.internal", jti="test-jti-1", ttl_seconds=300):
    exp = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
    return pyjwt.encode({"jti": jti, "sub": hostname, "exp": exp}, "unit-test-signing-key", algorithm="HS256")


def test_non_operator_cannot_create_enrollment_token():
    _register_host()
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.post("/hosts/agent-test.internal/agent-enrollment-tokens")
    _clear_user_override()
    assert resp.status_code == 403


def test_create_enrollment_token_unknown_host_404():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/does-not-exist/agent-enrollment-tokens")
    _clear_user_override()
    assert resp.status_code == 404


def test_create_enrollment_token_blocked_when_decommissioned():
    db = _TestSessionLocal()
    db.add(Host(
        hostname="decommissioned-host.internal", ip_address="10.0.0.60", os_family="Ubuntu",
        added_by="opuser", decommissioned_at=datetime.now(timezone.utc), decommissioned_by="opuser",
    ))
    db.commit()
    db.close()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/decommissioned-host.internal/agent-enrollment-tokens")
    _clear_user_override()
    assert resp.status_code == 422


def test_generate_install_script_blocked_when_decommissioned():
    db = _TestSessionLocal()
    db.add(Host(
        hostname="decommissioned-host.internal", ip_address="10.0.0.60", os_family="Ubuntu",
        added_by="opuser", decommissioned_at=datetime.now(timezone.utc), decommissioned_by="opuser",
    ))
    db.commit()
    db.close()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/decommissioned-host.internal/agent-install-script")
    _clear_user_override()
    assert resp.status_code == 422


def test_create_enrollment_token_success(monkeypatch, _mock_audit):
    _register_host()
    fake_token = _fake_ott()
    monkeypatch.setattr(agents_module, "create_agent_enrollment_token", lambda hostname: fake_token)

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-test.internal/agent-enrollment-tokens")
    _clear_user_override()

    assert resp.status_code == 201
    body = resp.json()
    assert body["token"] == fake_token
    assert body["hostname"] == "agent-test.internal"
    assert _mock_audit[0]["action"] == "agent_enrollment_token_created"


def _write_fake_assets(tmp_path):
    assets_dir = tmp_path / "agent-assets"
    assets_dir.mkdir()
    (assets_dir / "provision.sh").write_text("echo provision-marker\n", encoding="utf-8")
    (assets_dir / "hardening-agent.service").write_text(
        "[Unit]\nDescription=fake agent unit\n", encoding="utf-8"
    )
    (assets_dir / "hardening-executor.service").write_text(
        "[Unit]\nDescription=fake executor unit\n", encoding="utf-8"
    )
    return assets_dir


def test_non_operator_cannot_generate_install_script():
    _register_host()
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.post("/hosts/agent-test.internal/agent-install-script")
    _clear_user_override()
    assert resp.status_code == 403


def test_generate_install_script_unknown_host_404():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/does-not-exist/agent-install-script")
    _clear_user_override()
    assert resp.status_code == 404


def test_generate_install_script_success(monkeypatch, tmp_path, _mock_audit):
    _register_host()
    fake_token = _fake_ott()
    monkeypatch.setattr(agents_module, "create_agent_enrollment_token", lambda hostname: fake_token)
    monkeypatch.setattr(agents_module.settings, "agent_assets_dir", str(_write_fake_assets(tmp_path)))

    ca_root_file = tmp_path / "root_ca.crt"
    ca_root_file.write_text("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n", encoding="utf-8")
    monkeypatch.setattr(agents_module.settings, "stepca_root_cert_path", str(ca_root_file))

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-test.internal/agent-install-script")
    _clear_user_override()

    assert resp.status_code == 201
    body = resp.json()
    assert body["hostname"] == "agent-test.internal"
    script = body["script"]
    # Gộp đủ cả 4 phần: token, ca-root, provision.sh, 2 unit file.
    assert fake_token in script
    assert "-----BEGIN CERTIFICATE-----" in script
    assert "echo provision-marker" in script
    assert "fake agent unit" in script
    assert "fake executor unit" in script
    assert _mock_audit[-1]["action"] == "agent_install_script_generated"

    # Tái dùng đúng logic bookkeeping cũ — vẫn tạo 1 dòng agent_enrollment_tokens
    # (không lệch khỏi hành vi của create_enrollment_token).
    db = _TestSessionLocal()
    token_row = (
        db.query(agents_module.AgentEnrollmentToken)
        .filter_by(hostname="agent-test.internal")
        .first()
    )
    db.close()
    assert token_row is not None
    assert token_row.jti == "test-jti-1"


def test_generate_install_script_missing_assets_returns_500(monkeypatch, tmp_path):
    _register_host()
    fake_token = _fake_ott()
    monkeypatch.setattr(agents_module, "create_agent_enrollment_token", lambda hostname: fake_token)
    monkeypatch.setattr(agents_module.settings, "agent_assets_dir", str(tmp_path / "does-not-exist"))
    ca_root_file = tmp_path / "root_ca.crt"
    ca_root_file.write_text("FAKE-CA-ROOT\n", encoding="utf-8")
    monkeypatch.setattr(agents_module.settings, "stepca_root_cert_path", str(ca_root_file))

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-test.internal/agent-install-script")
    _clear_user_override()
    assert resp.status_code == 500


def test_verify_and_enroll_requires_shared_secret():
    resp = client.post("/internal/agent/verify-and-enroll", json={"hostname": "x", "token": "y"})
    assert resp.status_code == 401


def test_verify_and_enroll_unknown_host_404():
    resp = client.post(
        "/internal/agent/verify-and-enroll",
        json={"hostname": "does-not-exist", "token": _fake_ott()},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 404


def _issue_token_row(monkeypatch, hostname="agent-test.internal", jti="test-jti-1", ttl_seconds=300):
    fake_token = _fake_ott(hostname=hostname, jti=jti, ttl_seconds=ttl_seconds)
    monkeypatch.setattr(agents_module, "create_agent_enrollment_token", lambda h: fake_token)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.post(f"/hosts/{hostname}/agent-enrollment-tokens")
    _clear_user_override()
    return fake_token


def test_verify_and_enroll_success(monkeypatch, _mock_audit):
    _register_host()
    token = _issue_token_row(monkeypatch)
    monkeypatch.setattr(
        agents_module, "mint_agent_client_cert",
        lambda hostname, tok: ("FAKE-CERT-PEM", "FAKE-KEY-PEM"),
    )

    resp = client.post(
        "/internal/agent/verify-and-enroll",
        json={"hostname": "agent-test.internal", "token": token},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["cert_pem"] == "FAKE-CERT-PEM"
    assert body["key_pem"] == "FAKE-KEY-PEM"
    assert len(body["ca_root_pem"]) > 0
    actions = [c["action"] for c in _mock_audit]
    assert "agent_enrolled" in actions

    db = _TestSessionLocal()
    host = db.get(Host, "agent-test.internal")
    assert host.agent_enrolled_at is not None
    db.close()


def test_verify_and_enroll_rejects_reused_token(monkeypatch):
    _register_host()
    token = _issue_token_row(monkeypatch)
    monkeypatch.setattr(
        agents_module, "mint_agent_client_cert",
        lambda hostname, tok: ("FAKE-CERT-PEM", "FAKE-KEY-PEM"),
    )
    first = client.post(
        "/internal/agent/verify-and-enroll",
        json={"hostname": "agent-test.internal", "token": token},
        headers=AUTH_HEADER,
    )
    assert first.status_code == 200
    second = client.post(
        "/internal/agent/verify-and-enroll",
        json={"hostname": "agent-test.internal", "token": token},
        headers=AUTH_HEADER,
    )
    assert second.status_code == 401
    assert "đã được dùng" in second.json()["detail"]


def test_verify_and_enroll_rejects_expired_token(monkeypatch):
    _register_host()
    token = _issue_token_row(monkeypatch, ttl_seconds=-10)
    resp = client.post(
        "/internal/agent/verify-and-enroll",
        json={"hostname": "agent-test.internal", "token": token},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 401
    assert "hết hạn" in resp.json()["detail"]


def test_verify_and_enroll_rejects_unknown_jti():
    _register_host()
    unknown_token = _fake_ott(jti="never-issued")
    resp = client.post(
        "/internal/agent/verify-and-enroll",
        json={"hostname": "agent-test.internal", "token": unknown_token},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 401
    assert "không tồn tại" in resp.json()["detail"]


def test_heartbeat_updates_last_seen():
    _register_host()
    resp = client.post(
        "/internal/agent/heartbeat", json={"hostname": "agent-test.internal"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 204

    db = _TestSessionLocal()
    host = db.get(Host, "agent-test.internal")
    assert host.agent_last_seen is not None
    db.close()


def test_heartbeat_unknown_host_404():
    resp = client.post(
        "/internal/agent/heartbeat", json={"hostname": "does-not-exist"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 404


def test_heartbeat_requires_shared_secret():
    resp = client.post("/internal/agent/heartbeat", json={"hostname": "agent-test.internal"})
    assert resp.status_code == 401


def test_scan_result_creates_job(_mock_audit):
    _register_host()
    resp = client.post(
        "/internal/agent/scan-result",
        json={
            "hostname": "agent-test.internal",
            "scap_profile": "xccdf_org.ssgproject.content_profile_standard",
            "result_summary": {"scan_result_pass": "10", "scan_result_fail": "2"},
        },
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 201
    job_id = resp.json()["job_id"]

    db = _TestSessionLocal()
    job = db.get(Job, job_id)
    assert job.job_type == "agent-scan"
    assert job.status == "succeeded"
    assert job.triggered_by == "agent"
    db.close()
    assert any(c["action"] == "agent_scan_reported" for c in _mock_audit)


def test_server_cert_requires_shared_secret():
    resp = client.post("/internal/agent-manager/server-cert")
    assert resp.status_code == 401


def test_server_cert_success(monkeypatch, _mock_audit):
    monkeypatch.setattr(
        agents_module, "mint_agent_manager_server_cert",
        lambda: ("FAKE-AM-CERT-PEM", "FAKE-AM-KEY-PEM"),
    )
    resp = client.post("/internal/agent-manager/server-cert", headers=AUTH_HEADER)
    assert resp.status_code == 200
    body = resp.json()
    assert body["cert_pem"] == "FAKE-AM-CERT-PEM"
    assert body["key_pem"] == "FAKE-AM-KEY-PEM"
    assert len(body["ca_root_pem"]) > 0
    assert any(c["action"] == "agent_manager_server_cert_issued" for c in _mock_audit)


def test_server_cert_upstream_failure_returns_502(monkeypatch):
    def _boom():
        raise RuntimeError("step-ca không phản hồi")

    monkeypatch.setattr(agents_module, "mint_agent_manager_server_cert", _boom)
    resp = client.post("/internal/agent-manager/server-cert", headers=AUTH_HEADER)
    assert resp.status_code == 502


def test_fim_event_creates_row(_mock_audit):
    _register_host()
    resp = client.post(
        "/internal/agent/fim-event",
        json={
            "hostname": "agent-test.internal",
            "path": "/etc/ssh/sshd_config",
            "event_type": "modified",
            "old_hash": "a" * 64,
            "new_hash": "b" * 64,
        },
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 201
    assert any(c["action"] == "agent_fim_event" for c in _mock_audit)


def test_renew_cert_requires_shared_secret():
    resp = client.post("/internal/agent/renew-cert", json={"hostname": "agent-test.internal"})
    assert resp.status_code == 401


def test_renew_cert_rejects_wrong_shared_secret():
    resp = client.post(
        "/internal/agent/renew-cert",
        json={"hostname": "agent-test.internal"},
        headers={"Authorization": "Bearer wrong-secret"},
    )
    assert resp.status_code == 401


def test_renew_cert_unknown_host_404():
    resp = client.post(
        "/internal/agent/renew-cert", json={"hostname": "does-not-exist"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 404


def test_renew_cert_success(monkeypatch, _mock_audit):
    _register_host()
    monkeypatch.setattr(
        agents_module, "create_agent_enrollment_token",
        lambda hostname, ttl=None: "FAKE-INTERNAL-RENEW-TOKEN",
    )
    monkeypatch.setattr(
        agents_module, "mint_agent_client_cert",
        lambda hostname, tok: ("FAKE-RENEWED-CERT-PEM", "FAKE-RENEWED-KEY-PEM"),
    )

    resp = client.post(
        "/internal/agent/renew-cert", json={"hostname": "agent-test.internal"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["cert_pem"] == "FAKE-RENEWED-CERT-PEM"
    assert body["key_pem"] == "FAKE-RENEWED-KEY-PEM"
    assert len(body["ca_root_pem"]) > 0

    renew_calls = [c for c in _mock_audit if c["action"] == "agent_cert_renewed"]
    assert len(renew_calls) == 1
    assert renew_calls[0]["actor"] == "agent-manager"
    assert renew_calls[0]["resource"] == "agent-test.internal"
    assert renew_calls[0]["payload"] == {}


def test_renew_cert_blocked_host_403(monkeypatch, _mock_audit):
    _register_host(blocked=True)
    # Không mock mint_agent_client_cert/create_agent_enrollment_token: nếu bị
    # gọi nhầm (guard block bị bỏ qua) test sẽ crash thay vì âm thầm pass.
    resp = client.post(
        "/internal/agent/renew-cert", json={"hostname": "agent-test.internal"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 403
    assert "agent_renewal_blocked" in resp.json()["detail"]
    assert not any(c["action"] == "agent_cert_renewed" for c in _mock_audit)


# ---- Active Response (Agent thực thi remediation thật — mục 4.3/4.4) ----


def _register_control_and_variant(control_id="ctrl-1", remediation_ref="test-bundle-1"):
    db = _TestSessionLocal()
    db.add(Control(id=control_id, title="Test control", category="ssh", maturity="production", created_by="ruleuser"))
    db.add(RemediationVariant(
        control_id=control_id, os_family="Ubuntu", os_version="24.04",
        check_method="ansible-check", remediation_ref=remediation_ref,
    ))
    db.commit()
    variant_id = db.query(RemediationVariant).filter_by(remediation_ref=remediation_ref).first().id
    db.close()
    return variant_id


def _insert_remediate_job(
    hostname="agent-test.internal", job_type="remediate-dry-run", status="pending",
    control_id="ctrl-1", remediation_variant_id=None, triggered_by="opuser",
):
    db = _TestSessionLocal()
    job = Job(
        hostname=hostname, job_type=job_type, status=status, control_id=control_id,
        remediation_variant_id=remediation_variant_id, triggered_by=triggered_by,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    job_id = job.id
    db.close()
    return job_id


# ---- POST /internal/agent/remediate-jobs/claim ----


def test_claim_remediate_job_requires_shared_secret():
    resp = client.post("/internal/agent/remediate-jobs/claim", json={"hostname": "agent-test.internal"})
    assert resp.status_code == 401


def test_claim_remediate_job_unknown_host_404():
    resp = client.post(
        "/internal/agent/remediate-jobs/claim", json={"hostname": "does-not-exist"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 404


def test_claim_remediate_job_no_pending_job_returns_204():
    _register_host()
    resp = client.post(
        "/internal/agent/remediate-jobs/claim", json={"hostname": "agent-test.internal"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 204


def test_claim_remediate_job_claims_pending_dry_run_job():
    _register_host()
    variant_id = _register_control_and_variant()
    job_id = _insert_remediate_job(job_type="remediate-dry-run", status="pending", remediation_variant_id=variant_id)

    resp = client.post(
        "/internal/agent/remediate-jobs/claim", json={"hostname": "agent-test.internal"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["job_id"] == job_id
    assert body["control_id"] == "ctrl-1"
    assert body["remediation_ref"] == "test-bundle-1"
    assert body["dry_run"] is True

    db = _TestSessionLocal()
    job = db.get(Job, job_id)
    assert job.status == "running"
    db.close()


def test_claim_remediate_job_claims_pending_apply_job_sets_dry_run_false():
    _register_host()
    variant_id = _register_control_and_variant()
    _insert_remediate_job(job_type="remediate-apply", status="pending", remediation_variant_id=variant_id)

    resp = client.post(
        "/internal/agent/remediate-jobs/claim", json={"hostname": "agent-test.internal"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 200
    assert resp.json()["dry_run"] is False


def test_claim_remediate_job_ignores_non_pending_jobs():
    _register_host()
    variant_id = _register_control_and_variant()
    _insert_remediate_job(job_type="remediate-dry-run", status="running", remediation_variant_id=variant_id)

    resp = client.post(
        "/internal/agent/remediate-jobs/claim", json={"hostname": "agent-test.internal"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 204


def test_claim_remediate_job_ignores_other_hostname():
    _register_host("host-a.internal")
    _register_host("host-b.internal")
    variant_id = _register_control_and_variant()
    _insert_remediate_job(hostname="host-b.internal", status="pending", remediation_variant_id=variant_id)

    resp = client.post(
        "/internal/agent/remediate-jobs/claim", json={"hostname": "host-a.internal"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 204


# 3 test dưới đây vá lỗ hổng thật (TOCTOU): trước đây claim_remediate_job
# không re-check bất kỳ cờ kill-switch nào — 1 job đã "pending" (dispatch
# lúc cờ còn hợp lệ) vẫn bị claim + thực thi thật dù operator đã tắt
# active_response_enabled/đặt agent_renewal_blocked=true SAU KHI job pending.
def test_claim_remediate_job_global_killswitch_off_returns_204_leaves_job_pending(monkeypatch, _mock_audit):
    monkeypatch.setattr(agents_module.settings, "active_response_enabled", False)
    _register_host()
    variant_id = _register_control_and_variant()
    job_id = _insert_remediate_job(status="pending", remediation_variant_id=variant_id)

    resp = client.post(
        "/internal/agent/remediate-jobs/claim", json={"hostname": "agent-test.internal"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 204

    db = _TestSessionLocal()
    job = db.get(Job, job_id)
    assert job.status == "pending"
    db.close()
    assert any(c["action"] == "remediate_claim_blocked_killswitch" for c in _mock_audit)


def test_claim_remediate_job_host_killswitch_off_returns_204_leaves_job_pending(_mock_audit):
    _register_host(active_response_enabled=False)
    variant_id = _register_control_and_variant()
    job_id = _insert_remediate_job(status="pending", remediation_variant_id=variant_id)

    resp = client.post(
        "/internal/agent/remediate-jobs/claim", json={"hostname": "agent-test.internal"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 204

    db = _TestSessionLocal()
    job = db.get(Job, job_id)
    assert job.status == "pending"
    db.close()
    assert any(c["action"] == "remediate_claim_blocked_killswitch" for c in _mock_audit)


def test_claim_remediate_job_renewal_blocked_returns_204_leaves_job_pending(_mock_audit):
    _register_host(blocked=True)
    variant_id = _register_control_and_variant()
    job_id = _insert_remediate_job(status="pending", remediation_variant_id=variant_id)

    resp = client.post(
        "/internal/agent/remediate-jobs/claim", json={"hostname": "agent-test.internal"}, headers=AUTH_HEADER
    )
    assert resp.status_code == 204

    db = _TestSessionLocal()
    job = db.get(Job, job_id)
    assert job.status == "pending"
    db.close()
    assert any(c["action"] == "remediate_claim_blocked_killswitch" for c in _mock_audit)


# ---- POST /internal/agent/remediation-bundle ----


def test_remediation_bundle_requires_shared_secret():
    resp = client.post(
        "/internal/agent/remediation-bundle",
        json={"hostname": "agent-test.internal", "remediation_ref": "test-bundle-1"},
    )
    assert resp.status_code == 401


def test_remediation_bundle_unknown_host_404(monkeypatch, tmp_path):
    monkeypatch.setattr(agents_module.settings, "content_signing_signed_dir", str(tmp_path))
    resp = client.post(
        "/internal/agent/remediation-bundle",
        json={"hostname": "does-not-exist", "remediation_ref": "test-bundle-1"},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 404


def _write_fake_bundle(base_dir, ref, data=b"fake-tar-content", sig=b"fake-sig-content"):
    bundle_dir = os.path.join(base_dir, ref)
    os.makedirs(bundle_dir, exist_ok=True)
    with open(os.path.join(bundle_dir, "content.tar.gz"), "wb") as f:
        f.write(data)
    with open(os.path.join(bundle_dir, "content.tar.gz.sig"), "wb") as f:
        f.write(sig)


def test_remediation_bundle_reads_real_files_success(monkeypatch, tmp_path):
    _register_host()
    variant_id = _register_control_and_variant()
    _insert_remediate_job(status="running", remediation_variant_id=variant_id)
    monkeypatch.setattr(agents_module.settings, "content_signing_signed_dir", str(tmp_path))
    _write_fake_bundle(str(tmp_path), "test-bundle-1", data=b"TAR-BYTES", sig=b"SIG-BYTES")

    resp = client.post(
        "/internal/agent/remediation-bundle",
        json={"hostname": "agent-test.internal", "remediation_ref": "test-bundle-1"},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["remediation_ref"] == "test-bundle-1"
    assert base64.b64decode(body["content_tar_gz_b64"]) == b"TAR-BYTES"
    assert base64.b64decode(body["signature_asc_b64"]) == b"SIG-BYTES"


def test_remediation_bundle_no_matching_running_job_404(monkeypatch, tmp_path):
    # File tồn tại thật + chữ ký/path đều hợp lệ, nhưng KHÔNG có Job nào
    # đang "running" cho host này khớp remediation_ref — bundle PHẢI bị chặn
    # (vá lỗ hổng thật: trước đây bất kỳ agent hợp lệ nào cũng đọc được BẤT
    # KỲ bundle nào đang tồn tại, không ràng buộc theo job/host của chính nó).
    _register_host()
    monkeypatch.setattr(agents_module.settings, "content_signing_signed_dir", str(tmp_path))
    _write_fake_bundle(str(tmp_path), "test-bundle-1")

    resp = client.post(
        "/internal/agent/remediation-bundle",
        json={"hostname": "agent-test.internal", "remediation_ref": "test-bundle-1"},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 404


def test_remediation_bundle_unknown_ref_404(monkeypatch, tmp_path):
    _register_host()
    monkeypatch.setattr(agents_module.settings, "content_signing_signed_dir", str(tmp_path))
    resp = client.post(
        "/internal/agent/remediation-bundle",
        json={"hostname": "agent-test.internal", "remediation_ref": "does-not-exist-bundle"},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 404


@pytest.mark.parametrize(
    "bad_ref",
    [
        "../../etc/passwd",
        "..",
        "foo/../../etc/passwd",
        "/etc/passwd",
        "foo/bar",
        "foo\\bar",
    ],
)
def test_remediation_bundle_rejects_path_traversal(monkeypatch, tmp_path, bad_ref):
    _register_host()
    monkeypatch.setattr(agents_module.settings, "content_signing_signed_dir", str(tmp_path))
    # Đặt sẵn 1 file NHẠY CẢM ngoài signed_dir để chứng minh traversal thật
    # sự bị chặn (không chỉ tình cờ 404 vì file không tồn tại) — nếu guard bị
    # bỏ qua, request sẽ đọc được đúng nội dung "SECRET" này.
    outside = tmp_path.parent / "outside-secret"
    outside.write_text("SECRET")

    resp = client.post(
        "/internal/agent/remediation-bundle",
        json={"hostname": "agent-test.internal", "remediation_ref": bad_ref},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 404


# ---- POST /internal/agent/remediate-result ----


def test_remediate_result_requires_shared_secret():
    resp = client.post(
        "/internal/agent/remediate-result",
        json={
            "hostname": "agent-test.internal", "job_id": 1, "exit_code": 0, "dry_run": True, "log_tail": "ok",
        },
    )
    assert resp.status_code == 401


def test_remediate_result_unknown_job_404():
    resp = client.post(
        "/internal/agent/remediate-result",
        json={
            "hostname": "agent-test.internal", "job_id": 999999, "exit_code": 0, "dry_run": True, "log_tail": "ok",
        },
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 404


def test_remediate_result_hostname_mismatch_422():
    _register_host("host-a.internal")
    _register_host("host-b.internal")
    job_id = _insert_remediate_job(hostname="host-a.internal", status="running")

    resp = client.post(
        "/internal/agent/remediate-result",
        json={"hostname": "host-b.internal", "job_id": job_id, "exit_code": 0, "dry_run": True, "log_tail": "ok"},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 422


@pytest.mark.parametrize("status_value", ["pending", "succeeded", "failed"])
def test_remediate_result_rejects_when_job_not_running(status_value, _mock_audit):
    _register_host()
    job_id = _insert_remediate_job(status=status_value)

    resp = client.post(
        "/internal/agent/remediate-result",
        json={
            "hostname": "agent-test.internal", "job_id": job_id, "exit_code": 0, "dry_run": True, "log_tail": "ok",
        },
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 409
    # Vá lỗ hổng thật: trước đây báo lỗi 409 rồi VỨT BỎ HOÀN TOÀN, không ghi
    # đâu cả — 1 kết quả remediate THẬT đến muộn (sau khi Orchestrator đã tự
    # đánh job "failed" do hết timeout) sẽ mất dấu hoàn toàn. Giờ phải còn
    # lại đúng 1 audit event, dù không tự sửa được Job.
    assert any(c["action"] == "agent_remediate_result_discarded_not_running" for c in _mock_audit)


def test_remediate_result_success_happy_path(_mock_audit):
    _register_host()
    job_id = _insert_remediate_job(status="running", job_type="remediate-dry-run")

    resp = client.post(
        "/internal/agent/remediate-result",
        json={
            "hostname": "agent-test.internal", "job_id": job_id, "exit_code": 0, "dry_run": True,
            "diff_output": "-old\n+new", "log_tail": "remediate ok",
        },
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200

    db = _TestSessionLocal()
    job = db.get(Job, job_id)
    assert job.status == "succeeded"
    assert job.finished_at is not None
    assert job.result_summary["exit_code"] == 0
    assert job.result_summary["dry_run"] is True
    assert job.result_summary["dispatch_via"] == "agent"
    assert job.result_summary["diff_output"] == "-old\n+new"
    assert job.result_summary["log_tail"] == "remediate ok"
    db.close()

    result_events = [c for c in _mock_audit if c["action"] == "agent_remediate_result_reported"]
    assert len(result_events) == 1
    assert result_events[0]["payload"]["job_id"] == job_id
    assert result_events[0]["payload"]["status"] == "succeeded"


def test_remediate_result_nonzero_exit_code_marks_failed():
    _register_host()
    job_id = _insert_remediate_job(status="running", job_type="remediate-apply")

    resp = client.post(
        "/internal/agent/remediate-result",
        json={
            "hostname": "agent-test.internal", "job_id": job_id, "exit_code": 1, "dry_run": False,
            "log_tail": "lỗi khi apply", "error": "ansible-playbook exit 1",
        },
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200

    db = _TestSessionLocal()
    job = db.get(Job, job_id)
    assert job.status == "failed"
    assert job.result_summary["error"] == "ansible-playbook exit 1"
    db.close()


def test_remediate_result_truncates_oversized_backup():
    _register_host()
    job_id = _insert_remediate_job(status="running", job_type="remediate-apply")
    huge_backup = "A" * (jobs_module.BACKUP_MAX_BYTES + 1000)

    resp = client.post(
        "/internal/agent/remediate-result",
        json={
            "hostname": "agent-test.internal", "job_id": job_id, "exit_code": 0, "dry_run": False,
            "backup_tar_b64": huge_backup, "log_tail": "ok",
        },
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200

    db = _TestSessionLocal()
    job = db.get(Job, job_id)
    db.close()
    assert job.result_summary["backup_truncated"] is True
    assert len(job.result_summary["backup_tar_b64"]) == jobs_module.BACKUP_MAX_BYTES


def test_remediate_result_does_not_truncate_small_backup():
    _register_host()
    job_id = _insert_remediate_job(status="running", job_type="remediate-apply")

    resp = client.post(
        "/internal/agent/remediate-result",
        json={
            "hostname": "agent-test.internal", "job_id": job_id, "exit_code": 0, "dry_run": False,
            "backup_tar_b64": "ZmFrZS1iYWNrdXAtdGFyLWNvbnRlbnQ=", "log_tail": "ok",
        },
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200

    db = _TestSessionLocal()
    job = db.get(Job, job_id)
    db.close()
    assert job.result_summary["backup_truncated"] is False


# ---- POST /hosts/{hostname}/agent-install (remote-deploy tự động, khác
# create_agent_install_script dán tay — xem app/agents.py:trigger_agent_install) ----


def test_non_operator_cannot_trigger_agent_install():
    _register_host(ca_migration_status="trust_deployed")
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.post("/hosts/agent-test.internal/agent-install")
    _clear_user_override()
    assert resp.status_code == 403


def test_trigger_agent_install_unknown_host_404():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/does-not-exist/agent-install")
    _clear_user_override()
    assert resp.status_code == 404


def test_trigger_agent_install_blocked_when_decommissioned():
    _register_host(ca_migration_status="trust_deployed", decommissioned=True)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-test.internal/agent-install")
    _clear_user_override()
    assert resp.status_code == 422


def test_trigger_agent_install_blocked_when_not_started():
    # Mặc định _register_host() để ca_migration_status="not_started" — chưa
    # deploy CA trust thì chưa có cách nào SSH bằng cert ephemeral được.
    _register_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-test.internal/agent-install")
    _clear_user_override()
    assert resp.status_code == 422
    assert "ca_migration_status" in resp.json()["detail"] or "trust_deployed" in resp.json()["detail"]


def test_trigger_agent_install_rejects_ssh_user_not_in_allowlist():
    # Defense-in-depth, cùng lý do test_scan_rejects_host_ssh_user_no_longer_in_allowlist
    # (test_jobs.py) — allowlist bị thắt lại SAU khi host đã có giá trị cũ.
    _register_host(ca_migration_status="trust_deployed", ssh_user="scanner-svc")
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-test.internal/agent-install")
    _clear_user_override()
    assert resp.status_code == 422


def test_trigger_agent_install_requires_agent_bundle_ref_configured(monkeypatch):
    monkeypatch.setattr(agents_module.settings, "agent_bundle_ref", "")
    monkeypatch.setattr(agents_module.settings, "agent_bundle_trusted_fingerprint", "TEST-FPR-1234")
    _register_host(ca_migration_status="trust_deployed")
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-test.internal/agent-install")
    _clear_user_override()
    assert resp.status_code == 422
    assert "AGENT_BUNDLE_REF" in resp.json()["detail"]
    # Chưa qua được bước validate đầu tiên — không nên tạo Job row nào.
    db = _TestSessionLocal()
    count = db.query(Job).filter(Job.hostname == "agent-test.internal").count()
    db.close()
    assert count == 0


def test_trigger_agent_install_requires_agent_bundle_trusted_fingerprint_configured(monkeypatch):
    # agent_bundle_ref CỐ Ý tách khỏi content_signing_trusted_fingerprint
    # (dùng cho remediation) — thiếu RIÊNG fingerprint (dù đã có ref) cũng
    # phải chặn, không phải chỉ thiếu ref mới chặn.
    monkeypatch.setattr(agents_module.settings, "agent_bundle_ref", "agent-v1-20260101T000000Z")
    monkeypatch.setattr(agents_module.settings, "agent_bundle_trusted_fingerprint", "")
    _register_host(ca_migration_status="trust_deployed")
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-test.internal/agent-install")
    _clear_user_override()
    assert resp.status_code == 422
    assert "AGENT_BUNDLE_TRUSTED_FINGERPRINT" in resp.json()["detail"]


def test_trigger_agent_install_requires_agent_manager_public_url_configured(monkeypatch):
    # hardening-agent.service mặc định AGENT_MANAGER_URL=https://localhost:8443
    # (chỉ đúng khi Agent Manager chạy CÙNG máy) — thiếu biến này thì job
    # "chạy xong" nhưng Agent trên host thật KHÔNG BAO GIỜ enroll được (lỗi
    # âm thầm đã gặp thật), nên chặn NGAY từ lúc trigger, không để lọt xuống
    # execution-env.
    monkeypatch.setattr(agents_module.settings, "agent_bundle_ref", "agent-v1-20260101T000000Z")
    monkeypatch.setattr(agents_module.settings, "agent_bundle_trusted_fingerprint", "TEST-FPR-1234")
    monkeypatch.setattr(agents_module.settings, "agent_manager_public_url", "")
    _register_host(ca_migration_status="trust_deployed")
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-test.internal/agent-install")
    _clear_user_override()
    assert resp.status_code == 422
    assert "AGENT_MANAGER_PUBLIC_URL" in resp.json()["detail"]


def test_trigger_agent_install_success(monkeypatch, _mock_audit):
    monkeypatch.setattr(agents_module.settings, "agent_bundle_ref", "agent-v1-20260101T000000Z")
    monkeypatch.setattr(agents_module.settings, "agent_bundle_trusted_fingerprint", "TEST-FPR-1234")
    monkeypatch.setattr(agents_module.settings, "agent_manager_public_url", "https://192.0.2.1:8443")
    _register_host(ca_migration_status="trust_deployed")
    _mock_agent_install_dispatch(monkeypatch, exit_code=0, logs="AGENT_INSTALL_STATUS=ok\nReporter da chay\n")

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-test.internal/agent-install")
    _clear_user_override()

    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "succeeded"
    assert body["job_type"] == "agent-install"

    db = _TestSessionLocal()
    job = db.get(Job, body["id"])
    db.close()
    assert job.result_summary["agent_install_status"] == "ok"
    assert job.result_summary["exit_code"] == 0

    completed = [c for c in _mock_audit if c["action"] == "agent_install_completed"]
    assert len(completed) == 1
    assert completed[0]["payload"]["status"] == "succeeded"


def test_trigger_agent_install_script_failure_returns_202_with_failed_job(monkeypatch):
    # Script chạy được (dispatcher không lỗi) nhưng exit_code != 0 (vd verify
    # chữ ký bundle thất bại trên execution-env) — job "failed" nhưng response
    # HTTP vẫn 202 (khác nhánh cert-mint/dispatcher lỗi hạ tầng, trả 502).
    monkeypatch.setattr(agents_module.settings, "agent_bundle_ref", "agent-v1-20260101T000000Z")
    monkeypatch.setattr(agents_module.settings, "agent_bundle_trusted_fingerprint", "TEST-FPR-1234")
    monkeypatch.setattr(agents_module.settings, "agent_manager_public_url", "https://192.0.2.1:8443")
    _register_host(ca_migration_status="trust_deployed")
    _mock_agent_install_dispatch(
        monkeypatch, exit_code=1,
        logs="AGENT_INSTALL_STATUS=failed\nChu ky bundle khong hop le\n",
    )

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-test.internal/agent-install")
    _clear_user_override()

    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "failed"


def test_trigger_agent_install_cert_mint_failure_returns_502_and_marks_job_failed(monkeypatch, _mock_audit):
    monkeypatch.setattr(agents_module.settings, "agent_bundle_ref", "agent-v1-20260101T000000Z")
    monkeypatch.setattr(agents_module.settings, "agent_bundle_trusted_fingerprint", "TEST-FPR-1234")
    monkeypatch.setattr(agents_module.settings, "agent_manager_public_url", "https://192.0.2.1:8443")
    _register_host(ca_migration_status="trust_deployed")

    def _raise(principal):
        raise RuntimeError("step-ca không phản hồi")

    monkeypatch.setattr(agents_module, "mint_ssh_certificate", _raise)

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-test.internal/agent-install")
    _clear_user_override()

    assert resp.status_code == 502
    failed = [c for c in _mock_audit if c["action"] == "agent_install_failed"]
    assert len(failed) == 1
    assert failed[0]["payload"]["error"] == "ca_mint_failed"

    db = _TestSessionLocal()
    jobs = db.query(Job).filter(Job.hostname == "agent-test.internal").all()
    db.close()
    assert len(jobs) == 1
    assert jobs[0].status == "failed"
    assert jobs[0].finished_at is not None


def test_trigger_agent_install_dispatcher_failure_returns_502_and_marks_job_failed(monkeypatch, _mock_audit):
    monkeypatch.setattr(agents_module.settings, "agent_bundle_ref", "agent-v1-20260101T000000Z")
    monkeypatch.setattr(agents_module.settings, "agent_bundle_trusted_fingerprint", "TEST-FPR-1234")
    monkeypatch.setattr(agents_module.settings, "agent_manager_public_url", "https://192.0.2.1:8443")
    _register_host(ca_migration_status="trust_deployed")
    monkeypatch.setattr(
        agents_module, "mint_ssh_certificate", lambda principal: ("FAKE-PRIVATE-KEY", "FAKE-CERT-PUB")
    )
    monkeypatch.setattr(
        jobs_module, "mint_agent_manager_server_cert",
        lambda subject="agent-manager": ("FAKE-CLIENT-CERT-PEM", "FAKE-CLIENT-KEY-PEM"),
    )

    def _raise_connect_error(*a, **kw):
        raise httpx.ConnectError("job-dispatcher không phản hồi")

    monkeypatch.setattr(httpx, "post", _raise_connect_error)

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post("/hosts/agent-test.internal/agent-install")
    _clear_user_override()

    assert resp.status_code == 502
    failed = [c for c in _mock_audit if c["action"] == "agent_install_failed"]
    assert len(failed) == 1
    assert failed[0]["payload"]["error"] == "dispatcher_call_failed"

    db = _TestSessionLocal()
    jobs = db.query(Job).filter(Job.hostname == "agent-test.internal").all()
    db.close()
    assert len(jobs) == 1
    assert jobs[0].status == "failed"
