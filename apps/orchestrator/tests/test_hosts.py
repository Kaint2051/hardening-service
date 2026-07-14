"""Integration test cho Host Registry API — SQLite in-memory + override
get_current_user, verify RBAC qua HTTP thật (TestClient)."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import hosts as hosts_module
from app.auth import CurrentUser, get_current_user
from app.db import Base
from app.main import app

_engine = create_engine(
    "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
)
_TestSessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)


@pytest.fixture(autouse=True)
def _fresh_schema():
    Base.metadata.create_all(bind=_engine, tables=[Base.metadata.tables["hosts"]])
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


app.dependency_overrides[hosts_module._get_db] = _override_db
client = TestClient(app)


# write_audit_event dùng Postgres thật (audit role) — không có trong test
# SQLite in-memory, mock để test không phụ thuộc Postgres (giống test_jobs.py).
# Trả về list các payload đã "ghi" để test kiểm tra sự kiện có được ghi đúng.
@pytest.fixture(autouse=True)
def _mock_audit(monkeypatch):
    calls = []
    monkeypatch.setattr(hosts_module, "write_audit_event", lambda **kwargs: calls.append(kwargs))
    return calls


def _clear_user_override():
    app.dependency_overrides.pop(get_current_user, None)


def _register_sample_host(username="opuser", role="operator", tier=1):
    app.dependency_overrides[get_current_user] = _as(username, role)
    resp = client.post(
        "/hosts",
        json={
            "hostname": "pilot-host-01.internal",
            "ip_address": "10.0.0.11",
            "os_family": "Debian",
            "os_version": "12",
            "tier": tier,
        },
    )
    _clear_user_override()
    return resp


def test_viewer_cannot_register_host():
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.post(
        "/hosts",
        json={"hostname": "h1", "ip_address": "10.0.0.1", "os_family": "Debian"},
    )
    _clear_user_override()
    assert resp.status_code == 403


def test_operator_registers_host_with_default_status_and_viewer_can_read():
    resp = _register_sample_host()
    assert resp.status_code == 201
    body = resp.json()
    assert body["ca_migration_status"] == "not_started"
    assert body["added_by"] == "opuser"
    assert body["tier"] == 1

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    listed = client.get("/hosts")
    _clear_user_override()
    assert listed.status_code == 200
    assert len(listed.json()) == 1


@pytest.mark.parametrize(
    "bad_ip",
    [
        "169.254.169.254",  # cloud metadata endpoint
        "127.0.0.1",  # loopback
        "0.0.0.0",  # unspecified
        "224.0.0.1",  # multicast
        "not-an-ip-at-all",  # không parse được thành IP
        "10.0.0.1; rm -rf /",  # chuỗi lạ lọt xuống oscap-ssh nếu không chặn ở đây
    ],
)
def test_register_host_rejects_bad_ip_address(bad_ip):
    # Bug thật tìm được qua workflow review (không phải test thật ban đầu):
    # ip_address trước đây không được validate, dùng thẳng làm TARGET_HOST
    # cho oscap-ssh với StrictHostKeyChecking=no -> 1 operator có thể trỏ
    # scan (kèm SSH cert root thật) vào endpoint nội bộ nhạy cảm.
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts",
        json={"hostname": "bad-ip-host.internal", "ip_address": bad_ip, "os_family": "Debian"},
    )
    _clear_user_override()
    assert resp.status_code == 422


def test_register_host_accepts_private_ip_address():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts",
        json={"hostname": "good-ip-host.internal", "ip_address": "172.30.2.111", "os_family": "Debian"},
    )
    _clear_user_override()
    assert resp.status_code == 201
    assert resp.json()["ip_address"] == "172.30.2.111"


def test_register_host_rejects_bad_hostname():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts",
        json={"hostname": "not a valid host!", "ip_address": "10.0.0.5", "os_family": "Debian"},
    )
    _clear_user_override()
    assert resp.status_code == 422


def test_duplicate_hostname_conflict():
    assert _register_sample_host().status_code == 201
    resp = _register_sample_host()
    assert resp.status_code == 409


def test_rule_editor_cannot_update_migration_status():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    resp = client.patch(
        "/hosts/pilot-host-01.internal/ca-migration-status",
        json={"ca_migration_status": "trust_deployed"},
    )
    _clear_user_override()
    assert resp.status_code == 403


def test_operator_updates_migration_status_and_filter_works():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch(
        "/hosts/pilot-host-01.internal/ca-migration-status",
        json={"ca_migration_status": "trust_deployed"},
    )
    assert resp.status_code == 200
    assert resp.json()["ca_migration_status"] == "trust_deployed"

    filtered = client.get("/hosts", params={"ca_migration_status": "trust_deployed"})
    _clear_user_override()
    assert len(filtered.json()) == 1

    app.dependency_overrides[get_current_user] = _as("alice", "auditor")
    empty = client.get("/hosts", params={"ca_migration_status": "migrated"})
    _clear_user_override()
    assert empty.json() == []


def test_invalid_migration_status_rejected():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch(
        "/hosts/pilot-host-01.internal/ca-migration-status",
        json={"ca_migration_status": "not-a-real-status"},
    )
    _clear_user_override()
    assert resp.status_code == 422


def test_get_unknown_host_404():
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/hosts/does-not-exist")
    _clear_user_override()
    assert resp.status_code == 404


def test_register_host_writes_audit_event(_mock_audit):
    resp = _register_sample_host()
    assert len(_mock_audit) == 1
    assert _mock_audit[0]["action"] == "host_registered"
    assert _mock_audit[0]["resource"] == resp.json()["hostname"]
    assert _mock_audit[0]["payload"] == {"ip_address": "10.0.0.11", "tier": 1, "os_family": "Debian"}


def test_migration_status_update_writes_audit_event(_mock_audit):
    _register_sample_host()  # ghi 1 audit event (host_registered)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.patch(
        "/hosts/pilot-host-01.internal/ca-migration-status",
        json={"ca_migration_status": "trust_deployed"},
    )
    _clear_user_override()
    assert len(_mock_audit) == 2
    assert _mock_audit[1]["action"] == "host_ca_migration_status_updated"
    assert _mock_audit[1]["payload"] == {"from": "not_started", "to": "trust_deployed", "tier": 1}


def test_migrated_requires_trust_deployed_first():
    # Bug thật tìm được qua gọi API trực tiếp (không phải đọc code): nhảy
    # thẳng not_started -> migrated khiến ca_migration_updated_by vẫn None,
    # làm guard "is not None" của four-eyes tự tắt điều kiện -> bỏ qua hoàn
    # toàn kiểm tra four-eyes cho host Tier cao. Chặn ở tầng transition order
    # thay vì chỉ ở tầng four-eyes.
    _register_sample_host(tier=1)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch(
        "/hosts/pilot-host-01.internal/ca-migration-status",
        json={"ca_migration_status": "migrated"},
    )
    _clear_user_override()
    assert resp.status_code == 422
    assert "trust_deployed" in resp.json()["detail"]


def test_four_eyes_blocks_same_person_confirming_migrated_on_high_tier(_mock_audit):
    # Host Tier 1 ("production/Tier cao") — người đặt trust_deployed không
    # được tự xác nhận nốt "migrated" cho chính lần cập nhật đó (four-eyes).
    _register_sample_host(tier=1)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.patch(
        "/hosts/pilot-host-01.internal/ca-migration-status",
        json={"ca_migration_status": "trust_deployed"},
    )
    resp = client.patch(
        "/hosts/pilot-host-01.internal/ca-migration-status",
        json={"ca_migration_status": "migrated"},
    )
    _clear_user_override()
    assert resp.status_code == 403
    assert "four-eyes" in resp.json()["detail"]
    # host_registered + trust_deployed = 2; lần bị chặn 403 không ghi thêm.
    assert len(_mock_audit) == 2

    app.dependency_overrides[get_current_user] = _as("dave", "operator")
    resp = client.patch(
        "/hosts/pilot-host-01.internal/ca-migration-status",
        json={"ca_migration_status": "migrated"},
    )
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["ca_migration_status"] == "migrated"
    assert len(_mock_audit) == 3


def test_four_eyes_not_enforced_on_default_tier_host():
    # Tier 2 (mặc định) — chưa phải "production/Tier cao", cùng 1 người được
    # tự đặt trust_deployed rồi migrated.
    _register_sample_host(tier=2)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.patch(
        "/hosts/pilot-host-01.internal/ca-migration-status",
        json={"ca_migration_status": "trust_deployed"},
    )
    resp = client.patch(
        "/hosts/pilot-host-01.internal/ca-migration-status",
        json={"ca_migration_status": "migrated"},
    )
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["ca_migration_status"] == "migrated"


def test_new_host_has_agent_renewal_unblocked_by_default():
    resp = _register_sample_host()
    assert resp.status_code == 201
    assert resp.json()["agent_renewal_blocked"] is False


def test_rule_editor_cannot_update_agent_renewal():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    resp = client.patch(
        "/hosts/pilot-host-01.internal/agent-renewal",
        json={"blocked": True},
    )
    _clear_user_override()
    assert resp.status_code == 403


@pytest.mark.parametrize("role", ["operator", "admin"])
def test_operator_or_admin_blocks_and_unblocks_agent_renewal(role):
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", role)

    resp = client.patch(
        "/hosts/pilot-host-01.internal/agent-renewal",
        json={"blocked": True},
    )
    assert resp.status_code == 200
    assert resp.json()["agent_renewal_blocked"] is True

    resp2 = client.patch(
        "/hosts/pilot-host-01.internal/agent-renewal",
        json={"blocked": False},
    )
    _clear_user_override()
    assert resp2.status_code == 200
    assert resp2.json()["agent_renewal_blocked"] is False


def test_agent_renewal_update_unknown_host_404():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch(
        "/hosts/does-not-exist/agent-renewal",
        json={"blocked": True},
    )
    _clear_user_override()
    assert resp.status_code == 404


def test_agent_renewal_update_writes_audit_event(_mock_audit):
    _register_sample_host()  # ghi 1 audit event (host_registered)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch(
        "/hosts/pilot-host-01.internal/agent-renewal",
        json={"blocked": True},
    )
    _clear_user_override()
    assert resp.status_code == 200
    assert len(_mock_audit) == 2
    assert _mock_audit[1]["actor"] == "opuser"
    assert _mock_audit[1]["action"] == "agent_renewal_blocked_updated"
    assert _mock_audit[1]["resource"] == "pilot-host-01.internal"
    assert _mock_audit[1]["payload"] == {"blocked": True}


# ---- PATCH /hosts/{hostname}/active-response (Active Response, mục 4.3/4.4) ----


def test_new_host_has_active_response_disabled_by_default():
    resp = _register_sample_host()
    assert resp.status_code == 201
    assert resp.json()["active_response_enabled"] is False


def test_rule_editor_cannot_update_active_response():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    resp = client.patch(
        "/hosts/pilot-host-01.internal/active-response",
        json={"enabled": True},
    )
    _clear_user_override()
    assert resp.status_code == 403


@pytest.mark.parametrize("role", ["operator", "admin"])
def test_operator_or_admin_toggles_active_response(role):
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", role)

    resp = client.patch(
        "/hosts/pilot-host-01.internal/active-response",
        json={"enabled": True},
    )
    assert resp.status_code == 200
    assert resp.json()["active_response_enabled"] is True

    resp2 = client.patch(
        "/hosts/pilot-host-01.internal/active-response",
        json={"enabled": False},
    )
    _clear_user_override()
    assert resp2.status_code == 200
    assert resp2.json()["active_response_enabled"] is False


def test_active_response_update_unknown_host_404():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch(
        "/hosts/does-not-exist/active-response",
        json={"enabled": True},
    )
    _clear_user_override()
    assert resp.status_code == 404


def test_active_response_update_writes_audit_event(_mock_audit):
    _register_sample_host()  # ghi 1 audit event (host_registered)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch(
        "/hosts/pilot-host-01.internal/active-response",
        json={"enabled": True},
    )
    _clear_user_override()
    assert resp.status_code == 200
    assert len(_mock_audit) == 2
    assert _mock_audit[1]["actor"] == "opuser"
    assert _mock_audit[1]["action"] == "active_response_enabled_updated"
    assert _mock_audit[1]["resource"] == "pilot-host-01.internal"
    assert _mock_audit[1]["payload"] == {"enabled": True}
