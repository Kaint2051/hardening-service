"""Integration test cho Host Registry API — SQLite in-memory + override
get_current_user, verify RBAC qua HTTP thật (TestClient)."""
import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from datetime import datetime, timezone

from cryptography.fernet import Fernet

from app import hosts as hosts_module
from app.auth import CurrentUser, get_current_user
from app.db import Base
from app.main import app
from app.models import Job, RemediationRequest

_engine = create_engine(
    "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
)
_TestSessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)


@pytest.fixture(autouse=True)
def _fresh_schema():
    # "remediation_requests" cần cho test delete_host (xoá cascade thủ công
    # RemediationRequest trước Job trước Host, xem app/hosts.py:delete_host).
    Base.metadata.create_all(
        bind=_engine,
        tables=[
            Base.metadata.tables["hosts"],
            Base.metadata.tables["jobs"],
            Base.metadata.tables["remediation_requests"],
        ],
    )
    yield
    Base.metadata.drop_all(bind=_engine)


@pytest.fixture(autouse=True)
def _mock_encryption_key(monkeypatch):
    # Test riêng, không dùng key thật của .env — mỗi lần chạy test này tự
    # sinh 1 key hợp lệ, đủ để verify logic encrypt/decrypt mà không phụ
    # thuộc cấu hình môi trường.
    monkeypatch.setattr(hosts_module.settings, "host_credential_encryption_key", Fernet.generate_key().decode())


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
    # os_family/os_version KHÔNG còn khai lúc đăng ký (xem
    # app/schemas.py:HostCreate) — host mới luôn os_family=None, điền sau qua
    # Agent heartbeat hoặc PATCH /hosts/{hostname} (xem test riêng ở dưới).
    app.dependency_overrides[get_current_user] = _as(username, role)
    resp = client.post(
        "/hosts",
        json={
            "hostname": "pilot-host-01.internal",
            "ip_address": "10.0.0.11",
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
    # os_family luôn None ngay lúc đăng ký (không còn khai ở bước này) — xem
    # _register_sample_host.
    assert _mock_audit[0]["payload"] == {"ip_address": "10.0.0.11", "tier": 1, "os_family": None}


def test_register_host_os_family_defaults_to_none():
    # os_family/os_version không còn là field của HostCreate — điền qua
    # PATCH /hosts/{hostname} (test_operator_updates_os_family_and_os_version)
    # hoặc Agent heartbeat (test_agents.py) sau khi đăng ký.
    resp = _register_sample_host()
    body = resp.json()
    assert body["os_family"] is None
    assert body["os_version"] is None


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


def test_same_person_can_confirm_migrated_regardless_of_tier(_mock_audit):
    # Four-eyes cho bước "migrated" đã bị bỏ theo yêu cầu người dùng — cùng 1
    # người được tự đặt trust_deployed rồi migrated, kể cả host Tier cao.
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
    assert resp.status_code == 200
    assert resp.json()["ca_migration_status"] == "migrated"
    # host_registered + trust_deployed + migrated = 3, cùng 1 actor.
    assert len(_mock_audit) == 3


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


# ---- PATCH /hosts/{hostname}/decommission (ngừng/khôi phục quản lý, KHÔNG
# xoá record — xem docstring app/hosts.py để biết lý do không có hard-delete) ----


def test_new_host_not_decommissioned_by_default():
    resp = _register_sample_host()
    assert resp.status_code == 201
    assert resp.json()["decommissioned_at"] is None
    assert resp.json()["decommissioned_by"] is None


def test_rule_editor_cannot_update_decommission():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    resp = client.patch(
        "/hosts/pilot-host-01.internal/decommission",
        json={"decommissioned": True},
    )
    _clear_user_override()
    assert resp.status_code == 403


@pytest.mark.parametrize("role", ["operator", "admin"])
def test_operator_or_admin_decommissions_and_recommissions_host(role):
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", role)

    resp = client.patch(
        "/hosts/pilot-host-01.internal/decommission",
        json={"decommissioned": True},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decommissioned_at"] is not None
    assert body["decommissioned_by"] == "opuser"

    resp2 = client.patch(
        "/hosts/pilot-host-01.internal/decommission",
        json={"decommissioned": False},
    )
    _clear_user_override()
    assert resp2.status_code == 200
    body2 = resp2.json()
    assert body2["decommissioned_at"] is None
    assert body2["decommissioned_by"] is None


def test_decommission_update_unknown_host_404():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch(
        "/hosts/does-not-exist/decommission",
        json={"decommissioned": True},
    )
    _clear_user_override()
    assert resp.status_code == 404


def test_decommission_twice_returns_409():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.patch("/hosts/pilot-host-01.internal/decommission", json={"decommissioned": True})
    resp = client.patch("/hosts/pilot-host-01.internal/decommission", json={"decommissioned": True})
    _clear_user_override()
    assert resp.status_code == 409


def test_recommission_when_not_decommissioned_returns_409():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch("/hosts/pilot-host-01.internal/decommission", json={"decommissioned": False})
    _clear_user_override()
    assert resp.status_code == 409


def test_decommission_update_writes_audit_event(_mock_audit):
    _register_sample_host()  # ghi 1 audit event (host_registered)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch(
        "/hosts/pilot-host-01.internal/decommission",
        json={"decommissioned": True},
    )
    _clear_user_override()
    assert resp.status_code == 200
    assert len(_mock_audit) == 2
    assert _mock_audit[1]["actor"] == "opuser"
    assert _mock_audit[1]["action"] == "host_decommissioned"
    assert _mock_audit[1]["resource"] == "pilot-host-01.internal"


def test_list_hosts_excludes_decommissioned_by_default():
    _register_sample_host()  # "pilot-host-01.internal"
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.post(
        "/hosts",
        json={"hostname": "pilot-host-02.internal", "ip_address": "10.0.0.12", "os_family": "Debian"},
    )
    client.patch("/hosts/pilot-host-01.internal/decommission", json={"decommissioned": True})

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    default_resp = client.get("/hosts")
    all_resp = client.get("/hosts?include_decommissioned=true")
    _clear_user_override()

    default_hostnames = {h["hostname"] for h in default_resp.json()}
    all_hostnames = {h["hostname"] for h in all_resp.json()}
    assert default_hostnames == {"pilot-host-02.internal"}
    assert all_hostnames == {"pilot-host-01.internal", "pilot-host-02.internal"}


def test_ca_migration_status_update_blocked_when_decommissioned():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.patch("/hosts/pilot-host-01.internal/decommission", json={"decommissioned": True})
    resp = client.patch(
        "/hosts/pilot-host-01.internal/ca-migration-status",
        json={"ca_migration_status": "trust_deployed"},
    )
    _clear_user_override()
    assert resp.status_code == 422


# ---- ssh_user (mục "sửa host" — Host.ssh_user, xem app/hosts.py/app/jobs.py) ----


def test_new_host_defaults_ssh_user_to_root():
    resp = _register_sample_host()
    assert resp.status_code == 201
    assert resp.json()["ssh_user"] == "root"


def test_register_host_rejects_ssh_user_not_in_allowlist():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts",
        json={
            "hostname": "pilot-host-03.internal", "ip_address": "10.0.0.13",
            "os_family": "Debian", "ssh_user": "attacker-chosen-user",
        },
    )
    _clear_user_override()
    assert resp.status_code == 422


def test_register_host_accepts_ssh_user_in_custom_allowlist(monkeypatch):
    monkeypatch.setattr(hosts_module.settings, "allowed_ssh_users", "root,scanner-svc")
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts",
        json={
            "hostname": "pilot-host-04.internal", "ip_address": "10.0.0.14",
            "os_family": "Debian", "ssh_user": "scanner-svc",
        },
    )
    _clear_user_override()
    assert resp.status_code == 201
    assert resp.json()["ssh_user"] == "scanner-svc"


# ---- ssh_port (Host.ssh_port — chỉ KHAI LẠI qua đây, đổi THẬT có xác minh
# kết nối phải qua POST /hosts/{hostname}/ssh-port-change, xem test_jobs.py) ----


def test_new_host_defaults_ssh_port_to_22():
    resp = _register_sample_host()
    assert resp.status_code == 201
    assert resp.json()["ssh_port"] == 22


def test_register_host_accepts_custom_ssh_port():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts",
        json={
            "hostname": "pilot-host-05.internal", "ip_address": "10.0.0.15",
            "os_family": "Debian", "ssh_port": 2222,
        },
    )
    _clear_user_override()
    assert resp.status_code == 201
    assert resp.json()["ssh_port"] == 2222


def test_register_host_rejects_ssh_port_out_of_range():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts",
        json={
            "hostname": "pilot-host-06.internal", "ip_address": "10.0.0.16",
            "os_family": "Debian", "ssh_port": 70000,
        },
    )
    _clear_user_override()
    assert resp.status_code == 422


def test_operator_updates_ssh_port_declaration_only():
    # PATCH ở đây CHỈ khai lại — không gọi job/SSH gì, xem docstring
    # HostUpdate.ssh_port (app/schemas.py).
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch("/hosts/pilot-host-01.internal", json={"ssh_port": 2222})
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["ssh_port"] == 2222


# ---- PATCH /hosts/{hostname} (sửa host — mục "sửa host") ----


def test_rule_editor_cannot_update_host():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    resp = client.patch("/hosts/pilot-host-01.internal", json={"os_family": "Ubuntu"})
    _clear_user_override()
    assert resp.status_code == 403


def test_update_host_unknown_host_404():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch("/hosts/does-not-exist", json={"os_family": "Ubuntu"})
    _clear_user_override()
    assert resp.status_code == 404


def test_update_host_blocked_when_decommissioned():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.patch("/hosts/pilot-host-01.internal/decommission", json={"decommissioned": True})
    resp = client.patch("/hosts/pilot-host-01.internal", json={"os_family": "Ubuntu"})
    _clear_user_override()
    assert resp.status_code == 422


def test_operator_updates_os_family_and_os_version():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch(
        "/hosts/pilot-host-01.internal",
        json={"os_family": "Ubuntu", "os_version": "24.04"},
    )
    _clear_user_override()
    assert resp.status_code == 200
    body = resp.json()
    assert body["os_family"] == "Ubuntu"
    assert body["os_version"] == "24.04"


def test_operator_cannot_update_tier():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch("/hosts/pilot-host-01.internal", json={"tier": 0})
    _clear_user_override()
    assert resp.status_code == 403


def test_admin_can_update_tier():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("adminuser", "admin")
    resp = client.patch("/hosts/pilot-host-01.internal", json={"tier": 0})
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["tier"] == 0


def test_update_host_rejects_ssh_user_not_in_allowlist():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch(
        "/hosts/pilot-host-01.internal", json={"ssh_user": "attacker-chosen-user"}
    )
    _clear_user_override()
    assert resp.status_code == 422


def test_update_ip_address_resets_ca_migration_status():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.patch(
        "/hosts/pilot-host-01.internal/ca-migration-status",
        json={"ca_migration_status": "trust_deployed"},
    )
    resp = client.patch("/hosts/pilot-host-01.internal", json={"ip_address": "10.0.0.99"})
    _clear_user_override()
    assert resp.status_code == 200
    body = resp.json()
    assert body["ip_address"] == "10.0.0.99"
    assert body["ca_migration_status"] == "not_started"
    assert body["ca_migration_updated_by"] is None


def test_update_host_rejects_bad_ip_address():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch("/hosts/pilot-host-01.internal", json={"ip_address": "169.254.169.254"})
    _clear_user_override()
    assert resp.status_code == 422


def test_update_host_writes_audit_event(_mock_audit):
    _register_sample_host()  # ghi 1 audit event (host_registered)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch(
        "/hosts/pilot-host-01.internal", json={"os_family": "Ubuntu"}
    )
    _clear_user_override()
    assert resp.status_code == 200
    assert len(_mock_audit) == 2
    assert _mock_audit[1]["actor"] == "opuser"
    assert _mock_audit[1]["action"] == "host_updated"
    assert _mock_audit[1]["resource"] == "pilot-host-01.internal"
    # os_family còn None ngay sau đăng ký (không còn khai lúc đó nữa).
    assert _mock_audit[1]["payload"]["changes"]["os_family"] == {"from": None, "to": "Ubuntu"}


def test_update_host_with_no_changes_is_a_noop(_mock_audit):
    _register_sample_host()  # ghi 1 audit event (host_registered), os_family=None
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    # Lần đầu set os_family THẬT là 1 thay đổi (None -> Debian, ghi audit) —
    # phải làm bước này trước để lần PATCH thứ 2 dưới đây mới đúng nghĩa
    # "PATCH lại giá trị đã có sẵn", không phải chỉ tình cờ os_family vẫn còn
    # None.
    client.patch("/hosts/pilot-host-01.internal", json={"os_family": "Debian"})
    resp = client.patch("/hosts/pilot-host-01.internal", json={"os_family": "Debian"})
    _clear_user_override()
    assert resp.status_code == 200
    assert len(_mock_audit) == 2  # đăng ký + đúng 1 lần update thật — lần no-op không ghi thêm


# ---- ssh_password (lưu THAM KHẢO, mã hoá — xem app/hosts.py, CHƯA dùng cho
# job pipeline nào) ----

_FAKE_SSH_PASSWORD = "s3cr3t-reference-password-do-not-leak"


def test_register_host_with_ssh_password_sets_has_ssh_password_flag():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts",
        json={
            "hostname": "pilot-host-05.internal", "ip_address": "10.0.0.15",
            "os_family": "Debian", "ssh_password": _FAKE_SSH_PASSWORD,
        },
    )
    _clear_user_override()
    assert resp.status_code == 201
    assert resp.json()["has_ssh_password"] is True


def test_register_host_without_ssh_password_flag_false():
    resp = _register_sample_host()
    assert resp.status_code == 201
    assert resp.json()["has_ssh_password"] is False


def test_ssh_password_never_exposed_via_host_out():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.post(
        "/hosts",
        json={
            "hostname": "pilot-host-06.internal", "ip_address": "10.0.0.16",
            "os_family": "Debian", "ssh_password": _FAKE_SSH_PASSWORD,
        },
    )
    resp = client.get("/hosts/pilot-host-06.internal")
    _clear_user_override()
    assert resp.status_code == 200
    assert "ssh_password" not in resp.json()
    assert "ssh_password_encrypted" not in resp.json()
    assert _FAKE_SSH_PASSWORD not in resp.text


def test_update_host_sets_ssh_password():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch(
        "/hosts/pilot-host-01.internal", json={"ssh_password": _FAKE_SSH_PASSWORD}
    )
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["has_ssh_password"] is True
    assert _FAKE_SSH_PASSWORD not in resp.text


def test_update_host_clears_ssh_password_with_empty_string():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.patch("/hosts/pilot-host-01.internal", json={"ssh_password": _FAKE_SSH_PASSWORD})
    resp = client.patch("/hosts/pilot-host-01.internal", json={"ssh_password": ""})
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["has_ssh_password"] is False


def test_update_host_audit_does_not_leak_ssh_password(_mock_audit):
    _register_sample_host()  # 1 audit event (host_registered)
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.patch("/hosts/pilot-host-01.internal", json={"ssh_password": _FAKE_SSH_PASSWORD})
    _clear_user_override()
    assert len(_mock_audit) == 2
    assert _mock_audit[1]["payload"]["changes"]["ssh_password"] == "updated"
    assert _FAKE_SSH_PASSWORD not in str(_mock_audit[1])


# ---- GET /hosts/{hostname}/ssh-credential ----


def test_get_ssh_credential_requires_operator_role():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/hosts/pilot-host-01.internal/ssh-credential")
    _clear_user_override()
    assert resp.status_code == 403


def test_get_ssh_credential_unknown_host_404():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.get("/hosts/does-not-exist/ssh-credential")
    _clear_user_override()
    assert resp.status_code == 404


def test_get_ssh_credential_returns_none_when_not_set():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.get("/hosts/pilot-host-01.internal/ssh-credential")
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["ssh_password"] is None


def test_get_ssh_credential_decrypts_correctly():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.patch("/hosts/pilot-host-01.internal", json={"ssh_password": _FAKE_SSH_PASSWORD})
    resp = client.get("/hosts/pilot-host-01.internal/ssh-credential")
    _clear_user_override()
    assert resp.status_code == 200
    body = resp.json()
    assert body["ssh_password"] == _FAKE_SSH_PASSWORD
    assert body["ssh_user"] == "root"


def test_get_ssh_credential_writes_audit_event(_mock_audit):
    _register_sample_host()  # 1 audit event
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.get("/hosts/pilot-host-01.internal/ssh-credential")
    _clear_user_override()
    assert resp.status_code == 200
    assert len(_mock_audit) == 2
    assert _mock_audit[1]["action"] == "host_ssh_credential_viewed"
    assert _mock_audit[1]["actor"] == "opuser"


# ---- DELETE /hosts/{hostname} (hard-delete TOÀN BỘ, kể cả job/remediation
# request đã có — theo yêu cầu người dùng, xem docstring delete_host) ----


def _insert_job(hostname="pilot-host-01.internal", job_type="scan"):
    db = _TestSessionLocal()
    job = Job(
        hostname=hostname, job_type=job_type, status="succeeded",
        triggered_by="opuser", started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    job_id = job.id
    db.close()
    return job_id


def _insert_remediation_request(hostname="pilot-host-01.internal", dry_run_job_id=None):
    dry_run_job_id = dry_run_job_id or _insert_job(hostname, job_type="remediate-dry-run")
    db = _TestSessionLocal()
    db.add(RemediationRequest(
        hostname=hostname, control_id="does-not-need-to-exist-for-this-test",
        dry_run_job_id=dry_run_job_id, status="pending", requested_by="opuser",
        requested_at=datetime.now(timezone.utc),
    ))
    db.commit()
    db.close()


def _set_agent_enrolled(hostname="pilot-host-01.internal"):
    db = _TestSessionLocal()
    host = db.get(hosts_module.Host, hostname)
    host.agent_enrolled_at = datetime.now(timezone.utc)
    db.commit()
    db.close()


def test_delete_host_requires_admin_role():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.delete("/hosts/pilot-host-01.internal")
    _clear_user_override()
    assert resp.status_code == 403


def test_delete_host_unknown_host_404():
    app.dependency_overrides[get_current_user] = _as("adminuser", "admin")
    resp = client.delete("/hosts/does-not-exist")
    _clear_user_override()
    assert resp.status_code == 404


def test_delete_host_without_job_history_succeeds():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("adminuser", "admin")
    resp = client.delete("/hosts/pilot-host-01.internal")
    _clear_user_override()
    assert resp.status_code == 204

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    get_resp = client.get("/hosts/pilot-host-01.internal")
    _clear_user_override()
    assert get_resp.status_code == 404


def test_delete_host_with_job_history_also_succeeds_and_removes_jobs():
    # Khác thiết kế gốc (từng chặn 409) — giờ xoá LUÔN kèm lịch sử job.
    _register_sample_host()
    _insert_job()
    app.dependency_overrides[get_current_user] = _as("adminuser", "admin")
    resp = client.delete("/hosts/pilot-host-01.internal")
    _clear_user_override()
    assert resp.status_code == 204

    db = _TestSessionLocal()
    remaining = db.query(Job).filter(Job.hostname == "pilot-host-01.internal").count()
    db.close()
    assert remaining == 0


def test_delete_host_removes_remediation_requests_before_jobs():
    # RemediationRequest.dry_run_job_id là FK RESTRICT tới jobs.id — nếu xoá
    # Job trước mà chưa xoá RemediationRequest tham chiếu tới nó, Postgres
    # thật sẽ từ chối (SQLite test không tự bắt lỗi này vì không enforce FK,
    # nên test ở đây xác nhận ĐÚNG THỨ TỰ xoá qua code, không phải qua lỗi DB).
    _register_sample_host()
    _insert_remediation_request()
    app.dependency_overrides[get_current_user] = _as("adminuser", "admin")
    resp = client.delete("/hosts/pilot-host-01.internal")
    _clear_user_override()
    assert resp.status_code == 204

    db = _TestSessionLocal()
    remaining_requests = db.query(RemediationRequest).filter(
        RemediationRequest.hostname == "pilot-host-01.internal"
    ).count()
    remaining_jobs = db.query(Job).filter(Job.hostname == "pilot-host-01.internal").count()
    db.close()
    assert remaining_requests == 0
    assert remaining_jobs == 0


def test_delete_host_writes_audit_event(_mock_audit):
    _register_sample_host()  # 1 audit event
    app.dependency_overrides[get_current_user] = _as("adminuser", "admin")
    resp = client.delete("/hosts/pilot-host-01.internal")
    _clear_user_override()
    assert resp.status_code == 204
    assert len(_mock_audit) == 2
    assert _mock_audit[1]["action"] == "host_force_deleted"
    assert _mock_audit[1]["actor"] == "adminuser"
    assert _mock_audit[1]["payload"]["agent_uninstall"] == {"outcome": "skipped_no_agent"}


def test_delete_host_audit_event_counts_deleted_jobs_and_requests(_mock_audit):
    _register_sample_host()
    _insert_remediation_request()
    _insert_job(job_type="scan")  # +1 job ngoài job dry-run của remediation request
    app.dependency_overrides[get_current_user] = _as("adminuser", "admin")
    resp = client.delete("/hosts/pilot-host-01.internal")
    _clear_user_override()
    assert resp.status_code == 204
    payload = _mock_audit[-1]["payload"]
    assert payload["deleted_job_count"] == 2
    assert payload["deleted_remediation_request_count"] == 1


def test_delete_host_skips_agent_uninstall_when_ca_not_started(_mock_audit):
    # Host mới đăng ký -> ca_migration_status="not_started" mặc định -> chưa
    # cấp được SSH cert -> gỡ Agent bị bỏ qua (không chặn xoá).
    _register_sample_host()
    _set_agent_enrolled()
    app.dependency_overrides[get_current_user] = _as("adminuser", "admin")
    resp = client.delete("/hosts/pilot-host-01.internal")
    _clear_user_override()
    assert resp.status_code == 204
    assert _mock_audit[-1]["payload"]["agent_uninstall"]["outcome"] == "skipped_unreachable"


def test_delete_host_runs_agent_uninstall_when_reachable(monkeypatch, _mock_audit):
    _register_sample_host()
    _set_agent_enrolled()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    # "trust_deployed" đủ để mint SSH cert được (xem điều kiện trong
    # _run_agent_uninstall_best_effort) — không cần đủ 2 bước lên "migrated".
    client.patch("/hosts/pilot-host-01.internal/ca-migration-status", json={"ca_migration_status": "trust_deployed"})
    _clear_user_override()

    monkeypatch.setattr(
        hosts_module, "_get_ssh_dispatch_environment",
        lambda host, principal: {"SSH_KEY_B64": "RkFLRS1LRVk=", "SSH_CERT_B64": "RkFLRS1DRVJU"},
    )
    monkeypatch.setattr(
        hosts_module, "_call_job_dispatcher",
        lambda body, timeout: {"exit_code": 0, "logs": "AGENT_UNINSTALL_STATUS=ok\n"},
    )
    app.dependency_overrides[get_current_user] = _as("adminuser", "admin")
    resp = client.delete("/hosts/pilot-host-01.internal")
    _clear_user_override()
    assert resp.status_code == 204
    assert _mock_audit[-1]["payload"]["agent_uninstall"] == {"outcome": "succeeded"}


def test_delete_host_still_succeeds_when_agent_uninstall_fails(monkeypatch, _mock_audit):
    # Best-effort: gỡ Agent lỗi (vd máy đã tắt/mất mạng) KHÔNG chặn xoá record
    # console — đúng chủ đích "xoá hết" người dùng yêu cầu.
    _register_sample_host()
    _set_agent_enrolled()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.patch("/hosts/pilot-host-01.internal/ca-migration-status", json={"ca_migration_status": "trust_deployed"})
    _clear_user_override()

    monkeypatch.setattr(
        hosts_module, "_get_ssh_dispatch_environment",
        lambda host, principal: {"SSH_KEY_B64": "RkFLRS1LRVk=", "SSH_CERT_B64": "RkFLRS1DRVJU"},
    )

    def _raise(body, timeout):
        raise httpx.ConnectError("máy đích không phản hồi")

    monkeypatch.setattr(hosts_module, "_call_job_dispatcher", _raise)
    app.dependency_overrides[get_current_user] = _as("adminuser", "admin")
    resp = client.delete("/hosts/pilot-host-01.internal")
    _clear_user_override()
    assert resp.status_code == 204
    assert _mock_audit[-1]["payload"]["agent_uninstall"]["outcome"] == "failed"


# ---- exposure (register/update) ----


def test_register_host_exposure_defaults_local():
    resp = _register_sample_host()
    assert resp.json()["exposure"] == "local"


def test_register_host_exposure_direct():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts",
        json={
            "hostname": "public-web-01.internal",
            "ip_address": "10.0.0.20",
            "exposure": "direct",
        },
    )
    _clear_user_override()
    assert resp.status_code == 201
    assert resp.json()["exposure"] == "direct"


def test_register_host_rejects_invalid_exposure():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.post(
        "/hosts",
        json={
            "hostname": "bad-exposure.internal",
            "ip_address": "10.0.0.21",
            "exposure": "public",
        },
    )
    _clear_user_override()
    assert resp.status_code == 422


def test_operator_updates_exposure(_mock_audit):
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch("/hosts/pilot-host-01.internal", json={"exposure": "proxied"})
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["exposure"] == "proxied"
    assert _mock_audit[1]["payload"]["changes"]["exposure"] == {"from": "local", "to": "proxied"}


def test_update_host_rejects_invalid_exposure():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch("/hosts/pilot-host-01.internal", json={"exposure": "public"})
    _clear_user_override()
    assert resp.status_code == 422


# ---- clear_static_ssh_key (PATCH /hosts/{hostname}) — xem app/jobs.py:
# trigger_static_ssh_key_bootstrap để biết cách field này được SET (chỉ
# PATCH này mới XOÁ được, không có đường ghi giá trị mới qua đây). ----


def _set_static_ssh_key(hostname="pilot-host-01.internal"):
    db = _TestSessionLocal()
    host = db.get(hosts_module.Host, hostname)
    host.static_ssh_private_key_encrypted = "fernet-ciphertext-placeholder"
    db.commit()
    db.close()


def test_operator_clears_static_ssh_key(_mock_audit):
    _register_sample_host()
    _set_static_ssh_key()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch("/hosts/pilot-host-01.internal", json={"clear_static_ssh_key": True})
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["has_static_ssh_key"] is False
    assert _mock_audit[-1]["payload"]["changes"]["static_ssh_private_key"] == "cleared"


def test_clear_static_ssh_key_is_noop_when_not_set():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch("/hosts/pilot-host-01.internal", json={"clear_static_ssh_key": True})
    _clear_user_override()
    # Không có gì để xoá -> "changes" rỗng -> update_host trả nguyên host,
    # không lỗi, không ghi audit event (xem "if not changes: return host").
    assert resp.status_code == 200
    assert resp.json()["has_static_ssh_key"] is False


# ---- GET /hosts/risk-overview ----


def _insert_scan_job(hostname, findings, job_type="scan", finished_at=None):
    db = _TestSessionLocal()
    db.add(Job(
        hostname=hostname, job_type=job_type, status="succeeded",
        triggered_by="opuser", started_at=datetime.now(timezone.utc),
        finished_at=finished_at or datetime.now(timezone.utc),
        result_summary={"findings": findings},
    ))
    db.commit()
    db.close()


def test_risk_overview_never_scanned_low_tier_host_is_medium_with_null_score():
    _register_sample_host(tier=2)
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/hosts/risk-overview")
    _clear_user_override()
    assert resp.status_code == 200
    [item] = resp.json()
    assert item["hostname"] == "pilot-host-01.internal"
    assert item["compliance_score"] is None
    assert item["latest_scan_job_id"] is None
    assert item["attention_level"] == "medium"


def test_risk_overview_high_tier_not_started_ca_stays_high_even_with_perfect_scan():
    # Đăng ký luôn để ca_migration_status="not_started" (mặc định lúc tạo host)
    # -> luật 1 (app/risk.py) phải thắng, bất kể điểm quét sau đó ra sao.
    _register_sample_host(tier=0)
    _insert_scan_job(
        "pilot-host-01.internal",
        [{"rule_id": "r1", "title": "t", "result": "pass", "severity": "high"}],
    )
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/hosts/risk-overview")
    _clear_user_override()
    [item] = resp.json()
    assert item["compliance_score"] == 100.0
    assert item["attention_level"] == "high"


def test_risk_overview_excludes_decommissioned_host():
    _register_sample_host()
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.patch("/hosts/pilot-host-01.internal/decommission", json={"decommissioned": True})
    _clear_user_override()
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/hosts/risk-overview")
    _clear_user_override()
    assert resp.json() == []


def test_risk_overview_uses_latest_scan_not_an_older_one():
    _register_sample_host(tier=2)
    _insert_scan_job(
        "pilot-host-01.internal",
        [{"rule_id": "r1", "title": "t", "result": "fail", "severity": "high"}],
        finished_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    _insert_scan_job(
        "pilot-host-01.internal",
        [{"rule_id": "r1", "title": "t", "result": "pass", "severity": "high"}],
        finished_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/hosts/risk-overview")
    _clear_user_override()
    [item] = resp.json()
    assert item["compliance_score"] == 100.0  # bản quét sau (pass), không phải bản cũ (fail)


def test_risk_overview_sorted_high_before_medium_before_low():
    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    client.post("/hosts", json={
        "hostname": "z-low-risk.internal", "ip_address": "10.0.0.30",
        "os_family": "Debian", "tier": 2,
    })
    client.post("/hosts", json={
        "hostname": "a-high-risk.internal", "ip_address": "10.0.0.31",
        "os_family": "Debian", "tier": 0,
    })
    _clear_user_override()
    _insert_scan_job(
        "z-low-risk.internal",
        [{"rule_id": "r1", "title": "t", "result": "pass", "severity": "high"}],
    )
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/hosts/risk-overview")
    _clear_user_override()
    hostnames = [item["hostname"] for item in resp.json()]
    # "a-high-risk" đứng trước "z-low-risk" theo mức ưu tiên dù thua thứ tự
    # alphabet — xác nhận sort theo attention_level, không phải theo hostname.
    assert hostnames.index("a-high-risk.internal") < hostnames.index("z-low-risk.internal")


def test_risk_overview_readable_by_every_authenticated_role():
    _register_sample_host()
    for role in ("viewer", "auditor", "rule-editor", "approver", "operator", "admin"):
        app.dependency_overrides[get_current_user] = _as(f"user-{role}", role)
        resp = client.get("/hosts/risk-overview")
        _clear_user_override()
        assert resp.status_code == 200, f"role {role} bị chặn ngoài ý muốn"
