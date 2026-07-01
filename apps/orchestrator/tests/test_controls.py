"""Integration test cho Control Registry API — dùng SQLite in-memory (không
cần Postgres thật) + override get_current_user để giả lập từng vai trò,
verify đúng RBAC (kể cả ràng buộc four-eyes) chạy qua HTTP thật (TestClient),
không chỉ test hàm Python trần."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import controls as controls_module
from app.auth import CurrentUser, get_current_user
from app.db import Base
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
            Base.metadata.tables["controls"],
            Base.metadata.tables["standard_mappings"],
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


app.dependency_overrides[controls_module._get_db] = _override_db
client = TestClient(app)


def _clear_user_override():
    app.dependency_overrides.pop(get_current_user, None)


def test_viewer_cannot_create_control():
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.post("/controls", json={"title": "Disable root SSH login", "category": "ssh"})
    _clear_user_override()
    assert resp.status_code == 403


def test_rule_editor_can_create_and_viewer_can_read():
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    resp = client.post("/controls", json={"title": "Disable root SSH login", "category": "ssh"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["id"] == "disable-root-ssh-login"
    assert body["maturity"] == "draft"
    assert body["created_by"] == "bob"

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/controls")
    _clear_user_override()
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_four_eyes_blocks_self_approval():
    app.dependency_overrides[get_current_user] = _as("carol", "rule-editor")
    created = client.post("/controls", json={"title": "Enforce password complexity", "category": "auth"})
    control_id = created.json()["id"]

    # Chính người tạo (carol) có role approver luôn -> vẫn phải bị chặn tự duyệt.
    app.dependency_overrides[get_current_user] = _as("carol", "rule-editor", "approver")
    resp = client.patch(f"/controls/{control_id}/maturity", json={"maturity": "reviewed"})
    assert resp.status_code == 403
    assert "four-eyes" in resp.json()["detail"]

    # Người khác (dave) có role approver -> được phép.
    app.dependency_overrides[get_current_user] = _as("dave", "approver")
    resp = client.patch(f"/controls/{control_id}/maturity", json={"maturity": "reviewed"})
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["maturity"] == "reviewed"


def test_duplicate_titles_get_distinct_ids():
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    r1 = client.post("/controls", json={"title": "Same Title", "category": "x"})
    r2 = client.post("/controls", json={"title": "Same Title", "category": "x"})
    _clear_user_override()
    assert r1.json()["id"] == "same-title"
    assert r2.json()["id"] == "same-title-2"


def test_add_standard_mapping_and_remediation_variant():
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    control_id = client.post(
        "/controls", json={"title": "Set SSH Protocol 2", "category": "ssh"}
    ).json()["id"]

    resp = client.post(
        f"/controls/{control_id}/standard-mappings",
        json={
            "standard": "CIS",
            "standard_version": "CIS Ubuntu 22.04 v2.0.0",
            "section_id": "5.2.1",
        },
    )
    assert resp.status_code == 201

    resp = client.post(
        f"/controls/{control_id}/remediation-variants",
        json={
            "os_family": "Debian",
            "os_version": "22.04",
            "check_method": "openscap",
            "remediation_ref": "sha256:deadbeef...signed-role-v1",
        },
    )
    assert resp.status_code == 201

    app.dependency_overrides[get_current_user] = _as("alice", "auditor")
    detail = client.get(f"/controls/{control_id}").json()
    _clear_user_override()
    assert len(detail["standard_mappings"]) == 1
    assert len(detail["remediation_variants"]) == 1
