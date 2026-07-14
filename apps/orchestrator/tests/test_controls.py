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
            Base.metadata.tables["control_versions"],
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


# write_audit_event dùng Postgres thật (audit role) — không có trong test
# SQLite in-memory, mock để test không phụ thuộc Postgres (giống test_jobs.py).
@pytest.fixture(autouse=True)
def _mock_audit(monkeypatch):
    calls = []
    monkeypatch.setattr(controls_module, "write_audit_event", lambda **kwargs: calls.append(kwargs))
    return calls


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


def test_four_eyes_blocks_self_approval(_mock_audit):
    app.dependency_overrides[get_current_user] = _as("carol", "rule-editor")
    created = client.post("/controls", json={"title": "Enforce password complexity", "category": "auth"})
    control_id = created.json()["id"]
    assert len(_mock_audit) == 1  # create_control tự ghi audit

    # Chính người tạo (carol) có role approver luôn -> vẫn phải bị chặn tự duyệt.
    app.dependency_overrides[get_current_user] = _as("carol", "rule-editor", "approver")
    resp = client.patch(f"/controls/{control_id}/maturity", json={"maturity": "reviewed"})
    assert resp.status_code == 403
    assert "four-eyes" in resp.json()["detail"]
    assert len(_mock_audit) == 1  # lần bị chặn không ghi thêm audit event

    # Người khác (dave) có role approver -> được phép.
    app.dependency_overrides[get_current_user] = _as("dave", "approver")
    resp = client.patch(f"/controls/{control_id}/maturity", json={"maturity": "reviewed"})
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["maturity"] == "reviewed"
    assert len(_mock_audit) == 2
    assert _mock_audit[1]["action"] == "control_maturity_updated"
    assert _mock_audit[1]["payload"] == {"from": "draft", "to": "reviewed"}


def test_create_control_writes_audit_event(_mock_audit):
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    resp = client.post("/controls", json={"title": "Log all sudo usage", "category": "logging"})
    _clear_user_override()
    control_id = resp.json()["id"]
    assert len(_mock_audit) == 1
    assert _mock_audit[0]["action"] == "control_created"
    assert _mock_audit[0]["resource"] == control_id
    assert _mock_audit[0]["payload"] == {"title": "Log all sudo usage", "category": "logging"}


def test_non_approver_cannot_update_maturity():
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    control_id = client.post("/controls", json={"title": "X1", "category": "c"}).json()["id"]

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.patch(f"/controls/{control_id}/maturity", json={"maturity": "reviewed"})
    _clear_user_override()
    assert resp.status_code == 403

    app.dependency_overrides[get_current_user] = _as("eve", "rule-editor")
    resp = client.patch(f"/controls/{control_id}/maturity", json={"maturity": "reviewed"})
    _clear_user_override()
    assert resp.status_code == 403


def test_invalid_maturity_value_rejected():
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    control_id = client.post("/controls", json={"title": "X2", "category": "c"}).json()["id"]

    app.dependency_overrides[get_current_user] = _as("dave", "approver")
    resp = client.patch(f"/controls/{control_id}/maturity", json={"maturity": "not-a-real-level"})
    _clear_user_override()
    assert resp.status_code == 422


def test_get_unknown_control_404():
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/controls/does-not-exist")
    _clear_user_override()
    assert resp.status_code == 404


def test_add_mapping_and_variant_reject_viewer_and_unknown_control():
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    control_id = client.post("/controls", json={"title": "X3", "category": "c"}).json()["id"]

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.post(
        f"/controls/{control_id}/standard-mappings",
        json={"standard": "CIS", "standard_version": "1", "section_id": "1.1"},
    )
    assert resp.status_code == 403
    resp = client.post(
        f"/controls/{control_id}/remediation-variants",
        json={"os_family": "Debian", "check_method": "openscap", "remediation_ref": "ref1"},
    )
    assert resp.status_code == 403
    _clear_user_override()

    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    resp = client.post(
        "/controls/does-not-exist/standard-mappings",
        json={"standard": "CIS", "standard_version": "1", "section_id": "1.1"},
    )
    assert resp.status_code == 404
    resp = client.post(
        "/controls/does-not-exist/remediation-variants",
        json={"os_family": "Debian", "check_method": "openscap", "remediation_ref": "ref1"},
    )
    _clear_user_override()
    assert resp.status_code == 404


def test_add_mapping_and_variant_write_audit_events(_mock_audit):
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    control_id = client.post("/controls", json={"title": "X4", "category": "c"}).json()["id"]
    client.post(
        f"/controls/{control_id}/standard-mappings",
        json={"standard": "CIS", "standard_version": "1", "section_id": "1.1"},
    )
    client.post(
        f"/controls/{control_id}/remediation-variants",
        json={"os_family": "Debian", "check_method": "openscap", "remediation_ref": "ref1"},
    )
    _clear_user_override()
    actions = [c["action"] for c in _mock_audit]
    assert actions == ["control_created", "standard_mapping_added", "remediation_variant_added"]


def test_adding_content_to_production_control_demotes_to_draft(_mock_audit):
    # Bug thật tìm được qua workflow review (không phải test thật ban đầu):
    # rule-editor tạo control -> approver (người khác) duyệt production ->
    # CHÍNH rule-editor đó tự ý thêm remediation_ref mới mà maturity vẫn
    # "production" như thể nội dung đã được review -> bypass four-eyes.
    app.dependency_overrides[get_current_user] = _as("carol", "rule-editor")
    control_id = client.post("/controls", json={"title": "X5", "category": "c"}).json()["id"]

    app.dependency_overrides[get_current_user] = _as("dave", "approver")
    client.patch(f"/controls/{control_id}/maturity", json={"maturity": "reviewed"})
    resp = client.patch(f"/controls/{control_id}/maturity", json={"maturity": "production"})
    assert resp.json()["maturity"] == "production"

    app.dependency_overrides[get_current_user] = _as("carol", "rule-editor")
    resp = client.post(
        f"/controls/{control_id}/remediation-variants",
        json={"os_family": "Debian", "check_method": "openscap", "remediation_ref": "carol-controlled-ref"},
    )
    assert resp.status_code == 201

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    detail = client.get(f"/controls/{control_id}").json()
    _clear_user_override()
    assert detail["maturity"] == "draft"

    demotion_events = [c for c in _mock_audit if c["payload"].get("reason") == "content_changed_after_production"]
    assert len(demotion_events) == 1
    assert demotion_events[0]["payload"] == {"from": "production", "to": "draft", "reason": "content_changed_after_production"}


def test_adding_content_to_non_production_control_does_not_change_maturity(_mock_audit):
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    control_id = client.post("/controls", json={"title": "X6", "category": "c"}).json()["id"]
    resp = client.post(
        f"/controls/{control_id}/standard-mappings",
        json={"standard": "CIS", "standard_version": "1", "section_id": "1.1"},
    )
    _clear_user_override()
    assert resp.status_code == 201
    assert not any(c["payload"].get("reason") == "content_changed_after_production" for c in _mock_audit)


def test_oversized_standard_field_rejected_with_422_not_500():
    # Bug thật tìm được qua workflow review: trước đây các field text này
    # không có max_length, nên chuỗi quá dài qua được Pydantic rồi mới vỡ ở
    # tầng INSERT Postgres thật (String(32)) thành 500 không kiểm soát được
    # — SQLite (dùng trong test) không tự enforce VARCHAR(N) nên bug này
    # không lộ ra qua test cũ. Test bằng đúng tầng Pydantic (không phụ thuộc
    # DB backend) để verify max_length đã được thêm.
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    control_id = client.post("/controls", json={"title": "X", "category": "c"}).json()["id"]
    resp = client.post(
        f"/controls/{control_id}/standard-mappings",
        json={"standard": "X" * 40, "standard_version": "1", "section_id": "1.1"},
    )
    _clear_user_override()
    assert resp.status_code == 422


def test_duplicate_titles_get_distinct_ids():
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    r1 = client.post("/controls", json={"title": "Same Title", "category": "x"})
    r2 = client.post("/controls", json={"title": "Same Title", "category": "x"})
    _clear_user_override()
    assert r1.json()["id"] == "same-title"
    assert r2.json()["id"] == "same-title-2"


def test_duplicate_standard_mapping_rejected_with_409_not_500():
    # Bug thật tìm được qua test API trực tiếp (không phải chỉ đọc code):
    # add_standard_mapping trước đây insert thẳng, không bắt IntegrityError
    # khi vi phạm uq_standard_mapping (control_id, standard, standard_version,
    # section_id) -> lộ nguyên 500 Internal Server Error thay vì 409.
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    control_id = client.post("/controls", json={"title": "Y1", "category": "c"}).json()["id"]
    body = {"standard": "CIS", "standard_version": "1", "section_id": "1.1"}
    first = client.post(f"/controls/{control_id}/standard-mappings", json=body)
    second = client.post(f"/controls/{control_id}/standard-mappings", json=body)
    _clear_user_override()
    assert first.status_code == 201
    assert second.status_code == 409


def test_duplicate_remediation_variant_rejected_with_409_not_500():
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    control_id = client.post("/controls", json={"title": "Y2", "category": "c"}).json()["id"]
    body = {"os_family": "Ubuntu", "os_version": "22.04", "check_method": "oscap", "remediation_ref": "ref1"}
    first = client.post(f"/controls/{control_id}/remediation-variants", json=body)
    second = client.post(
        f"/controls/{control_id}/remediation-variants",
        json={**body, "remediation_ref": "ref2"},
    )
    _clear_user_override()
    assert first.status_code == 201
    assert second.status_code == 409


def test_get_history_unknown_control_404():
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/controls/does-not-exist/history")
    _clear_user_override()
    assert resp.status_code == 404


def test_control_history_records_full_lifecycle():
    app.dependency_overrides[get_current_user] = _as("carol", "rule-editor")
    control_id = client.post("/controls", json={"title": "Z1", "category": "c"}).json()["id"]
    client.post(
        f"/controls/{control_id}/standard-mappings",
        json={"standard": "CIS", "standard_version": "1", "section_id": "1.1"},
    )

    app.dependency_overrides[get_current_user] = _as("dave", "approver")
    client.patch(f"/controls/{control_id}/maturity", json={"maturity": "reviewed"})
    client.patch(f"/controls/{control_id}/maturity", json={"maturity": "production"})

    # carol tự đổi nội dung sau khi đã production -> tự động demote, cũng
    # phải xuất hiện trong lịch sử như 1 sự kiện maturity_changed riêng.
    app.dependency_overrides[get_current_user] = _as("carol", "rule-editor")
    client.post(
        f"/controls/{control_id}/remediation-variants",
        json={"os_family": "Debian", "check_method": "openscap", "remediation_ref": "ref1"},
    )

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get(f"/controls/{control_id}/history")
    _clear_user_override()
    assert resp.status_code == 200
    events = resp.json()
    assert [e["event_type"] for e in events] == [
        "created",
        "standard_mapping_added",
        "maturity_changed",
        "maturity_changed",
        "remediation_variant_added",
        "maturity_changed",
    ]
    assert events[0]["actor"] == "carol"
    assert events[0]["to_maturity"] == "draft"
    assert events[2]["from_maturity"] == "draft"
    assert events[2]["to_maturity"] == "reviewed"
    assert events[-1]["from_maturity"] == "production"
    assert events[-1]["to_maturity"] == "draft"
    assert events[-1]["detail"] == {"reason": "content_changed_after_production"}


def test_duplicate_standard_mapping_does_not_leave_orphan_history_row():
    # Bảo đảm history row và mapping insert cùng 1 transaction: nếu commit
    # thất bại vì trùng (uq_standard_mapping), row lịch sử của lần thất bại
    # đó KHÔNG được tồn tại (mới rollback đúng, không lệch với việc mapping
    # thật sự không được tạo).
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    control_id = client.post("/controls", json={"title": "Z2", "category": "c"}).json()["id"]
    body = {"standard": "CIS", "standard_version": "1", "section_id": "1.1"}
    client.post(f"/controls/{control_id}/standard-mappings", json=body)
    client.post(f"/controls/{control_id}/standard-mappings", json=body)
    resp = client.get(f"/controls/{control_id}/history")
    _clear_user_override()
    events = resp.json()
    assert [e["event_type"] for e in events] == ["created", "standard_mapping_added"]


# ---- PATCH /controls/{control_id}/risk-group (app/controls.py) ----


def test_risk_group_four_eyes_blocks_self_approval(_mock_audit):
    app.dependency_overrides[get_current_user] = _as("carol", "rule-editor", "approver")
    control_id = client.post(
        "/controls", json={"title": "Risk group self approve", "category": "auth"}
    ).json()["id"]

    # Chính carol (dù có role approver) tự gán risk_group cho control mình
    # tạo -> phải bị chặn (four-eyes), giống hệt update_control_maturity.
    # Dùng risk_group="B" (không phải "A") để cô lập đúng four-eyes, không
    # trộn với ràng buộc "risk_group A cần maturity production" (control ở
    # đây vẫn còn "draft").
    resp = client.patch(f"/controls/{control_id}/risk-group", json={"risk_group": "B"})
    assert resp.status_code == 403
    assert "four-eyes" in resp.json()["detail"]

    # Người khác (dave) -> được phép.
    app.dependency_overrides[get_current_user] = _as("dave", "approver")
    resp = client.patch(f"/controls/{control_id}/risk-group", json={"risk_group": "B"})
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["risk_group"] == "B"


def test_risk_group_requires_production_maturity():
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    control_id = client.post(
        "/controls", json={"title": "Risk group needs production", "category": "x"}
    ).json()["id"]
    _clear_user_override()

    app.dependency_overrides[get_current_user] = _as("dave", "approver")
    resp = client.patch(f"/controls/{control_id}/risk-group", json={"risk_group": "A"})
    _clear_user_override()
    assert resp.status_code == 422


def test_risk_group_rejects_invalid_value():
    app.dependency_overrides[get_current_user] = _as("bob", "rule-editor")
    control_id = client.post(
        "/controls", json={"title": "Invalid risk group", "category": "x"}
    ).json()["id"]
    _clear_user_override()

    app.dependency_overrides[get_current_user] = _as("dave", "approver")
    resp = client.patch(f"/controls/{control_id}/risk-group", json={"risk_group": "C"})
    _clear_user_override()
    assert resp.status_code == 422


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
