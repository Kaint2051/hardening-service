"""Integration test cho Control Templates API (app/control_templates.py) —
dùng 1 fixture YAML tối giản (KHÔNG phải file CIS thật 21000 dòng) mô phỏng
đúng cấu trúc ComplianceAsCode: 1 task "always" dùng chung + 2 rule, mỗi rule
nhiều task liền kề chia sẻ đúng 1 tag rule-id. Test file thật (298 rule CIS
Ubuntu 22.04) đã verify thủ công qua curl trên lab server trước khi viết test
này — xem lịch sử làm việc."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import control_templates as control_templates_module
from app import controls as controls_module
from app.auth import CurrentUser, get_current_user
from app.db import Base
from app.main import app

_engine = create_engine(
    "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
)
_TestSessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)

_FIXTURE_PLAYBOOK = """---
###############################################################################
# Ansible Playbook for FIXTURE Test Benchmark for Level 1 - Server
###############################################################################

- name: Ansible Playbook for xccdf_org.ssgproject.content_profile_test
  hosts: all
  vars:
    test_var: 'hello'
  tasks:
  - name: Gather the package facts
    ansible.builtin.package_facts:
      manager: auto
    tags:
    - always

  - name: Do Thing A - step 1 of 2
    ansible.builtin.debug:
      msg: step1
    tags:
    - NIST-800-53-CM-6(a)
    - low_complexity
    - low_disruption
    - medium_severity
    - rule_a

  - name: Do Thing A
    ansible.builtin.debug:
      msg: main
    tags:
    - NIST-800-53-CM-6(a)
    - low_complexity
    - low_disruption
    - medium_severity
    - rule_a

  - name: Do Thing B (risky, locks something)
    ansible.builtin.debug:
      msg: onlyb
    tags:
    - PCI-DSSv4-2.2
    - high_severity
    - rule_b
"""


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


app.dependency_overrides[control_templates_module._get_db] = _override_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def _mock_audit(monkeypatch):
    # create_control/add_standard_mapping (app/controls.py) tự ghi audit —
    # gọi TRỰC TIẾP như hàm Python thường (không qua Depends), nên mock trên
    # đúng namespace controls_module, không phải control_templates_module.
    calls = []
    monkeypatch.setattr(controls_module, "write_audit_event", lambda **kwargs: calls.append(kwargs))
    return calls


@pytest.fixture(autouse=True)
def _fixture_template_dir(tmp_path, monkeypatch):
    (tmp_path / "fixture-template.yml").write_text(_FIXTURE_PLAYBOOK, encoding="utf-8")
    monkeypatch.setattr(control_templates_module.settings, "control_templates_dir", str(tmp_path))
    control_templates_module._TEMPLATE_CACHE.clear()
    yield
    control_templates_module._TEMPLATE_CACHE.clear()


def _clear_user_override():
    app.dependency_overrides.pop(get_current_user, None)


def test_list_control_templates():
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/control-templates")
    _clear_user_override()
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["id"] == "fixture-template"
    assert body[0]["title"] == "FIXTURE Test Benchmark for Level 1 - Server"
    assert body[0]["rule_count"] == 2  # rule_a, rule_b (task "always" không tính là rule)


def test_list_template_rules_no_filter():
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/control-templates/fixture-template/rules")
    _clear_user_override()
    assert resp.status_code == 200
    body = resp.json()
    assert {r["rule_id"] for r in body} == {"rule_a", "rule_b"}
    rule_a = next(r for r in body if r["rule_id"] == "rule_a")
    assert rule_a["title"] == "Do Thing A"  # tên ngắn nhất trong nhóm, không có hậu tố " - ..."
    assert rule_a["task_count"] == 2
    assert rule_a["severity"] == "medium"
    assert rule_a["complexity"] == "low"
    assert rule_a["compliance_refs"] == ["NIST-800-53-CM-6(a)"]
    rule_b = next(r for r in body if r["rule_id"] == "rule_b")
    assert rule_b["severity"] == "high"
    assert rule_b["compliance_refs"] == ["PCI-DSSv4-2.2"]


def test_list_template_rules_filter_matches_title_or_id():
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/control-templates/fixture-template/rules?q=risky")
    _clear_user_override()
    assert resp.status_code == 200
    body = resp.json()
    assert [r["rule_id"] for r in body] == ["rule_b"]


def test_list_template_rules_unknown_template_404():
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/control-templates/does-not-exist/rules")
    _clear_user_override()
    assert resp.status_code == 404


def test_preview_requires_editor_role():
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.post("/control-templates/fixture-template/preview", json={"rule_ids": ["rule_a"]})
    _clear_user_override()
    assert resp.status_code == 403


def test_preview_assembles_prereq_and_selected_rule_only():
    app.dependency_overrides[get_current_user] = _as("ruleuser", "rule-editor")
    resp = client.post("/control-templates/fixture-template/preview", json={"rule_ids": ["rule_a"]})
    _clear_user_override()
    assert resp.status_code == 200
    playbook = resp.json()["playbook_yaml"]
    assert "Gather the package facts" in playbook  # prereq luôn có mặt
    assert "Do Thing A" in playbook
    assert "Do Thing B" not in playbook  # KHÔNG chọn rule_b thì không xuất hiện
    assert "test_var" in playbook  # vars: block giữ nguyên


def test_preview_unknown_rule_id_422():
    app.dependency_overrides[get_current_user] = _as("ruleuser", "rule-editor")
    resp = client.post("/control-templates/fixture-template/preview", json={"rule_ids": ["no-such-rule"]})
    _clear_user_override()
    assert resp.status_code == 422


def test_create_control_from_template_creates_control_and_standard_mappings(_mock_audit):
    app.dependency_overrides[get_current_user] = _as("ruleuser", "rule-editor")
    resp = client.post(
        "/control-templates/fixture-template/create-control",
        json={
            "title": "Test control from template",
            "category": "test",
            "rule_ids": ["rule_a", "rule_b"],
            "playbook_yaml": "---\n# gia su operator da sua tay o day\n",
        },
    )
    _clear_user_override()
    assert resp.status_code == 201
    body = resp.json()
    assert body["standard_mappings_added"] == 2  # 1 tu rule_a (NIST) + 1 tu rule_b (PCI-DSS)
    assert body["playbook_yaml"] == "---\n# gia su operator da sua tay o day\n"  # dùng ĐÚNG bản gửi lên, không re-assemble

    db = _TestSessionLocal()
    from app.models import Control, StandardMapping

    control = db.get(Control, body["control_id"])
    assert control is not None
    assert control.maturity == "draft"
    assert control.risk_group == "B"
    mappings = db.query(StandardMapping).filter(StandardMapping.control_id == body["control_id"]).all()
    db.close()
    standards = {m.standard for m in mappings}
    # _split_compliance_ref cắt tại dấu "-" CUỐI CÙNG (đã verify thật —
    # "NIST-800-53-CM-6(a)" -> standard="NIST-800-53-CM", section_id="6(a)",
    # không phải "NIST-800-53"/"CM-6(a)" như có thể đoán nhầm trực giác).
    assert "NIST-800-53-CM" in standards
    assert "PCI-DSSv4" in standards

    created = [c for c in _mock_audit if c["action"] == "control_created"]
    assert len(created) == 1


def test_create_control_from_template_unknown_rule_id_422():
    app.dependency_overrides[get_current_user] = _as("ruleuser", "rule-editor")
    resp = client.post(
        "/control-templates/fixture-template/create-control",
        json={
            "title": "Should not be created",
            "category": "test",
            "rule_ids": ["no-such-rule"],
            "playbook_yaml": "---\n",
        },
    )
    _clear_user_override()
    assert resp.status_code == 422

    db = _TestSessionLocal()
    from app.models import Control

    count = db.query(Control).count()
    db.close()
    assert count == 0
