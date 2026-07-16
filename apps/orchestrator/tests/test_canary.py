"""Integration test cho Canary Rollout (app/canary.py) + risk_group additions
(app/controls.py, dùng chung control production+Nhóm A làm điều kiện chạy
canary — xem app/canary.py POST .../canary-rollout).

SQLite in-memory RIÊNG cho file này (không share engine với test_jobs.py/
test_controls.py), theo đúng quy ước "mỗi file test tự override đúng router
mình cần" đã thấy ở test_jobs.py (comment cạnh `app.dependency_overrides[...]`
dưới đây). File này cần CẢ 2 override: canary_module._get_db (routes
POST canary-rollout/GET/PATCH cancel) VÀ controls_module._get_db (dựng control
qua đúng API thật /controls/.../maturity, .../risk-group, .../remediation-
variants — cần cho các test risk_group ở mục 2/3, để đi đúng luồng
_demote_if_production thay vì insert thẳng DB).

GOTCHA quan trọng #1 (đã đọc kỹ app/canary.py để xác nhận, không đoán):
`_run_rollout` chạy trong FastAPI BackgroundTasks, KHÔNG qua Depends — nó tự
mở session bằng `SessionLocal()` (tên global import thẳng trong app/canary.py,
lấy từ app.db.SessionLocal — engine Postgres thật theo settings). Override
`app.dependency_overrides[canary_module._get_db]` chỉ đổi được session
request-scoped của 3 route handler, KHÔNG chạm được lời gọi `SessionLocal()`
trực tiếp này. Nếu không tự trỏ `canary_module.SessionLocal` về engine SQLite
test, `_run_rollout` sẽ cố kết nối Postgres thật.

GOTCHA #2 (phát hiện qua CHẠY THẬT bộ test này, không phải chỉ đọc code —
ban đầu giả định sai): response body của POST .../canary-rollout được FastAPI
serialize từ đối tượng `rollout` NGAY LÚC route trả về (status vẫn "running"
tại thời điểm đó) — BackgroundTasks chỉ chạy SAU khi nội dung response đã bị
chốt, nên `resp.json()["status"]` của chính request POST đó KHÔNG BAO GIỜ
phản ánh kết quả cuối cùng, dù TestClient có đợi BackgroundTasks chạy xong
đồng bộ hay không trước khi trả quyền điều khiển lại cho test. Vì vậy bộ test
này VÔ HIỆU HOÁ hẳn nhánh `background_tasks.add_task(_run_rollout, ...)` thật
(monkeypatch `canary_module._run_rollout` thành no-op trong `_mock_infra`) và
mỗi test tự gọi `_real_run_rollout(...)` (tham chiếu hàm THẬT, giữ lại TRƯỚC
khi patch — xem module-level ngay dưới import) như 1 lời gọi hàm Python đồng
bộ bình thường để quan sát kết quả — loại bỏ hoàn toàn phụ thuộc vào có phải
polling GET hay đoán đúng thời điểm BackgroundTasks thật sự thực thi hay
không (tránh cả nguy cơ chạy 2 lần chồng nhau nếu bản thật cũng vô tình chạy).

GOTCHA #2b (cũng phát hiện qua chạy thật — lúc đầu bị 4 test tưởng nhầm là
do GOTCHA #2, hoá ra là 1 bug thật RIÊNG, đã sửa trong app/models.py):
`CanaryRollout.cancel_requested` khai báo `server_default="false"` (chuỗi
Python trần) compile thành literal CHUỖI `DEFAULT 'false'` trong DDL —
Postgres tự cast chuỗi 'false' này sang boolean khi đọc (production không bị
ảnh hưởng), nhưng SQLite (Base.metadata.create_all() dùng trong test) lưu
nguyên chuỗi "false" rồi trả về y hệt, và SQLAlchemy Boolean type coi chuỗi
non-empty đó là truthy — khiến MỌI CanaryRollout mới tạo qua route thật
(start_canary_rollout không set cancel_requested tường minh, luôn dựa vào
server_default) có `cancel_requested=True` NGAY TỪ ĐẦU khi test qua SQLite,
tự abort "cancelled" trước khi chạm tới host nào. Đã sửa app/models.py +
migrations/0009 dùng `sa.false()` (construct SQL, compile đúng theo dialect:
0 cho SQLite, false cho Postgres) thay vì chuỗi "false".

GOTCHA #3 (cũng phát hiện qua chạy thật, không phải đọc code): file này CẦN
override `controls_module._get_db` (dựng control qua đúng API thật để test
đúng luồng `_demote_if_production`) — NHƯNG test_controls.py CŨNG override
đúng key này ở module scope trong file của nó. Nếu file này cũng set permanent
ở module scope, file nào được pytest COLLECT sau sẽ đè vĩnh viễn lên file kia
cho suốt phiên chạy (lỗi thật gặp phải: "no such table: controls" — 2 engine
SQLite khác nhau lẫn vào nhau). Fixture `_controls_db_override` bên dưới set/
khôi phục lại NGAY TRƯỚC/SAU MỖI test (thay vì 1 lần ở module scope) để 2 file
độc lập nhau bất kể thứ tự collect.

`run_remediate_dry_run`/`run_remediate_apply` (app/jobs.py, canary.py gọi lại
verbatim) tự tham chiếu global riêng của MODULE app/jobs.py cho
mint_ssh_certificate/write_audit_event/httpx.post — phải monkeypatch đúng
`jobs_module.mint_ssh_certificate`/`jobs_module.write_audit_event` (không phải
gắn lên canary_module), còn `httpx.post` monkeypatch thẳng trên module `httpx`
dùng chung (jobs.py gọi `httpx.post(...)`, không phải `from httpx import
post`). Audit event do CHÍNH app/canary.py tự ghi (canary_rollout_started/
_aborted/_completed) lại dùng `canary_module.write_audit_event` (import riêng
trong canary.py) — phải mock CẢ HAI tên.
"""
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import canary as canary_module
from app import controls as controls_module
from app import jobs as jobs_module
from app.auth import CurrentUser, get_current_user
from app.db import Base
from app.main import app
from app.models import CanaryRollout, Control, Host, Job, RemediationVariant

# Giữ tham chiếu hàm THẬT trước khi bất kỳ test nào monkeypatch
# canary_module._run_rollout thành no-op (xem GOTCHA #2 ở docstring đầu file)
# — dùng để tự gọi trực tiếp, đồng bộ, khi 1 test cần quan sát kết quả rollout.
_real_run_rollout = canary_module._run_rollout

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
            Base.metadata.tables["controls"],
            Base.metadata.tables["control_versions"],
            # standard_mappings: GET /controls/{id} (app/controls.py get_control)
            # dùng joinedload(Control.standard_mappings) — bảng phải tồn tại
            # (dù rỗng) hay query vỡ "no such table" (phát hiện qua chạy test
            # thật ở test_risk_group_resets_to_b_when_demoted_via_content_edit).
            Base.metadata.tables["standard_mappings"],
            Base.metadata.tables["remediation_variants"],
            Base.metadata.tables["jobs"],
            Base.metadata.tables["canary_rollouts"],
        ],
    )
    # ux_canary_rollouts_running (migration 0009) là 1 partial unique index
    # tạo bằng raw SQL (op.execute), KHÔNG phải Index() khai báo trên model
    # CanaryRollout -> Base.metadata.create_all() ở trên KHÔNG tự tạo nó. Test
    # "409 khi đã có rollout đang chạy" bên dưới cần đúng ràng buộc DB này để
    # IntegrityError thật sự xảy ra trong app/canary.py start_canary_rollout —
    # SQLite hỗ trợ cú pháp partial index giống Postgres (từ 3.8.0) nên tái
    # tạo y hệt migration ở đây.
    with _engine.begin() as conn:
        conn.execute(
            text(
                "CREATE UNIQUE INDEX ux_canary_rollouts_running "
                "ON canary_rollouts (control_id) WHERE status = 'running'"
            )
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


# canary_module._get_db là key DUY NHẤT file này set permanent ở module scope
# — an toàn vì không file test nào khác đụng tới router canary.py (khác hẳn
# controls_module._get_db bên dưới, xem GOTCHA #3 ở docstring đầu file).
app.dependency_overrides[canary_module._get_db] = _override_db
client = TestClient(app)


def _clear_user_override():
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture(autouse=True)
def _controls_db_override():
    # Xem GOTCHA #3 đầu file — set/khôi phục NGAY TRƯỚC/SAU MỖI test (thay vì
    # 1 lần ở module scope như canary_module._get_db ở trên) để không đè vĩnh
    # viễn lên override riêng của test_controls.py (hay ngược lại) bất kể thứ
    # tự pytest collect 2 file.
    previous = app.dependency_overrides.get(controls_module._get_db)
    app.dependency_overrides[controls_module._get_db] = _override_db
    yield
    if previous is None:
        app.dependency_overrides.pop(controls_module._get_db, None)
    else:
        app.dependency_overrides[controls_module._get_db] = previous


@pytest.fixture(autouse=True)
def _mock_infra(monkeypatch):
    # Xem docstring đầu file — _run_rollout mở session RIÊNG qua tên global
    # SessionLocal trong app/canary.py, dependency override phía trên không
    # chạm tới lời gọi này.
    monkeypatch.setattr(canary_module, "SessionLocal", _TestSessionLocal)

    # Vô hiệu hoá nhánh BackgroundTasks thật (GOTCHA #2) — mỗi test tự gọi
    # `_real_run_rollout(...)` trực tiếp khi cần quan sát kết quả rollout,
    # tránh 2 lần chạy chồng lên nhau/đua thời điểm với bản thật không xác
    # định được lúc nào hoàn tất.
    monkeypatch.setattr(canary_module, "_run_rollout", lambda *a, **kw: None)

    monkeypatch.setattr(
        jobs_module, "mint_ssh_certificate", lambda principal: ("FAKE-PRIVATE-KEY", "FAKE-CERT-PUB")
    )
    # _call_job_dispatcher (mTLS Giai đoạn 2, app/jobs.py) tự mint 1 cert
    # CLIENT mỗi lần gọi job-dispatcher — mock để test không cần step-ca
    # thật, cùng lý do mint_ssh_certificate ở trên.
    monkeypatch.setattr(
        jobs_module, "mint_agent_manager_server_cert",
        lambda subject="agent-manager": ("FAKE-CLIENT-CERT-PEM", "FAKE-CLIENT-KEY-PEM"),
    )

    calls = []
    monkeypatch.setattr(jobs_module, "write_audit_event", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr(canary_module, "write_audit_event", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr(controls_module, "write_audit_event", lambda **kwargs: calls.append(kwargs))
    return calls


def _mock_dispatcher(monkeypatch, exit_code_for=None):
    """exit_code_for: dict {(target_ip, dry_run_bool): exit_code}; cặp không
    có trong dict mặc định thành công (exit_code=0) — dùng để giả lập ĐÚNG 1
    host/1 bước (dry-run hoặc apply) lỗi mà không ảnh hưởng các host/bước
    khác, dựa theo TARGET_HOST/DRY_RUN thật sự truyền trong dispatch_body
    (app/jobs.py `_dispatch_remediate_job`)."""
    exit_code_for = exit_code_for or {}

    def _fake_post(*args, **kwargs):
        body = kwargs["json"]
        env = body["environment"]
        key = (env["TARGET_HOST"], env["DRY_RUN"] == "true")
        exit_code = exit_code_for.get(key, 0)

        class _FakeResponse:
            def raise_for_status(self):
                pass

            def json(self):
                return {"job_id": body["job_id"], "exit_code": exit_code, "logs": "SCAN_JOB_STATUS=completed\n"}

        return _FakeResponse()

    monkeypatch.setattr(httpx, "post", _fake_post)


def _register_host(
    hostname, ip_address, tier=2, os_family="Ubuntu", os_version="22.04", decommissioned=False,
):
    db = _TestSessionLocal()
    db.add(
        Host(
            hostname=hostname, ip_address=ip_address, os_family=os_family, os_version=os_version,
            tier=tier, added_by="opuser",
            decommissioned_at=datetime.now(timezone.utc) if decommissioned else None,
            decommissioned_by="opuser" if decommissioned else None,
        )
    )
    db.commit()
    db.close()


def _register_control(control_id="ctrl-a", maturity="production", risk_group="A", created_by="ruleuser"):
    db = _TestSessionLocal()
    db.add(
        Control(
            id=control_id, title="Canary control", category="ssh", maturity=maturity,
            risk_group=risk_group, created_by=created_by,
        )
    )
    db.commit()
    db.close()


def _register_remediation_variant(
    control_id="ctrl-a", os_family="Ubuntu", os_version="22.04", remediation_ref="bundle-1"
):
    db = _TestSessionLocal()
    db.add(
        RemediationVariant(
            control_id=control_id, os_family=os_family, os_version=os_version,
            check_method="ansible-check", remediation_ref=remediation_ref,
        )
    )
    db.commit()
    db.close()


def _insert_running_rollout(control_id="ctrl-a", triggered_by="opuser", eligible_host_count=0):
    db = _TestSessionLocal()
    rollout = CanaryRollout(
        control_id=control_id, status="running", triggered_by=triggered_by,
        eligible_host_count=eligible_host_count,
    )
    db.add(rollout)
    db.commit()
    db.refresh(rollout)
    rollout_id = rollout.id
    db.close()
    return rollout_id


def _start_rollout(control_id="ctrl-a", username="opuser"):
    app.dependency_overrides[get_current_user] = _as(username, "operator")
    resp = client.post(f"/controls/{control_id}/canary-rollout")
    _clear_user_override()
    return resp


# ---- (1) zero eligible hosts -> completes immediately, no background task ----


def test_decommissioned_host_excluded_from_eligible_hosts():
    _register_control("ctrl-a", maturity="production", risk_group="A")
    _register_remediation_variant("ctrl-a")
    # Khớp variant hoàn hảo + đúng Tier 2 NHƯNG đã decommission -> vẫn phải
    # bị loại (xem app/canary.py truy vấn eligible hosts).
    _register_host("decommissioned-host.internal", "10.0.9.2", tier=2, decommissioned=True)

    resp = _start_rollout("ctrl-a")
    assert resp.status_code == 200
    assert resp.json()["eligible_host_count"] == 0


def test_zero_eligible_hosts_all_tier_high_completes_immediately():
    _register_control("ctrl-a", maturity="production", risk_group="A")
    _register_remediation_variant("ctrl-a")
    # Khớp variant hoàn hảo NHƯNG Tier 1 ("Tier cao") -> vẫn phải bị loại,
    # eligible_host_count phải là 0.
    _register_host("prod-host.internal", "10.0.9.1", tier=1)

    resp = _start_rollout("ctrl-a")
    # KHÔNG 202 — không có background task nào cần chờ khi eligible=0 (xem
    # app/canary.py: response.status_code chỉ bị ép 202 ở nhánh eligible>0).
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert body["eligible_host_count"] == 0
    assert body["finished_at"] is not None
    assert body["aborted_hostname"] is None


def test_zero_eligible_hosts_no_matching_variant_completes_immediately():
    _register_control("ctrl-a", maturity="production", risk_group="A")
    _register_host("canary-host.internal", "10.0.9.2", tier=2, os_family="Ubuntu", os_version="22.04")
    # Variant chỉ có cho Debian 12 — không khớp distro/version của host Tier 2 duy nhất.
    _register_remediation_variant("ctrl-a", os_family="Debian", os_version="12")

    resp = _start_rollout("ctrl-a")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert body["eligible_host_count"] == 0


def test_rollout_requires_production_maturity_and_risk_group_a():
    _register_control("ctrl-a", maturity="production", risk_group="B")
    resp = _start_rollout("ctrl-a")
    assert resp.status_code == 422


def test_rollout_unknown_control_404():
    resp = _start_rollout("does-not-exist")
    assert resp.status_code == 404


# ---- (2)/(3) risk_group gating + reset trên đúng control dùng cho canary ----


def test_risk_group_patch_requires_production_maturity():
    app.dependency_overrides[get_current_user] = _as("carol", "rule-editor")
    control_id = client.post("/controls", json={"title": "Draft control", "category": "x"}).json()["id"]
    _clear_user_override()

    app.dependency_overrides[get_current_user] = _as("dave", "approver")
    resp = client.patch(f"/controls/{control_id}/risk-group", json={"risk_group": "A"})
    _clear_user_override()
    assert resp.status_code == 422


def test_risk_group_resets_to_b_when_maturity_demoted():
    app.dependency_overrides[get_current_user] = _as("carol", "rule-editor")
    control_id = client.post("/controls", json={"title": "Promote then demote", "category": "x"}).json()["id"]
    _clear_user_override()

    app.dependency_overrides[get_current_user] = _as("dave", "approver")
    client.patch(f"/controls/{control_id}/maturity", json={"maturity": "reviewed"})
    client.patch(f"/controls/{control_id}/maturity", json={"maturity": "production"})
    resp = client.patch(f"/controls/{control_id}/risk-group", json={"risk_group": "A"})
    assert resp.status_code == 200
    assert resp.json()["risk_group"] == "A"

    # Demote ra khỏi production (kể cả không phải xuống "draft") phải reset
    # risk_group="A" -> "B" theo (app/controls.py update_control_maturity).
    resp = client.patch(f"/controls/{control_id}/maturity", json={"maturity": "reviewed"})
    _clear_user_override()
    assert resp.status_code == 200
    assert resp.json()["risk_group"] == "B"


def test_risk_group_resets_to_b_when_demoted_via_content_edit():
    app.dependency_overrides[get_current_user] = _as("carol", "rule-editor")
    control_id = client.post("/controls", json={"title": "Content demote", "category": "x"}).json()["id"]
    _clear_user_override()

    app.dependency_overrides[get_current_user] = _as("dave", "approver")
    client.patch(f"/controls/{control_id}/maturity", json={"maturity": "reviewed"})
    client.patch(f"/controls/{control_id}/maturity", json={"maturity": "production"})
    client.patch(f"/controls/{control_id}/risk-group", json={"risk_group": "A"})
    _clear_user_override()

    # carol (người tạo, chỉ cần role rule-editor — route này không có
    # four-eyes) tự thêm remediation-variant mới cho control đã production ->
    # _demote_if_production phải kích hoạt, đưa cả maturity VÀ risk_group về
    # trạng thái mặc định trong CÙNG 1 sự kiện lịch sử.
    app.dependency_overrides[get_current_user] = _as("carol", "rule-editor")
    resp = client.post(
        f"/controls/{control_id}/remediation-variants",
        json={"os_family": "Debian", "check_method": "openscap", "remediation_ref": "carol-ref"},
    )
    _clear_user_override()
    assert resp.status_code == 201

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    detail = client.get(f"/controls/{control_id}").json()
    _clear_user_override()
    assert detail["maturity"] == "draft"
    assert detail["risk_group"] == "B"


# ---- (4) full successful rollout across 2 eligible Tier-2 hosts ----


def test_full_successful_rollout_across_two_hosts(monkeypatch, _mock_infra):
    _mock_dispatcher(monkeypatch)
    _register_control("ctrl-a", maturity="production", risk_group="A")
    _register_remediation_variant("ctrl-a")
    _register_host("canary-a.internal", "10.0.10.1", tier=2)
    _register_host("canary-b.internal", "10.0.10.2", tier=2)

    resp = _start_rollout("ctrl-a")
    assert resp.status_code == 202
    body = resp.json()
    rollout_id = body["id"]
    assert body["eligible_host_count"] == 2
    # Response body của chính request POST này chốt nội dung TRƯỚC khi
    # BackgroundTasks chạy (xem GOTCHA #2 đầu file) -> luôn là "running" ở
    # đây, bất kể rollout có xử lý xong hay không.
    assert body["status"] == "running"

    # BackgroundTasks thật đã bị vô hiệu hoá (no-op) — tự gọi hàm thực thi
    # nền THẬT trực tiếp, đồng bộ, để có kết quả xác định.
    _real_run_rollout(rollout_id, ["canary-a.internal", "canary-b.internal"], "ctrl-a", "opuser")

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    detail = client.get(f"/canary-rollouts/{rollout_id}").json()
    _clear_user_override()
    assert detail["status"] == "completed"
    hosts_by_name = {h["hostname"]: h for h in detail["hosts"]}
    assert set(hosts_by_name) == {"canary-a.internal", "canary-b.internal"}
    for outcome in hosts_by_name.values():
        assert outcome["status"] == "succeeded"
        assert outcome["dry_run_job_id"] is not None
        assert outcome["apply_job_id"] is not None

    assert "canary_rollout_completed" in {c["action"] for c in _mock_infra}


# ---- (5) 1 host lỗi (dry-run HOẶC apply) -> abort ngay, không đụng host sau ----


def test_rollout_aborts_on_dry_run_failure_and_skips_remaining_hosts(monkeypatch):
    _register_control("ctrl-a", maturity="production", risk_group="A")
    _register_remediation_variant("ctrl-a")
    # Thứ tự xử lý theo Host.hostname.asc() — "host-b" (lỗi) đứng GIỮA
    # "host-a" (xử lý trước, thành công) và "host-c" (KHÔNG BAO GIỜ được chạm
    # tới sau khi host-b làm rollout abort).
    _register_host("host-a.internal", "10.0.11.1", tier=2)
    _register_host("host-b.internal", "10.0.11.2", tier=2)
    _register_host("host-c.internal", "10.0.11.3", tier=2)
    _mock_dispatcher(monkeypatch, exit_code_for={("10.0.11.2", True): 1})  # host-b dry-run lỗi

    resp = _start_rollout("ctrl-a")
    assert resp.status_code == 202
    body = resp.json()
    rollout_id = body["id"]
    assert body["eligible_host_count"] == 3

    _real_run_rollout(
        rollout_id, ["host-a.internal", "host-b.internal", "host-c.internal"], "ctrl-a", "opuser"
    )

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    detail = client.get(f"/canary-rollouts/{rollout_id}").json()
    _clear_user_override()
    assert detail["status"] == "aborted"
    assert detail["aborted_hostname"] == "host-b.internal"
    assert detail["abort_reason"] == "dry_run_failed"

    db = _TestSessionLocal()
    host_c_job_count = db.query(Job).filter(Job.hostname == "host-c.internal").count()
    host_a_succeeded_count = (
        db.query(Job).filter(Job.hostname == "host-a.internal", Job.status == "succeeded").count()
    )
    host_b_jobs = db.query(Job).filter(Job.hostname == "host-b.internal").all()
    db.close()
    assert host_c_job_count == 0  # host-c KHÔNG BAO GIỜ được dry-run/apply
    assert host_a_succeeded_count == 2  # host đứng trước: dry-run + apply đều thành công
    assert len(host_b_jobs) == 1  # chỉ có dry-run (lỗi) — KHÔNG có apply job kế tiếp
    assert host_b_jobs[0].job_type == "remediate-dry-run"
    assert host_b_jobs[0].status == "failed"


def test_rollout_aborts_on_apply_failure_and_skips_remaining_hosts(monkeypatch):
    _register_control("ctrl-a", maturity="production", risk_group="A")
    _register_remediation_variant("ctrl-a")
    _register_host("host-a.internal", "10.0.12.1", tier=2)
    _register_host("host-b.internal", "10.0.12.2", tier=2)
    # host-a dry-run OK nhưng APPLY lỗi (DRY_RUN=false).
    _mock_dispatcher(monkeypatch, exit_code_for={("10.0.12.1", False): 1})

    resp = _start_rollout("ctrl-a")
    body = resp.json()
    assert resp.status_code == 202
    rollout_id = body["id"]

    _real_run_rollout(rollout_id, ["host-a.internal", "host-b.internal"], "ctrl-a", "opuser")

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    detail = client.get(f"/canary-rollouts/{rollout_id}").json()
    _clear_user_override()
    assert detail["status"] == "aborted"
    assert detail["aborted_hostname"] == "host-a.internal"
    assert detail["abort_reason"] == "apply_failed"

    db = _TestSessionLocal()
    host_b_job_count = db.query(Job).filter(Job.hostname == "host-b.internal").count()
    host_a_jobs = {j.job_type: j.status for j in db.query(Job).filter(Job.hostname == "host-a.internal")}
    db.close()
    assert host_b_job_count == 0
    assert host_a_jobs == {"remediate-dry-run": "succeeded", "remediate-apply": "failed"}


# ---- (6) host Tier 0/1 KHÔNG BAO GIỜ eligible dù khớp RemediationVariant ----


def test_tier_high_host_never_eligible_even_with_matching_variant(monkeypatch):
    _mock_dispatcher(monkeypatch)
    _register_control("ctrl-a", maturity="production", risk_group="A")
    _register_remediation_variant("ctrl-a")
    _register_host("tier0-host.internal", "10.0.13.1", tier=0)  # khớp variant NHƯNG Tier 0
    _register_host("tier1-host.internal", "10.0.13.2", tier=1)  # khớp variant NHƯNG Tier 1
    _register_host("tier2-host.internal", "10.0.13.3", tier=2)  # duy nhất đủ điều kiện

    resp = _start_rollout("ctrl-a")
    body = resp.json()
    assert body["eligible_host_count"] == 1
    rollout_id = body["id"]

    _real_run_rollout(rollout_id, ["tier2-host.internal"], "ctrl-a", "opuser")

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    detail = client.get(f"/canary-rollouts/{rollout_id}").json()
    _clear_user_override()
    assert [h["hostname"] for h in detail["hosts"]] == ["tier2-host.internal"]

    db = _TestSessionLocal()
    tier0_job_count = db.query(Job).filter(Job.hostname == "tier0-host.internal").count()
    tier1_job_count = db.query(Job).filter(Job.hostname == "tier1-host.internal").count()
    db.close()
    assert tier0_job_count == 0
    assert tier1_job_count == 0


# ---- (5b) job vẫn mang đúng canary_rollout_id dù run_remediate_* RAISE ----
# (thay vì trả Job status="failed" bình thường) — hồi quy cho lỗ hổng phát
# hiện qua rà soát đối kháng: trước khi sửa, app/canary.py chỉ gán
# `dry_run_job.canary_rollout_id = rollout_id` SAU KHI run_remediate_dry_run
# return — nếu hàm đó raise (vd mint_ssh_certificate lỗi) thay vì return, dòng
# gán đó không bao giờ chạy, khiến GET /canary-rollouts/{id} không thấy job
# gây lỗi dù aborted_hostname đã đúng. Đã sửa: app/jobs.py gán
# canary_rollout_id NGAY lúc tạo Job (trước khi dispatch), không phải sau khi
# hàm return.


def test_rollout_tags_job_with_rollout_id_even_when_dispatch_raises(monkeypatch):
    _register_control("ctrl-a", maturity="production", risk_group="A")
    _register_remediation_variant("ctrl-a")
    _register_host("host-a.internal", "10.0.15.1", tier=2)
    _register_host("host-b.internal", "10.0.15.2", tier=2)

    call_count = {"n": 0}

    def _raise_once(principal):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise RuntimeError("step-ca tạm thời không cấp được cert")
        return ("FAKE-PRIVATE-KEY", "FAKE-CERT-PUB")

    monkeypatch.setattr(jobs_module, "mint_ssh_certificate", _raise_once)

    resp = _start_rollout("ctrl-a")
    assert resp.status_code == 202
    rollout_id = resp.json()["id"]

    _real_run_rollout(rollout_id, ["host-a.internal", "host-b.internal"], "ctrl-a", "opuser")

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    detail = client.get(f"/canary-rollouts/{rollout_id}").json()
    _clear_user_override()
    assert detail["status"] == "aborted"
    assert detail["aborted_hostname"] == "host-a.internal"
    assert detail["abort_reason"] == "internal_error"

    # Đúng điểm đã sửa: job của host-a (dù run_remediate_dry_run raise) vẫn
    # phải xuất hiện trong "hosts", không phải danh sách rỗng.
    assert [h["hostname"] for h in detail["hosts"]] == ["host-a.internal"]
    assert detail["hosts"][0]["status"] == "failed"

    db = _TestSessionLocal()
    host_a_job = db.query(Job).filter(Job.hostname == "host-a.internal").one()
    assert host_a_job.canary_rollout_id == rollout_id
    host_b_job_count = db.query(Job).filter(Job.hostname == "host-b.internal").count()
    db.close()
    assert host_b_job_count == 0


# ---- (7) rollout thứ 2 khi rollout đầu vẫn "running" -> 409 ----


def test_second_rollout_while_running_returns_409():
    _register_control("ctrl-a", maturity="production", risk_group="A")
    _insert_running_rollout("ctrl-a")

    resp = _start_rollout("ctrl-a")
    assert resp.status_code == 409


# ---- (8) PATCH cancel -> _run_rollout đọc cancel_requested -> aborted ----


def test_cancel_running_rollout_aborts_with_cancelled_reason():
    _register_control("ctrl-a", maturity="production", risk_group="A")
    _register_remediation_variant("ctrl-a")
    _register_host("host-a.internal", "10.0.14.1", tier=2)
    _register_host("host-b.internal", "10.0.14.2", tier=2)
    rollout_id = _insert_running_rollout("ctrl-a", eligible_host_count=2)

    app.dependency_overrides[get_current_user] = _as("opuser", "operator")
    resp = client.patch(f"/canary-rollouts/{rollout_id}/cancel")
    _clear_user_override()
    assert resp.status_code == 200

    db = _TestSessionLocal()
    rollout = db.get(CanaryRollout, rollout_id)
    assert rollout.cancel_requested is True
    assert rollout.status == "running"  # PATCH chỉ đặt cờ, KHÔNG tự đổi status
    db.close()

    # Rollout này được tạo thẳng qua DB (không qua POST), nên không có
    # BackgroundTasks nào đang chạy cho nó — gọi trực tiếp hàm thực thi nền
    # THẬT (_real_run_rollout — canary_module._run_rollout đã bị _mock_infra
    # patch thành no-op, xem GOTCHA #2 đầu file) như 1 hàm Python thường (đúng
    # gợi ý đề bài), mô phỏng đúng việc "_run_rollout tự kiểm tra
    # cancel_requested ở đầu MỖI vòng lặp host".
    _real_run_rollout(rollout_id, ["host-a.internal", "host-b.internal"], "ctrl-a", "opuser")

    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    detail = client.get(f"/canary-rollouts/{rollout_id}").json()
    _clear_user_override()
    assert detail["status"] == "aborted"
    assert detail["abort_reason"] == "cancelled"
    assert detail["aborted_hostname"] is None  # nhánh cancel không set hostname (xem app/canary.py)

    db = _TestSessionLocal()
    job_count = db.query(Job).filter(Job.canary_rollout_id == rollout_id).count()
    db.close()
    assert job_count == 0  # cancel được phát hiện TRƯỚC khi host nào được dry-run/apply


# ---- (9) reconcile_orphaned_rollouts (app/main.py lifespan, mô phỏng restart) ----


def test_reconcile_orphaned_rollouts_aborts_and_unblocks_control(_mock_infra):
    _register_control("ctrl-a", maturity="production", risk_group="A")
    rollout_id = _insert_running_rollout("ctrl-a", eligible_host_count=1)

    reconciled = canary_module.reconcile_orphaned_rollouts()
    assert reconciled == 1

    db = _TestSessionLocal()
    rollout = db.get(CanaryRollout, rollout_id)
    assert rollout.status == "aborted"
    assert rollout.abort_reason == "orchestrator_restarted"
    assert rollout.finished_at is not None
    db.close()

    audit_actions = [c["action"] for c in _mock_infra]
    assert "canary_rollout_aborted" in audit_actions

    # ux_canary_rollouts_running không còn chặn -> control mở khoá lại được.
    resp = _start_rollout("ctrl-a")
    assert resp.status_code == 200


def test_reconcile_orphaned_rollouts_ignores_finished_rollouts(_mock_infra):
    _register_control("ctrl-a", maturity="production", risk_group="A")
    _register_control("ctrl-b", maturity="production", risk_group="A")
    running_id = _insert_running_rollout("ctrl-a", eligible_host_count=1)

    db = _TestSessionLocal()
    db.add(
        CanaryRollout(
            control_id="ctrl-b", status="completed", triggered_by="opuser",
            eligible_host_count=0, finished_at=datetime.now(timezone.utc),
        )
    )
    db.commit()
    db.close()

    reconciled = canary_module.reconcile_orphaned_rollouts()
    assert reconciled == 1  # chỉ đúng rollout "running", không đụng "completed"

    db = _TestSessionLocal()
    still_completed = db.query(CanaryRollout).filter(CanaryRollout.control_id == "ctrl-b").one()
    assert still_completed.status == "completed"
    assert still_completed.abort_reason is None
    db.close()


def test_reconcile_orphaned_rollouts_noop_when_none_running(_mock_infra):
    assert canary_module.reconcile_orphaned_rollouts() == 0
    assert _mock_infra == []


def test_reconcile_orphaned_rollouts_survives_audit_failure(monkeypatch):
    # write_audit_event dùng session/engine RIÊNG (audit_database_url) —
    # có thể lỗi độc lập với DB chính. reconcile_orphaned_rollouts() chạy
    # trong app/main.py lifespan, để lỗi ở đây văng ra sẽ sập cả Orchestrator
    # chỉ vì thiếu 1 dòng audit — phải nuốt lỗi, KHÔNG được để mất state đã
    # abort đúng trong DB chính.
    def _raise(**kwargs):
        raise RuntimeError("audit DB tạm thời không kết nối được")

    monkeypatch.setattr(canary_module, "write_audit_event", _raise)

    _register_control("ctrl-a", maturity="production", risk_group="A")
    rollout_id = _insert_running_rollout("ctrl-a", eligible_host_count=1)

    reconciled = canary_module.reconcile_orphaned_rollouts()  # KHÔNG được raise
    assert reconciled == 1

    db = _TestSessionLocal()
    rollout = db.get(CanaryRollout, rollout_id)
    assert rollout.status == "aborted"  # state chính vẫn đúng dù audit lỗi
    assert rollout.abort_reason == "orchestrator_restarted"
    db.close()


# ---- (10) _run_rollout tự dừng nếu rollout không còn "running" (race với
# reconcile_orphaned_rollouts chạy ở 1 process khác — xem comment trong
# app/canary.py) ----


def test_run_rollout_stops_immediately_if_status_no_longer_running():
    _register_control("ctrl-a", maturity="production", risk_group="A")
    _register_host("host-a.internal", "10.0.14.1", tier=2)
    rollout_id = _insert_running_rollout("ctrl-a", eligible_host_count=1)

    # Mô phỏng 1 process KHÁC (vd reconcile_orphaned_rollouts ở lần khởi động
    # song song) đã abort rollout này TRƯỚC khi process này kịp xử lý host
    # đầu tiên.
    db = _TestSessionLocal()
    rollout = db.get(CanaryRollout, rollout_id)
    rollout.status = "aborted"
    rollout.abort_reason = "orchestrator_restarted"
    db.commit()
    db.close()

    _real_run_rollout(rollout_id, ["host-a.internal"], "ctrl-a", "opuser")

    db = _TestSessionLocal()
    rollout = db.get(CanaryRollout, rollout_id)
    # KHÔNG bị ghi đè — process này phải nhường, không tự ý coi đây là lỗi
    # của riêng nó (vd "internal_error") rồi đổi lại abort_reason.
    assert rollout.status == "aborted"
    assert rollout.abort_reason == "orchestrator_restarted"
    job_count = db.query(Job).filter(Job.canary_rollout_id == rollout_id).count()
    db.close()
    assert job_count == 0  # không hề đụng tới host nào


def test_run_rollout_skips_apply_if_status_flips_during_dry_run(monkeypatch):
    # Cửa sổ TOCTOU hẹp hơn: process khác abort rollout ĐÚNG lúc dry-run của
    # process này đang chạy dở (không phải trước cả vòng lặp như test trên) —
    # phải chặn ở bước re-check ngay trước apply (bước THẬT sự đổi cấu hình
    # host), không chỉ ở đầu vòng lặp.
    _register_control("ctrl-a", maturity="production", risk_group="A")
    _register_host("host-a.internal", "10.0.14.1", tier=2)
    rollout_id = _insert_running_rollout("ctrl-a", eligible_host_count=1)

    fake_dry_run_job = SimpleNamespace(id=999, status="succeeded")

    def _fake_dry_run(db, hostname, control_id, user, canary_rollout_id=None):
        rollout = db.get(CanaryRollout, rollout_id)
        rollout.status = "aborted"
        rollout.abort_reason = "orchestrator_restarted"
        db.commit()
        return fake_dry_run_job

    def _fail_if_called(*a, **kw):
        raise AssertionError("run_remediate_apply KHÔNG được gọi sau khi rollout đã bị process khác abort")

    monkeypatch.setattr(canary_module, "run_remediate_dry_run", _fake_dry_run)
    monkeypatch.setattr(canary_module, "run_remediate_apply", _fail_if_called)

    _real_run_rollout(rollout_id, ["host-a.internal"], "ctrl-a", "opuser")

    db = _TestSessionLocal()
    rollout = db.get(CanaryRollout, rollout_id)
    assert rollout.status == "aborted"
    assert rollout.abort_reason == "orchestrator_restarted"  # _abort() KHÔNG được ghi đè lên
    db.close()
