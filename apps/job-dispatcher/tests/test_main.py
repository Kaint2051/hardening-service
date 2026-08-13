"""Test cho job-dispatcher (app/main.py) — mock docker.from_env() hoàn toàn,
KHÔNG cần Docker daemon thật để test logic auth/allowlist/volume mount.

Chạy qua container python:3.12-slim tạm (mount thư mục này vào, KHÔNG bake
pytest vào requirements.txt production — image job-dispatcher cố tình tối
giản vì đây là service DUY NHẤT giữ quyền Docker, xem app/main.py):

    docker run --rm -v <path-repo>/apps/job-dispatcher:/src -w /src \\
      python:3.12-slim sh -c \\
      "pip install -q -r requirements.txt pytest httpx && python -m pytest tests/ -v"

(httpx không có trong requirements.txt production — chỉ starlette.testclient
cần nó lúc test, xác nhận qua chạy thật: thiếu httpx làm collection lỗi ngay
"RuntimeError: The starlette.testclient module requires the httpx package".)
"""
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("JOB_DISPATCHER_SHARED_SECRET", "test-secret")
os.environ.setdefault("ALLOWED_EXECUTION_IMAGE", "test-image:latest")
os.environ.setdefault("CONTENT_SIGNING_SIGNED_HOST_PATH", "/host/signed")
# Cố định thay vì để mặc định theo os.cpu_count() của máy chạy test (không xác
# định, phụ thuộc host CI/lab) — cần giá trị nhỏ, biết trước để test được giới
# hạn đồng thời. JOB_SLOT_WAIT_SECONDS nhỏ để test không phải chờ thật vài giây.
os.environ.setdefault("MAX_CONCURRENT_JOBS", "2")
os.environ.setdefault("JOB_SLOT_WAIT_SECONDS", "0.2")

import docker.errors
import pytest
from fastapi.testclient import TestClient

# app/main.py gọi docker.from_env() NGAY LÚC IMPORT (module-level) — phải
# mock TRƯỚC import, không phải sau, nếu không sẽ thử kết nối Docker daemon
# thật (không có trong container test này).
with patch("docker.from_env") as _mock_from_env:
    _mock_from_env.return_value = MagicMock()
    from app import main as main_module

client = TestClient(main_module.app)
AUTH_HEADER = {"Authorization": "Bearer test-secret"}


@pytest.fixture(autouse=True)
def _reset_mock_client():
    main_module._docker_client.reset_mock()
    yield


def _mock_container(exit_code=0, logs=b"job output"):
    container = MagicMock()
    container.wait.return_value = {"StatusCode": exit_code}
    container.logs.return_value = logs
    return container


def test_healthz():
    resp = client.get("/healthz")
    assert resp.status_code == 200


def test_missing_auth_header_401():
    resp = client.post("/run", json={"job_id": "1", "image": "test-image:latest", "command": ["scan"]})
    assert resp.status_code == 401


def test_wrong_secret_401():
    resp = client.post(
        "/run",
        json={"job_id": "1", "image": "test-image:latest", "command": ["scan"]},
        headers={"Authorization": "Bearer wrong-secret"},
    )
    assert resp.status_code == 401


def test_disallowed_image_rejected_even_with_correct_secret():
    resp = client.post(
        "/run",
        json={"job_id": "1", "image": "attacker-chosen-image:latest", "command": ["scan"]},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 403


def test_run_passes_content_signing_volume_mount():
    # remediate.sh cần đọc bundle đã ký trong scripts/content-signing/signed/
    # — job-dispatcher phải mount đúng path HOST (không phải path nội bộ
    # container job-dispatcher) vào /content:ro cho container sibling.
    main_module._docker_client.containers.run.return_value = _mock_container(exit_code=0)
    resp = client.post(
        "/run",
        json={"job_id": "42", "image": "test-image:latest", "command": ["remediate"]},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200
    _, kwargs = main_module._docker_client.containers.run.call_args
    assert kwargs["volumes"] == {"/host/signed": {"bind": "/content", "mode": "ro"}}


def test_run_success_returns_exit_code_and_logs():
    main_module._docker_client.containers.run.return_value = _mock_container(exit_code=0, logs=b"all good")
    resp = client.post(
        "/run",
        json={"job_id": "1", "image": "test-image:latest", "command": ["scan"]},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["exit_code"] == 0
    assert body["logs"] == "all good"


def test_run_applies_cpu_and_pid_resource_limits():
    # Chặn 1 job "xấu"/bị compromise chiếm hết CPU hoặc spawn fork bomb ảnh
    # hưởng các job khác hay chính host job-dispatcher (xem comment trong
    # app/main.py cạnh containers.run()).
    main_module._docker_client.containers.run.return_value = _mock_container(exit_code=0)
    resp = client.post(
        "/run",
        json={"job_id": "42", "image": "test-image:latest", "command": ["scan"]},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200
    _, kwargs = main_module._docker_client.containers.run.call_args
    assert kwargs["nano_cpus"] == 1_000_000_000
    assert kwargs["pids_limit"] == 128


def test_run_always_removes_container():
    container = _mock_container(exit_code=0)
    main_module._docker_client.containers.run.return_value = container
    client.post(
        "/run",
        json={"job_id": "1", "image": "test-image:latest", "command": ["scan"]},
        headers=AUTH_HEADER,
    )
    container.remove.assert_called_once_with(force=True)


def test_run_kills_container_and_reports_error_on_wait_failure():
    container = MagicMock()
    container.wait.side_effect = Exception("giả lập lỗi giao tiếp Docker daemon lúc chờ kết quả")
    main_module._docker_client.containers.run.return_value = container
    resp = client.post(
        "/run",
        json={"job_id": "1", "image": "test-image:latest", "command": ["scan"]},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 200
    assert resp.json()["exit_code"] == -1
    container.kill.assert_called_once()
    container.remove.assert_called_once_with(force=True)


def test_run_rejects_with_503_when_at_concurrency_limit():
    # Chiếm hết mọi slot thủ công (mô phỏng đã có MAX_CONCURRENT_JOBS job khác
    # đang chạy) thay vì dựng thật nhiều thread song song — đơn giản, xác định,
    # test đúng logic từ chối thay vì phụ thuộc timing thread thật.
    for _ in range(main_module.MAX_CONCURRENT_JOBS):
        assert main_module._job_slots.acquire(timeout=1)
    try:
        resp = client.post(
            "/run",
            json={"job_id": "over-limit", "image": "test-image:latest", "command": ["scan"]},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 503
        # Không được đụng Docker khi đã từ chối do hết slot.
        main_module._docker_client.containers.run.assert_not_called()
    finally:
        for _ in range(main_module.MAX_CONCURRENT_JOBS):
            main_module._job_slots.release()


def test_run_releases_slot_after_completion_for_next_job():
    # Xác nhận slot được trả lại đúng sau khi job xong — nếu quên release sẽ
    # rò rỉ dần tới khi mọi request đều bị 503 dù không còn job nào chạy thật.
    main_module._docker_client.containers.run.return_value = _mock_container(exit_code=0)
    for job_id in ("seq-1", "seq-2", "seq-3"):
        resp = client.post(
            "/run",
            json={"job_id": job_id, "image": "test-image:latest", "command": ["scan"]},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 200


def test_run_releases_slot_even_when_docker_create_fails():
    # Slot phải được trả lại kể cả khi containers.run() ném lỗi, không chỉ khi
    # thành công — nếu không, lỗi Docker dồn dập sẽ khoá luôn mọi slot còn lại.
    main_module._docker_client.containers.run.side_effect = docker.errors.DockerException("boom")
    main_module._docker_client.containers.get.return_value = MagicMock()
    for _ in range(main_module.MAX_CONCURRENT_JOBS + 1):
        resp = client.post(
            "/run",
            json={"job_id": "fail", "image": "test-image:latest", "command": ["scan"]},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 500


def test_startup_reconciles_orphaned_containers():
    # Mô phỏng job-dispatcher bị crash/OOM-kill/restart đúng lúc giữa
    # containers.run() thành công và finally: container.remove() của LẦN
    # CHẠY TRƯỚC — container "job-*" đó còn sót lại trên Docker daemon,
    # phải bị dọn ngay lúc tiến trình mới khởi động (xem lifespan trong
    # app/main.py). Dùng `with TestClient(...)` (khác client module-level ở
    # đầu file) để lifespan startup thật sự chạy.
    orphan = MagicMock()
    orphan.name = "job-orphaned-42"
    main_module._docker_client.containers.list.return_value = [orphan]
    with TestClient(main_module.app):
        pass
    main_module._docker_client.containers.list.assert_called_once_with(all=True)
    orphan.remove.assert_called_once_with(force=True)


def test_startup_reconcile_does_not_remove_job_dispatcher_own_container():
    # Hồi quy cho BUG THẬT tự gây ra rồi tự phát hiện qua verify E2E trên lab:
    # container docker-compose của CHÍNH job-dispatcher tên
    # "hardening-console-job-dispatcher-1" chứa substring "job-" ở giữa (từ
    # "job-dispatcher"), nên filter Docker filters={"name": "job-"} (unanchored,
    # khớp substring) trước đây khớp NHẦM cả nó — reconciliation tự xoá chính
    # container đang chạy mình lúc khởi động. Giờ lọc bằng
    # str.startswith("job-") ở tầng Python nên KHÔNG được khớp tên này (không
    # bắt đầu bằng "job-", bắt đầu bằng "hardening-console-").
    own_container = MagicMock()
    own_container.name = "hardening-console-job-dispatcher-1"
    real_orphan = MagicMock()
    real_orphan.name = "job-42"
    main_module._docker_client.containers.list.return_value = [own_container, real_orphan]
    with TestClient(main_module.app):
        pass
    own_container.remove.assert_not_called()
    real_orphan.remove.assert_called_once_with(force=True)


def test_startup_reconcile_tolerates_docker_list_failure():
    # Lỗi liệt kê container (vd Docker daemon tạm thời không phản hồi lúc
    # khởi động) không được chặn tiến trình khởi động — chỉ cảnh báo, không
    # raise (không có gì bắt exception từ lifespan ở tầng uvicorn/Compose
    # healthcheck cho job-dispatcher, raise ở đây sẽ làm cả service không
    # bao giờ lên được, tệ hơn nhiều so với 1 vài container mồ côi).
    main_module._docker_client.containers.list.side_effect = docker.errors.DockerException("boom")
    with TestClient(main_module.app):
        pass  # không raise là đủ — assert ngầm định qua việc chạy tới đây


def test_run_removes_orphaned_container_on_create_failure():
    # docker-py .run() không atomic (create rồi start) — nếu start lỗi sau
    # khi create đã thành công, không có handle container trả về; dọn bằng
    # cách tra theo tên cố định job-{job_id} (xem comment trong app/main.py).
    main_module._docker_client.containers.run.side_effect = docker.errors.DockerException("boom")
    orphan = MagicMock()
    main_module._docker_client.containers.get.return_value = orphan
    resp = client.post(
        "/run",
        json={"job_id": "1", "image": "test-image:latest", "command": ["scan"]},
        headers=AUTH_HEADER,
    )
    assert resp.status_code == 500
    main_module._docker_client.containers.get.assert_called_once_with("job-1")
    orphan.remove.assert_called_once_with(force=True)


# ---- GET /jobs/{job_id}/progress (đọc log LIVE của container đang chạy —
# xem app/main.py, tính năng progress bar % thật cho ssh-check/agent-install) ----


def test_job_progress_missing_auth_header_401():
    resp = client.get("/jobs/1/progress")
    assert resp.status_code == 401


def test_job_progress_wrong_secret_401():
    resp = client.get("/jobs/1/progress", headers={"Authorization": "Bearer wrong-secret"})
    assert resp.status_code == 401


def test_job_progress_returns_last_marker_when_multiple_present():
    container = MagicMock()
    container.logs.return_value = (
        b"=== Verify chu ky ===\n##PROGRESS## 5 verify_signature\n"
        b"=== Giai nen ===\n##PROGRESS## 20 extract_bundle\n"
    )
    main_module._docker_client.containers.get.return_value = container
    resp = client.get("/jobs/42/progress", headers=AUTH_HEADER)
    assert resp.status_code == 200
    assert resp.json() == {"pct": 20, "stage": "extract_bundle"}
    main_module._docker_client.containers.get.assert_called_once_with("job-42")


def test_job_progress_defaults_when_no_marker_yet():
    container = MagicMock()
    container.logs.return_value = b"chua co marker nao ca\n"
    main_module._docker_client.containers.get.return_value = container
    resp = client.get("/jobs/42/progress", headers=AUTH_HEADER)
    assert resp.status_code == 200
    assert resp.json() == {"pct": 0, "stage": "starting"}


def test_job_progress_404_when_container_not_found():
    main_module._docker_client.containers.get.side_effect = docker.errors.NotFound("khong tim thay")
    resp = client.get("/jobs/42/progress", headers=AUTH_HEADER)
    assert resp.status_code == 404


def test_job_progress_502_on_other_docker_error():
    main_module._docker_client.containers.get.side_effect = docker.errors.DockerException("boom")
    resp = client.get("/jobs/42/progress", headers=AUTH_HEADER)
    assert resp.status_code == 502
