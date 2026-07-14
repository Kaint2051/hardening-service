"""Job Dispatcher — service NỘI BỘ DUY NHẤT được mount /var/run/docker.sock
(mục 7 roadmap, xem trao đổi thiết kế trong README.md thư mục này).

Orchestrator KHÔNG giữ quyền Docker trực tiếp — nếu Orchestrator (bề mặt tấn
công lớn hơn, có API công khai) bị RCE, kẻ tấn công vẫn phải xuyên qua thêm
service này (chỉ nhận lệnh qua job-net nội bộ, không public port, chỉ chạy
đúng 1 image được allowlist) mới chạm được tới Docker/host.

Hai lớp phòng thủ, cả hai đều bắt buộc — thiếu 1 lớp là hỏng mô hình:
  1. Shared secret (Bearer token, so sánh hằng thời gian).
  2. Allowlist đúng 1 image (KHÔNG nhận image tuỳ ý dù secret đúng).
"""
import hmac
import os
import threading

import docker
import docker.errors
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Job Dispatcher (nội bộ — không public)")

SHARED_SECRET = os.environ["JOB_DISPATCHER_SHARED_SECRET"]
ALLOWED_IMAGE = os.environ["ALLOWED_EXECUTION_IMAGE"]
# Mỗi container job đã bị giới hạn 1 vCPU (nano_cpus, xem containers.run() bên
# dưới), nhưng KHÔNG có gì chặn TỔNG SỐ container chạy đồng thời — nếu nhiều
# host (tới 50 theo quy mô dự án) cùng trigger job 1 lúc (vd scan theo lịch),
# job-dispatcher trước đây sẽ cố spawn hết tất cả cùng lúc, dễ oversubscribe
# CPU/RAM của chính host Docker (phát hiện qua rà soát, không phải sự cố thật
# đã xảy ra). Mặc định lấy theo số CPU thật của host — mỗi job 1 vCPU nên số
# job chạy đồng thời hợp lý không nên vượt số core vật lý; cho phép override
# qua env nếu vận hành muốn siết chặt hơn.
MAX_CONCURRENT_JOBS = int(os.environ.get("MAX_CONCURRENT_JOBS", os.cpu_count() or 2))
_job_slots = threading.Semaphore(MAX_CONCURRENT_JOBS)
# Job hàng đợi tối đa vài giây chờ 1 slot trống rồi mới báo bận (503) — chỉ để
# san phẳng các request đến gần như cùng lúc, KHÔNG phải hàng đợi thật sự (đợi
# lâu hơn dễ va timeout=340s phía Orchestrator, xem app/jobs.py, khiến job bị
# đánh "failed" một cách khó hiểu thay vì báo "đang bận" rõ ràng ngay). Cho
# phép override qua env để test không phải chờ thật vài giây mỗi lần.
JOB_SLOT_WAIT_SECONDS = float(os.environ.get("JOB_SLOT_WAIT_SECONDS", "5"))
# Đường dẫn TRÊN HOST DOCKER thật, không phải trong container job-dispatcher
# — service này chạy Docker-outside-of-Docker (mount docker.sock, spawn
# container SIBLING qua job-net), nên bind-mount cho sibling phải tính theo
# hệ toạ độ của host, không phải của chính tiến trình job-dispatcher (nếu
# dùng nhầm đường dẫn nội bộ container, Docker daemon trên host sẽ tìm path
# đó trên HOST và thường tạo ra 1 thư mục rỗng thay vì báo lỗi rõ ràng — lỗi
# âm thầm, không phải crash ngay).
CONTENT_SIGNING_SIGNED_HOST_PATH = os.environ["CONTENT_SIGNING_SIGNED_HOST_PATH"]
_docker_client = docker.from_env()


class RunJobRequest(BaseModel):
    job_id: str
    image: str
    command: list[str]
    environment: dict[str, str] = {}
    timeout_seconds: int = 300


def _check_auth(authorization: str | None) -> None:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="thiếu Authorization header")
    token = authorization[len("Bearer "):]
    if not hmac.compare_digest(token, SHARED_SECRET):
        raise HTTPException(status_code=401, detail="shared secret sai")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/run")
def run_job(body: RunJobRequest, authorization: str | None = Header(default=None)) -> dict:
    _check_auth(authorization)

    if body.image != ALLOWED_IMAGE:
        raise HTTPException(
            status_code=403,
            detail=f"chỉ được chạy image '{ALLOWED_IMAGE}', từ chối '{body.image}'",
        )

    if not _job_slots.acquire(timeout=JOB_SLOT_WAIT_SECONDS):
        raise HTTPException(
            status_code=503,
            detail=(
                f"job-dispatcher đang chạy đủ {MAX_CONCURRENT_JOBS} job đồng thời "
                "(giới hạn theo số CPU host) — thử lại sau"
            ),
        )

    try:
        # Đặt tên cố định theo job_id: docker-py .run() không atomic (create rồi
        # start) — nếu start lỗi sau khi create đã thành công, không có handle
        # container trả về để dọn, để lại container mồ côi trên host (phát hiện
        # qua code review). Có tên cố định thì dọn được bằng cách tra theo tên.
        container_name = f"job-{body.job_id}"
        try:
            container = _docker_client.containers.run(
                body.image,
                name=container_name,
                command=body.command,
                environment=body.environment,
                detach=True,
                mem_limit="512m",
                # Chặn 1 job "xấu" (hoặc bị compromise) chiếm hết CPU/spawn fork
                # bomb ảnh hưởng các job khác hoặc chính host job-dispatcher.
                nano_cpus=1_000_000_000,  # 1 vCPU
                pids_limit=128,
                network_mode="bridge",
                # Luôn mount read-only — job-dispatcher không cần biết job là
                # scan hay remediate (giữ tối giản, không phân loại theo job
                # type, đúng triết lý hiện tại: chỉ allowlist đúng 1 image).
                # scan.sh hiện không cần path này (SCAP content bake sẵn trong
                # image qua apt), nhưng remediate.sh (nội dung remediation ký
                # riêng theo job) thì có.
                volumes={CONTENT_SIGNING_SIGNED_HOST_PATH: {"bind": "/content", "mode": "ro"}},
            )
        except docker.errors.DockerException as exc:
            try:
                _docker_client.containers.get(container_name).remove(force=True)
            except docker.errors.NotFound:
                pass
            raise HTTPException(status_code=500, detail=f"lỗi khởi tạo container job: {exc}") from exc

        try:
            wait_result = container.wait(timeout=body.timeout_seconds)
            exit_code = wait_result.get("StatusCode", -1)
            logs = container.logs().decode("utf-8", errors="replace")
        except Exception as exc:  # timeout hoặc lỗi giao tiếp Docker daemon
            try:
                container.kill()
            except docker.errors.APIError:
                pass
            exit_code = -1
            logs = f"job vượt timeout hoặc lỗi khi chờ kết quả: {exc}"
        finally:
            container.remove(force=True)
    finally:
        _job_slots.release()

    return {"job_id": body.job_id, "exit_code": exit_code, "logs": logs}
