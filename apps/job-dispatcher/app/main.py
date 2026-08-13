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
import contextlib
import hmac
import os
import re
import threading

import docker
import docker.errors
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

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


def _reconcile_orphaned_containers() -> None:
    """Dọn container "job-*" còn sót lại từ lần chạy TRƯỚC của chính tiến
    trình job-dispatcher (rủi ro lý thuyết đã ghi nhận trước đây: nếu
    job-dispatcher bị crash/OOM-kill/restart đúng lúc giữa
    `containers.run()` thành công và `finally: container.remove()` trong
    `run_job` bên dưới, không còn gì trong tiến trình cũ để dọn container
    đó nữa). Khác `app/canary.py:reconcile_orphaned_rollouts` phía
    Orchestrator (nơi phải phân biệt "đang chạy hợp lệ" vs "mồ côi" qua
    trạng thái DB) — job-dispatcher không giữ state nào sống lâu hơn đúng 1
    request `/run` (mọi container nó tạo ra đều được dọn trong CÙNG request
    đã tạo ra nó, xem `finally` bên dưới), nên BẤT KỲ container "job-*" nào
    còn tồn tại lúc tiến trình mới vừa khởi động chắc chắn là mồ côi từ lần
    chạy trước, không cần điều kiện phân biệt gì thêm.
    """
    try:
        # KHÔNG dùng Docker filters={"name": "job-"} — filter name của Docker
        # khớp SUBSTRING không neo đầu chuỗi (unanchored), nên "job-" cũng
        # khớp luôn chính container "hardening-console-job-dispatcher-1" của
        # docker-compose (chứa "job-dispatcher" ở giữa tên) — BUG THẬT tự
        # gây ra rồi tự phát hiện qua verify E2E: reconciliation tự xoá
        # container CỦA CHÍNH MÌNH lúc khởi động (force=True xoá cả container
        # đang chạy), khiến job-dispatcher biến mất khỏi compose project ngay
        # sau khi vừa lên. Liệt kê KHÔNG filter rồi tự lọc bằng Python
        # str.startswith() — chỉ khớp đúng quy ước tên "job-{job_id}" tạo ra
        # ở run_job() bên dưới (không có tiền tố "hardening-console-" vì
        # containers.run() ở đó đặt tên trực tiếp, không qua compose).
        all_containers = _docker_client.containers.list(all=True)
    except docker.errors.DockerException as exc:
        print(f"CANH BAO: khong the liet ke container de reconcile luc khoi dong: {exc}")
        return
    orphans = [c for c in all_containers if c.name.startswith("job-")]
    for container in orphans:
        try:
            container.remove(force=True)
            print(f"da don container mo coi tu lan chay truoc: {container.name}")
        except docker.errors.DockerException as exc:
            print(f"CANH BAO: khong the xoa container mo coi {container.name}: {exc}")


@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI):
    _reconcile_orphaned_containers()
    yield


app = FastAPI(title="Job Dispatcher (nội bộ — không public)", lifespan=lifespan)


class RunJobRequest(BaseModel):
    job_id: str
    image: str
    command: list[str]
    environment: dict[str, str] = {}
    timeout_seconds: int = 300


class JobProgressOut(BaseModel):
    pct: int
    stage: str


# Marker tiến độ do chính script execution-env in ra stdout (mục "progress
# bar % thật" cho ssh-check/agent-install — xem apps/execution-env/{ssh-check,
# agent-install}.sh). KHÔNG đổi gì ở /run hay vòng đời container — endpoint
# /jobs/{job_id}/progress bên dưới chỉ ĐỌC THÊM log của container đang chạy
# (container job-{job_id} vẫn tồn tại/ghi log sống trong lúc container.wait()
# ở /run đang chặn), không cần container tự báo cáo qua kênh nào khác.
_PROGRESS_RE = re.compile(r"^##PROGRESS## (\d{1,3}) (\S+)$")


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


@app.get("/jobs/{job_id}/progress", response_model=JobProgressOut)
def job_progress(job_id: str, authorization: str | None = Header(default=None)) -> JobProgressOut:
    """Đọc tiến độ 1 job ĐANG CHẠY qua log hiện tại của container — KHÔNG
    đụng gì tới /run hay vòng đời container. Chỉ dùng được trong lúc
    container job-{job_id} còn tồn tại (container.wait() ở /run vẫn đang
    chặn) — 404 nếu chưa tạo xong (job-dispatcher đang đợi slot trống) HOẶC
    đã dọn xong (job kết thúc, /run's finally đã remove) — 2 case này KHÔNG
    phân biệt được ở đây, Orchestrator tự phân biệt qua Job.status của nó.
    """
    _check_auth(authorization)
    try:
        container = _docker_client.containers.get(f"job-{job_id}")
        logs = container.logs().decode("utf-8", errors="replace")
    except docker.errors.NotFound:
        raise HTTPException(
            status_code=404, detail="container không tồn tại (chưa tạo hoặc đã dọn xong)"
        )
    except docker.errors.DockerException as exc:
        raise HTTPException(status_code=502, detail=f"lỗi đọc log container: {exc}") from exc

    last_match = None
    for line in logs.splitlines():
        m = _PROGRESS_RE.match(line.strip())
        if m:
            last_match = m
    if last_match is None:
        return JobProgressOut(pct=0, stage="starting")
    return JobProgressOut(pct=min(int(last_match.group(1)), 100), stage=last_match.group(2))
