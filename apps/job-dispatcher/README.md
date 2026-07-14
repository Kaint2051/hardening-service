# Job Dispatcher

Service nội bộ DUY NHẤT trong hệ thống được mount `/var/run/docker.sock`, để
spawn container "Ephemeral Execution Environment" (`apps/execution-env/`) cho
mỗi job (scan/remediate).

## Vì sao tách riêng khỏi Orchestrator

Orchestrator có API công khai hơn (dù đã có RBAC) — nếu bị RCE mà chính nó
giữ quyền Docker (mount docker.sock), kẻ tấn công có ngay quyền tương đương
root trên host. Tách dispatcher riêng buộc kẻ tấn công phải xuyên qua thêm
1 lớp: dispatcher không có port public, chỉ nhận request từ `job-net` (mạng
nội bộ, chỉ Orchestrator + dispatcher nối vào), và CHỈ chạy đúng 1 image được
allowlist qua biến môi trường `ALLOWED_EXECUTION_IMAGE` — dù có lấy được
shared secret, không thể yêu cầu dispatcher chạy image tuỳ ý.

Đây là quyết định đánh đổi độ phức tạp (thêm 1 service) lấy đúng nguyên tắc
"không có control node thường trực nắm quyền lớn" đã đặt ra ở Giai đoạn 0.

## API

`POST /run` (yêu cầu header `Authorization: Bearer <JOB_DISPATCHER_SHARED_SECRET>`
**VÀ** client cert mTLS hợp lệ — xem mục "mTLS" bên dưới):
```json
{
  "job_id": "123",
  "image": "hardening-console-execution-env:latest",
  "command": ["scan"],
  "environment": {"TARGET_HOST": "...", "...": "..."},
  "timeout_seconds": 300
}
```
Trả về `{"job_id", "exit_code", "logs"}`. Container luôn bị xoá (`remove(force=True)`)
sau khi chạy xong, kể cả khi timeout/lỗi — không để lại container/state.

## mTLS giữa Orchestrator/job-dispatcher (Giai đoạn 2)

3 lớp phòng thủ (trước đây chỉ có shared secret + allowlist image):

1. **mTLS** — job-dispatcher chỉ chấp nhận kết nối TLS có client cert hợp lệ
   (`ssl_cert_reqs=ssl.CERT_REQUIRED` trong `app/serve.py`), ký bởi cùng root
   CA (step-ca) đang dùng cho SSH/agent. job-dispatcher KHÔNG nối `ca-net`
   (chỉ Orchestrator được gọi CA trực tiếp) nên xin cert SERVER của chính nó
   qua `POST /internal/job-dispatcher/server-cert` (Orchestrator, cùng
   pattern `apps/agent-manager/`), tự renew mỗi 4h (TTL provisioner 8h) —
   hot-swap vào `SSLContext` đang chạy (`app/tls_identity.py`), KHÔNG cần
   restart process.
   Orchestrator (đã nối `ca-net`) tự mint 1 cert CLIENT MỚI cho MỖI lần gọi
   `/run` thay vì cache/renew (`app/jobs.py:_call_job_dispatcher`) — cùng
   triết lý "no standing privilege" của `mint_ssh_certificate` (mỗi job 1
   SSH cert ngắn hạn riêng), đơn giản hơn nhiều so với duy trì renewal loop
   ở phía client vì mỗi lần gọi chỉ là 1 request/response ngắn.
2. Shared secret (Bearer token) — **vẫn giữ nguyên**, không bị mTLS thay thế.
3. Allowlist đúng 1 image.

## Giới hạn tài nguyên

## Giới hạn tài nguyên

- Mỗi container job: `mem_limit=512m`, `nano_cpus=1_000_000_000` (1 vCPU),
  `pids_limit=128` — chặn 1 job xấu/bị compromise chiếm hết tài nguyên host
  hoặc ảnh hưởng job khác.
- **Tổng số job chạy đồng thời**: giới hạn qua `threading.Semaphore`, mặc định
  bằng `os.cpu_count()` của host (mỗi job 1 vCPU nên không nên vượt số core
  vật lý), override qua env `MAX_CONCURRENT_JOBS`. Nếu hết slot, request mới
  đợi tối đa `JOB_SLOT_WAIT_SECONDS` (mặc định 5s, chỉ để san phẳng burst gần
  cùng lúc, không phải hàng đợi thật) rồi trả về `503` thay vì cố spawn thêm —
  quan trọng ở quy mô tới 50 host: nếu không giới hạn, 1 đợt scan theo lịch
  trigger đồng thời trên nhiều host có thể oversubscribe CPU/RAM của chính
  host Docker (Starlette threadpool mặc định ~40 thread cũng ngầm giới hạn,
  nhưng không theo tài nguyên thật của host, chỉ theo số thread cố định).
  `503` được Orchestrator xử lý như mọi lỗi dispatch khác (đánh job "failed"
  với message rõ ràng, xem `app/jobs.py`) — không cần logic mới phía
  Orchestrator.

## Việc CHƯA làm

(hiện không còn mục nào — xem README gốc mục checklist Giai đoạn 2 để biết
lịch sử mTLS đã được thêm khi nào.)
