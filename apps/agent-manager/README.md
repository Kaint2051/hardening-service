# Agent Manager

Control-plane thứ hai (mục 4.3 `docs/architecture-proposal.md`) — relay mTLS
đứng giữa Agent tự phát triển (chạy trên từng máy fleet, xem `apps/agent/`)
và Orchestrator. **Không giữ state, không gọi step-ca trực tiếp** — mọi thao
tác enroll/heartbeat chỉ relay sang Orchestrator qua shared secret
(`AGENT_MANAGER_SHARED_SECRET`, cùng pattern `JOB_DISPATCHER_SHARED_SECRET`).

## Vì sao không tự gọi CA

Nguyên tắc xuyên suốt kiến trúc: **chỉ Orchestrator được gọi CA** (nó là
service duy nhất nối `ca-net`). Agent Manager nối `agent-net` + `mgmt-net`,
KHÔNG nối `ca-net` — kể cả cert TLS server của chính Agent Manager cũng xin
qua Orchestrator (`POST /internal/agent-manager/server-cert`), tự renew định
kỳ (mặc định mỗi 4h, cert provisioner cấp TTL 8h) thay vì tự ký hay gọi
step-ca. Nếu Agent Manager bị chiếm, kẻ tấn công vẫn phải xuyên qua thêm lớp
shared-secret + RBAC của Orchestrator mới chạm được CA thật.

## API

- `POST /enroll` — KHÔNG cần client cert (agent chưa có cert lúc này).
  Body `{"hostname", "token"}`, relay nguyên sang
  `Orchestrator:/internal/agent/verify-and-enroll`, trả nguyên response
  (thành công: `{cert_pem, key_pem, ca_root_pem}`; token đã dùng/hết hạn:
  401 pass-through).
- `POST /heartbeat`, `/scan-result`, `/fim-event`, `/renew`,
  `/remediate-jobs/claim`, `/remediation-bundle`, `/remediate-result` —
  BẮT BUỘC client cert mTLS hợp lệ (ký bởi root CA của step-ca). CN trong
  cert phải khớp `hostname` trong body (không phân biệt hoa/thường) — chặn 1
  agent dùng cert hợp lệ của chính nó để giả mạo report cho hostname khác.
  Cả 7 route dùng chung `handleMTLSRelay` (decode JSON vào `map[string]any`,
  chỉ cần đọc `hostname` để so khớp CN — thân body còn lại relay nguyên,
  không cần struct riêng cho `result_summary` lồng nhau tuỳ ý của
  scan-result/remediate-result). 3 route `remediate-*` là đường Active
  Response (claim job → tải bundle đã ký → báo kết quả) — đã nối dây thật
  tới Orchestrator, kill-switch `active_response_enabled` (mặc định TẮT)
  vẫn nằm ở phía Orchestrator, không phải ở đây.
- `GET /healthz` — không cần client cert, dùng cho Docker healthcheck.
- `GET /metrics` — không cần client cert, format text Prometheus (tự viết,
  không thêm dependency ngoài — cùng lý do `rateLimiter`). Xem mục "Metrics"
  bên dưới.

## Metrics

`GET /metrics` expose 3 chỉ số vận hành cơ bản:

- `agent_manager_relay_requests_total{endpoint,status}` (counter) — tổng số
  request đã xử lý theo endpoint (`enroll`/`heartbeat`/`scan-result`/
  `fim-event`/`renew`) và mã trạng thái HTTP trả về client, đếm qua
  `metricsMiddleware` bọc ngoài từng handler (không đụng logic bên trong nên
  không ảnh hưởng bộ test hiện có của các handler đó).
- `agent_manager_known_hosts` (gauge) — số hostname khác nhau đã từng gọi
  endpoint relay ít nhất 1 lần (lấy từ kích thước map của `rateLimiter`, vốn
  không tự dọn theo thời gian) — đây là số ĐÃ TỪNG thấy, không phải số agent
  đang giữ kết nối (mỗi request là 1 lần gọi HTTP rời rạc, agent-manager
  không giữ state kết nối lâu dài).
- `agent_manager_server_cert_renewal_success`/
  `agent_manager_server_cert_renewal_timestamp_seconds` (gauge) — kết quả +
  thời điểm lần renew cert gần nhất của CHÍNH agent-manager (`serverIdentity`,
  không phải cert của agent nào).

Không yêu cầu xác thực — cùng mức lộ thông tin như `/healthz` (chỉ số liệu
tổng hợp, không có hostname cụ thể nào), đúng quy ước Prometheus tiêu chuẩn
(để lớp mạng lo việc chặn truy cập nếu cần), chấp nhận được dù agent-manager
publish thẳng port ra LAN.

## Rate limit

`/heartbeat`, `/scan-result`, `/fim-event`, `/renew` dùng CHUNG 1 token bucket
theo CN đã xác thực (không theo IP — agent có thể đứng sau NAT chung IP với
agent khác), burst 20 + refill 0.5 token/giây (~30 request/phút bền vững) —
rộng rãi hơn nhiều so với lưu lượng hợp lệ thực tế (heartbeat 60s/lần, FIM chỉ
báo file thật sự đổi, renew nửa chu kỳ TTL ~4h, xem `apps/agent/main.go`)
nhưng vẫn chặn được 1 agent lỗi/bị compromise dồn dập ở tần suất bất thường.
Vượt ngưỡng trả `429`. Tự viết token bucket (`rateLimiter` trong `main.go`)
thay vì thêm dependency ngoài — `go.mod` cố tình không có dependency nào,
agent-manager là mặt tiếp xúc LAN duy nhất publish port.

## Việc CHƯA làm (đúng theo kế hoạch đã thống nhất)

(hiện không còn mục nào — xem README gốc mục checklist Giai đoạn 2 để biết
lịch sử "expose metric Prometheus" đã được thêm khi nào.)
