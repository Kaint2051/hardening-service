# Web UI (khung sườn)

React + TypeScript + Vite + MUI, đăng nhập qua Keycloak (Authorization Code +
PKCE, client public `web` — khác client `orchestrator` confidential dùng cho
service/test). Sau khi build, được serve bằng nginx (không có server-side gì
khác — mọi logic nghiệp vụ nằm ở Orchestrator API).

## Có gì trong khung sườn này

- Đăng nhập/đăng xuất qua Keycloak thật (không tự làm login form).
- Trang **Hosts**: đăng ký host, xem danh sách, cập nhật `ca_migration_status`
  (four-eyes cho Tier 0/1 do Orchestrator enforce — UI chỉ hiển thị lỗi 403
  trả về, không tự chặn ở phía client), trigger scan thật và xem kết quả
  (per-rule findings) ngay trong dialog.
- Trang **Controls**: tạo control, xem danh sách, duyệt maturity (draft ->
  reviewed -> production, four-eyes do Orchestrator enforce), xem/thêm
  standard mapping + remediation variant.
- Trang **Jobs**: lịch sử TOÀN BỘ job đã chạy (scan/agent-scan/remediate-dry-
  run/remediate-apply/restore), lọc theo hostname/job_type/status, phân
  trang (20 job/trang, nút "Trang sau" tự tắt khi trang hiện tại trả về ít
  hơn 1 trang đầy — không cần `COUNT(*)` riêng phía backend), dialog xem chi
  tiết 1 job (bảng findings nếu là job scan, JSON thô cho các loại còn lại).

## Chưa làm (đúng theo scope "khung sườn")

- Không có UI ẩn/hiện theo role (RBAC vẫn được Orchestrator enforce đầy đủ ở
  API — UI chỉ hiển thị lỗi khi bị từ chối, chưa tự ẩn nút theo role).
- Không có dark mode/responsive tối ưu — ưu tiên đúng chức năng trước.

## Biến môi trường (bake vào bundle lúc build — xem Dockerfile)

`VITE_KEYCLOAK_REALM`, `VITE_KEYCLOAK_CLIENT_ID` — chỉ 2 biến này còn baked
lúc build. Mục "thống nhất 1 port": KHÔNG còn `VITE_API_BASE_URL`/
`VITE_KEYCLOAK_URL` — `api/client.ts` gọi `/api` (relative) và
`auth/keycloak.ts` dùng `window.location.origin`, cả 2 đều same-origin với
chính SPA vì nginx (`nginx.conf`) reverse-proxy `/api/*` sang Orchestrator và
`/realms/*`, `/resources/*` sang Keycloak — không cần biết trước IP/hostname
trình duyệt dùng để truy cập nữa (trước đây phải rebuild image mỗi khi đổi IP).
