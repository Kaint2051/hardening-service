# Keycloak realm — Giai đoạn 0

`realm-export.json` được import tự động khi container khởi động lần đầu
(`start-dev --import-realm`). Thiết lập sẵn:

- 6 vai trò RBAC tối thiểu theo mục 4.7: `viewer`, `auditor`, `rule-editor`,
  `approver`, `operator`, `admin`.
- Client `orchestrator` (confidential, Authorization Code flow) cho backend.
- Client `orchestrator-admin` (confidential, `serviceAccountsEnabled: true`,
  không flow tương tác nào) — Orchestrator tự gọi Keycloak Admin REST API
  bằng service account này cho tính năng Quản lý người dùng
  (`app/keycloak_admin.py`). Entry trong file này CHỈ khai client shell —
  **KHÔNG** tự cấp 4 role `manage-users`/`view-users`/`query-users`/
  `view-realm` cho service account lúc import (Keycloak's realm-export
  không tự làm điều đó qua `clients[]`, cần 1 block `users[]` riêng mà file
  này chưa có). Dù import lần đầu hay tạo thêm vào 1 instance đang chạy, đều
  PHẢI chạy `./infra/keycloak/bootstrap-admin-client.sh` 1 lần để cấp role +
  lấy secret dán vào `.env` — xem chi tiết + lý do trong chính file script
  đó (`view-realm` PHÁT HIỆN QUA TEST THẬT — thiếu nó, `GET
  /roles/{role}/users` trả 403 dù đã có 3 role user-centric kia).
- `CONFIGURE_TOTP` là required action mặc định — user mới bắt buộc thiết lập
  MFA khi đăng nhập lần đầu.

## ⚠️ Việc còn thiếu, cần cấu hình thủ công trước khi dùng thật

1. ~~Đổi client secret~~ — **đã sửa**: `realm-export.json` trước đây hardcode
   sẵn 1 chuỗi secret thật (`changeme-in-prod-use-env-secret`), và secret đó
   bị commit vào git rồi push lên GitHub public mà không ai đổi lại — phát
   hiện qua kiểm tra thật trên lab server (secret live vẫn trùng y hệt file).
   Đã: (1) rotate secret live trên Keycloak qua Admin API, (2) bỏ hẳn field
   `"secret"` khỏi `realm-export.json` — Keycloak tự sinh secret ngẫu nhiên
   lúc import nếu không có field này, (3) rewrite git history để xoá chuỗi
   cũ khỏi commit đã push (xem ghi chú trong README gốc/commit message).
   **Không có code nào trong repo này đọc secret của client `orchestrator`**
   (JWT verify dùng JWKS/RS256, không cần secret) — chỉ script test thủ công
   (`fourseyes_e2e_test.sh`, `scan_e2e_test.sh`) tự fetch secret hiện tại qua
   Admin API lúc chạy, không hardcode. Nếu sau này có code thật cần secret
   này, lấy qua Admin Console → Clients → orchestrator → Credentials, không
   hardcode lại vào file JSON.
2. **`admin` không tự phê duyệt thay đổi của chính mình** (nguyên tắc 4.7) —
   Keycloak không tự enforce được ràng buộc nghiệp vụ này, phải kiểm tra ở
   tầng Orchestrator (so sánh actor_id đề xuất vs actor_id phê duyệt).
3. **`start-dev` chỉ dùng cho local/dev** — production cần `start` (production
   mode thật, đóng luôn cổng HTTP nội bộ 8080 mà `start-dev` luôn tự bật lại
   dù có `--http-enabled=false`, xem `command:` của service `keycloak` trong
   docker-compose.yml), DB Postgres riêng cho Keycloak (không dùng H2 mặc
   định), và review lại `bruteForceProtected`/session timeout theo policy
   tổ chức.
   - **ĐÃ CẬP NHẬT (mục "Dựng TLS thật" + "thống nhất 1 port")**: `sslRequired`
     giờ là `"external"` — Keycloak/Orchestrator/Web đều có TLS thật (cert do
     step-ca nội bộ ký), và browser chỉ còn vào qua ĐÚNG 1 port (3000, Web) —
     nginx ở đó reverse-proxy `/realms/*`, `/resources/*` sang chính Keycloak
     (xem `apps/web/nginx.conf`), Keycloak không còn publish port riêng ra
     host. Ghi chú cũ dưới đây (khi `sslRequired` còn `"none"`) giữ lại làm
     tham khảo lịch sử, KHÔNG còn đúng với trạng thái hiện tại:
     ~~Phát hiện qua test thật: mọi lần verify trước đó đều chạy qua SSH
     `docker compose exec ... curl http://localhost:8080/...` (Keycloak coi
     là "nội bộ" nên không bị chặn), nên gap này không lộ ra cho tới khi có
     người dùng trình duyệt thật kết nối tới `http://172.30.2.111:8080`
     (network path "external" thật sự) — Keycloak trả `403
     {"error":"invalid_request","error_description":"HTTPS required"}`,
     khiến SPA không bao giờ redirect được sang trang login.~~
4. Nếu VNNIC có LDAP/AD nội bộ, cấu hình User Federation trỏ tới đó thay vì
   tạo user cục bộ trong Keycloak (việc này thuộc Giai đoạn 3 theo roadmap,
   nhưng có thể làm sớm hơn nếu LDAP đã sẵn sàng).
