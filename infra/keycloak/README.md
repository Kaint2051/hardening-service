# Keycloak realm — Giai đoạn 0

`realm-export.json` được import tự động khi container khởi động lần đầu
(`start-dev --import-realm`). Thiết lập sẵn:

- 6 vai trò RBAC tối thiểu theo mục 4.7: `viewer`, `auditor`, `rule-editor`,
  `approver`, `operator`, `admin`.
- Client `orchestrator` (confidential, Authorization Code flow) cho backend.
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
3. **`start-dev` chỉ dùng cho local/dev** — production cần `start` với TLS
   thật, DB Postgres riêng cho Keycloak (không dùng H2 mặc định), và review
   lại `bruteForceProtected`/session timeout theo policy tổ chức.
4. Nếu VNNIC có LDAP/AD nội bộ, cấu hình User Federation trỏ tới đó thay vì
   tạo user cục bộ trong Keycloak (việc này thuộc Giai đoạn 3 theo roadmap,
   nhưng có thể làm sớm hơn nếu LDAP đã sẵn sàng).
