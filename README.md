# Linux Hardening Service Tool

Web-console quản lý hardening & cấu hình service cho máy chủ Linux. Kiến
trúc đầy đủ và lý do các quyết định thiết kế nằm ở
[`docs/architecture-proposal.md`](docs/architecture-proposal.md) — đọc file
đó trước khi đọc tiếp phần dưới.

Trạng thái hiện tại: **Giai đoạn 0 + Giai đoạn 1 hoàn thành**, **Giai đoạn 2
hoàn tất phần kỹ thuật thuần tuý** (xem checklist tương ứng bên dưới) — RBAC/
Control Registry/Host Registry/Job pipeline/Canary/Agent tự phát triển đều đã
verify end-to-end thật trên lab server (không chỉ unit test). Đường Active
Response (Agent thực thi remediation thật) đã nối dây + rà soát bảo mật + E2E
thật xong, kill-switch cố tình vẫn tắt chờ pentest riêng trước khi dùng thật
cho fleet — 2 hạng mục còn lại của Giai đoạn 2 (nội dung STIG/TCVN thật,
pentest Agent) không phải việc kỹ thuật, xem mục "Việc CHƯA làm" cuối file.

## Cấu trúc thư mục

```
docs/                     Tài liệu kiến trúc
docker-compose.yml         Postgres + Keycloak + step-ca + orchestrator
infra/
  postgres/init/           Script tạo role audit-only (INSERT/SELECT, không UPDATE/DELETE)
  keycloak/                Realm export (SSO/OIDC/MFA, 6 vai trò RBAC)
  step-ca/                 CA/SSH — README + script cấu hình provisioner
apps/
  orchestrator/            FastAPI: RBAC thật qua Keycloak (app/auth.py), Audit Log
                           hash-chain, Control/Host Registry, trigger scan (app/jobs.py)
  execution-env/           "Ephemeral Execution Environment" — scan.sh (oscap-ssh + SSG)
  job-dispatcher/          Service DUY NHẤT giữ quyền Docker, spawn container job
  web/                     Web UI khung sườn (React+TS+Vite+MUI), đăng nhập qua Keycloak
scripts/content-signing/   Quy trình 3 vai trò Puller/Reviewer/Signer (ký nội dung policy)
ansible/                   Playbook Zero-to-CA Migration (2 bước: deploy trust, rồi mới revoke credential cũ)
```

## Chạy thử local (Phase 0)

```bash
cp .env.example .env      # rồi đổi các giá trị "changeme"
docker compose up -d postgres keycloak step-ca
docker compose up -d --build orchestrator

# Kiểm tra
curl http://localhost:8000/healthz
```

Mọi endpoint khác (`/me`, `/controls`, `/internal/audit-events*`) yêu cầu
Bearer access token thật lấy từ Keycloak (RBAC — xem `app/auth.py`), không
còn nhận request không xác thực như bản demo Giai đoạn 0. Lấy token qua
Authorization Code flow (browser) với client `orchestrator`; client này cố
tình để `directAccessGrantsEnabled: false` (không hỗ trợ ROPC) — chỉ bật tạm
khi cần test tự động rồi tắt lại, xem cách làm trong lịch sử test RBAC.

Keycloak admin console: http://localhost:8080 (user/pass theo `.env`).

> Lưu ý (phát hiện khi test thật): Orchestrator chạy trong container riêng
> nên KHÔNG dùng `KEYCLOAK_ISSUER_URL` (URL công khai cho browser, vd
> `localhost:8080`) để tự fetch JWKS — container không resolve được tới
> `localhost` của host. Đã tách riêng `KEYCLOAK_INTERNAL_URL` (hostname docker
> network `keycloak:8080`) chỉ dùng để fetch JWKS, còn việc verify claim
> `iss` trong token vẫn dùng `KEYCLOAK_ISSUER_URL` như bình thường. Xem
> `app/config.py`.

Sau khi step-ca chạy lần đầu, siết TTL provisioner theo thiết kế:
```bash
./infra/step-ca/setup-provisioners.sh
```
> Lưu ý (phát hiện khi test thật): `--x509-*-dur` chỉ giới hạn x509 leaf
> cert. SSH user cert (loại cấp quyền đăng nhập không thường trực) phải siết
> riêng bằng `--ssh-user-*-dur` — nếu thiếu, step-ca mặc định cấp SSH cert
> TTL 16 giờ thay vì 5-15 phút như thiết kế. Script hiện đã có cả hai.

Playbook Ansible chỉ chạy được từ máy Linux/macOS (không chạy được trên
Windows kể cả không dùng WSL) — và `service` module cần tên unit đúng theo
distro (`ssh` trên Debian/Ubuntu, `sshd` trên RHEL/CentOS — biến
`sshd_service_name` trong `zero-to-ca-migration.yml` tự chọn theo
`ansible_os_family`).

## Checklist Giai đoạn 0 (đối chiếu mục 7 trong architecture-proposal.md)

- [x] CA/SSH hoạt động, host/network tách khỏi web console (`ca-net` riêng
      trong docker-compose.yml)
- [x] Keycloak: SSO/OIDC, 6 vai trò RBAC, MFA bắt buộc (CONFIGURE_TOTP)
- [x] Audit log append-only, hash-chain (enforce bằng Postgres GRANT, không
      chỉ code)
- [x] Ephemeral Execution Env pipeline (Dockerfile — **cần điền commit hash
      đã review vào `apps/execution-env/requirements.yml` trước khi build
      image thật**)
- [x] Content Signing Service — quy trình 3 vai trò, script tự chặn nếu trùng
      GPG key giữa Puller/Reviewer/Signer
- [x] Zero-to-CA Migration playbook (2 bước, canary `serial: 1`) — **đã chạy
      thật** (không chỉ syntax-check) trên Ubuntu 24.04: deploy trust → cấp
      SSH cert ngắn hạn thật từ step-ca → login bằng cert thành công → revoke
      credential cũ → xác nhận credential cũ bị từ chối. Xem ghi chú TTL SSH
      bên dưới.
- [ ] **Rà soát pháp lý ban đầu** (rủi ro #1, mục 8) — xác nhận với bộ phận
      pháp lý/quản lý VNNIC xem hệ thống có thuộc diện "hệ thống thông tin
      quan trọng về an ninh quốc gia" hay không, và OSS nước ngoài dùng ở đây
      (Keycloak/OpenBao-step-ca) có vướng yêu cầu kiểm định sản phẩm ATTT
      trong nước không. **Việc này làm song song, không chặn kỹ thuật, nhưng
      phải xong trước khi go-live thật.**
- [ ] Root CA hiện đang chạy online trong container (dev). Trước production:
      sinh root CA trên máy air-gapped — runbook + script đã chuẩn bị sẵn và
      đã rehearsal thật trên lab (xem checklist "Runbook + script sinh Root
      CA trên máy air-gapped" bên dưới), chỉ còn thiếu bước chạy nghi lễ thật
      trên phần cứng air-gapped thật của tổ chức (`infra/step-ca/root-ca-airgap-runbook.md`).
- [x] Đổi toàn bộ giá trị `changeme` trong `.env` và secret Keycloak client
      trước khi dùng ngoài môi trường dev cá nhân — đã xác nhận trên lab
      server: `grep -ic changeme .env` = 0 (không kiểm tra được độ mạnh của
      từng secret vì không đọc giá trị thật, chỉ xác nhận không còn
      placeholder mặc định).
      - **[HIGH, phát hiện thêm khi rà lại mục này] `.env` đã sạch nhưng
        `infra/keycloak/realm-export.json` lại hardcode sẵn 1 secret thật
        (`changeme-in-prod-use-env-secret`) cho client `orchestrator`, và
        secret đó đã được commit + **push lên GitHub public**
        (`github.com/Kaint2051/hardening-service`, commit gốc `f2a4b10`) mà
        chưa ai đổi lại — verify thật trên lab server: secret live trên
        Keycloak vẫn trùng y hệt chuỗi trong file. Đã sửa: (1) rotate secret
        live qua Keycloak Admin API, (2) bỏ hẳn field `"secret"` khỏi
        `realm-export.json` (Keycloak tự sinh ngẫu nhiên lúc import nếu
        thiếu field này), (3) rewrite lại đúng commit đó (amend, không tạo
        commit mới) để xoá chuỗi khỏi git history, force-push đè lên
        `origin/main` (đã xác nhận qua GitHub raw content: 0 occurrence).
        Chi tiết đầy đủ + lý do không cần rewrite sâu hơn (chỉ 1 commit duy
        nhất trong toàn bộ history) xem `infra/keycloak/README.md`.

## Checklist Giai đoạn 1 (đang làm — mục 7 architecture-proposal.md)

- [x] RBAC thật trong Orchestrator API qua Keycloak (`app/auth.py`) — verify
      JWT bằng JWKS thật (RS256), chặn theo 1 trong 6 vai trò realm, kiểm tra
      `azp` khớp client `orchestrator`. **Đã verify end-to-end bằng token
      Keycloak thật** (không mock): tạo user/role thật qua Admin API, lấy
      access token thật, xác nhận đúng 200/403/401 cho từng vai trò.
- [x] Control Registry — schema `controls`/`standard_mappings`/
      `remediation_variants` (migration 0002) + CRUD API (`app/controls.py`):
      rule-editor/admin tạo control (mặc định `maturity=draft`), mọi vai trò
      đọc, approver/admin chuyển maturity. **Four-eyes cho duyệt maturity đã
      verify thật**: người tạo control (kể cả có role approver) bị chặn tự
      duyệt chính control của mình (403), người khác duyệt được (200).
- [x] Sửa lỗi actor-spoofing ở `/internal/audit-events`: `actor` giờ lấy từ
      token đã xác thực, không nhận từ request body như bản demo cũ.
- [x] Host Registry — bảng `hosts` (migration 0003) + CRUD API
      (`app/hosts.py`): operator/admin đăng ký máy + cập nhật
      `ca_migration_status` (not_started/trust_deployed/migrated — bám theo
      runbook `ansible/README.md`), mọi vai trò đọc/lọc theo trạng thái. Đã
      verify end-to-end bằng token Keycloak thật.
- [x] Job/scan thật qua Ephemeral Execution Environment (`app/jobs.py`,
      `apps/job-dispatcher/`, `apps/execution-env/scan.sh`) — kiến trúc:
      Orchestrator tự cấp SSH cert ngắn hạn cho từng job (`app/ca_client.py`,
      gọi step-ca trực tiếp) rồi gọi **job-dispatcher** (service DUY NHẤT giữ
      `/var/run/docker.sock`, không public port, chỉ chạy đúng 1 image được
      allowlist) để spawn container execution-env chạy `oscap-ssh` (SSG —
      xem lưu ý licence bên dưới) rồi tự huỷ. **Đã verify end-to-end thật**:
      đăng ký host → trigger scan qua API thật → cấp cert thật → spawn
      container thật → SSH thật vào target → OpenSCAP scan thật → parse kết
      quả → cập nhật Job + audit log. Kết quả gồm cả **chi tiết từng rule**
      (`result_summary.findings`: rule_id/title/result/severity, chỉ giữ
      pass/fail — bỏ notapplicable để tránh phình dữ liệu), không chỉ số đếm
      tổng. Toàn bộ chuỗi bug thật tìm thấy qua test (không phải chỉ đọc
      code) đã sửa — xem mục ghi chú vận hành bên dưới. Sau đó có thêm sửa
      lỗi qua code review (allowlist `ssh_user`, four-eyes host migration —
      xem mục ngay trên), nâng tổng lên **32/32 unit test pass** (thêm 1 sau
      khi vá bug bypass four-eyes mô tả bên dưới) — đã
      rebuild lại `orchestrator`/`job-dispatcher` và rerun `pytest` thật
      trên lab server để xác nhận (không chỉ đọc code). Cả 2 fix cũng đã
      verify end-to-end thật qua API thật bằng token Keycloak thật: trigger
      scan với `ssh_user` khác "root" trên host đã đăng ký trả về 422 đúng
      như thiết kế; host Tier 1 — operator A đặt `trust_deployed` rồi tự
      xác nhận `migrated` bị chặn 403 (four-eyes), operator B xác nhận được
      200, và bảng `audit_log` chỉ ghi đúng 2 sự kiện thành công (lần bị
      chặn 403 không ghi audit — đúng thiết kế).
- [x] Mở rộng four-eyes ra ngoài Control maturity (mục 1.3
      architecture-proposal.md: "four-eyes cho mọi thay đổi trên
      production/Tier cao") + vá lỗ hổng thiếu audit: xác nhận
      `ca_migration_status="migrated"` cho host Tier 0/1 (`Host.tier <= 1`)
      không được do đúng người vừa đặt `trust_deployed` tự xác nhận nốt
      (migration 0005 thêm cột `hosts.ca_migration_updated_by`) — Tier 2
      (mặc định) chưa cần vì chưa phải "production/Tier cao". Trigger scan
      KHÔNG cần four-eyes vì không đổi state trên target (chỉ đọc). Nhân
      tiện phát hiện qua review: `update_control_maturity` (đã có four-eyes
      từ trước) và cập nhật `ca_migration_status` đều **chưa từng ghi audit
      log** dù đây đúng là loại hành động audit hash-chain sinh ra để theo
      dõi — đã thêm `write_audit_event` cho cả hai.
      **BUG THẬT phát hiện sau đó qua gọi API trực tiếp (không phải đọc
      code)**: check four-eyes ở trên có thể bị bỏ qua hoàn toàn bằng cách
      nhảy thẳng `not_started -> migrated` (bỏ qua `trust_deployed`) — lúc đó
      `ca_migration_updated_by` vẫn là `None`, guard `is not None` tự tắt cả
      điều kiện four-eyes, cho phép 1 operator một mình xác nhận `migrated`
      cho host Tier cao. Verify được bằng call API thật (200 trước fix, 422
      sau fix). Đã sửa: bắt buộc `ca_migration_status` hiện tại phải là
      `trust_deployed` mới được chuyển sang `migrated`, mọi trường hợp khác
      trả 422 — nhờ vậy `ca_migration_updated_by` luôn chắc chắn không còn
      `None` tại thời điểm check four-eyes chạy.
- [x] Web UI khung sườn (`apps/web/` — React + TypeScript + Vite + MUI, xem
      `apps/web/README.md`): đăng nhập qua Keycloak thật (Authorization Code
      + PKCE, client public **`web`** riêng — KHÔNG dùng chung client
      `orchestrator` confidential đang dùng cho service/test), trang Hosts
      (đăng ký/list/cập nhật ca_migration_status/trigger scan + xem per-rule
      findings) và Controls (tạo/list/duyệt maturity/standard mapping/
      remediation variant). Serve bằng nginx sau khi build tĩnh.
      **Phát sinh thêm khi build** (không phải đọc code suông — lộ ra vì đây
      là client đầu tiên chạy trong trình duyệt thật, không phải service/SSH
      curl như trước giờ):
        - Orchestrator thiếu **CORS middleware** — SPA khác origin (`:3000`
          vs API `:8000`) sẽ bị trình duyệt chặn mọi request; đã thêm
          `CORSMiddleware` allowlist đúng 1 origin (`WEB_ORIGIN`), không dùng
          `"*"` vì request có gửi `Authorization` header thật.
        - Check `azp` trong `app/auth.py` trước đó hardcode đúng 1 client
          (`orchestrator`) — token cấp cho client `web` sẽ luôn bị 401. Đổi
          `keycloak_client_id` (1 giá trị) thành `keycloak_client_ids` (danh
          sách phân cách dấu phẩy, mặc định `orchestrator,web`) + verify
          thật bằng token thật của client `web` (trước fix 401, sau fix 200
          trên `/me`).
        - **`KEYCLOAK_ISSUER_URL=http://localhost:8080/...` chỉ đúng nếu
          trình duyệt và Keycloak chạy cùng máy** — với Web UI chạy trong
          trình duyệt thật (không phải SSH curl trên chính lab server),
          "localhost" trong JWT `iss` sẽ không khớp. Đổi sang IP thật của
          lab server (`172.30.2.111`) — phải cập nhật lại toàn bộ script
          test thật (`scan_e2e_test.sh`, `fourseyes_e2e_test.sh`) dùng cùng
          IP để lấy token, rerun lại xác nhận không có gì gãy (31/31 pytest
          + 2 kịch bản e2e đều pass sau khi đổi).
      Chưa làm trong khung sườn: trang liệt kê toàn bộ job (backend chưa có
      `GET /jobs`, chỉ có `GET /jobs/{id}`), UI tự ẩn nút theo role (RBAC vẫn
      do Orchestrator enforce đầy đủ, UI chỉ hiển thị lỗi 403 trả về).
- [x] **Rà soát bảo mật/logic toàn bộ codebase qua multi-agent workflow**
      (7 hướng độc lập: RBAC/four-eyes, job pipeline & secrets, audit log
      integrity, web frontend, infra/network config, schema validation, test
      coverage gaps — mỗi phát hiện được 3 "skeptic" độc lập phản biện, chỉ
      giữ lại nếu ≥2/3 không bác bỏ được). Kết quả: **17/17 phát hiện được
      xác nhận** (0 bị bác bỏ). Đã sửa toàn bộ, verify lại bằng cả
      pytest (52/52 pass) lẫn API thật cho 2 lỗi nghiêm trọng nhất:
        - **[HIGH] SSRF qua `ip_address` không kiểm tra** — `HostCreate.
          ip_address` trước đây là `str` tự do, dùng thẳng làm `TARGET_HOST`
          cho `oscap-ssh` với `StrictHostKeyChecking=no`. Một operator có
          thể đăng ký "host" trỏ vào endpoint nội bộ nhạy cảm (vd
          `169.254.169.254` — cloud metadata) rồi trigger scan, khiến SSH
          cert `root` thật (mint riêng cho job) bị gửi thẳng tới đó. Đã sửa:
          validate `ip_address` là IPv4/IPv6 hợp lệ, chặn
          loopback/link-local/multicast/reserved; thêm charset cho
          `hostname`. Verify thật: `169.254.169.254` → 422 sau fix.
        - **[HIGH] Four-eyes trên Control maturity="production" có thể bị
          bypass qua nội dung** — `add_standard_mapping`/
          `add_remediation_variant` không hề kiểm tra `maturity`, nên chính
          rule-editor đã tạo control (không cần là approver) có thể tự ý
          đổi `remediation_ref` (con trỏ nội dung Agent Active Response tin
          tưởng thực thi) SAU KHI đã được approver duyệt production, mà
          maturity vẫn hiển thị "production" như thể nội dung đã được
          review. Đã sửa: thêm/sửa mapping hoặc variant cho 1 control đang
          "production" sẽ tự động đưa control về "draft" (ghi audit
          `content_changed_after_production`), buộc phải qua lại four-eyes
          của `update_control_maturity` để production phản ánh đúng nội
          dung đã duyệt. Verify thật: control production → rule-editor tự
          thêm remediation-variant → maturity tự về "draft".
        - **[MEDIUM] 4 endpoint mutate DB nhưng chưa từng ghi audit event**:
          `create_control`, `add_standard_mapping`, `add_remediation_variant`,
          `register_host` — đã thêm `write_audit_event` cho cả 4.
        - **[MEDIUM] `mint_ssh_certificate` chỉ raise `RuntimeError` cho lỗi
          "step-ca từ chối cấp"**, không bọc lỗi timeout (`subprocess.
          TimeoutExpired`)/lỗi hệ thống (`OSError`, vd thiếu binary `step`)
          — các lỗi này lọt qua `except RuntimeError` ở `jobs.py`, khiến Job
          kẹt vĩnh viễn ở `status="running"` không bao giờ được đánh dấu
          failed. Đã sửa: `ca_client.py` bọc toàn bộ lỗi cấp cert (kể cả
          timeout/OSError) thành `RuntimeError`, giữ đúng hợp đồng "raise
          RuntimeError cho mọi lỗi cấp cert".
        - **[MEDIUM] `AuditLog.record_hash` thiếu `unique=True` trong ORM
          model** dù migration 0001 đã tạo cột này với UNIQUE constraint —
          lệch schema nếu ai đó provision bảng qua `Base.metadata.
          create_all()` thay vì Alembic (đúng pattern các bảng khác đã dùng
          trong test). Đã thêm `unique=True` vào model cho khớp.
        - **[MEDIUM] Nhiều field text tự do không giới hạn độ dài**
          (`ControlCreate.title/category`, `StandardMappingCreate.*`,
          `RemediationVariantCreate.*`, `HostCreate.hostname/os_family/
          os_version`) — chuỗi quá dài qua được Pydantic rồi mới vỡ ở tầng
          INSERT Postgres thật (`VARCHAR(N)`) thành lỗi 500 không kiểm soát
          được thay vì 422 sạch (SQLite dùng trong test không tự enforce
          VARCHAR(N) nên bug không lộ qua test cũ). Đã thêm `max_length`
          khớp đúng kích thước cột DB cho toàn bộ field liên quan.
        - **[LOW/MEDIUM] 6 lỗ hổng test coverage** (nhánh lỗi cấp cert
          `RuntimeError` trong `trigger_scan`, 404 của `GET /jobs/{id}` và
          `GET /controls/{id}`, RBAC chặn non-approver trên `PATCH .../
          maturity`, giá trị maturity không hợp lệ, RBAC + 404 của
          add-mapping/add-variant) — mỗi nhánh này trước đây không có test
          nào chạy tới, có thể regression âm thầm mà không ai biết. Đã thêm
          đủ test cho từng nhánh (tổng 52 test, từ 31 trước đó).
        - **[LOW, chấp nhận không sửa]** `update_control_maturity` chưa có
          state-machine validation (1 approver có thể tự đổi production ->
          draft -> production nhiều lần không qua "reviewed", không cần
          approver thứ 2 mỗi lần) — với fix "tự demote khi đổi nội dung" ở
          trên, việc draft->production lặp lại giờ là luồng BÌNH THƯỜNG
          (nội dung đổi -> cần duyệt lại), không phải lỗi; four-eyes
          creator-vs-approver vẫn được enforce mỗi lần. Xây state-machine
          đầy đủ (bắt buộc qua "reviewed", đổi approver mỗi vòng) cần thêm
          bảng lịch sử phê duyệt — vượt phạm vi "khung sườn", để dành cho
          hạng mục "versioning lịch sử thay đổi Control" bên dưới.
- [x] **Rà soát thủ công lại lần 2 sau đợt workflow trên** — phát hiện thêm
      1 bug thật qua test API trực tiếp (không chỉ đọc code):
        - **[MEDIUM] `add_standard_mapping`/`add_remediation_variant` insert
          thẳng, không bắt `IntegrityError`** khi vi phạm
          `uq_standard_mapping` (control_id, standard, standard_version,
          section_id) hoặc `uq_remediation_variant` (control_id, os_family,
          os_version) — 1 rule-editor submit trùng (double-submit form, hoặc
          2 rule-editor cùng thêm 1 mapping) làm lộ nguyên
          `IntegrityError` thành `500 Internal Server Error` thay vì `409`
          sạch. Verify thật trên API thật (Postgres, không phải SQLite test)
          trước fix: cả 2 endpoint trả `500`. Đã sửa: bọc `db.commit()` bằng
          `try/except IntegrityError` → `db.rollback()` + `409`. Verify lại:
          cả 2 trả `409` với message rõ ràng. Thêm 2 test
          (`test_duplicate_standard_mapping_rejected_with_409_not_500`,
          `test_duplicate_remediation_variant_rejected_with_409_not_500`) —
          tổng 54 test (từ 52).
      Cũng rà lại `apps/job-dispatcher/`, `apps/execution-env/{entrypoint,
      scan}.sh`, `docker-compose.yml` (network isolation, image allowlist,
      shared-secret auth) — không phát hiện thêm bug cụ thể nào chứng minh
      được bằng exploit thật; ghi nhận 1 rủi ro lý thuyết chấp nhận được:
      nếu `job-dispatcher` bị crash đúng lúc giữa `containers.run()` và
      `finally: container.remove()`, container job có thể bị mồ côi (không
      ai dọn) — cửa sổ rủi ro nhỏ, cert SSH bên trong hết hạn sau 5-15 phút
      (TTL provisioner), chưa đủ mức ưu tiên để thêm cơ chế reconciliation
      riêng ở khung sườn này.
- [x] **Rà soát thủ công lại lần 3** — mở rộng phạm vi sang các phần chưa
      từng qua review sâu (`apps/web/`, `ansible/`, `scripts/content-signing/`,
      và các file lõi `app/auth.py`/`app/audit.py`/`app/db.py` chưa bị đụng
      tới trong 2 lần trước). Dùng 2 agent song song rà `apps/web/` và
      `ansible/`+`scripts/content-signing/`, tự đọc `auth.py`/`audit.py`/`db.py`:
        - **[MEDIUM] `get_current_user` chấp nhận cả ID token, không chỉ
          access token** — Keycloak ID token và access token dùng chung
          issuer/azp, chỉ khác claim `"typ"` (`"ID"` vs `"Bearer"`); trước đây
          không kiểm tra claim này. Verify thật: lấy cả `access_token` lẫn
          `id_token` từ 1 lần đăng nhập password-grant, gọi `GET /me` bằng
          `id_token` → **200** (đáng lẽ phải 401). Impact hiện tại bị giới hạn
          vì `realm_access` rỗng trong ID token của realm này (mọi endpoint
          có `require_roles()` vẫn tự chặn 403) — nhưng đây là anti-pattern
          OIDC đã biết, và bất kỳ endpoint mới nào chỉ dùng
          `Depends(get_current_user)` mà quên `require_roles()` sẽ lập tức bị
          ảnh hưởng. Đã sửa: thêm kiểm tra `claims.get("typ") != "Bearer"` →
          401. Verify lại: `id_token` → 401, `access_token` vẫn 200 bình
          thường.
        - **[LOW] `apps/web/nginx.conf` không có header bảo mật nào** (không
          CSP/X-Frame-Options/X-Content-Type-Options) — SPA có thể bị nhúng
          iframe (clickjacking) và không có lớp phòng thủ thứ 2 nếu lỡ có
          XSS (dù review không tìm thấy XSS cụ thể nào — token lưu in-memory
          qua keycloak-js mặc định, không phải localStorage; mọi dữ liệu API
          render qua JSX nên React tự escape). Đã thêm đủ 4 header; verify
          qua `curl -I` trên lab server thấy đúng cả 4. `connect-src *` cố
          tình để mở (API/Keycloak URL khác origin, chỉ biết lúc build qua
          Vite build-arg, nginx.conf lại là file tĩnh không template hoá) —
          chấp nhận đánh đổi này ở khung sườn, có thể thắt chặt sau bằng
          cách envsubst nginx.conf theo cùng build-arg.
        - **[LOW] `scripts/content-signing/{review,sign}.sh`: check "khác
          key Puller/Reviewer" và lệnh `gpg` ký thật có thể dùng 2 key khác
          nhau** — `current_signer_fingerprint()` chỉ lấy secret key ĐẦU TIÊN
          trong keyring để so sánh, nhưng lệnh `gpg --clearsign`/`--detach-sign`
          ngay sau đó không truyền `--local-user` nên GPG tự chọn key mặc
          định của máy — nếu keyring có nhiều secret key, 2 key này không
          đảm bảo là một. Đã sửa: thêm `--local-user "$REVIEWER_FPR"` /
          `--local-user "$SIGNER_FPR"` để pin đúng key đã kiểm tra vào lệnh
          ký thật. Đã `bash -n` cả 3 script, chưa test end-to-end với GPG
          thật (cần bộ key riêng cho từng vai trò, ngoài phạm vi lần rà này).
        - **[LOW] `pull.sh`: `NAME` (tham số CLI) không được validate** trước
          khi ghép vào đường dẫn thư mục `staging/${NAME}-${STAMP}` — `NAME`
          chứa `../` có thể ghi ra ngoài `staging/` (path traversal), chứa
          `"` sẽ làm hỏng cấu trúc JSON của `manifest.json` (ghi bằng heredoc,
          không escape). `NAME` là tham số CLI do Puller tự gõ (không phải
          input từ mạng/attacker) nên rủi ro thấp, nhưng sửa rẻ nên vẫn làm:
          chặn còn lại `[a-zA-Z0-9._-]+`.
      Không phát hiện gì thêm ở `apps/web/` (token storage, PKCE, XSS, CORS
      đều ổn), ở `ansible/*.yml` (gate xác nhận thủ công + `serial: 1` +
      `max_fail_percentage: 0` đều là cơ chế Ansible thực thi thật, không
      phải comment trang trí), hay ở `verify.sh`/phần lõi mật mã của
      `sign.sh` (không có TOCTOU, không trust theo tên file, có strict
      fingerprint compare).
- [x] **[HIGH] `sslRequired: "external"` của Keycloak chặn hoàn toàn đăng
      nhập qua trình duyệt thật** — phát hiện KHÔNG PHẢI qua review đọc code
      mà qua chính người dùng thật báo "không thấy trang login" khi mở
      `http://172.30.2.111:3000` lần đầu. Nguyên nhân: mọi lần verify trước
      đó (kể cả toàn bộ 3 vòng rà soát ở trên) đều gọi Keycloak qua SSH
      `docker compose exec ... curl http://localhost:8080/...` — Keycloak
      coi nguồn `localhost` là "nội bộ" nên bỏ qua yêu cầu HTTPS; gap này
      không thể lộ ra qua bất kỳ cách test nào chạy từ trong SSH session,
      CHỈ lộ khi có kết nối "external" thật (trình duyệt người dùng, hoặc
      `curl` từ máy khác gọi thẳng `172.30.2.111:8080`) — lúc đó Keycloak trả
      `403 {"error":"invalid_request","error_description":"HTTPS required"}`,
      khiến `keycloak-js` không bao giờ khởi tạo xong để redirect sang trang
      login. Đã sửa (sau khi xác nhận với người dùng vì đây là nới lỏng cấu
      hình bảo mật): đổi `sslRequired` từ `"external"` về `"none"` — chấp
      nhận được ở dev/lab vì TOÀN BỘ hệ thống (web/API/Keycloak) hiện chưa có
      TLS ở đâu cả; **bắt buộc đổi lại `"external"`/`"all"` khi có TLS thật
      trước production**, nếu không mật khẩu/token sẽ đi qua mạng dạng
      plaintext. Verify lại: endpoint `.well-known/openid-configuration` và
      `protocol/openid-connect/auth` gọi từ ngoài (không qua SSH) đều trả
      `200` thay vì `403`. Xem chi tiết `infra/keycloak/README.md`.
        - **Root cause thứ 2 (sau khi sslRequired đã sửa, vẫn trắng trang)**:
          `keycloak.init()` mặc định `checkLoginIframe: true` — tự chèn 1
          iframe ẩn trỏ sang origin Keycloak (khác port với SPA → khác
          origin, bị coi third-party) để phát hiện đăng xuất ở tab khác. Cơ
          chế này cần trình duyệt cho phép storage/cookie third-party trong
          iframe — trình duyệt chặn mặc định (người dùng dùng Brave, có
          Shields chặn third-party mặc định; Safari ITP và dần các trình
          duyệt khác cũng vậy) làm bước check treo vĩnh viễn, `init()` không
          bao giờ resolve, app không bao giờ redirect sang trang login.
          Người dùng gửi ảnh chụp DevTools xác nhận: root div rỗng, chỉ có 1
          `<iframe src=".../3p-cookies/step1.html" style="display:none">`.
          Đã sửa: `checkLoginIframe: false` trong `main.tsx` — không mất bảo
          mật (mỗi request API vẫn tự `updateToken()` riêng), chỉ mất khả
          năng tự phát hiện logout ở tab khác (không phải yêu cầu của khung
          sườn này).
- [x] **Versioning lịch sử thay đổi Control** — bảng `control_versions`
      (migration 0006), ghi 1 dòng mỗi khi: tạo control, đổi maturity (kể cả
      auto-demote), thêm standard mapping, thêm remediation variant.
        - Cố tình **KHÔNG dùng chung cơ chế với `audit_log`** (bảng audit
          dùng session/role Postgres riêng — `orchestrator_audit`, chỉ
          INSERT/SELECT — không atomic với thay đổi nghiệp vụ, xem
          `app/audit.py`). `control_versions` ghi trong CÙNG session/
          transaction với thay đổi thực tế (`db.add(...)` + `db.commit()`
          chung với `Control`/`StandardMapping`/`RemediationVariant`), nên
          không thể lệch khỏi trạng thái thật kể cả khi ghi audit log gặp sự
          cố — và khi `add_standard_mapping`/`add_remediation_variant` bị
          `IntegrityError` (trùng), dòng lịch sử của lần thất bại đó cũng
          rollback theo, không để lại rác. `audit_log` vẫn là nguồn
          tamper-evident duy nhất cho toàn hệ thống; bảng này chỉ phục vụ
          xem lịch sử MỘT control cụ thể mà không phải lọc trong audit log
          dùng chung.
        - `GET /controls/{id}/history` — mọi role đã đăng nhập đọc được (đọc
          không hạn chế hơn `GET /controls/{id}` sẵn có).
        - Web UI: `ControlsPage.tsx` hiển thị lịch sử ngay trong dialog chi
          tiết control, load song song với detail lúc mở dialog.
        - Verify: 57/57 pytest pass (thêm 3 test, gồm 1 test full lifecycle
          — created → mapping → reviewed → production → variant (tự demote)
          — và 1 test xác nhận không để lại dòng lịch sử mồ côi khi trùng
          key). Verify thêm bằng API thật (Postgres) qua kịch bản đúng chuỗi
          trên, thứ tự và nội dung từng dòng khớp 100% với kỳ vọng. Docker
          build frontend (`tsc && vite build`) qua không lỗi — **chưa mở
          trình duyệt thật để xem UI** (môi trường hiện tại không có công cụ
          browser automation), chỉ verify qua build + API contract khớp.
- [~] **`job_type="remediate-dry-run"`/`"remediate-apply"`** — pipeline
      remediation qua Ansible (agentless), điều kiện tiên quyết cho "canary
      tự động cho control Nhóm A" (Giai đoạn 2). **Pipeline/plumbing đã xong
      và verify E2E thật** — nội dung remediation thật vẫn chờ commit hash
      Ansible role đã review (`apps/execution-env/requirements.yml`, KHÔNG
      tự điền — quyết định của Reviewer, đúng nguyên tắc tách 3 vai trò Giai
      đoạn 0) + 1 public key Signer thật (`apps/execution-env/trusted-signer-pubkey.asc`,
      hiện là placeholder, xem chi tiết bên dưới):
        - Đã bàn thiết kế qua Plan Mode trước khi code (3 quyết định người
          dùng chọn: four-eyes chỉ Tier 0/1 khớp tiền lệ CA migration, backup
          cơ bản ngay pass này, dry-run/apply 2 endpoint tách biệt).
        - 2 endpoint mới (`app/jobs.py`): `POST
          /hosts/{hostname}/controls/{control_id}/remediate/dry-run` (chạy
          `ansible-playbook --check --diff`, KHÔNG đổi gì) và
          `.../remediate/apply` (bắt buộc tham chiếu đúng 1 dry-run đã
          `succeeded`, còn mới trong 30 phút — không có đường tắt "apply
          trực tiếp", đúng nguyên tắc cốt lõi #2). `RemediationVariant` chọn
          TỰ ĐỘNG theo distro/version máy đích (không cho client tự chọn,
          khác `scap_profile_key` của scan — remediate rủi ro cao hơn).
        - **Maturity gate**: control `draft` chỉ cho dry-run, chặn apply
          thật (422) — đúng nguyên tắc mục 3 kiến trúc.
        - **Four-eyes CHỈ Tier 0/1** (khớp tiền lệ CA migration,
          `app/hosts.py`): người đề xuất dry-run không được tự duyệt apply
          cho host Tier cao (403); Tier 2 không cần người thứ 2.
        - **Backup cơ bản TRƯỚC khi apply thật** (nguyên tắc cốt lõi #7,
          KHÔNG phải mục có thể trì hoãn): `remediate.sh` tar
          `/etc/ssh /etc/pam.d /etc/sysctl.conf /etc/sysctl.d /etc/security
          /etc/login.defs` trước khi chạy playbook thật, nhúng base64 vào
          `Job.result_summary.backup_tar_b64` (giới hạn 2 MiB) — MVP, CHƯA
          có "1-click restore" tự động.
        - **`remediate.sh` (mới) tự verify chữ ký GPG bundle trước khi chạy
          bất cứ gì** — tái dùng đúng cơ chế
          `scripts/content-signing/lib-gpg-fingerprint.sh`. Phát hiện quan
          trọng qua thiết kế: container chạy job mới mỗi lần có keyring GPG
          TRỐNG — biết fingerprint tin cậy (biến môi trường) là chưa đủ, cần
          CHÍNH public key đó nằm trong keyring mới verify được. Giải pháp:
          bake public key vào IMAGE lúc build
          (`apps/execution-env/trusted-signer-pubkey.asc`, cùng tinh thần
          `requirements.yml` pin theo commit hash) — hiện là placeholder,
          `remediate.sh` **từ chối MỌI bundle** cho tới khi Signer thật cung
          cấp public key thật (an toàn mặc định, đã verify thật bằng cách
          bake 1 key thử nghiệm, test full pipeline OK, rồi revert lại
          placeholder và xác nhận CHÍNH bundle vừa chạy được giờ bị từ chối).
        - Phát hiện quan trọng khác qua khảo sát: `job-dispatcher`'s
          `containers.run()` từ trước tới giờ **không hề mount volume nào**
          dù comment/README nói content SCAP "mount read-only lúc chạy
          container" — scan chưa bao giờ thực sự cần nó (SCAP content apt-
          install sẵn trong image). Remediate là nơi ĐẦU TIÊN cần mount thật
          — đã thêm (`CONTENT_SIGNING_SIGNED_HOST_PATH`, phải là đường dẫn
          HOST DOCKER thật vì job-dispatcher chạy Docker-outside-of-Docker).
        - Verify: 26/26 test mới trong `test_jobs.py` (variant không khớp
          distro, maturity draft, dry-run thiếu/hết hạn/sai host/control,
          four-eyes đúng Tier 0/1 và KHÔNG chặn Tier 2, backup xuất hiện
          trong response), 9 test mới cho `job-dispatcher` (thư mục
          `tests/` đầu tiên của service này — chạy qua container
          python:3.12-slim tạm, KHÔNG bake pytest vào image production vì
          đây là service duy nhất giữ quyền Docker). Verify E2E thật trên
          lab server: sinh GPG key thử nghiệm + playbook tối giản (chỉ tạo
          1 marker file, không phải nội dung hardening thật) → dry-run thật
          xác nhận không đổi gì trên host đích → four-eyes chặn đúng user đã
          dry-run trên Tier 0 (403) → apply thật với user khác thành công,
          marker được tạo + backup 63 KB xuất hiện trong response.
        - **Bug thật tìm được qua chính live E2E này** (không phải chỉ đọc
          code): (1) `remediate.sh`/`entrypoint.sh` bị lưu với line-ending
          CRLF (Windows) khi tạo file trên máy local, khiến shebang
          `#!/usr/bin/env bash` báo lỗi `bash\r: No such file or directory`
          — sửa bằng `sed -i 's/\r$//'` cả local lẫn lab server. (2) execution-env
          Dockerfile thiếu gói `gnupg` (chỉ phát hiện khi thật sự cần `gpg`
          cho remediate, scan không cần) — đã thêm vào layer apt-get.
      **CHƯA làm**: nội dung remediation thật (chờ Reviewer) — cần chuyên
      môn compliance, không phải việc kỹ thuật thuần. ("1-click restore" và
      giới hạn tài nguyên khi chạy song song nhiều job đã xong, xem 2 mục
      tương ứng bên dưới.) Xem `apps/execution-env/README.md` để biết đầy đủ
      convention bundle (`playbook.yml` + `content.tar.gz(.sig)`).
- [x] **Canary tự động cho control Nhóm A (Giai đoạn 2, mục 4.5/7)** —
      `Control.risk_group` ("A"/"B", mặc định "B") + `POST
      /controls/{id}/canary-rollout` tự động dry-run rồi apply NGAY lần lượt
      từng host Tier 2 đủ điều kiện (tự phát hiện qua `RemediationVariant`,
      không cho chọn tay), dừng ngay khi 1 host lỗi (giống
      `max_fail_percentage: 0` của Ansible), chạy nền qua FastAPI
      `BackgroundTasks` (202 trả về ngay, poll `GET /canary-rollouts/{id}`) —
      xem `apps/orchestrator/app/canary.py`.
      3 quyết định thiết kế người dùng chọn qua AskUserQuestion: chạy bất
      đồng bộ (không treo request 10-30 phút); Tier 0/1 loại HOÀN TOÀN khỏi
      tự động (four-eyes hiện có sẽ luôn chặn nếu 1 actor tự động vừa
      dry-run vừa apply — Tier 0/1 vẫn bắt buộc qua luồng thủ công 2 người);
      `risk_group="A"` chỉ tồn tại khi `maturity=="production"` (bất biến
      enforce ở PATCH `/controls/{id}/risk-group`, tự reset về "B" ở CẢ 2
      đường có thể đưa control rời khỏi production — `_demote_if_production`
      VÀ `update_control_maturity` trực tiếp, phát hiện có 2 đường qua rà
      soát chứ không phải 1).
      Khoá đồng thời 1 rollout/control bằng partial unique index Postgres
      (`ux_canary_rollouts_running ... WHERE status='running'`), không chỉ
      check-rồi-insert ở tầng app. `run_remediate_dry_run`/`run_remediate_apply`
      (trước đây là thân riêng của 2 endpoint remediate) được tách thành hàm
      public dùng chung giữa luồng thủ công và canary — đảm bảo four-eyes/
      staleness/audit event không bao giờ lệch nhau giữa 2 đường.
      **Quy trình xây dựng**: research + design bằng Agent tool (khảo sát
      xác nhận chưa có field phân loại rủi ro/endpoint multi-host/host
      grouping nào, "canary" hiện có hoàn toàn thủ công qua Ansible
      `--limit`), 1 Plan agent phản biện hướng đi (đề xuất chạy bất đồng bộ
      thay vì đồng bộ — được chọn), Plan Mode + 2 AskUserQuestion chốt thiết
      kế, rồi 1 Workflow 3 chặng (backend core → test+frontend song song →
      rà soát đối kháng toàn diff) thực thi.
      **Bug thật tìm được qua chạy test thật** (không phải chỉ đọc code):
      `CanaryRollout.cancel_requested` khai báo `server_default="false"`
      (chuỗi Python trần, không phải `sa.false()`) — Postgres tự cast đúng
      nhưng SQLite (test) lưu nguyên chuỗi và coi mọi chuỗi non-empty là
      truthy, khiến MỌI rollout mới tạo "sinh ra đã bị cancel" khi test qua
      SQLite — sửa dùng `sa.false()` (construct SQL, đúng theo dialect).
      **2 lỗ hổng thật tìm được qua rà soát đối kháng, đã vá + có test hồi
      quy riêng**: (1) Job của 1 host raise exception (vd `mint_ssh_certificate`
      lỗi) thay vì trả về status="failed" bình thường trước đây KHÔNG được
      gắn `canary_rollout_id` (vì canary.py chỉ gán SAU KHI hàm return, mà
      đường raise không bao giờ return) — khiến `GET /canary-rollouts/{id}`
      không thấy job gây lỗi dù `aborted_hostname` vẫn đúng; sửa bằng cách
      gán `canary_rollout_id` NGAY lúc tạo Job trong `app/jobs.py`, trước khi
      dispatch, không phải sau khi trả về. (2) 1 phần code trong vòng lặp nền
      (đọc `cancel_requested` đầu mỗi vòng, commit/audit nhánh cancel và sau
      khi hết vòng lặp) nằm NGOÀI try/except bảo vệ — lỗi DB tạm thời ở đó có
      thể khiến rollout kẹt mãi ở "running"; thêm 1 lớp try/except bao toàn
      bộ hàm làm lưới an toàn cuối.
      Verify: 106 test pytest pass (thêm 1 test hồi quy cho bug (1) ở trên),
      `tsc --noEmit` + `vite build` (bên trong Docker build thật) pass không
      lỗi kiểu. **E2E thật trên lab server** (dùng bundle KHÔNG TỒN TẠI có
      chủ đích để test đường lỗi mà không cần nội dung remediation thật):
      tạo 2 user throwaway qua Keycloak Admin API, control+host+variant thật,
      `POST canary-rollout` trả 202 ngay (không treo) → poll `GET
      /canary-rollouts/{id}` thấy chuyển từ "running" sang "aborted" sau ~6s
      (chứng minh `BackgroundTasks` THẬT chạy, không chỉ mock trong test) với
      đúng `abort_reason="dry_run_failed"` và đúng hostname — xác nhận
      `remediate.sh` từ chối đúng bundle không tồn tại qua chính đường canary
      mới. Dọn sạch toàn bộ: 2 user Keycloak, `directAccessGrantsEnabled`
      revert về `false`, mọi row DB test (`controls`/`hosts`/
      `canary_rollouts`/`jobs` LIKE 'canary-e2e%' → 0 dòng còn lại).
      **CHƯA làm**: `PATCH /canary-rollouts/{id}/cancel` đã có nhưng chưa có
      UI polling xác nhận trên trình duyệt thật (chỉ verify qua API). Việc tự
      động phục hồi rollout kẹt "running" nếu orchestrator restart giữa chừng
      — từng ghi là gap chấp nhận ở MVP — **đã làm sau đó**, xem mục "Tự động
      hồi phục canary rollout mồ côi" bên dưới.
- [~] **Agent tự phát triển (mục 4.3)** — hạng mục kỹ thuật rủi ro nhất dự án
      theo chính tài liệu kiến trúc; đã bàn thiết kế đầy đủ với người dùng
      (kế hoạch lưu tại `.claude/plans/`) trước khi code, KHÔNG tự ý nhảy
      vào implement. **Phase 1/5 (backend foundation)**:
        - `Host.agent_enrolled_at`/`agent_last_seen` (migration 0007), bảng
          `agent_enrollment_tokens` (bootstrap token OTT dùng 1 lần, enforce
          `used_at` ở tầng application qua `SELECT ... FOR UPDATE` — không
          chỉ dựa vào hành vi nội bộ chưa verify hết của step-ca), bảng
          `agent_fim_events`.
        - `ca_client.py`: `create_agent_enrollment_token()` (gọi `step ca
          token` qua provisioner `agent-enrollment` — **đã có sẵn từ Giai
          đoạn 0**, `infra/step-ca/setup-provisioners.sh`, chỉ chưa ai dùng
          tới) và `mint_agent_client_cert()` (`step ca certificate --token`).
        - 5 endpoint mới (`app/agents.py`): tạo enrollment token
          (operator/admin), `verify-and-enroll`/`heartbeat`/`scan-result`/
          `fim-event` (auth `AGENT_MANAGER_SHARED_SECRET`, cùng pattern
          `JOB_DISPATCHER_SHARED_SECRET`). Scan result tái dùng thẳng bảng
          `jobs` có sẵn (`job_type="agent-scan"`) thay vì tạo bảng riêng.
        - **Bug thật tìm được qua test** (không phải chỉ đọc code): so sánh
          `token_row.expires_at < datetime.now(timezone.utc)` ném
          `TypeError` trên SQLite (test) vì SQLite trả `DateTime(timezone=
          True)` dạng naive (mất tzinfo) trong khi Postgres (thật) trả dạng
          aware — Postgres không bị ảnh hưởng nhưng test suite (SQLite) thì
          có, nên vẫn sửa: chuẩn hoá về aware/UTC trước khi so sánh, đúng
          trên cả 2 backend.
      **Phase 2/5 (Agent Manager tối giản + Agent binary tối giản — chỉ
      enrollment + heartbeat, CHƯA scan/FIM)**, bước rủi ro kỹ thuật cao nhất
      của cả kế hoạch (mTLS handshake thật) nên làm sớm để lộ vướng mắc ngay:
        - `apps/agent-manager/` (Go, `net/http` + `crypto/tls` thuần, không
          thêm dependency ngoài) — relay mTLS `POST /enroll` (chưa cần client
          cert) và `POST /heartbeat` (bắt buộc client cert, CN trong cert
          phải khớp hostname khai báo trong body — chặn 1 agent hợp lệ giả
          mạo heartbeat cho hostname khác). **Không giữ state, không gọi
          step-ca trực tiếp** — kể cả cert TLS server của chính nó cũng xin
          qua Orchestrator (`POST /internal/agent-manager/server-cert`, endpoint
          mới trong `app/agents.py`, dùng `mint_agent_manager_server_cert()`),
          tự renew mỗi 4h (cert provisioner cấp TTL 8h).
        - `apps/agent/` (Go) — Reporter tối giản: đọc bootstrap token +
          `ca-root.crt` (operator đặt sẵn out-of-band, **không bí mật** — chỉ
          root KEY mới bí mật), enroll qua Agent Manager, lưu cert/key
          (0600), xoá token, sau đó vòng lặp heartbeat mỗi
          `AGENT_HEARTBEAT_INTERVAL` (mặc định 60s) qua mTLS thật.
          **Không dùng `InsecureSkipVerify` ở bất kỳ bước nào** — verify
          server cert của Agent Manager bằng root đã đặt sẵn ngay từ request
          `/enroll` đầu tiên (giải quyết bài toán con gà-quả trứng bootstrap
          PKI bằng cách phân phối root cert công khai qua cùng kênh
          out-of-band với token, thay vì bỏ qua verify).
        - Giữ nguyên ràng buộc "chỉ Orchestrator được gọi CA" — mở rộng
          phạm vi áp dụng sang cả danh tính dịch vụ dài hạn của Agent Manager,
          không chỉ cert dùng-1-lần của từng host trong fleet.
        - Verify: `go test ./...` cho cả 2 module (7 + 10 test, `net/httptest`
          — không cần step-ca/Postgres thật để test logic handler/enroll/
          heartbeat), 74/74 pytest Orchestrator (thêm 3 test cho endpoint
          server-cert mới). Verify E2E thật trên lab server: build agent
          binary qua Docker (không cần Go trên host), chạy như 1 process
          thật, enroll qua Agent Manager thật (mTLS handshake thật, không
          mock) → cert x509 thật 1644 byte + EC key 227 byte đúng permission
          0600 → 3 heartbeat liên tiếp thành công → dùng lại token cũ bị từ
          chối 401 → `GET /hosts/{hostname}` phản ánh đúng
          `agent_enrolled_at`/`agent_last_seen` (giá trị thời gian thật, không
          phải mock).
        - **2 bug thật tìm được qua verify sống trên lab server** (không lộ ra
          qua `go test` vì cả hai đều nằm ở hành vi thật của
          `http.Server.ServeTLS`/`docker compose depends_on`, ngoài phạm vi
          unit test thuần):
          1. `depends_on: condition: service_started` chỉ đảm bảo container
             Orchestrator đã start, KHÔNG đảm bảo alembic migrate + uvicorn
             đã sẵn sàng nhận request — Agent Manager crash-loop vài lần lúc
             `docker compose up` mới. Sửa bằng retry-với-backoff
             (`waitForServerCert`, 2s/lần, tối đa 60s) thay vì `log.Fatal`
             ngay ở lần thử đầu, chỉ Fatal thật khi đã hết thời gian chờ hợp
             lý (phân biệt "chưa sẵn sàng" tạm thời với "thật sự hỏng").
          2. `http.Server.ServeTLS` chỉ bỏ qua `tls.LoadX509KeyPair("","")`
             khi `tls.Config.Certificates` hoặc `.GetCertificate` được set —
             **không biết tới `GetConfigForClient`** dù đó là cách app này hot-
             reload cert khi renew. Thiếu `GetCertificate` khiến MỌI kết nối
             TLS lỗi `open : no such file or directory` dù cert vừa renew
             thành công — log khởi động vẫn in "nghe mTLS" (gây hiểu nhầm đã
             chạy tốt) trước khi crash. Phát hiện bằng `curl -k` thật vào
             `/healthz` sau khi build+deploy, không phải đọc code hay
             `go test` (test dùng `httptest`, không đi qua
             `http.Server.ServeTLS` thật). Sửa bằng set thêm `GetCertificate`
             trỏ tới cùng snapshot cert hiện hành.
      **Phase 3/5 (scan runner OpenSCAP cục bộ + FIM hasher thật trong
      Reporter)**:
        - `apps/agent/scan.go` — chạy `oscap xccdf eval` NGAY trên máy đang
          chạy agent (không qua SSH như đường agentless hiện có), parse
          `results.xml` bằng `encoding/xml` (token-walk + `DecodeElement`
          trên từng `<Rule>`/`<rule-result>`, khớp theo local name nên
          KHÔNG cần biết trước prefix namespace XCCDF — verify bằng test có
          fixture namespace thật), chỉ giữ pass/fail (bỏ notapplicable/
          error), cùng quy ước exit-code (0/2=hợp lệ, khác=lỗi thật) và
          cùng shape `result_summary` với `apps/execution-env/scan.sh` phía
          agentless (`scan_job_status`, `scan_result_pass/fail`, `findings`,
          `findings_count`) — POST qua Agent Manager `/scan-result` (relay
          mới, dùng chung `handleMTLSRelay` với heartbeat/fim-event) tới
          `/internal/agent/scan-result`, ghi vào đúng bảng `jobs` có sẵn.
        - `apps/agent/fim.go` — hash-compare định kỳ (SHA-256), KHÔNG dùng
          `inotify` (đúng MVP theo tài liệu kiến trúc). Agent không có state
          qua lần restart nên lượt quét ĐẦU TIÊN mỗi lần khởi động là
          baseline (không báo event) — chỉ báo `created`/`modified`/
          `deleted` ở các lượt sau trong cùng vòng đời process.
        - Agent Manager: tổng quát hoá `handleHeartbeat` thành
          `handleMTLSRelay` dùng chung cho cả 3 endpoint (`/heartbeat`,
          `/scan-result`, `/fim-event`) — decode body vào `map[string]any`
          thay vì struct riêng từng loại, vì `result_summary` của scan-result
          lồng nhau tuỳ ý.
        - Verify: 22 test mới cho `apps/agent` (fixture XCCDF có namespace
          thật, 5 kịch bản FIM: baseline/modified/deleted/created/no-change,
          `performLocalScan` khi thiếu binary `oscap` trả lỗi có kiểm soát
          thay vì panic) + 3 test mới cho `apps/agent-manager`
          (scan-result/fim-event relay đúng, JSON hỏng bị từ chối 400).
          Verify E2E thật trên lab server: trích xuất datastream SSG từ
          image `execution-env` đã build sẵn ra host (`docker cp`, KHÔNG cài
          thêm package nào lên host) → agent chạy `oscap` thật (exit 0,
          datastream chỉ có tới Ubuntu 22.04 nên trên lab server 24.04 mọi
          rule ra `notapplicable` — hành vi ĐÚNG đã biết từ trước, không
          phải bug mới) → `jobs` có row `job_type="agent-scan"`,
          `status="succeeded"` thật → sửa 1 file đang theo dõi lúc agent
          đang chạy → FIM tick sau đó phát hiện đúng `modified` với
          `old_hash`/`new_hash` khác nhau, ghi đúng vào `agent_fim_events`.
      **Phase 4/5 (scaffold Executor — Unix socket + verify chữ ký, KHÔNG
      kích hoạt Active Response)**:
        - `apps/agent/executor/` — binary Go **riêng biệt** với Reporter
          (process khác, dù chung module Go) — đúng nguyên tắc "tách 2 tiến
          trình" mục 4.3 (Reporter quyền tối thiểu lộ ra mạng, Executor
          quyền root chỉ nhận qua Unix socket nội bộ, không mở port mạng).
        - Nhận job envelope `{control_id, remediation_ref}` qua socket,
          verify chữ ký GPG của bundle `remediation_ref` trong
          `scripts/content-signing/signed/` — tái dùng ĐÚNG cơ chế
          `scripts/content-signing/verify.sh` đã có (`gpg --status-fd 1
          --verify`, parse dòng `VALIDSIG` máy đọc được, không tự chế
          crypto, không đọc fingerprint tin cậy từ chính bundle đang
          verify). Trả `{verified, signer_fingerprint, reason}` rồi
          **DỪNG LẠI — không thực thi remediation nào**, dù verify pass.
        - **Không có caller thật**: Reporter không gửi job nào cho Executor
          — không có đường dây nối Orchestrator → Agent Manager → Reporter
          → Executor cho remediation trong toàn bộ hệ thống hiện tại.
          Binary tồn tại độc lập, chỉ test qua dial thẳng socket.
        - Verify: 12 test mới, dùng **GPG key thật** sinh trong `GNUPGHOME`
          tạm (không mock crypto) — chữ ký hợp lệ, fingerprint không khớp
          danh sách tin cậy, content bị sửa SAU khi ký (chữ ký detached
          không còn khớp), bundle không tồn tại, JSON hỏng, permission
          socket `0600`. Verify E2E thật trên lab server: sinh GPG key thật
          + ký 1 bundle thật + chạy Executor như process thật + dial socket
          bằng script Python độc lập (không qua code Go) gửi 3 job thật —
          bundle hợp lệ → `verified:true` đúng fingerprint; bundle không
          tồn tại → `verified:false`; content bị sửa sau khi ký →
          `verified:false` — cả 3 khớp kỳ vọng, không có gì được thực thi
          (chỉ log "KHÔNG thực thi").
      **Phase 5/5 (Web UI hiển thị trạng thái agent)** — hoàn tất kế hoạch
      "Agent tự phát triển" đã thống nhất:
        - `apps/web/src/api/types.ts` — thêm `agent_enrolled_at`/
          `agent_last_seen` vào `HostOut` (khớp chính xác
          `apps/orchestrator/app/schemas.py:HostOut`), thêm
          `AgentEnrollmentTokenOut`.
        - `apps/web/src/api/client.ts` — `createAgentEnrollmentToken(hostname)`.
        - `apps/web/src/pages/HostsPage.tsx` — cột "Agent" mới (Chip màu:
          xám "Chưa enroll" / vàng "Đã enroll, chưa có heartbeat" hoặc quá
          5 phút không heartbeat / xanh "N phút trước"), nút "Tạo enrollment
          token" mỗi dòng — bấm là gọi API ngay (không cần bước cấu hình gì
          thêm) và mở dialog hiện token + `expires_at` **đúng 1 lần**, kèm
          nút sao chép clipboard. Không thêm role-gating phía client — giữ
          đúng quy ước có sẵn của toàn bộ `apps/web` (RBAC 100% phía
          backend, UI chỉ hiện lỗi 403 qua Snackbar, không tự ẩn nút).
        - Verify: build thật trên lab server (`docker compose build web` —
          `tsc && vite build`, 0 lỗi TypeScript, 573 module) + **workflow
          review 2 lăng kính độc lập** (correctness/security và
          UX-consistency, đọc trực tiếp diff + đối chiếu `ControlsPage.tsx`)
          chạy song song với build check — phát hiện **3 lỗi thật, đã sửa**:
          1. **Race condition (severity cao)**: bấm "Tạo enrollment token"
             liên tiếp cho 2 host khác nhau trước khi request đầu xong có
             thể khiến token của host A hiển thị dưới dialog đang mở cho
             host B (hoặc lỗi của A đóng nhầm dialog đang hiển thị kết quả
             hợp lệ của B) — sửa bằng request-id tăng dần
             (`enrollRequestIdRef`), chỉ áp dụng kết quả nếu vẫn là request
             mới nhất khi resolve.
          2. Lỗi tạo token đóng luôn dialog thay vì giữ mở để retry tại chỗ
             (khác mọi handler khác trong app, vd `handleTriggerScan`) — sửa
             bằng cách giữ dialog mở khi lỗi + thêm nút "Thử lại".
          3. `navigator.clipboard.writeText()` không bắt lỗi/không báo
             thành công — copy thất bại (context không secure, quyền
             clipboard bị chặn...) im lặng như copy thành công, trong khi
             token dùng-1-lần không lấy lại được nếu thật sự copy hỏng —
             sửa bằng Snackbar báo rõ thành công/thất bại.
          Rebuild + redeploy sau khi sửa, container `web` chạy khoẻ lại.
        - **Chưa mở trình duyệt thật để xem UI** (môi trường hiện tại không
          có công cụ browser automation) — chỉ verify qua build thật + đối
          chiếu API contract + 2 lượt review độc lập, đúng phương pháp đã
          ghi nhận từ các tính năng UI trước.
      **Đã làm tiếp sau đó** (xem mục "Hoàn thiện Agent" bên dưới): renew
      cert phía Agent, đóng gói systemd, giới hạn tài nguyên, mô hình quyền
      socket — cả 4 mục CHƯA làm liệt kê ở bản trước đã xong.
      Kích hoạt Active Response (Executor nhận job remediate thật) **cố tình
      để sau pentest riêng**, đúng khuyến nghị của tài liệu kiến trúc —
      không phải thiếu sót. Kế hoạch 5 phase đã thống nhất coi như hoàn tất
      ở mức "pilot SCA/báo cáo, chưa bật Active Response" đúng roadmap Giai
      đoạn 1.
- [x] **Hoàn thiện Agent: cert renew, systemd, socket permission, resource
      limit** — 4 việc kỹ thuật thuần tuý còn lại của "Agent tự phát triển",
      không đụng Active Response (vẫn tắt, chờ pentest riêng).
      1. **Renew cert tự động phía Agent**: endpoint mới
         `POST /internal/agent/renew-cert` (Orchestrator) qua relay mTLS có
         sẵn của Agent Manager (`handleMTLSRelay`, thêm đúng 1 dòng route,
         không viết lại logic relay) — khác cơ chế renew của Agent Manager
         (dựa vào shared secret, chỉ hợp cho 1 service tin cậy duy nhất),
         Agent renew bằng CHÍNH cert mTLS hiện có làm bằng chứng danh tính
         (không qua bootstrap token dùng-1-lần). `apps/agent/pki.go` thêm
         `certHolder` + `tls.Config.GetClientCertificate` để hot-swap cert
         mới vào client đang chạy, KHÔNG cần restart process. Mốc renew tính
         ĐỘNG từ chính cert hiện hành (`NotBefore + (NotAfter-NotBefore)/2`),
         không hardcode như vòng lặp 4h của Agent Manager — tự thích ứng nếu
         provisioner đổi TTL sau này. Thêm cờ `Host.agent_renewal_blocked` +
         `PATCH /hosts/{hostname}/agent-renewal` làm kill-switch — renew tự
         động mà không có cách chặn sẽ YẾU hơn hành vi cũ (cert tự hết hạn
         tối đa 24h vốn là cơ chế thu hồi ngầm định duy nhất hiện có).
      2. **Socket permission Reporter/Executor**: bind-then-rename (Listen
         vào đường dẫn tạm, chown+chmod 0660 group `hardening-agent`, rồi
         `os.Rename` đè lên đường dẫn thật) — đường dẫn thật không bao giờ
         tồn tại với quyền mặc định dù chỉ 1 khoảnh khắc, thay hẳn gap TOCTOU
         đã biết trước đây (không cần `syscall.Umask()` toàn tiến trình).
      3. **Systemd**: 2 unit mới (`hardening-agent.service`,
         `hardening-executor.service`) + `provision.sh` idempotent (tạo
         group `hardening-agent`, user `hardening-agent`/`hardening-executor`).
         Executor chạy **KHÔNG đặc quyền** (quyết định người dùng — Active
         Response tắt nên chưa cần root), `CapabilityBoundingSet=` rỗng.
      4. **Resource limit**: `job-dispatcher` container thêm `nano_cpus=1
         vCPU` + `pids_limit=128` (trước chỉ có `mem_limit`); Agent hạ nice
         value tiến trình `oscap` cục bộ qua `syscall.Setpriority` (chuẩn Go,
         không phụ thuộc binary `nice`/`ionice` ngoài).
      **Quy trình**: 3 agent khảo sát song song → 1 Plan agent chốt kỹ thuật
      (renew endpoint, unit file, giá trị resource limit) → Plan Mode + 2
      AskUserQuestion (quyền Executor, đường dẫn state dir) → Workflow 4
      chặng (backend+relay → Go/systemd/limit song song → test → rà soát
      đối kháng) — **workflow bị chạm rate limit giữa chừng, resume từ cache
      thành công, không mất việc đã làm**.
      **2 lỗ hổng thật tìm được qua rà soát đối kháng, đã tự đọc code và vá
      trực tiếp** (không qua workflow lần 2): (1) cert/key/ca-root ghi qua 3
      lần `rename` ĐỘC LẬP, không phải 1 giao dịch — crash đúng lúc giữa 2
      lần rename để lại cặp cert/key lệch nhau, khiến Agent tự "brick" lúc
      khởi động lại (`tls.LoadX509KeyPair` lỗi → `log.Fatalf`); đã áp dụng
      `writeFileAtomic` luôn cho `enroll()` (trước đó còn kém an toàn hơn cả
      renew — dùng `os.WriteFile` trần) + thêm thông báo lỗi rõ ràng, hướng
      dẫn operator re-enroll thay vì crash khó hiểu — KHÔNG đổi sang layout
      combined-file/symlink-swap phức tạp hơn (gap hẹp, chấp nhận ở mức
      hiện tại, ghi rõ trong code comment). (2) An toàn của socket fix thực
      ra phụ thuộc hoàn toàn vào `UMask=0077` khai báo trong unit file —
      code tự nó CHƯA đảm bảo, README khẳng định "đóng HẲN" hơi quá lời; đã
      sửa `server.go` tự `syscall.Umask(0177)` bao quanh ĐÚNG lệnh
      `net.Listen`, khôi phục ngay sau — an toàn vì `serve()` chạy đơn luồng
      lúc khởi động, trước khi có goroutine/subprocess `gpg` nào tồn tại.
      **Verify**: build lại `orchestrator`/`agent-manager`/`job-dispatcher`
      → migration `0010` chạy sạch → 117 test pytest pass (+ 10 test
      job-dispatcher) → build + `go vet` + `go test` cả 2 module Go qua
      Docker (cài thêm `gnupg` trong container test để chạy đủ, không skip)
      → toàn bộ pass, gồm cả test mới cho `certHolder`/renew/socket
      permission. **E2E thật trên lab server**: chạy `provision.sh` thật
      (tạo user/group hệ thống thật) → build binary thật → cài 2 systemd
      unit → xác nhận Executor chạy **0 capability** (`CapEff:
      0000000000000000`), socket đúng `hardening-executor:hardening-agent
      660` → enroll Agent thật qua systemd (mTLS thật, không mock) → gọi
      `renew-cert` thật qua mTLS bằng đúng cert vừa enroll → 200, cert/key
      mới hợp lệ → set `agent_renewal_blocked=true` → renew tiếp theo → 403
      đúng thông báo → Agent vẫn heartbeat + chạy xong 1 vòng scan OpenSCAP
      bình thường sau các thử nghiệm trên (không crash). **Không** đổi TTL
      chung của provisioner `agent-enrollment` để test nhanh renew tự nhiên
      (bị chặn đúng — sẽ ảnh hưởng vòng renew 4h cố định CỦA Agent Manager
      đang chạy thật) — chọn cách an toàn hơn: gọi thẳng endpoint renew qua
      mTLS thật, verify đúng phần mạng/relay mới mà không đụng cấu hình
      dùng chung. Dọn sạch sau test: user/group provisioning, unit file,
      binary cài, `/etc/hardening-agent`, host/token test trong DB, user
      Keycloak throwaway, `directAccessGrantsEnabled` revert.
- [x] **Rà soát bảo mật/logic lần 4 — toàn bộ code "Agent tự phát triển"**
      (workflow đa agent: 5 dimension đọc song song — Agent Manager,
      Agent+Executor, Orchestrator backend, docker-compose/infra, Web UI —
      mỗi finding qua thêm 2 agent verify độc lập cố gắng bác bỏ trước khi
      tính là xác nhận). 5 candidate, 2 xác nhận qua verify, nhưng sửa cả 4
      (2 candidate còn lại bị "bác bỏ" chỉ vì hiện chưa có caller thật gọi
      tới Executor — không phải vì bản thân code an toàn, nên vẫn sửa trước
      khi Reporter được nối dây thật vào Executor, đúng tinh thần "không để
      lại bom nổ chậm" đã dùng xuyên suốt dự án):
        - **[MEDIUM, xác nhận] `apps/agent-manager/main.go`**: `http.Server`
          không đặt `ReadTimeout`/`WriteTimeout`/`IdleTimeout`/
          `ReadHeaderTimeout` (mặc định = vô hạn), và `/enroll` (không yêu
          cầu client cert) lẫn `/heartbeat`/`/scan-result`/`/fim-event`
          không giới hạn kích thước body — 1 client (kể cả chưa xác thực)
          gửi header/body nhỏ giọt hoặc body khổng lồ có thể giữ kết nối mở
          vô thời hạn, cạn goroutine/bộ nhớ, vì agent-manager publish thẳng
          port ra LAN không qua reverse proxy. Đã thêm 4 timeout hợp lý
          (10-60s) + `http.MaxBytesReader` giới hạn 1 MiB/request, trả 413
          đúng mã khi vượt giới hạn thay vì lỗi 400 chung chung.
        - **[MEDIUM, xác nhận] `apps/agent/scan.go`**: tiến trình `oscap`
          không có timeout — 1 lần `oscap` treo (content lỗi/quá lớn, I/O bị
          khoá) sẽ kẹt vòng lặp scan vĩnh viễn, không tự phục hồi. Đã thêm
          `context.WithTimeout` (mặc định 10 phút, `AGENT_SCAN_TIMEOUT`).
        - **[HIGH ở dimension review, "bác bỏ" ở bước verify vì chưa có
          caller thật, vẫn sửa] `apps/agent/executor/verify.go`**: path
          traversal — `remediation_ref` từ job envelope (chưa đáng tin)
          được nối thẳng vào `filepath.Join(signedContentDir, remediationRef)`
          không kiểm tra containment; `filepath.Join` tự resolve `".."` nên
          `"../../etc"` có thể thoát hẳn ra ngoài thư mục nội dung đã ký.
          Chưa khai thác được ngay bây giờ (Reporter chưa gửi job nào cho
          Executor) nhưng là lỗ hổng thật một khi có caller — đã chặn 2 lớp
          độc lập: từ chối `remediation_ref` chứa `/`, `\`, hoặc `".."`, VÀ
          containment-check đường dẫn sau `Clean()` vẫn phải nằm trong
          `signedContentDir`.
        - **[LOW, "bác bỏ" cùng lý do — vẫn sửa] `apps/agent/executor/verify.go`**:
          tiến trình `gpg --verify` không có timeout — thêm
          `context.WithTimeout` 30s (tách hàm `verifyBundleSignatureWithTimeout`
          để test được đường timeout nhanh, không cần đợi hết 30s thật).
        - **[LOW, không sửa]** cửa sổ TOCTOU rất hẹp giữa `net.Listen` và
          `os.Chmod(0600)` cho Unix socket của Executor — cả 2 agent verify
          đều bác bỏ (thời gian window chỉ vài instruction, cần attacker
          local đã có quyền poll `connect()` đúng lúc khởi động, và hiện
          chưa có caller thật); cách sửa triệt để (đặt umask thay vì chmod
          sau) có tác dụng phụ tới toàn tiến trình (umask là state toàn cục,
          không an toàn giữa nhiều goroutine) nên rủi ro fix còn cao hơn lỗi
          — chấp nhận làm gap đã biết, ghi lại ở đây thay vì âm thầm bỏ qua.
        - **Bug thật tìm được khi VIẾT TEST cho 2 fix timeout ở trên** (không
          phải chỉ đọc code): `exec.CommandContext` mặc định chỉ `Kill()`
          đúng 1 tiến trình trực tiếp (oscap/gpg) khi hết timeout — nếu tiến
          trình đó tự fork thêm con (test dùng shell script gọi `sleep` để
          mô phỏng), con đó vẫn giữ đầu ghi của pipe stdout/stderr mở sau
          khi cha bị kill, khiến `cmd.Wait()`/`cmd.Output()` TREO tới khi
          con tự thoát — bỏ qua toàn bộ timeout vừa thêm. Phát hiện vì cả 2
          test timeout ban đầu FAIL (đợi đủ 5s thay vì bị kill sớm), xác
          nhận qua thực nghiệm trực tiếp trên lab server (viết 2 chương
          trình Go tối giản, 1 không capture stdout chạy đúng, 1 có capture
          stdout thì treo — cô lập chính xác nguyên nhân). Sửa bằng
          `SysProcAttr{Setpgid: true}` + `cmd.Cancel` kill cả process group
          (`syscall.Kill(-pid, ...)`) thay vì chỉ kill 1 tiến trình, cộng
          `cmd.WaitDelay` làm lưới an toàn cuối.
        - Verify: 14 test agent-manager (+3 test mới), 22 test agent (+2:
          timeout thật đo được dưới 0.2s thay vì đợi hết 5s giả treo), 12
          test executor (+2: path traversal 4 payload, timeout gpg). Rebuild
          + redeploy `agent-manager` trên lab server, 74/74 pytest
          Orchestrator không đổi (không phần nào trong review này chạm tới
          backend Python).

## Ghi chú vận hành — Job/Scan pipeline (phát hiện qua test thật)

- **Nội dung SCAP dùng để scan** là gói `ssg-debderived` (Debian package
  chính thức, chứa nội dung SCAP Security Guide/ComplianceAsCode mã nguồn
  mở) — profile `xccdf_org.ssgproject.content_profile_cis_level1_server`
  của datastream Ubuntu 22.04 **không phải benchmark CIS được CIS chứng nhận
  chính thức** (đòi hỏi mua CIS SecureSuite). Đủ dùng cho mục đích kỹ
  thuật/demo, nhưng cần xác nhận yêu cầu pháp lý/licence trước khi dùng làm
  căn cứ tuân thủ chính thức (liên quan rủi ro #1, mục 8 architecture-proposal.md).
- Datastream đóng gói sẵn chỉ có tới Ubuntu 22.04 — scan máy Ubuntu 24.04
  (như lab server) bằng content 22.04 khiến toàn bộ rule bị đánh giá
  `notapplicable` (CPE platform-check của XCCDF không khớp phiên bản) — đây
  là hành vi ĐÚNG theo chuẩn SCAP, không phải bug, nhưng có nghĩa là kết quả
  scan demo hiện tại không phản ánh tình trạng hardening thật của máy.
- `oscap-ssh` (từ `openscap-utils`) chỉ upload NỘI DUNG SCAP qua `scp` — máy
  đích vẫn cần cài sẵn gói `openscap-scanner` (binary `oscap`). Không phải
  zero-install hoàn toàn như Ansible (chỉ cần Python).
- `grep` trả mã thoát 1 khi không có dòng khớp (vd 0 rule fail) — kết hợp
  `set -e -o pipefail` trong `scan.sh` làm cả script dừng giữa chừng dù
  `oscap-ssh` chạy đúng — đã thêm `|| true` sau các lệnh đếm.
- `KEYCLOAK_ISSUER_URL` không dùng được để cấp SSH cert nội bộ — Orchestrator
  gọi step-ca trực tiếp qua `ca-net`, cần root cert của CA để verify TLS;
  `step ssh certificate --ca-url` **bắt buộc** `--root` hoặc `--token` (đã
  verify: không có cờ nào bỏ qua bước này) — mount `step-ca-data` read-only
  vào Orchestrator để lấy đúng `certs/root_ca.crt`.
- **2 test file cùng gọi API `/hosts` sẽ đụng nhau** nếu cả hai override
  `hosts_module._get_db` trên `app.dependency_overrides` (dict toàn cục dùng
  chung `app` instance) — pytest import (collect) TOÀN BỘ file test trước
  khi chạy bất kỳ test nào, nên file import sau sẽ đè override của file
  trước, làm sai lệch cả những test đã pass trước đó. `test_jobs.py` sửa
  bằng cách insert `Host` thẳng qua ORM thay vì gọi API `/hosts`, không cần
  override `hosts_module._get_db` nữa.
- **`JSONB` (Postgres-specific) không compile được trên SQLite** — cột
  `Job.result_summary` đổi sang `JSON` (generic, chạy được cả 2 nơi).
  `AuditLog.payload` vẫn giữ `JSONB` vì test integration của nó luôn chạy
  qua Postgres thật, không qua SQLite.
- **`BigInteger` primary key không tự autoincrement trên SQLite** — SQLite
  chỉ alias ROWID-autoincrement cho cột khai đúng affinity `INTEGER`. Đổi
  `Job.id` sang `Integer` (đủ dùng ở quy mô jobs bảng này; `AuditLog.id` giữ
  `BigInteger`, chỉ test qua Postgres thật).
- Sau MỌI lần sửa code Python trong `apps/orchestrator`, phải
  `docker compose build orchestrator` lại trước khi test/chạy — `docker
  compose run`/`up` dùng image đã build sẵn (`COPY . .` ở build-time), KHÔNG
  tự đọc lại file đã sửa trên host (quên bước này gây debug nhầm hướng tốn
  thời gian nhất trong quá trình làm tính năng này).
- **`ssh_user` trong `ScanTrigger` không được allowlist** (phát hiện qua code
  review, không phải test thật) — provisioner `orchestrator` trên step-ca chỉ
  siết TTL (`infra/step-ca/setup-provisioners.sh`), không tự giới hạn
  principal, nên bất kỳ operator/admin nào cũng có thể tự chọn cấp SSH cert
  cho principal tuỳ ý. Đã thêm `ALLOWED_SSH_USERS = ("root",)` và validate
  422 trong `app/jobs.py`.
- **Container mồ côi nếu Docker create thành công nhưng start lỗi** (phát
  hiện qua code review) — `docker-py .run()` không atomic; đã đặt tên cố
  định `job-{job_id}` cho container để `job-dispatcher` dọn được bằng cách
  tra theo tên khi `containers.run()` ném lỗi, thay vì chỉ dựa vào object
  trả về (có thể không tồn tại nếu lỗi xảy ra sau bước create).

- [x] **Mở rộng SCAP scan sang Debian (Giai đoạn 2, mục 7)** — chỉ mở rộng
      **scan**, KHÔNG phải remediation content (vẫn cần Reviewer/Signer thật
      cho từng distro, giống Ubuntu). Phát hiện qua kiểm tra thật (không chỉ
      đọc tên gói): package `ssg-debderived` đã cài sẵn trong
      `apps/execution-env/Dockerfile` **CHỈ chứa nội dung Ubuntu**
      (`ssg-ubuntu{1604,1804,2004,2204}-*.xml`) dù tên gây hiểu nhầm — "derived
      FROM Debian" nghĩa là họ Ubuntu, không phải Debian thật. Debian thật
      (buster/bullseye) nằm ở package RIÊNG `ssg-debian`, chưa từng được cài.
      Thêm `ssg-debian` vào Dockerfile, thêm `debian10-standard`/
      `debian11-standard` vào `app/jobs.py:SCAP_PROFILES` (chỉ có 1 profile
      "standard" cho Debian, không có bản CIS riêng như Ubuntu; **không có**
      debian12/bookworm trong version gói hiện tại 0.1.65-1, không thêm entry
      cho version không tồn tại). Đồng bộ danh sách hardcode phía Web UI
      (`apps/web/src/api/types.ts:SCAP_PROFILE_KEYS` — chưa có endpoint tự
      khám phá danh sách profile, comment đã ghi rõ phải tự đồng bộ tay).
      Verify thật trên lab server: rebuild image `execution-env` xác nhận cả
      2 file datastream Debian tồn tại đúng chỗ, `oscap info` xác nhận đúng
      profile id, **chạy thật `oscap xccdf eval` với datastream Debian 11 —
      hoàn tất, exit code 0** (không chỉ kiểm tra profile id tồn tại mà chưa
      biết chạy được không). 118 test pytest pass (thêm 1 test hồi quy cho
      profile key mới), build `orchestrator`/`web` (`tsc && vite build`)
      thành công.

- [x] **Runbook + script sinh Root CA trên máy air-gapped (mục 4.1)** — chuẩn
      bị đầy đủ quy trình thay cấu hình dev hiện tại (root+intermediate cùng
      sinh trong 1 container online) bằng nghi lễ air-gap thật: root sinh +
      lưu trên máy không mạng, chỉ CSR (không phải private key) băng qua ranh
      giới air-gap để lấy chữ ký, intermediate đã ký + root public quay lại
      máy online. 4 script `infra/step-ca/airgap/01-04-*.sh` (mỗi script tự
      kiểm tra input, dừng an toàn nếu thiếu) + runbook đầy đủ
      `infra/step-ca/root-ca-airgap-runbook.md` (vai trò, lưu trữ/backup
      root key, quy trình renew intermediate, disaster recovery).
      **Rehearsal thật trên lab** (không chỉ đọc code): mô phỏng máy
      air-gapped bằng container `docker run --network none` (bắt buộc cấu
      trúc "không có khả năng nối mạng" ở tầng OS, không chỉ thủ tục), máy
      online bằng 1 project Docker Compose throwaway tách biệt hoàn toàn khỏi
      volume `step-ca-data` thật đang chạy (đã xác nhận uptime/health của CA
      thật không đổi trước/sau rehearsal). Diễn tập phát hiện và sửa 3 lỗi
      thật (không phải lý thuyết): (1) `step certificate create --csr` không
      tương thích với `--profile` (profile áp dụng lúc ký, không phải lúc tạo
      CSR); (2) `secrets/password` trong volume step-ca là mật khẩu DÙNG
      CHUNG để tự mở khoá mọi key lúc khởi động — không chỉ
      `intermediate_ca_key` mà cả `ssh_host_ca_key`/`ssh_user_ca_key`, nên
      script phải re-key 2 khoá SSH CA đó (đổi mật khẩu, giữ nguyên khoá)
      sang cùng mật khẩu mới, nếu không step-ca crash lúc khởi động lại với
      lỗi "decryption password incorrect"; (3) `root_ca_key` TẠM do
      `DOCKER_STEPCA_INIT_*` tự sinh lúc auto-init lần đầu bị bỏ sót, không bị
      xoá khỏi volume online — vi phạm đúng bất biến đang thiết lập, script
      đã thêm bước xoá tường minh + assert xác nhận không tồn tại trước khi
      coi là xong. Sau khi sửa: rehearsal đầy đủ 4 bước, cert intermediate
      mới verify chain thành công về root mới, CA khởi động lại khoẻ mạnh,
      **cấp thử 1 leaf cert thật qua provisioner hiện có và xác nhận chain
      hợp lệ tới root mới**, xác nhận `root_ca_key` không tồn tại trong volume
      online. Toàn bộ artifact rehearsal (throwaway, không phải khoá thật) đã
      dọn sạch khỏi lab server.
      **CHƯA làm** (không thể làm thay): chạy nghi lễ thật trên phần cứng
      air-gapped thật cho production — cần máy vật lý + người vận hành, đây
      là quyết định/hành động vận hành ngoài phạm vi engineering thuần tuý.

- [x] **Giới hạn số job chạy đồng thời ở Job Dispatcher** (mục CHƯA làm cũ
      của `apps/job-dispatcher/README.md`) — trước đây mỗi container job đã bị
      giới hạn 1 vCPU/512MB/128 pid, nhưng KHÔNG có gì chặn tổng số container
      chạy đồng thời; ở quy mô tới 50 host, 1 đợt trigger job đồng loạt (vd
      scan theo lịch) có thể oversubscribe CPU/RAM của chính host Docker (ẩn
      sau ngưỡng ~40 thread mặc định của Starlette threadpool — giới hạn theo
      số thread cố định, không theo tài nguyên host thật). Thêm
      `threading.Semaphore` mặc định bằng `os.cpu_count()` (mỗi job 1 vCPU nên
      không nên vượt số core vật lý), override qua env `MAX_CONCURRENT_JOBS`;
      hết slot thì đợi tối đa `JOB_SLOT_WAIT_SECONDS` (mặc định 5s, san phẳng
      burst gần cùng lúc) rồi trả `503` thay vì cố spawn thêm — `503` được
      Orchestrator xử lý tự nhiên qua đường lỗi dispatch có sẵn (đánh job
      "failed", không cần code Orchestrator mới). 3 test mới (từ chối đúng khi
      hết slot + không gọi Docker khi từ chối, slot được trả lại đúng sau
      thành công lẫn sau lỗi Docker) — 13/13 test job-dispatcher pass. Nhân
      tiện sửa 1 lỗi tài liệu có sẵn không liên quan trực tiếp (phát hiện qua
      chạy thật lệnh test đã ghi trong docstring): thiếu `httpx` trong lệnh
      cài đặt khiến `pytest` lỗi ngay từ bước collect.
      **Verify E2E thật trên lab** (không chỉ unit test mock Docker): rebuild
      image, tạm override `MAX_CONCURRENT_JOBS=1` qua
      `docker-compose.override.yml` (xoá ngay sau test, không đụng cấu hình
      chính), gọi thẳng job-dispatcher (bỏ qua Orchestrator) với 2 job scan
      thật nhắm `TARGET_HOST` không route được (buộc container giữ slot đủ
      lâu qua `ConnectTimeout=10` của `scan.sh`) — job đầu giữ slot 14.6s,
      job thứ 2 (bắn sau 0.5s) nhận đúng `503` sau ~2s đợi. Xác nhận không có
      container/job DB row nào sót lại sau test, job-dispatcher đã revert về
      cấu hình mặc định.

- [x] **Rate-limit cho Agent Manager** (mục CHƯA làm cũ của
      `apps/agent-manager/README.md`) — `/heartbeat`/`/scan-result`/
      `/fim-event`/`/renew` trước đây không có giới hạn tần suất nào; 1 agent
      lỗi hoặc bị compromise (vẫn có cert mTLS hợp lệ) có thể dồn dập gọi liên
      tục, tốn tài nguyên Orchestrator/Postgres phía sau. Thêm token bucket tự
      viết (`rateLimiter` trong `apps/agent-manager/main.go`, KHÔNG thêm
      dependency ngoài — `go.mod` cố tình không có dependency nào vì đây là
      mặt tiếp xúc LAN duy nhất publish port) theo CN đã xác thực (không theo
      IP), dùng CHUNG 1 instance cho cả 4 endpoint relay — 1 agent dồn dập
      dù rải qua nhiều endpoint khác nhau vẫn tính vào cùng ngưỡng. Burst 20 +
      refill 0.5 token/s (~30 request/phút) — đối chiếu với lưu lượng hợp lệ
      thực tế trong `apps/agent/main.go` (heartbeat 60s/lần, FIM 5 phút/lần,
      renew ~4h/lần) để chọn ngưỡng rộng rãi hơn nhiều so với nhu cầu thật.
      Vượt ngưỡng trả `429`. 6 test mới (burst/refill/tách theo key ở tầng
      `rateLimiter`, cộng 2 test ở tầng handler xác nhận 429 đúng lúc và
      không ảnh hưởng hostname khác) — 20/20 test agent-manager pass.
      Rebuild + deploy lại trên lab, xác nhận `/healthz` và hành vi từ chối
      thiếu client cert (401) không đổi sau khi thêm rate-limit. **Không**
      chạy thêm nghi lễ enroll mTLS thật cho riêng việc này — khác
      job-dispatcher (nơi live test phát hiện lỗi thật ở tầng tương tác
      Docker), đây là logic Go thuần trong tiến trình, đã được unit test qua
      đúng handler thật với `r.TLS` giả lập (không mock hoá phần rate-limit),
      chi phí dựng lại toàn bộ enrollment ceremony thật không tương xứng với
      rủi ro còn lại.

- [x] **"1-click restore" từ backup remediate-apply** (mục CHƯA làm cũ của
      "Ephemeral Execution Environment pipeline") — endpoint mới
      `POST /hosts/{hostname}/restore` (`app/jobs.py:run_restore`), tham
      chiếu đúng 1 job `remediate-apply` đã `succeeded` làm nguồn backup, từ
      chối rõ ràng (422) nếu backup bị cắt (`backup_truncated`), sai loại
      job, hoặc khác host — KHÔNG âm thầm khôi phục 1 phần. KHÔNG yêu cầu
      dry-run/four-eyes riêng như apply — coi đây là công cụ khôi phục khẩn
      cấp (break-glass), four-eyes đã áp dụng lúc APPLY ban đầu, đòi hỏi
      duyệt lại lúc restore chỉ làm chậm phản ứng sự cố. Script mới
      `apps/execution-env/restore.sh`: giải nén backup lên host đích qua
      SSH, **kiểm tra `sshd -t` trước khi reload** (an toàn — không tự khoá
      SSH nếu backup có vấn đề), chỉ reload nếu hợp lệ.
      **Phát hiện qua thử thật, không phải đọc tài liệu**: 1 biến môi
      trường Docker đơn lẻ bị giới hạn `MAX_ARG_STRLEN` của kernel Linux
      (131072 byte — xác nhận bằng binary search thật qua docker-py, không
      phải qua `docker` CLI) — backup tới `BACKUP_MAX_BYTES` (2 MiB) vượt xa
      ngưỡng này nếu nhét vào 1 biến. Giải quyết bằng cách chia backup
      thành nhiều biến `BACKUP_TAR_B64_{i}` (100.000 ký tự/biến, xem
      `RESTORE_CHUNK_SIZE`), `restore.sh` ghép lại đúng thứ tự bằng bash
      indirect expansion trước khi base64 decode.
      9 test mới (chunk/reassemble, 403 viewer, 404 host, 422 sai loại
      job/khác host/backup bị cắt, 202 dispatch đúng env đã chia chunk, 502
      khi job-dispatcher lỗi) — 127/127 test orchestrator pass.
      **Verify E2E thật** (không chỉ unit test mock httpx) — có xin phép
      trước vì đây là test chạy trên chính lab server (hạ tầng dùng chung,
      không phải máy test riêng): thêm 1 dòng marker vô hại vào
      `/etc/login.defs` (mô phỏng 1 remediate đã đổi cấu hình), chụp backup
      TỐI GIẢN chỉ chứa đúng file này (không đụng `/etc/ssh` — tránh xử lý
      SSH host key thật ngoài phạm vi cần thiết), gọi `run_restore()` thật
      (đi qua đúng job-dispatcher → container execution-env thật →
      `restore.sh` thật → SSH thật) — xác nhận marker biến mất, file về
      đúng 395 dòng gốc, `sshd -t`/kết nối SSH vẫn khoẻ sau reload. Dọn sạch
      toàn bộ Job DB row + file tạm sau test.
      **CHƯA làm**: nút bấm Web UI (hiện chỉ có API) — không tự làm vì
      không có công cụ duyệt trình duyệt thật để tự verify UI trước khi báo
      xong (đúng nguyên tắc "không claim UI xong nếu chưa tự test qua
      browser").

- [x] **Tự động hồi phục canary rollout mồ côi lúc Orchestrator khởi động**
      (mục CHƯA làm cũ của "Canary rollout tự động cho Nhóm A") — `_run_rollout`
      (`app/canary.py`) chạy trong FastAPI `BackgroundTasks`, sống trong chính
      process Orchestrator; nếu process chết/restart (deploy, OOM-kill,
      `docker compose restart`...) đúng lúc 1 rollout đang "running", không có
      gì còn chạy để đưa nó về "completed"/"aborted" — kẹt "running" MÃI MÃI.
      Vì `ux_canary_rollouts_running` (migration 0009) chỉ cho phép tối đa 1
      rollout "running"/control, 1 rollout mồ côi còn **khoá cứng luôn control
      đó** khỏi mọi canary rollout kế tiếp cho tới khi có người sửa DB tay —
      không chỉ là "báo cáo sai trạng thái" mà là mất khả năng dùng tính năng.
      Thêm `reconcile_orphaned_rollouts()` (`app/canary.py`), gọi đúng 1 lần
      qua FastAPI `lifespan` (`app/main.py`, thay `on_event` cũ chưa từng dùng
      — `lifespan` là API hiện hành, `on_event` chỉ còn được giữ tương thích
      ngược) TRƯỚC khi nhận request đầu tiên: mọi `CanaryRollout` còn
      "running" bị đưa thẳng về "aborted" với `abort_reason=
      "orchestrator_restarted"`, ghi audit event `canary_rollout_aborted`
      (actor `"system"`). Cố tình **không** thử tự resume dry-run/apply dở
      dang — trạng thái thật trên host tại đúng thời điểm restart không xác
      định chắc chắn (job cuối có thể đã apply xong trên host nhưng chưa kịp
      commit DB), resume mù rủi ro áp nhầm hoặc bỏ sót bước; "aborted" chỉ mở
      khoá lại control để operator tự trigger rollout mới sau khi đã tự xác
      minh tình trạng host, đúng tinh thần an toàn mặc định xuyên suốt dự án.
      3 test mới (`test_canary.py`): abort đúng + mở khoá lại được control bị
      kẹt, không đụng tới rollout đã "completed" khác, no-op khi không có
      rollout "running" nào — 130/130 test orchestrator pass.
      **Verify E2E thật trên lab server** (không chỉ unit test SQLite): tạo 1
      control + 1 `canary_rollouts` row "running" throwaway thẳng qua SQL
      (mô phỏng đúng tình huống crash giữa chừng, không cần chờ crash thật xảy
      ra) → xác nhận insert 1 rollout "running" thứ 2 cho CHÍNH control đó bị
      chặn bởi `ux_canary_rollouts_running` (đúng hành vi TRƯỚC khi restart) →
      `docker compose restart orchestrator` → log khởi động in đúng dòng "đã
      abort 1 canary rollout mồ côi" → xác nhận DB: `status=aborted`,
      `abort_reason=orchestrator_restarted`, `finished_at` đã set, audit_log
      có đúng dòng `canary_rollout_aborted` actor `system` → xác nhận control
      ĐÃ MỞ KHOÁ: insert rollout "running" mới cho cùng control thành công.
      Dọn sạch: xoá control + cả 2 `canary_rollouts` row test (audit_log GIỮ
      NGUYÊN không xoá — đúng nguyên tắc ledger chỉ-thêm/hash-chain, nhất
      quán với mọi lần verify E2E trước).

- [x] **`GET /jobs` (lịch sử job) + trang Web UI Jobs** (mục CHƯA làm cũ của
      `apps/web/README.md`: "Không có trang liệt kê TOÀN BỘ job đã chạy" —
      trước đây chỉ có `GET /jobs/{id}`, không có cách nào xem lại job đã
      chạy ngoài phiên làm việc lúc trigger) — endpoint mới
      `GET /jobs` (`app/jobs.py:list_jobs`, cùng quyền đọc như
      `GET /jobs/{id}`: mọi role đã đăng nhập), lọc theo
      `hostname`/`job_type`/`status` (khớp chính xác, không phải substring),
      sắp xếp mới nhất trước (`Job.id.desc()` — id tăng đơn điệu đúng thứ tự
      tạo, không cần index riêng trên `created_at`), phân trang `limit`
      (mặc định 50, tối đa 200)/`offset` — bảng `jobs` là bảng DUY NHẤT tăng
      không giới hạn theo thời gian trong hệ thống (khác `hosts`/`controls`
      bị chặn tự nhiên bởi quy mô ≤50 máy), nên phải phân trang ngay từ đầu
      thay vì `list()` không giới hạn như 2 endpoint kia.
      **Lỗi thật tự gây ra rồi tự phát hiện qua deploy thật (không phải qua
      test)**: ban đầu định thêm migration tạo index `ix_jobs_hostname` cho
      cột lọc phổ biến nhất, giả định cột `hostname` chưa có index — SAI, đã
      đọc nhầm mà không kiểm tra lại: migration `0004_create_jobs.py`
      (`create jobs`) đã tự tạo `ix_jobs_hostname`/`ix_jobs_status` từ đầu.
      Deploy migration mới lên lab server làm **Orchestrator crash-loop
      thật** (`DuplicateTable: relation "ix_jobs_hostname" already exists`,
      `alembic upgrade head` fail giữa transaction nên `alembic_version` may
      không tăng lên — không mất dữ liệu, nhưng service downtime thật trên hạ
      tầng dùng chung). Phát hiện NGAY qua `docker compose logs` sau khi
      redeploy (không phải để lọt qua unit test — bộ test SQLite dùng
      `Base.metadata.create_all()`, không chạy qua Alembic nên không thể bắt
      được lớp lỗi migration-only này), xoá ngay file migration thừa, rebuild,
      xác nhận `alembic current` = `0010 (head)` khớp DB, service khoẻ lại
      trong vài phút. Ghi lại đây làm lời nhắc: **luôn kiểm tra migration
      history/schema thật trước khi thêm index/cột mới, không suy đoán từ tên
      cột**.
      6 test mới (`test_jobs.py`): viewer đọc được, sắp mới nhất trước, lọc
      hostname/job_type/status, phân trang limit+offset đúng dữ liệu, 422 khi
      limit/offset không hợp lệ — 136/136 test orchestrator pass.
      **Verify thật trên lab server** (không chỉ SQLite): sau khi sửa lỗi
      migration ở trên, chạy thẳng query ORM giống hệt `list_jobs` qua
      `docker compose exec orchestrator python3` nhắm đúng Postgres thật
      đang có sẵn 7 job row thật (từ các lần scan E2E trước) — xác nhận thứ
      tự mới nhất trước, lọc `status="failed"` đúng 1 job (`giapha`, lỗi SSH
      trust có sẵn từ trước), `offset=2 limit=2` trả đúng 2 id kế tiếp.
      **Web UI**: trang Jobs mới (`apps/web/src/pages/JobsPage.tsx`) — ô lọc
      hostname + dropdown job_type/status, bảng + phân trang (nút "Trang sau"
      tự tắt khi trang trả về ít hơn 1 trang đầy, không cần thêm `COUNT(*)`
      phía backend), dialog chi tiết (bảng findings cho job scan, JSON thô
      cho loại còn lại). Build thật (`tsc && vite build`, 0 lỗi, 574 module)
      + 1 lượt review độc lập phát hiện **1 lỗi thật, đã sửa**: race condition
      giống hệt lớp bug đã gặp ở tính năng agent-enrollment trước đây (dialog
      token) — đổi filter/trang liên tiếp trước khi request trước hoàn tất có
      thể khiến response CŨ (vd hostname chậm hơn) ghi đè lên response MỚI
      hơn đã tới trước; sửa bằng request-id tăng dần (`requestIdRef`), lặp
      lại đúng kỹ thuật `enrollRequestIdRef` của `HostsPage.tsx`. Rebuild +
      redeploy sau khi sửa. **Chưa mở trình duyệt thật để xem UI** — chỉ
      verify qua build + đối chiếu API contract + review độc lập, đúng
      phương pháp đã dùng cho mọi tính năng UI trước.

- [x] **Rà soát đối kháng 2 tính năng vừa xong ở trên (canary reconciliation +
      `GET /jobs`)** — 2 việc này chưa qua vòng rà soát nào (khác các batch
      lớn trước đó luôn có 1 vòng rà soát riêng sau khi xong). Chạy 1 agent
      review đọc trực tiếp code (không phải workflow đối kháng) tìm được 3
      candidate; sau đó dùng **workflow 3 agent độc lập chạy song song**, mỗi
      agent cố tình tìm cách BÁC BỎ đúng 1 candidate — 2/3 xác nhận đã sửa
      đúng, 1/3 tìm ra khoảng hở còn sót:
        1. **[Đã sửa]** `list_jobs` (`GET /jobs`) dùng chung `JobOut` (có
           `result_summary`) — job `remediate-apply` nhúng base64 cả backup
           tới 2 MiB, trả cho MỖI job trong 1 trang tới `limit=200` ép response
           lên hàng trăm MB, gọi được bởi role `viewer`. Thêm schema riêng
           `JobListOut` (bỏ hẳn `result_summary`) chỉ dùng cho list; `GET
           /jobs/{id}` (đúng 1 job/request, không nhân theo trang) vẫn giữ
           `JobOut` đầy đủ. Web UI: nút "Xem chi tiết" đổi từ dùng lại thẳng
           item trong bảng sang tự gọi riêng `api.getJob(id)` khi mở dialog
           (kèm loading state + request-id guard chống 2 dialog mở liên tiếp
           đè kết quả lên nhau).
        2. **[Đã sửa]** `reconcile_orphaned_rollouts()` (chạy trong
           `lifespan` lúc khởi động) ghi audit event qua vòng lặp không có
           try/except — 1 lỗi audit-DB tạm thời (khác DB chính, xem
           `app/audit.py`) sẽ làm exception văng ra khỏi `lifespan`, khiến
           **toàn bộ Orchestrator không khởi động được** chỉ vì thiếu đúng 1
           dòng audit. Bọc riêng lời gọi `write_audit_event` trong try/except,
           chỉ log lỗi — state chính (đã `commit()` trước đó) không phụ thuộc
           vào audit có ghi được hay không.
        3. **[Xác nhận CÒN SÓT, đã vá tiếp]** Check `rollout.status !=
           "running"` mới thêm ở đầu vòng lặp `_run_rollout` (mục "Tự động hồi
           phục canary rollout mồ côi" ở trên) chỉ chặn được nếu process khác
           (vd `reconcile_orphaned_rollouts` ở 1 replica khác — CHƯA xảy ra
           thật vì hiện chỉ 1 process/1 replica, nhưng không gì cấm sau này)
           abort rollout TRƯỚC khi vòng lặp bắt đầu xử lý host đó; nếu abort
           xảy ra giữa lúc dry-run (`--check --diff`, không đổi gì trên host,
           nên đủ chậm để tạo cửa sổ) đang chạy dở, code cũ vẫn chạy tiếp
           `run_remediate_apply` — đúng bước THẬT SỰ đổi cấu hình host — sau
           khi rollout đã bị coi là mồ côi, và `_abort()` còn ghi đè lên lý do
           abort mà process kia đã ghi. Vá bằng 2 thay đổi tối thiểu (KHÔNG
           dựng cơ chế khoá phân tán/lease — quá tay so với rủi ro thật ở quy
           mô 1 process/≤50 host hiện tại, đúng nguyên tắc #9 kiến trúc "không
           over-engineer ngược lại"): (a) re-check `rollout.status` thêm 1 lần
           NGAY TRƯỚC `run_remediate_apply` (không cần re-check trước dry-run
           vì không có I/O chen giữa 2 dòng đó), (b) `_abort()` chỉ ghi nếu
           rollout vẫn còn `"running"` tại thời điểm gọi, không ghi đè vô điều
           kiện. Cửa sổ hở còn lại (dry-run vẫn có thể chạy sau khi rollout đã
           mồ côi) chấp nhận được — `--check --diff` không đổi gì trên host,
           chỉ tốn 1 lượt SSH đọc thừa.
      4 test mới (`test_canary.py`): audit lỗi không làm `reconcile_orphaned_rollouts`
      raise, re-check trước apply chặn đúng khi status đổi giữa dry-run — 140/140
      test orchestrator pass. Rebuild + redeploy `orchestrator`/`web`, 7/7
      service healthy sau khi deploy.

- [x] **Metric Prometheus cho Agent Manager** (mục CHƯA làm cũ của
      `apps/agent-manager/README.md`) — `GET /metrics` mới, tự viết format
      text Prometheus bằng tay (không thêm dependency ngoài, cùng lý do
      `rateLimiter` tự viết token bucket thay vì `golang.org/x/time/rate`;
      `go.mod` vẫn 0 dependency). 3 chỉ số: `agent_manager_relay_requests_total{endpoint,status}`
      (counter, đếm qua `metricsMiddleware` bọc NGOÀI từng handler hiện có —
      không sửa `handleEnroll`/`handleMTLSRelay`/`relayJSON`, tránh phải sửa
      lại hơn chục lời gọi trong `main_test.go` chỉ để thêm quan sát),
      `agent_manager_known_hosts` (gauge, lấy từ kích thước map có sẵn của
      `rateLimiter`), `agent_manager_server_cert_renewal_success`/
      `..._timestamp_seconds` (gauge, trạng thái renew cert gần nhất của
      CHÍNH agent-manager — thêm 2 field vào `serverIdentity`, tách hàm
      `refresh()` cũ thành `doRefresh()` giữ nguyên logic + `refresh()` mới
      chỉ làm nhiệm vụ ghi lại kết quả, nên không phải sửa
      `waitForServerCert`/`renewalLoop` hay 2 test đang gọi `waitForServerCert`
      trực tiếp). `/metrics` không yêu cầu xác thực — cùng mức lộ thông tin
      như `/healthz` đã có (chỉ số liệu tổng hợp, không có hostname cụ thể),
      đúng quy ước Prometheus tiêu chuẩn.
      8 test mới (đếm đúng theo endpoint/status, middleware không đổi status
      trả về client, `hostCount()` không tăng khi gọi lại host cũ, trạng thái
      renew phản ánh đúng lần refresh gần nhất, output đúng cú pháp Prometheus)
      — 26/26 test agent-manager pass (`go vet` sạch). **Verify E2E thật trên
      lab server**: rebuild + redeploy, `curl -k https://.../metrics` thật
      qua HTTPS thấy đúng 3 nhóm chỉ số, gọi thật 1 request `POST /enroll`
      thiếu field (400, không relay đi đâu) rồi xác nhận `/metrics` đếm đúng
      `{endpoint="enroll",status="400"} 1` — chứng minh middleware hoạt động
      qua đúng đường HTTP thật, không chỉ qua handler gọi trực tiếp trong
      unit test.

- [x] **Rà soát + hoàn thành phần kỹ thuật còn lại của Giai đoạn 2** (đối
      chiếu trực tiếp với mục 7 `docs/architecture-proposal.md`, không chỉ
      đọc README tự nhận). Giai đoạn 2 có 4 hạng mục: (a) nội dung STIG/TCVN,
      (b) mở rộng `RemediationVariant` cho Debian, (c) canary tự động Nhóm A,
      (d) pentest Agent rồi mới bật Active Response. (c) đã xong từ trước;
      (a) và (d) **không phải việc kỹ thuật** — cần Reviewer chuyên môn
      compliance và đội pentest độc lập tương ứng, tự dự án không thể quyết
      định thay. Rà soát (1 agent Explore đọc chéo code thật, không chỉ tin
      README) xác nhận (b) kỹ thuật đã sẵn sàng từ trước (`_find_remediation_variant`
      trong `app/jobs.py` lọc theo `os_family`/`os_version` hoàn toàn generic,
      `remediate.sh` cũng generic — không có gì hardcode riêng Ubuntu) nhưng
      **chưa từng được verify bằng thực nghiệm cho Debian** — mọi lần test
      "thành công" trước giờ đều dùng Ubuntu, Debian chỉ xuất hiện ở 1 test
      xác nhận KHÔNG khớp (đúng phân biệt distro, chưa chứng minh CHẠY được).
      Thêm 2 test (`test_jobs.py`): dry-run + apply thành công trọn vẹn cho
      host `os_family="Debian"` (kèm backup xuất hiện đúng), và phân biệt
      đúng bundle khi CÙNG 1 control có cả variant Ubuntu lẫn Debian (dispatch
      đúng `REMEDIATION_REF` của Debian, không lẫn sang Ubuntu) — 142/142 test
      orchestrator pass. **Không lặp lại toàn bộ nghi lễ E2E thật** (sinh GPG
      key + ký bundle + rebuild execution-env như đã làm cho Ubuntu trước
      đây) — cân nhắc tương xứng rủi ro: khác biệt DUY NHẤT giữa 2 distro
      trong toàn bộ pipeline là 1 giá trị chuỗi `os_family` so sánh bằng `=`
      (không có kiểu dữ liệu/dialect đặc biệt như các bug JSONB/BigInteger
      từng gặp), và `remediate.sh` + playbook test tối giản (chỉ tạo 1 file
      marker) không có nhánh nào phân biệt distro — đường thật (SSH + Ansible
      + ký bundle) đã verify E2E đầy đủ cho Ubuntu, lặp lại y hệt cho Debian
      không có gì mới để phát hiện, khác các trường hợp trước (`MAX_ARG_STRLEN`,
      bypass four-eyes) nơi chỉ có test thật trên hạ tầng thật mới lộ ra bug.
      Rà soát cũng phát hiện thêm 1 gap kỹ thuật khác dự án tự liệt kê thuộc
      Giai đoạn 2 nhưng chưa làm: **mTLS giữa Orchestrator/job-dispatcher**
      (hiện chỉ shared secret, xem `apps/job-dispatcher/README.md`) — rủi ro
      thực tế thấp (`job-net` không public, chỉ 2 service nối vào) nên tự dự
      án từng đánh giá "đủ dùng ở MVP", nhưng đây là thay đổi quy mô lớn hơn
      nhiều (cấp phát + renew cert cho job-dispatcher, đổi giao thức 2 service
      lõi) — hỏi người dùng qua AskUserQuestion trước khi làm, **được xác
      nhận làm luôn** (xem mục tiếp theo).

- [x] **mTLS giữa Orchestrator và job-dispatcher** (đóng nốt gap kỹ thuật
      cuối cùng của Giai đoạn 2, phát hiện qua rà soát ở mục trên) — 3 lớp
      phòng thủ (trước chỉ 2): **mTLS** (mới) + shared secret (giữ nguyên,
      không bị thay thế) + allowlist đúng 1 image (giữ nguyên).
      **Thiết kế**: job-dispatcher (Python/FastAPI/uvicorn) KHÔNG nối
      `ca-net` (chỉ Orchestrator được gọi CA) nên xin cert SERVER của chính
      nó qua `POST /internal/job-dispatcher/server-cert` (Orchestrator, cùng
      auth + hàm `mint_agent_manager_server_cert` đã dùng cho Agent Manager
      — chỉ khác `subject`), tự renew mỗi 4h (TTL provisioner 8h, module mới
      `apps/job-dispatcher/app/tls_identity.py`). Orchestrator (đã nối
      `ca-net`) thì NGƯỢC LẠI: tự mint 1 cert CLIENT MỚI cho MỖI LẦN gọi
      `/run` thay vì cache/renew (`app/jobs.py:_call_job_dispatcher`, dùng
      chung cho cả 3 nơi gọi job-dispatcher: scan/remediate/restore) — cùng
      triết lý "no standing privilege" của `mint_ssh_certificate` (mỗi job 1
      SSH cert riêng), đơn giản hơn nhiều so với duy trì renewal loop ở phía
      client vì mỗi lần gọi chỉ là 1 request/response ngắn (TTL 5-15 phút
      của provisioner "orchestrator" thừa đủ).
      **2 lỗi thật tự phát hiện qua chạy thật, không phải đọc code**:
      (1) `orchestrator: depends_on: job-dispatcher` (cũ, không rõ lý do —
      Orchestrator không thực sự cần dispatcher start trước) + `job-dispatcher:
      depends_on: orchestrator` (mới, THẬT SỰ cần vì job-dispatcher phải xin
      cert lúc khởi động) tạo thành **circular dependency**, Docker Compose
      từ chối khởi động — xoá chiều cũ (không có lý do thật), giữ chiều mới.
      (2) `uvicorn.Config` KHÔNG tự gán `config.ssl` (SSLContext) ngay lúc
      khởi tạo như giả định ban đầu — đọc source code uvicorn xác nhận
      `config.ssl` chỉ được gán BÊN TRONG `config.load()`, mà `load()` chỉ tự
      chạy bên trong `Server._serve()` (tức là bên trong `server.run()`) —
      cần renewal thread lấy `config.ssl` TRƯỚC khi gọi `server.run()` (để
      truyền vào `identity.renewal_loop`), nên phải tự gọi `config.load()`
      tường minh trước (an toàn: `_serve()` tự kiểm tra `if not config.loaded`
      trước khi gọi lại). Phát hiện qua chạy thật (`AttributeError: 'Config'
      object has no attribute 'ssl'`), không phải đọc tài liệu.
      **Verify mTLS thật hoạt động đúng** (không chỉ giả định từ code, kể cả
      sau khi đã hết lỗi khởi động): dùng `openssl s_client -state` (không
      phải chỉ đọc log ngắn) xác nhận job-dispatcher THẬT SỰ gửi "server
      certificate request" trong handshake; gửi tiếp 1 HTTP request thật qua
      kết nối KHÔNG có client cert — server chủ động đóng kết nối
      (`ECONNRESET`), đúng hành vi `CERT_REQUIRED`. Sau đó verify chiều
      THÀNH CÔNG: gọi thẳng `_call_job_dispatcher()` thật từ trong container
      Orchestrator (mint client cert thật qua step-ca, gọi job-dispatcher
      thật qua HTTPS) — nhận đúng kết quả từ container execution-env thật do
      job-dispatcher spawn, xác nhận dọn sạch container sau đó (không có
      container rác nào sót lại theo tên).
      8 test mới (`test_jobs.py`: endpoint cấp cert + mint client cert lỗi
      rơi đúng nhánh 502; `apps/job-dispatcher/tests/test_tls_identity.py`,
      mới hoàn toàn: bootstrap thành công/retry/hết hạn, hot-swap cert hợp
      lệ vào `SSLContext` thật đang chạy, từ chối cert hỏng KHÔNG đụng file
      cũ, renewal loop không dừng khi 1 lần renew lỗi — dùng `cryptography`
      tự sinh cert test thật, không mock crypto) — 147/147 test orchestrator
      + 19/19 test job-dispatcher pass. Rebuild + redeploy cả 2 service theo
      ĐÚNG THỨ TỰ (Orchestrator trước — có endpoint cấp cert mới — rồi mới
      tới job-dispatcher, tránh job-dispatcher bootstrap thất bại vì gọi
      endpoint chưa tồn tại), 7/7 service healthy sau khi deploy.

- [x] **Nối dây thật đường Active Response (claim/bundle/report) + rà soát
      bảo mật lần 5 + E2E thật có kiểm soát** — phát hiện qua audit lại từng
      phase (không tin README tự nhận): code + migration cho 3 endpoint
      `/internal/agent/remediate-jobs/claim`, `/remediation-bundle`,
      `/remediate-result` (`app/agents.py`) và route relay tương ứng phía
      Agent Manager đã VIẾT SẴN trong working tree nhưng **chưa từng sync
      lên lab, chưa migrate, chưa build lại image, chưa verify thật** — đúng
      loại "treo giữa đường" README Phase 4/5 từng ghi ("chưa có caller
      thật"). Đã hoàn thành đồng bộ (migration `0011` thêm
      `hosts.active_response_enabled`) + rebuild/redeploy `orchestrator`/
      `agent-manager`, rồi rà soát bảo mật đối kháng toàn diện (workflow đa
      agent + tự đọc code bổ sung phần bị hụt phiếu do chạm rate limit giữa
      chừng) trước khi cho phép bất kỳ thử nghiệm sống nào. **14 lỗi thật
      xác nhận, đã sửa hết, có test hồi quy cho từng lỗi**:
        - **[HIGH] TOCTOU xoá sạch ý nghĩa verify GPG**: `verifyBundleSignature`
          và `extractBundle` (cũ) mở `content.tar.gz` theo PATH 2 lần độc
          lập — Reporter (lộ ra mạng, kém tin cậy hơn Executor) có thể
          `os.Rename` đè file NGAY giữa khoảng hở đó, khiến Executor (chạy
          root) giải nén+chạy nội dung CHƯA TỪNG được ký trong khi vẫn báo
          `Verified=true`. Sửa: verify.go trả về `*os.File` đã mở (seek lại
          về 0 sau khi gpg đọc qua stdin), execute.go tái dùng ĐÚNG fd đó để
          giải nén (`extractBundleFromReader`) — rename() không ảnh hưởng fd
          đã mở (POSIX: fd tham chiếu inode, không tham chiếu path).
        - **[HIGH] Kill-switch chỉ được check lúc dispatch, không re-check
          lúc claim** — tắt kill-switch (`active_response_enabled` toàn cục
          hoặc riêng host, hoặc `agent_renewal_blocked`) SAU KHI job đã ở
          trạng thái "pending" không có tác dụng, Agent vẫn claim và thực
          thi được. Sửa: `claim_remediate_job` re-check đủ cả 3 điều kiện
          NGAY trước khi trả job cho Agent, trả 204 + ghi audit
          `remediate_claim_blocked_killswitch` nếu bị chặn.
        - **[HIGH] Job mồ côi vĩnh viễn nếu Orchestrator restart giữa lúc
          poll** — vòng poll của `_dispatch_remediate_job_via_agent` sống
          trong process, restart giữa chừng để lại Job kẹt "pending"/
          "running" mãi mãi, khoá cứng host khỏi mọi remediate job sau
          (`_lock_host_for_remediate` chặn 409 nếu còn job dở). Sửa: thêm
          `reconcile_orphaned_remediate_jobs()` (cùng mẫu
          `canary.py:reconcile_orphaned_rollouts` có sẵn), gọi trong
          `lifespan` TRƯỚC khi nhận request đầu tiên.
        - **[HIGH] Race ghi đè kết quả thật bằng "failed" do timeout** — nếu
          Agent báo kết quả thật ĐÚNG lúc vòng poll vừa timeout, nhánh
          timeout ghi đè `job.status="failed"` vô điều kiện, xoá mất kết quả
          + backup thật vừa nhận. Sửa: `db.refresh(job)` rồi kiểm tra
          `job.status` đã là `succeeded`/`failed` chưa TRƯỚC khi ghi đè.
        - **[HIGH] Kết quả thật đến muộn (sau khi job đã bị đánh timeout) bị
          409 và mất dấu hoàn toàn, không audit** — thêm
          `write_audit_event("agent_remediate_result_discarded_not_running")`
          ngay trước khi trả 409, để vận hành còn biết kết quả này từng tồn
          tại.
        - **[HIGH] Case-insensitive hostname cho phép agent hợp lệ giả mạo
          kết quả của host khác** — `handleMTLSRelay` (Agent Manager) forward
          NGUYÊN hostname client tự khai trong body, chỉ so khớp
          case-insensitive với CN cert lúc xác thực — 1 agent enroll đúng cho
          "Host-A" gửi body `{"hostname":"host-a"}` vẫn qua được so khớp
          nhưng Orchestrator (so khớp case-sensitive) nhận nhầm thành hostname
          khác nếu có host case khác tồn tại. Sửa: relay đúng CN đã xác thực
          (`body["hostname"] = cn`), không dùng lại chuỗi client tự khai.
        - **[HIGH] Ngân sách timeout dispatch nhỏ hơn tổng ngân sách Agent
          thật** — `AGENT_REMEDIATE_DISPATCH_TIMEOUT=340s` (cũ) < 15s poll +
          30s gpg verify + 300s executor timeout = 345s+ — sai lệch cấu hình
          MẶC ĐỊNH, không phải race hiếm. Nâng lên `600s`, ghi rõ ràng buộc
          "tăng `EXECUTOR_REMEDIATE_TIMEOUT` thì phải tăng theo hằng số này".
        - **[HIGH] Secret rỗng fail-open nếu thiếu trong `.env` thật** —
          `docker-compose.yml` dùng `${VAR}` không có fallback
          `${VAR:-default}`; thiếu 1 dòng trong `.env` thật khiến Compose âm
          thầm thay bằng chuỗi rỗng (không phải unset). Field `bool`/`int`
          pydantic tự chặn (crash rõ ràng), nhưng field `str` (gồm
          `job_dispatcher_shared_secret`, `agent_manager_shared_secret` —
          dùng `hmac.compare_digest()`) chấp nhận `""` như giá trị hợp lệ,
          và `compare_digest("", "")` luôn `True` = fail-open hoàn toàn cho
          mọi endpoint `/internal/*`. Phát hiện KHÔNG PHẢI lý thuyết — xảy ra
          thật 1 lần với `ACTIVE_RESPONSE_ENABLED` thiếu trong `.env` lab
          (crash-loop vì đây là field bool, tự lộ ra ngay). Sửa: thêm
          `model_validator(mode="after")` chặn tường minh mọi field secret
          bắt buộc bị rỗng, fail loudly cùng mức field bool.
        - **[HIGH] Executor infra-failure báo `exit_code=0` "succeeded" giả**
          — khi Executor verify chữ ký OK nhưng thực thi thất bại (giải nén
          lỗi, thiếu `playbook.yml`, backup lỗi...), Reporter cũ chỉ chặn
          theo `Verified`, không chặn theo `Executed` — compliance status
          giả mạo "thành công" dù không có gì được thực thi. Sửa:
          `pollAndExecuteRemediation` kiểm tra thêm `!result.Executed` →
          báo lỗi hạ tầng rõ ràng qua `/remediate-result` (`exit_code!=0`).
        - **[MEDIUM]** `get_remediation_bundle` không ràng buộc theo job —
          bất kỳ agent đã enroll đọc được bundle của BẤT KỲ remediation_ref
          nào đang tồn tại trên hệ thống, không chỉ đúng job đã claim cho
          host đó. Sửa: thêm điều kiện join `Job` đang `running` khớp đúng
          `hostname` + `remediation_ref` trước khi trả bundle, 404 nếu không
          khớp; ghi audit `agent_remediation_bundle_served`.
        - **[MEDIUM]** Thiếu truncate `log_tail`/`diff_output` phía đường
          Agent (đã truncate ở đường SSH agentless từ trước) — output
          `ansible-playbook` dài tuỳ ý phình `result_summary`.
        - **[MEDIUM]** Goroutine panic ở BẤT KỲ 1 trong 5 vòng lặp của
          Reporter (heartbeat/scan/FIM/renew/remediate) giết chết toàn bộ
          process — mâu thuẫn với comment cũ khẳng định "1 vòng lỗi/chậm
          không chặn các vòng còn lại" (Go: panic không recover ở 1
          goroutine chấm dứt toàn OS process, không chỉ goroutine đó). Sửa:
          helper `runProtected()` bọc `recover()` quanh mỗi vòng lặp.
        - **[LOW]** Chưa giới hạn kích thước response `/remediation-bundle`
          phía Reporter — thêm `maxBundleResponseBytes` (64 MiB) qua
          `io.LimitReader`.
        - **[LOW]** `maxExtractedBytes` (cũ) chỉ cộng dồn theo
          `tar.TypeReg`, không chặn được zip-bomb kiểu "hàng triệu entry
          gần-như-rỗng" (dir/symlink) — mỗi entry vẫn tốn 1 syscall thật.
          Thêm `maxExtractedEntries=100_000` độc lập với giới hạn byte.
      Verify: 197/197 pytest orchestrator, toàn bộ `go test` (agent,
      agent-manager, executor) pass — thêm ~10 test hồi quy mới, 1 cho mỗi
      lỗi có thể tái hiện qua unit/integration test.
      **E2E thật có kiểm soát trên lab server** (không chỉ tin unit test) —
      lần đầu toàn bộ đường Active Response chạy thật từ đầu tới cuối:
      phát hiện `scripts/content-signing/signed/` trên lab **chưa từng có
      bundle nào được ký** (chỉ có `.gitkeep`, keyring GPG trống hoàn toàn)
      — nghĩa là remediate (cả đường SSH agentless cũ lẫn Agent mới) chưa
      từng được verify với nội dung ký thật. Dựng trust anchor lab từ đầu
      (3 GPG key tạm đóng vai Puller/Reviewer/Signer, tự chạy đủ cả 3 vai vì
      là test lab — ghi rõ đây KHÔNG phải quy trình 3-người-3-máy thật), ký
      1 bundle test tuyệt đối an toàn (chỉ tạo 1 file marker vô hại trong
      `/var/tmp`, không đụng SSH/sysctl/service nào) qua đúng pipeline
      `pull.sh → review.sh → sign.sh`, verify qua chính `verify.sh`. Build
      lại Agent+Executor từ source hiện tại (binary cũ trên lab từ trước khi
      vá 14 lỗi trên — không dùng lại được), enroll thật qua step-ca lên
      host `console` (chính lab server, đã `ca_migration_status=
      trust_deployed` từ trước), bật kill-switch (global + riêng host) rồi:
      **dry-run** (Agent claim → tải bundle → Executor verify GPG → ansible
      `--check --diff` → báo kết quả) → `succeeded`, diff đúng, file KHÔNG
      được tạo (đúng hành vi dry-run); **apply thật** (four-eyes: người apply
      khác người dry-run vì host tier=1) → file được tạo đúng nội dung/
      permission (verify qua `nsenter` vào mount namespace riêng của
      Executor — `PrivateTmp=true` trong `hardening-executor.service`
      privatize `/var/tmp`, không phải bug, chỉ là đặc điểm cần biết khi
      test bằng path này; playbook remediation thật nhắm `/etc/ssh` v.v.
      không bị ảnh hưởng), backup 47 KB capture trước khi apply, audit
      trail đủ 13 event khớp chính xác luồng thiết kế (gồm đúng
      `agent_remediation_bundle_served` xác nhận fix job-binding hoạt động).
      Sau test: tắt lại CẢ 2 kill-switch, dừng+disable 2 systemd unit, xác
      nhận `settings.active_response_enabled=False` + host
      `active_response_enabled=False` — hệ thống trở lại đúng trạng thái
      dormant mặc định. 197/197 pytest vẫn pass, 7/7 service healthy sau
      cùng.
      **Còn 1 điểm mở, chưa tự quyết định thay người dùng**: fingerprint tin
      cậy cũ trong `.env` (`CONTENT_SIGNING_TRUSTED_FINGERPRINT`) trước đây
      trỏ tới 1 key không tồn tại trong bất kỳ keyring nào trên lab (chưa
      từng ký/verify được gì từ đầu dự án tới lúc rà lại lần này) — đã đổi
      sang key Signer test vừa tạo ở trên để có ít nhất 1 trust anchor hoạt
      động thật cho lab (backup `.env` cũ tại `.env.bak-before-e2e-test`);
      cần quyết định sau có dựng 1 key "chính thức" riêng hay giữ nguyên key
      test này làm tạm.

## Việc CHƯA làm (đúng theo roadmap, không phải thiếu sót)

Theo quyết định giới hạn quy mô ban đầu ≤50 máy (xem mục 0 và rủi ro #9 trong
architecture-proposal.md): **chưa** làm HA control-plane, multi-site Local
Relay, Kubernetes. Các hạng mục này thuộc Giai đoạn 2/3 — xem mục 7 trong tài
liệu kiến trúc. Agent tự phát triển (Reporter/Executor) — cả 5 phase theo kế
hoạch đã thống nhất (xem checklist "Agent tự phát triển (mục 4.3)" ở trên)
đã xong ở mức pilot SCA/báo cáo, và đường Active Response (claim/bundle/
report) giờ đã **nối dây thật, rà soát bảo mật, và verify E2E thật trên lab**
(xem mục "Nối dây thật đường Active Response..." ở trên) — về mặt kỹ thuật
đã sẵn sàng chạy thật cho fleet. Kill-switch (`ACTIVE_RESPONSE_ENABLED` toàn
cục + `Host.active_response_enabled` riêng từng host) **cố tình vẫn để tắt**
sau khi test xong, chờ pentest riêng theo đúng khuyến nghị tài liệu kiến
trúc trước khi bật thật cho máy trong fleet — không phải thiếu sót kỹ thuật.

**Giai đoạn 2 (mục 7 kiến trúc) — phần kỹ thuật thuần tuý đã hoàn tất**: cả 4
hạng mục (STIG/TCVN, RemediationVariant Debian, canary tự động Nhóm A,
pentest Agent→Active Response) đã được rà soát đối chiếu trực tiếp với code
thật (không chỉ tin README tự nhận). 2 hạng mục kỹ thuật (Debian, canary) đã
xong + verify thật; mTLS Orchestrator/job-dispatcher (phát hiện thêm qua rà
soát, không nằm trong 4 mục gốc nhưng tự dự án từng liệt kê thuộc Giai đoạn
2) cũng đã xong. **2 hạng mục còn lại (nội dung STIG/TCVN thật, pentest
Agent) không phải việc kỹ thuật** — cần Reviewer có chuyên môn compliance và
đội pentest độc lập tương ứng, ngoài khả năng tự quyết định của assistant.
