# Linux Hardening Service Tool

Web-console quản lý hardening & cấu hình service cho máy chủ Linux. Kiến
trúc đầy đủ và lý do các quyết định thiết kế nằm ở
[`docs/architecture-proposal.md`](docs/architecture-proposal.md) — đọc file
đó trước khi đọc tiếp phần dưới.

Trạng thái hiện tại: **Giai đoạn 0 hoàn thành** (nền tảng an toàn, đã verify
thật trên lab server) — **Giai đoạn 1 đang bắt đầu**: RBAC thật qua Keycloak
+ Control Registry (schema Control/StandardMapping/RemediationVariant) đã có
và verify end-to-end bằng token Keycloak thật.

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
                           hash-chain, Control Registry (app/controls.py)
  execution-env/           Dockerfile "Ephemeral Execution Environment" (Ansible + OpenSCAP)
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
      sinh root CA trên máy air-gapped theo `infra/step-ca/README.md`.
- [ ] Đổi toàn bộ giá trị `changeme` trong `.env` và secret Keycloak client
      trước khi dùng ngoài môi trường dev cá nhân.

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
- [ ] Web UI, four-eyes cho toàn bộ luồng nghiệp vụ khác (không chỉ maturity),
      versioning lịch sử thay đổi Control — chưa làm.
- [ ] Agentless scan/remediate qua Ansible+OpenSCAP cho 1 benchmark CIS —
      chưa làm.

## Việc CHƯA làm (đúng theo roadmap, không phải thiếu sót)

Theo quyết định giới hạn quy mô ban đầu ≤50 máy (xem mục 0 và rủi ro #9 trong
architecture-proposal.md): **chưa** làm HA control-plane, multi-site Local
Relay, Kubernetes, Agent tự phát triển (Reporter/Executor). Các hạng mục này
thuộc Giai đoạn 2/3 — xem mục 7 trong tài liệu kiến trúc.
