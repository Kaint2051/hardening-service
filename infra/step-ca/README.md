# step-ca — CA/Secrets Cluster (Giai đoạn 0)

Container này khởi tạo tự động qua biến môi trường `DOCKER_STEPCA_INIT_*` trong
`docker-compose.yml` (xem ảnh `smallstep/step-ca`). Lần chạy đầu tiên sẽ tự
sinh root CA + intermediate CA + SSH host/user CA, lưu trong volume
`step-ca-data`.

## ⚠️ Đây là cấu hình DEV, chưa phải production

Theo nguyên tắc 4.1 trong `docs/architecture-proposal.md`, root CA phải
**offline/HSM**, chỉ intermediate online. Cấu hình Docker Compose ở đây chạy
cả root lẫn intermediate trong cùng container để tiện phát triển local.

**Trước khi đưa vào môi trường thật:**
1. Sinh root CA trên máy air-gapped (không nối mạng), export intermediate CSR,
   ký bằng root, rồi disable/tháo máy root khỏi mạng — root private key không
   bao giờ được nằm trên máy có kết nối mạng.
2. Chỉ intermediate CA (đã ký bởi root) mới chạy online trong container này.
3. Đặt container này trên `ca-net` cô lập như đã cấu hình sẵn — không thêm
   port publish, không nối thêm service nào khác ngoài `orchestrator`.

## Provisioner

- Provisioner mặc định (`orchestrator`, JWK) — dùng cho Orchestrator gọi CA
  cấp SSH certificate ngắn hạn cho Ephemeral Execution Env (mục 4.1/4.2).
- Provisioner `agent-enrollment` (thêm bằng `setup-provisioners.sh`) — dùng
  riêng cho bootstrap token một-lần khi enrollment agent mới (mục 4.3/4.4),
  TTL token cực ngắn, tách biệt khỏi provisioner của Orchestrator để một token
  bootstrap bị lộ không thể dùng để giả làm Orchestrator xin cert tuỳ ý.

Chạy sau khi `docker compose up -d step-ca` lần đầu:

```bash
./infra/step-ca/setup-provisioners.sh
```

## Chính sách TTL (khớp mục 1 và 4.3 trong architecture-proposal.md)

| Loại cert | TTL |
|---|---|
| SSH cert cho Execution Env (qua Orchestrator) | 5–15 phút |
| Cert mTLS cho Agent (Reporter) | vài giờ, tự renew trước hạn |
| Bootstrap token enrollment agent | vài phút, dùng một lần |
