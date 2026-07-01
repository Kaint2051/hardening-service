# Zero-to-CA Migration — runbook (Giai đoạn 0/1, mục 4.4)

Đưa máy hiện hữu (đang dùng static SSH key/password) sang tin cậy SSH CA của
step-ca, KHÔNG bao giờ xoá đường truy cập cũ trước khi có đường mới hoạt
động. Quy trình 2 bước, tách rời có chủ đích:

## Bước 1 — Deploy trust (playbook `zero-to-ca-migration.yml`)

1. Export public key của SSH User CA:
   ```bash
   docker compose exec step-ca step ssh config --roots > ansible/files/ssh_user_ca.pub
   ```
2. Copy `ansible/inventory/hosts.example.ini` → `hosts.ini`, điền 1-2 máy cho
   canary batch đầu tiên (KHÔNG điền cả 50 máy).
3. Chạy với credential CŨ (một lần duy nhất cho việc này):
   ```bash
   ansible-playbook -i ansible/inventory/hosts.ini \
     ansible/playbooks/zero-to-ca-migration.yml --limit batch1 --ask-pass
   ```
   Sau bước này: máy đã tin cậy CA, nhưng **credential cũ vẫn còn hoạt động**.

## Bước 2 — Verify rồi mới thu hồi credential cũ

1. Tự tay (hoặc qua Orchestrator khi đã có luồng cấp cert thật) xin 1 SSH
   cert ngắn hạn từ step-ca và **thử kết nối thành công** tới đúng máy vừa
   deploy trust:
   ```bash
   step ssh certificate <email> /tmp/id_ecdsa --provisioner orchestrator
   ssh -i /tmp/id_ecdsa admin@pilot-host-01.internal echo ok
   ```
2. Chỉ sau khi bước trên thành công, thu hồi credential cũ **cho đúng máy
   đó** (không dùng group, chỉ định đích danh hostname):
   ```bash
   ansible-playbook -i ansible/inventory/hosts.ini \
     ansible/playbooks/revoke-old-credential.yml --limit pilot-host-01.internal
   ```

## Nguyên tắc bắt buộc khi mở rộng batch

- Không tăng số máy/batch cho tới khi batch trước đã hoàn tất CẢ 2 bước và
  chạy ổn định một thời gian.
- Máy mới thêm vào fleet **sau này** vẫn phải đi qua đúng 2 bước này, không
  dùng lối tắt (mục 4.4, rủi ro #8 trong `docs/architecture-proposal.md`).
- Theo dõi tiến độ qua audit log của Orchestrator (`GET /internal/audit-events/verify`
  để kiểm tra chain còn nguyên vẹn; truy vấn DB trực tiếp để xem máy nào đang
  ở trạng thái `ca_trust_deployed` mà chưa có `legacy_credential_revoked`
  tương ứng — đó là danh sách "đang migrate dở dang" cần theo dõi).
