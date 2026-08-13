# ssh-cis-official-v1 — ĐÃ KÝ VÀ VERIFY THẬT

Thay thế `ssh-hardening-v1` (dùng role cộng đồng `devsec.hardening.ssh_hardening`) —
theo yêu cầu dùng đúng **chuẩn CIS chính thức**, cùng nguồn nội dung đang dùng
để "Quét" (ComplianceAsCode), không phải tự chọn role khác.

## Nguồn

`ansible/ubuntu2204-playbook-cis_level1_server.yml` trích từ bản phát hành
chính thức `ComplianceAsCode/content` v0.1.81
(https://github.com/ComplianceAsCode/content/releases/tag/v0.1.81) — đã verify
sha512 khớp công bố trước khi dùng. File gốc 21281 dòng, cho TOÀN BỘ profile
CIS Ubuntu 22.04 LTS Benchmark v2.0.0 Level 1 Server (>100 rule).

`playbook.yml` ở đây là **bản trích** chỉ giữ:
- 1 task bắt buộc `Gather the package facts` (nhiều rule khác phụ thuộc).
- Toàn bộ rule liên quan SSH (đúng nguyên văn, không sửa nội dung/tags).

**Đã loại bỏ 1 rule**: `Disable SSH Root Login` (tag `sshd_disable_root_login`)
— rule này viết cứng `PermitRootLogin no` (không có biến để chỉnh, khác các
rule khác trong cùng file). Hệ thống SSH vào bằng root qua cert CA ngắn hạn
(`remediate-apply` luôn cứng `SSH_USER=root`) — áp `PermitRootLogin no` sẽ tự
khoá kênh quản lý chính host đó. Xem comment đầy đủ trong `playbook.yml`.

## Đã verify thật (không phải lý thuyết)

- Control: `cis-ubuntu-22-04-benchmark-v2-0-0-ssh-controls-level-1-server`
  (`risk_group=B` mặc định), có `StandardMapping` trỏ CIS Ubuntu 22.04 §5.2.
- Ký qua đúng quy trình 3 vai trò (`.content-signing-keys/` trên lab server).
- Bundle đã ký: `ssh-cis-official-v1-20260716T092213Z`
  (`scripts/content-signing/signed/`).
- `remediate-dry-run` thật trên host `console`: **148 ok, 30 changed (dự
  kiến), 0 failed, 24 skipped** — verify lại trực tiếp sau đó xác nhận
  KHÔNG có gì đổi thật (`/etc/ssh/sshd_config.d/` vẫn chỉ có file gốc,
  `PermitRootLogin` vẫn nguyên giá trị cũ).

## Việc còn lại trước khi apply thật

1. Đọc kỹ 30 thay đổi dự kiến (MACs/KexAlgorithms/ClientAlive*/MaxSessions/
   MaxStartups/LoginGraceTime/Banner/...) — xác nhận phù hợp với vận hành
   thật (vd Banner text, idle timeout) trước khi apply lên host đầu tiên.
2. Test apply thật trên 1 host Tier thấp trước — KHÔNG áp trực tiếp Tier 0/1
   (chưa có out-of-band recovery, mục 4.6 architecture-proposal.md).
3. Cân nhắc bổ sung lại rule `sshd_disable_root_login` (dạng
   `PermitRootLogin prohibit-password`, không phải `no`) sau khi có out-of-band
   recovery cho host đó.
