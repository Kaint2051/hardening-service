# Content Signing Service — quy trình 3 vai trò (Giai đoạn 0)

Thực thi nguyên tắc "ký số nội dung policy/benchmark" (mục 1.6) và chuỗi cung
ứng nội dung 3 vai trò tách biệt (mục 3) trong `docs/architecture-proposal.md`.
Bắt buộc **3 người khác nhau, 3 GPG key khác nhau** — không một người vừa tải
vừa ký, script tự chặn nếu phát hiện trùng key.

```
pull.sh   (Puller)   → staging/<name>-<timestamp>/
review.sh (Reviewer) → reviewed/<name>-<timestamp>/
sign.sh   (Signer)   → signed/<name>-<timestamp>/
```

## Yêu cầu

- Mỗi người tham gia (Puller/Reviewer/Signer) có **GPG key cá nhân riêng**
  (`gpg --full-generate-key`), import vào keyring của máy họ dùng để chạy
  script tương ứng. Không dùng chung 1 máy/1 keyring cho cả 3 vai trò.
- `python3` (dùng để đọc/ghi JSON trong script — không cần cài thêm thư viện).

## Quy trình dùng

```bash
# Máy của Puller
./pull.sh https://github.com/ComplianceAsCode/content/releases/download/v0.1.73/scap-security-guide-0.1.73.tar.gz \
           complianceascode-v0.1.73

# Chuyển thư mục staging/complianceascode-v0.1.73-<timestamp>/ sang máy Reviewer
# (qua kênh nội bộ đã kiểm soát, không qua email/USB không kiểm soát)

# Máy của Reviewer
./review.sh staging/complianceascode-v0.1.73-<timestamp>

# Chuyển thư mục reviewed/... sang máy Signer

# Máy của Signer
./sign.sh reviewed/complianceascode-v0.1.73-<timestamp>
```

## Verify trước khi dùng (Execution Env / pipeline nạp nội dung)

```bash
./verify.sh signed/complianceascode-v0.1.73-<timestamp> <FINGERPRINT_CUA_SIGNER_TIN_CAY>
```

`<FINGERPRINT_CUA_SIGNER_TIN_CAY>` nên được cấu hình cứng (hoặc qua biến môi
trường) ở phía Orchestrator/Execution Env — không đọc fingerprint tin cậy từ
chính bundle đang verify.

## Giới hạn của bản Giai đoạn 0 (cần biết trước khi dùng thật)

- Script hiện giả định 3 vai trò chạy trên 3 máy/3 keyring riêng biệt do kỷ
  luật vận hành đảm bảo — chưa tích hợp với Keycloak để xác thực danh tính
  qua SSO. Việc gắn định danh tổ chức (thay vì chỉ dựa vào GPG fingerprint)
  là hạng mục cần bổ sung trước khi vận hành production.
- Chuyển file giữa 3 máy (staging → reviewed → signed) hiện làm thủ công —
  cần quy định kênh chuyển an toàn (không qua email cá nhân/USB không kiểm
  soát) như một phần runbook vận hành, không phải vấn đề của riêng script.
- `sha256` trong `manifest.json` do chính Puller tự tính — chỉ chống thay đổi
  nội dung *sau* bước Pull, không thay cho việc Reviewer tự kiểm tra nội dung
  tải về có đúng nguồn gốc mong đợi hay không (đọc kỹ diff, không chỉ bấm
  APPROVE).
