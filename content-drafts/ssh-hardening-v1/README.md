# SUPERSEDED — ssh-hardening-v1

**Đã bị thay thế bởi `content-drafts/ssh-cis-official-v1/`** — theo yêu cầu
dùng đúng chuẩn CIS chính thức (ComplianceAsCode, cùng nguồn với tính năng
Quét) thay vì role cộng đồng `devsec.hardening.ssh_hardening` dùng ở đây.
Control `ssh-hardening-cipher-forwarding-root-login` + bundle
`ssh-hardening-v1-20260715T093759Z` đã ký/tạo trong Control Registry vẫn còn
tồn tại (không xoá được — ràng buộc audit trail), nhưng KHÔNG nên dùng tiếp,
chỉ còn giá trị lịch sử. Dùng `ssh-cis-official-v1` cho mọi việc liên quan
SSH hardening từ giờ.

---

**Chưa qua review/ký, chưa dùng thật.** Đây là bản soạn thử theo yêu cầu
"soạn thử playbook đi" — Reviewer đọc kỹ `playbook.yml` (đặc biệt phần comment
giải thích override `ssh_permit_root_login`) trước khi quyết định đưa vào
quy trình ký thật hay sửa lại.

## Nếu quyết định dùng bản này — các bước còn lại (thủ công, ngoài phạm vi code)

1. **Tạo Control trong Control Registry** (`POST /controls`, role rule-editor):
   ```json
   {"title": "SSH hardening (cipher/forwarding/root-login)", "category": "ssh"}
   ```
   Sau đó set `risk_group=B` (`PATCH /controls/{id}/risk-group`) — **không**
   để mặc định A, vì đây đúng loại control "tự khoá kênh" (mục 4.5
   architecture-proposal.md).

2. **Đóng gói bundle** — quy trình `pull.sh` vốn thiết kế cho tải nội dung từ
   URL, tự sinh `content.tar.gz` — nhưng `remediate.sh` đọc `playbook.yml`
   **trực tiếp** trong thư mục bundle (KHÔNG tự giải nén content.tar.gz —
   xem `apps/execution-env/remediate.sh`), nên cần thêm 1 bước tay:
   ```bash
   tar czf /tmp/ssh-hardening-v1-payload.tar.gz -C content-drafts/ssh-hardening-v1 playbook.yml
   scripts/content-signing/pull.sh "file:///tmp/ssh-hardening-v1-payload.tar.gz" ssh-hardening-v1
   # copy playbook.yml ra NGOÀI tar, vào ĐÚNG thư mục staging/ vừa tạo:
   cp content-drafts/ssh-hardening-v1/playbook.yml scripts/content-signing/staging/ssh-hardening-v1-<timestamp>/
   ```

3. **Review + Sign** — đúng quy trình 3 vai trò như đã làm với `agent-v1`
   (3 người/3 GPG key khác nhau, không phải 1 người 3 key nếu đây là nội
   dung áp lên fleet thật, không còn là giai đoạn pilot):
   ```bash
   scripts/content-signing/review.sh staging/ssh-hardening-v1-<timestamp>
   scripts/content-signing/sign.sh reviewed/ssh-hardening-v1-<timestamp>
   ```
   Fingerprint Signer set vào `CONTENT_SIGNING_TRUSTED_FINGERPRINT` (`.env`)
   — biến này RIÊNG, không dùng chung với `AGENT_BUNDLE_TRUSTED_FINGERPRINT`.
   Cần thêm public key Signer vào `apps/execution-env/trusted-signer-pubkey.asc`
   (nối vào, không xoá key `agent-signer` đang có) rồi rebuild execution-env.

4. **Tạo RemediationVariant** (`POST /controls/{id}/remediation-variants`,
   role rule-editor) trỏ `remediation_ref` = đúng tên thư mục vừa ký (vd
   `ssh-hardening-v1-<timestamp>`), `os_family` khớp distro máy đích,
   `check_method="ansible-check"`.

5. **BẮT BUỘC dry-run trước** (`POST /hosts/{hostname}/remediate-dry-run`) —
   xác nhận diff hiển thị đúng như mong đợi (KHÔNG tạo state gì) — rồi mới
   test apply thật trên 1 host Tier thấp, KHÔNG áp trực tiếp Tier 0/1 (mục
   4.6 — out-of-band recovery cho Tier 0/1 project này chưa có).
