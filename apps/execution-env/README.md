# Ephemeral Execution Environment

Image dùng làm môi trường chạy job SSH (agentless: scan OpenSCAP / remediate
Ansible). Orchestrator tạo **1 container mới cho mỗi job** từ image này, rồi
huỷ ngay sau khi job kết thúc — không có container sống lâu dài nắm giữ SSH
cert + playbook (xem rủi ro "Ansible Control Node..." đã phân tích trong
`docs/architecture-proposal.md`).

## `remediate.sh` — bundle convention

`RemediationVariant.remediation_ref` (`apps/orchestrator/app/models.py`) trỏ
tới 1 thư mục con trong `scripts/content-signing/signed/<remediation_ref>/`,
mount read-only vào container tại `/content` bởi job-dispatcher (xem
`apps/job-dispatcher/app/main.py` — **luôn mount, không phân biệt scan hay
remediate**, `CONTENT_SIGNING_SIGNED_HOST_PATH` phải là đường dẫn TRÊN HOST
DOCKER thật, xem `.env.example`). Bundle phải có đúng 3 file:

```
scripts/content-signing/signed/<remediation_ref>/
  content.tar.gz       # (không thực sự cần giải nén — chỉ để verify chữ ký)
  content.tar.gz.sig    # chữ ký GPG detached, armored
  playbook.yml          # entrypoint Ansible thật sự chạy — có thể include_role
                         # tới các role bake sẵn trong image (xem dưới)
```

`remediate.sh` verify chữ ký `content.tar.gz.sig` khớp
`CONTENT_SIGNING_TRUSTED_FINGERPRINT` (cùng cơ chế
`scripts/content-signing/lib-gpg-fingerprint.sh`) **trước khi chạy bất cứ
gì** — TỪ CHỐI nếu chữ ký sai/thiếu/không khớp, không chạy `ansible-playbook`
trong mọi trường hợp đó.

**`trusted-signer-pubkey.asc`**: container chạy job MỚI mỗi lần, keyring GPG
trống — biết fingerprint nào đáng tin (biến môi trường) là chưa đủ, cần
CHÍNH public key đó nằm trong keyring mới verify được. Bake public key vào
IMAGE lúc build (`Dockerfile` tự `gpg --import`), cùng tinh thần
`requirements.yml` pin theo commit hash, thay vì truyền qua biến môi trường
runtime. File này hiện là **placeholder** — `gpg --import` sẽ thất bại lúc
build (không chặn build, chỉ in cảnh báo) khiến `remediate.sh` **từ chối MỌI
bundle** cho tới khi Signer xuất public key thật thay vào (xem hướng dẫn
trong chính file `trusted-signer-pubkey.asc`) — an toàn mặc định, không phải
thiếu sót.

**2 cơ chế phân phối nội dung KHÁC NHAU, đừng nhầm lẫn**:
- `requirements.yml` (dưới đây) — role hardening CHUNG, bake sẵn vào image
  lúc build (`/etc/ansible/roles`), pin theo commit hash đã review.
- `scripts/content-signing/signed/<ref>/playbook.yml` — nội dung CỤ THỂ
  theo từng job/Control, ký + mount riêng, có thể `include_role` tới role ở
  trên.

## Trước khi dùng thật

1. **Điền commit hash đã review vào `requirements.yml`** — hiện đang là
   placeholder. Không build/deploy image với placeholder còn nguyên.
2. Build lại image mỗi khi `requirements.yml` đổi, gắn tag theo hash nội dung
   (`docker build -t execution-env:<content-hash> .`) để Orchestrator có thể
   pin đúng version image khi tạo job, không dùng tag `latest`.
3. Nội dung SCAP/benchmark (ComplianceAsCode) KHÔNG nằm trong image này — được
   mount read-only từ `scripts/content-signing/signed/` lúc chạy container,
   sau khi đã qua quy trình Puller → Reviewer → Signer.
4. **Chuẩn bị ít nhất 1 bundle remediation đã ký** theo đúng convention ở
   trên (playbook.yml + content-signing pipeline) trước khi remediate thật
   có ý nghĩa — pipeline (Orchestrator endpoint + execution-env script) đã
   sẵn sàng, chỉ còn thiếu nội dung đã qua review.

## Backup + restore trước/sau remediate

`remediate.sh` (nhánh apply thật, KHÔNG áp dụng cho dry-run) tar các path cấu
hình cố định trước khi chạy playbook thật — đúng phạm vi 2 role dev-sec
os-hardening/ssh-hardening hay đụng chạm:
`/etc/ssh /etc/pam.d /etc/sysctl.conf /etc/sysctl.d /etc/security
/etc/login.defs`. Kết quả nhúng base64 vào `Job.result_summary.backup_tar_b64`
(giới hạn 2 MiB, `backup_truncated: true` nếu vượt) — đúng nguyên tắc cốt lõi
#7 ("rollback/backup được tạo TRƯỚC khi remediate").

`restore.sh` (mới) là chiều ngược lại — gọi qua
`POST /hosts/{hostname}/restore` (`source_job_id` trỏ tới 1 job remediate-apply
đã succeeded), giải nén backup lên host đích qua SSH, `sshd -t` trước khi
reload (không tự khoá SSH nếu backup có vấn đề). Backup 1 biến môi trường duy
nhất vượt `MAX_ARG_STRLEN` (131072 byte) của kernel Linux nên được chia thành
nhiều biến `BACKUP_TAR_B64_{i}` (xem `RESTORE_CHUNK_SIZE` trong
`app/jobs.py`), `restore.sh` ghép lại trước khi giải nén. Từ chối restore
(422, không âm thầm khôi phục 1 phần) nếu backup nguồn bị `backup_truncated`.
Chưa có nút bấm Web UI (chỉ API) — xem README gốc.

## Đã verify (lab server, Ubuntu 24.04)

Build thật đã được chạy với `requirements.yml` còn nguyên placeholder: các
layer tooling (apt-get ansible/ansible-lint/openscap-scanner/openssh-client,
pip install ansible-runner) build thành công; build **dừng cứng đúng như
thiết kế** ở bước `ansible-galaxy role install` với lỗi
`pathspec 'REPLACE_WITH_REVIEWED_COMMIT_SHA' did not match any file(s) known
to git` — xác nhận không thể vô tình build ra image dùng role chưa qua
review. Chưa build image dùng role thật (cần điền commit hash đã review
trước).

**`remediate.sh` + toàn bộ pipeline job_type=remediate-* đã verify E2E thật**
trên lab server (build với `INSTALL_REMEDIATION_ROLES=false` — không cần
commit hash thật để test plumbing): sinh 1 GPG key thử nghiệm + 1 playbook
Ansible tối giản (chỉ tạo 1 file marker, không phải nội dung hardening thật),
ký bundle, TẠM thời bake public key thử nghiệm vào `trusted-signer-pubkey.asc`
để test → dry-run thật (`--check --diff`) xác nhận KHÔNG tạo marker trên host
đích → apply thật (user khác — four-eyes Tier 0 chặn đúng user đã dry-run,
403) tạo marker thành công + backup (63 KB base64) xuất hiện trong
`Job.result_summary`. Sau đó revert lại `trusted-signer-pubkey.asc` về
placeholder, rebuild, xác nhận **CHÍNH bundle vừa verify thành công đó** giờ
bị từ chối (keyring trống) — chứng minh an toàn mặc định thật sự hoạt động,
không chỉ lý thuyết.

## Chạy thử cục bộ

```bash
docker build -t execution-env:dev ./apps/execution-env

docker run --rm \
  -v "$(pwd)/scripts/content-signing/signed:/content:ro" \
  execution-env:dev --help
```
