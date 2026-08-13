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
runtime. File hiện có 1 key THẬT (`agent-signer`, dùng cho
`AGENT_BUNDLE_TRUSTED_FINGERPRINT` — xem `apps/agent/README.md` mục đóng gói
bundle Agent) — **KHÔNG phải Signer cho remediation content**. `remediate.sh`
verify theo `CONTENT_SIGNING_TRUSTED_FINGERPRINT` (biến RIÊNG, đã tách khỏi
`AGENT_BUNDLE_TRUSTED_FINGERPRINT` — xem `app/config.py`), fingerprint này
hiện KHÔNG có key tương ứng trong file → `remediate.sh` vẫn **từ chối MỌI
bundle remediation** cho tới khi làm xong mục A dưới đây (an toàn mặc định,
không phải thiếu sót). `gpg --import` chấp nhận nhiều key trong 1 file —
thêm key remediation Signer vào CUỐI file này (không xoá key agent-signer
đang có).

**2 cơ chế phân phối nội dung KHÁC NHAU, đừng nhầm lẫn**:
- `requirements.yml` (dưới đây) — collection hardening CHUNG (`devsec.hardening`),
  bake sẵn vào image lúc build (`/usr/share/ansible/collections`), pin theo
  commit hash đã review.
- `scripts/content-signing/signed/<ref>/playbook.yml` — nội dung CỤ THỂ
  theo từng job/Control, ký + mount riêng, `include_role` tới role FQCN ở
  trên (vd `devsec.hardening.os_hardening`).

## Trước khi dùng thật

Pipeline kỹ thuật (Orchestrator endpoint + execution-env script + Agent Active
Response) đã sẵn sàng và verify E2E thật — phần còn thiếu là **2 việc cần
người/danh tính thật**, không phải code. Cố tình KHÔNG tạo key/commit hash giả
để "lấp chỗ trống": mục đích của 2 placeholder này là buộc phải có 1 người cụ
thể chịu trách nhiệm, không phải 1 bước kỹ thuật có thể tự động hoá.

### A. Xác lập Signer thật (`trusted-signer-pubkey.asc`)

1. Tổ chức chỉ định 1 người làm **Signer** — phải KHÁC người làm Puller và
   Reviewer trong quy trình `scripts/content-signing/` (script tự chặn nếu
   trùng key, xem `scripts/content-signing/README.md`).
2. Signer sinh GPG key cá nhân **trên máy của họ** (không phải lab server dùng
   chung, không phải máy chạy Orchestrator): `gpg --full-generate-key`.
3. Xuất public key: `gpg --armor --export <fingerprint-đầy-đủ> > trusted-signer-pubkey.asc`.
4. Thay TOÀN BỘ nội dung `apps/execution-env/trusted-signer-pubkey.asc` bằng
   output ở bước 3 (public key không bí mật, an toàn commit vào git).
5. Đặt `CONTENT_SIGNING_TRUSTED_FINGERPRINT` trong `.env` thật (lab/production)
   bằng đúng fingerprint đầy đủ (40 ký tự hex, không rút gọn 8 ký tự cuối —
   tránh nhầm lẫn/collision) của key vừa tạo.
6. Rebuild image theo đúng tag mà `ALLOWED_EXECUTION_IMAGE` (job-dispatcher)
   trỏ tới, xác nhận log build KHÔNG còn cảnh báo `gpg --import` thất bại.
7. Verify: ký thử 1 bundle vô hại (vd chỉ tạo 1 file marker trong `/var/tmp`,
   giống cách đã verify E2E trước đây) qua đúng `pull.sh → review.sh → sign.sh`,
   chạy `remediate.sh` dry-run xác nhận `verified:true` đúng fingerprint.

### B. Review + ghim Ansible role thật (`requirements.yml`) — ĐÃ XONG

Review thật đã thực hiện (không phải placeholder nữa) — 2 phát hiện quan
trọng lúc review, đọc kỹ trước khi động vào `requirements.yml`:

1. `dev-sec/ansible-os-hardening` và `dev-sec/ansible-ssh-hardening` (2 role
   standalone dùng trong bản đề xuất gốc) **đã bị chính dev-sec deprecate** —
   `ssh-hardening` archived từ 2020 (đóng băng ~6 năm), `os-hardening` bị
   merge vào 1 collection chung. Đã pin vào collection kế thừa còn maintain
   thật: `devsec.hardening` (`https://github.com/dev-sec/ansible-collection-hardening`,
   tag `10.6.0`, commit `f5a6c4b652eca494e5ece586b45677ecfb0feec8`).
2. **Tên role đổi khác hoàn toàn** khi viết `playbook.yml` cho bundle
   remediation: `devsec.hardening.os_hardening` /
   `devsec.hardening.ssh_hardening` (FQCN có namespace, không phải
   `dev-sec.os-hardening` cũ) — role cài bằng
   `ansible-galaxy collection install` vào `/usr/share/ansible/collections`
   (path mặc định ansible-playbook tự tìm collection), KHÔNG còn ở
   `/etc/ansible/roles` như trước.

Kết quả review chi tiết (không có gì đáng ngại, nhưng 1 điểm PHẢI nhớ trước
khi dùng `ssh_hardening`) — xem comment đầy đủ trong `requirements.yml`.
Build xác nhận thật: `docker run <image> ansible-doc -t role -l | grep devsec`
thấy đúng `devsec.hardening.os_hardening`/`ssh_hardening`.

### C. Ký bundle remediation thật đầu tiên

Sau khi (A) xong, dùng đúng quy trình `scripts/content-signing/` (Puller tải
nội dung remediation thật → Reviewer duyệt diff → Signer ký bằng key đã thiết
lập ở mục A) cho từng `RemediationVariant.remediation_ref` cần dùng — xem
`scripts/content-signing/README.md`.

### Ngoài phạm vi engineering — cần quyết định của tổ chức trước khi go-live

- Nội dung STIG/TCVN thật (cần Reviewer chuyên môn compliance).
- Pentest độc lập cho Agent trước khi bật `ACTIVE_RESPONSE_ENABLED` cho fleet
  thật (kill-switch cố tình đang tắt).

## Datastream STIG cho Ubuntu 22.04 (profile `ubuntu2204-stig`)

Gói apt `ssg-debderived` (0.1.65-1, cài trong `Dockerfile`) chỉ có profile
CIS/standard cho Ubuntu — **không có profile STIG**. Đã verify thật: profile
`stig` (DISA "Canonical Ubuntu 22.04 LTS STIG V2R7") có tồn tại trong release
chính thức ComplianceAsCode v0.1.81 (cùng release đang dùng cho
`control-templates/ubuntu2204-cis_level1_server.yml`), nên vendor riêng file
`ssg-ubuntu2204-ds.xml` của release đó vào repo dưới tên
`ssg-ubuntu2204-stig-ds.xml` (sha512 tarball đã verify trước khi lấy, xem
`control-templates/README.md` mục quy trình chung) — **KHÔNG** thay thế/nâng
cấp file CIS đang chạy (giữ nguyên 100% hành vi scan CIS hiện có), chỉ cộng
thêm 1 datastream riêng, dù bản thân file này có chứa cả 2 loại profile.
`SCAP_PROFILES["ubuntu2204-stig"]` (`app/jobs.py`) trỏ đúng
`xccdf_org.ssgproject.content_profile_stig` của file này.

Verify thật: build lại image, `oscap xccdf eval --profile
xccdf_org.ssgproject.content_profile_stig` chạy hoàn tất (exit 0, 230
rule-result sinh ra) — cơ chế dispatch (`scan.sh`) hoàn toàn generic
(`SCAP_PROFILE`/`SCAP_DATASTREAM` truyền qua biến môi trường, không có
nhánh code riêng theo profile) nên không lặp lại toàn bộ nghi lễ E2E qua SSH
thật như lần thêm Debian — rủi ro tương đương (chỉ thêm 1 entry dữ liệu vào
dict đã có, không đổi code dispatch). Bổ sung tab "Template" (Control
Registry) cho cùng profile này qua `control-templates/ubuntu2204-stig.yml`
— xem `control-templates/README.md`.

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
Đã có nút "Restore" trên trang Jobs (Web UI), không chỉ API.

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
