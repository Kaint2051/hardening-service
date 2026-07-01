# Ephemeral Execution Environment

Image dùng làm môi trường chạy job SSH (agentless: scan OpenSCAP / remediate
Ansible). Orchestrator tạo **1 container mới cho mỗi job** từ image này, rồi
huỷ ngay sau khi job kết thúc — không có container sống lâu dài nắm giữ SSH
cert + playbook (xem rủi ro "Ansible Control Node..." đã phân tích trong
`docs/architecture-proposal.md`).

## Trước khi dùng thật

1. **Điền commit hash đã review vào `requirements.yml`** — hiện đang là
   placeholder. Không build/deploy image với placeholder còn nguyên.
2. Build lại image mỗi khi `requirements.yml` đổi, gắn tag theo hash nội dung
   (`docker build -t execution-env:<content-hash> .`) để Orchestrator có thể
   pin đúng version image khi tạo job, không dùng tag `latest`.
3. Nội dung SCAP/benchmark (ComplianceAsCode) KHÔNG nằm trong image này — được
   mount read-only từ `scripts/content-signing/signed/` lúc chạy container,
   sau khi đã qua quy trình Puller → Reviewer → Signer.

## Đã verify (lab server, Ubuntu 24.04)

Build thật đã được chạy với `requirements.yml` còn nguyên placeholder: các
layer tooling (apt-get ansible/ansible-lint/openscap-scanner/openssh-client,
pip install ansible-runner) build thành công; build **dừng cứng đúng như
thiết kế** ở bước `ansible-galaxy role install` với lỗi
`pathspec 'REPLACE_WITH_REVIEWED_COMMIT_SHA' did not match any file(s) known
to git` — xác nhận không thể vô tình build ra image dùng role chưa qua
review. Chưa build image thật (cần điền commit hash đã review trước).

## Chạy thử cục bộ

```bash
docker build -t execution-env:dev ./apps/execution-env

docker run --rm \
  -v "$(pwd)/scripts/content-signing/signed:/content:ro" \
  execution-env:dev --help
```
