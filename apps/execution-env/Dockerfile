# Ephemeral Execution Environment (mục 2 & 4.2 trong docs/architecture-proposal.md)
#
# Image này chỉ chứa TOOLING (ansible, ansible-runner, oscap) — KHÔNG bake
# nội dung SCAP/benchmark vào image. Nội dung đó đến từ Content Signing
# Service (scripts/content-signing/signed/), được mount read-only lúc chạy
# job sau khi đã verify chữ ký (xem scripts/content-signing/README.md).
#
# Container dựng từ image này được tạo mới cho MỖI job và huỷ ngay sau khi
# chạy xong — không có "control node" sống lâu dài nắm giữ cert + playbook.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ansible \
        ansible-lint \
        openscap-scanner \
        openssh-client \
        python3-pip \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --break-system-packages ansible-runner==2.4.0

WORKDIR /runner

COPY requirements.yml .
# Pin theo commit hash cụ thể trong requirements.yml (KHÔNG dùng "master"/"main"
# di động) — nguyên tắc 4.2: "Ansible role bên thứ ba pin version + hash-verify".
# requirements.yml hiện còn placeholder — xem README.md trong thư mục này
# trước khi build image thật.
RUN ansible-galaxy role install -r requirements.yml -p /etc/ansible/roles

ENTRYPOINT ["ansible-runner"]
