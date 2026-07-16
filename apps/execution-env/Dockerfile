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
        openscap-utils \
        ssg-debderived \
        # ssg-debderived chỉ chứa nội dung benchmark cho các distro "derived
        # from Debian" (Ubuntu) — TÊN GÂY HIỂU NHẦM, không phải Debian thật
        # (phát hiện qua kiểm tra thật: package này chỉ có
        # ssg-ubuntu{1604,1804,2004,2204}-*.xml, không có bản debian nào cả).
        # Debian thật (buster/bullseye) nằm ở package RIÊNG ssg-debian.
        ssg-debian \
        openssh-client \
        python3-pip \
        ca-certificates \
        git \
        gnupg \
        # Chỉ dùng cho ca-bootstrap.sh (bootstrap CA trust bằng credential CŨ
        # dạng password, mục "Zero-to-CA Migration" — xem app/jobs.py:
        # trigger_ca_bootstrap). Đọc password qua -f <file> (không phải -p
        # <chuỗi>) để tránh lộ qua `ps aux`.
        sshpass \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --break-system-packages ansible-runner==2.4.0

WORKDIR /runner

# Cho phép build image "chỉ scan" (KHÔNG có khả năng remediate) mà không cần
# chờ commit hash đã review — scan qua OpenSCAP không cần các role bên dưới,
# chỉ remediate mới cần. Mặc định build (không truyền build-arg) vẫn giữ
# nguyên hành vi cũ: BẮT BUỘC cài role, và BẮT BUỘC FAIL nếu requirements.yml
# còn placeholder (đã verify thật — xem apps/execution-env/README.md).
ARG INSTALL_REMEDIATION_ROLES=true
COPY requirements.yml .
RUN if [ "$INSTALL_REMEDIATION_ROLES" = "true" ]; then \
        ansible-galaxy role install -r requirements.yml -p /etc/ansible/roles; \
    else \
        echo "SKIP: remediation roles KHONG duoc cai (INSTALL_REMEDIATION_ROLES=false)."; \
        echo "Image nay CHI dung de scan, KHONG dung de remediate."; \
    fi

# remediate.sh chạy trong container MỚI, keyring GPG trống — nó biết fingerprint
# nào đáng tin (CONTENT_SIGNING_TRUSTED_FINGERPRINT, truyền lúc chạy job) nhưng
# cần chính PUBLIC KEY đó nằm sẵn trong keyring mới verify được chữ ký. Bake vào
# IMAGE lúc build (cùng tinh thần requirements.yml pin theo commit hash) thay vì
# truyền qua biến môi trường runtime — public key KHÔNG bí mật nhưng TOÀN VẸN của
# nó quan trọng, gắn vào quá trình build/pin image an toàn hơn 1 giá trị
# Orchestrator gửi xuống lúc chạy job. Import thất bại (placeholder chưa thay)
# KHÔNG làm fail build — remediate.sh tự từ chối MỌI bundle nếu keyring trống
# (an toàn mặc định), giống cách INSTALL_REMEDIATION_ROLES=false vẫn build được.
COPY trusted-signer-pubkey.asc /tmp/trusted-signer-pubkey.asc
RUN gpg --import /tmp/trusted-signer-pubkey.asc 2>&1 || \
    echo "CANH BAO: trusted-signer-pubkey.asc con la placeholder/khong hop le - remediate.sh se TU CHOI moi bundle cho toi khi thay bang public key that."

COPY scan.sh /usr/local/bin/scan.sh
COPY remediate.sh /usr/local/bin/remediate.sh
COPY restore.sh /usr/local/bin/restore.sh
COPY ssh-check.sh /usr/local/bin/ssh-check.sh
COPY ca-bootstrap.sh /usr/local/bin/ca-bootstrap.sh
COPY agent-install.sh /usr/local/bin/agent-install.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/scan.sh /usr/local/bin/remediate.sh /usr/local/bin/restore.sh /usr/local/bin/ssh-check.sh /usr/local/bin/ca-bootstrap.sh /usr/local/bin/agent-install.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
