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
        # static-ssh-key-bootstrap.sh dùng mã hoá private key mới sinh (key/
        # iv raw, KHÔNG qua -pass/-pbkdf2) trước khi in ra stdout — xem
        # app/jobs.py:trigger_static_ssh_key_bootstrap. Cài rõ ràng, không
        # suy đoán có sẵn qua dependency khác.
        openssl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --break-system-packages ansible-runner==2.4.0

# Datastream STIG cho Ubuntu 22.04 (DISA "Canonical Ubuntu 22.04 LTS STIG
# V2R7") — gói apt ssg-debderived (0.1.65-1) chỉ có profile CIS/standard,
# KHÔNG có stig. Vendor riêng 1 file từ đúng release ComplianceAsCode chính
# thức (v0.1.81, sha512 đã verify trước khi thêm vào repo — xem
# control-templates/README.md, cùng nguồn dùng cho tab Template) thay vì
# nâng cấp/thay thế file CIS đang chạy — giữ nguyên 100% hành vi scan CIS
# hiện có, chỉ CỘNG THÊM khả năng chọn profile STIG. Đặt tên khác file apt
# cài (ssg-ubuntu2204-ds.xml) để không đụng nhau, dù file này thực ra chứa
# đủ cả profile CIS lẫn STIG — chỉ dùng đúng profile "stig" của nó qua
# SCAP_PROFILES (app/jobs.py), không dùng để scan CIS (vẫn dùng file apt).
COPY ssg-ubuntu2204-stig-ds.xml /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-stig-ds.xml

# Datastream CIS cho Ubuntu 24.04 — gói apt ssg-debderived (0.1.65-1, Debian
# bookworm) KHÔNG có product ubuntu2404 (ComplianceAsCode chỉ thêm hỗ trợ
# 24.04 từ v0.1.76 trở đi, mãi mãi không tự vào được qua apt vì Debian
# stable không nâng version gói này). Vendor riêng file này từ CÙNG release
# v0.1.81 đã dùng cho STIG ở trên (sha512 tarball đã verify khớp công bố
# chính thức trước khi trích xuất) — chỉ mở rộng "Quét" (scan), KHÔNG kèm
# nội dung remediation cho 24.04 (vẫn cần qua quy trình content-signing
# 3 vai trò riêng nếu muốn remediate thật, giống tiền lệ mở rộng Debian —
# xem README.md "Mở rộng SCAP scan sang Debian").
COPY ssg-ubuntu2404-ds.xml /usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml

WORKDIR /runner

# Cho phép build image "chỉ scan" (KHÔNG có khả năng remediate) — scan qua
# OpenSCAP không cần collection bên dưới, chỉ remediate mới cần. Mặc định
# build (không truyền build-arg) cài collection devsec.hardening (đã review +
# ghim commit thật, xem requirements.yml — KHÔNG còn placeholder). Dùng
# "collection install" (không phải "role install" cũ) vì dev-sec đã
# deprecate 2 role standalone, merge chung vào 1 collection duy nhất — role
# trong playbook.yml giờ gọi qua FQCN devsec.hardening.os_hardening/
# devsec.hardening.ssh_hardening. Cài vào /usr/share/ansible/collections —
# 1 trong các path mặc định ansible-playbook tự tìm collection (khác
# /etc/ansible/roles cho role kiểu cũ), không cần khai thêm ansible.cfg.
ARG INSTALL_REMEDIATION_ROLES=true
COPY requirements.yml .
RUN if [ "$INSTALL_REMEDIATION_ROLES" = "true" ]; then \
        ansible-galaxy collection install -r requirements.yml -p /usr/share/ansible/collections; \
    else \
        echo "SKIP: remediation collection KHONG duoc cai (INSTALL_REMEDIATION_ROLES=false)."; \
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
COPY static-ssh-key-bootstrap.sh /usr/local/bin/static-ssh-key-bootstrap.sh
COPY agent-install.sh /usr/local/bin/agent-install.sh
COPY agent-uninstall.sh /usr/local/bin/agent-uninstall.sh
COPY ssh-port-change.sh /usr/local/bin/ssh-port-change.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/scan.sh /usr/local/bin/remediate.sh /usr/local/bin/restore.sh /usr/local/bin/ssh-check.sh /usr/local/bin/ca-bootstrap.sh /usr/local/bin/static-ssh-key-bootstrap.sh /usr/local/bin/agent-install.sh /usr/local/bin/agent-uninstall.sh /usr/local/bin/ssh-port-change.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
