"""Cấp SSH user cert ngắn hạn cho từng job, gọi trực tiếp step-ca qua ca-net
(mục 4.1/4.7 architecture-proposal.md — "no standing privilege").

Orchestrator là thành phần DUY NHẤT nối ca-net nên là nơi hợp lý để giữ
provisioner password và tự cấp cert — cert sinh ra chỉ tồn tại trong bộ nhớ
tiến trình này (thư mục tạm bị xoá ngay sau khi đọc xong), KHÔNG ghi vào DB
hay volume nào, và TTL do provisioner quyết định (5-15 phút — xem
infra/step-ca/setup-provisioners.sh).
"""
import os
import subprocess
import tempfile

from app.config import settings


def mint_ssh_certificate(principal: str) -> tuple[str, str]:
    """Trả về (private_key_pem, cert_pub_content) cho 1 SSH user cert mới cấp.

    Raises RuntimeError cho MỌI lỗi cấp cert — step-ca từ chối cấp (vd
    provisioner password sai), timeout (`step` treo quá 30s), hoặc lỗi cấp
    tiến trình (thiếu binary `step`, lỗi đọc/ghi file tạm). Gói tất cả vào
    đúng 1 loại exception để jobs.py chỉ cần bắt RuntimeError là đủ — trước
    đây chỉ raise RuntimeError cho trường hợp returncode != 0, khiến
    subprocess.TimeoutExpired/OSError lọt qua try/except ở jobs.py, làm Job
    kẹt vĩnh viễn ở status "running" (phát hiện qua review, không phải test
    thật — xem README).
    """
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            pw_file = os.path.join(tmpdir, "pw")
            key_file = os.path.join(tmpdir, "job_key")
            with open(pw_file, "w", encoding="utf-8") as f:
                f.write(settings.stepca_provisioner_password)

            result = subprocess.run(
                [
                    "step", "ssh", "certificate", principal, key_file,
                    "--provisioner", settings.stepca_provisioner_name,
                    "--provisioner-password-file", pw_file,
                    "--no-password", "--insecure", "--force",
                    "--ca-url", settings.stepca_url,
                    "--root", settings.stepca_root_cert_path,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                raise RuntimeError(f"cấp SSH cert thất bại: {result.stderr.strip()}")

            with open(key_file, encoding="utf-8") as f:
                private_key = f.read()
            with open(f"{key_file}-cert.pub", encoding="utf-8") as f:
                cert_pub = f.read()
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"cấp SSH cert timeout sau {exc.timeout}s") from exc
    except OSError as exc:
        raise RuntimeError(f"lỗi hệ thống khi cấp SSH cert: {exc}") from exc

    return private_key, cert_pub


def create_agent_enrollment_token(
    hostname: str, ttl: str = "5m", extra_sans: list[str] | None = None,
) -> str:
    """Sinh 1 bootstrap token (OTT — one-time token) cho agent trên
    `hostname` dùng provisioner "agent-enrollment" (JWK, tạo sẵn từ Giai
    đoạn 0 — xem infra/step-ca/setup-provisioners.sh, dùng chung password
    với provisioner "orchestrator"). Token này KHÔNG phải cert, chỉ là vé
    đổi cert đúng 1 lần — việc thực thi "chỉ dùng 1 lần" nằm ở tầng
    application (bảng agent_enrollment_tokens.used_at), không chỉ dựa vào
    step-ca, để không phải phụ thuộc đúng hành vi nội bộ chưa verify hết
    của step-ca cho từng loại provisioner.

    `extra_sans` (mục TLS Keycloak/Web/Orchestrator — cần cả DNS name nội bộ
    LẪN IP public để browser/service nội bộ đều verify được đúng 1 cert):
    `step ca token` chỉ đưa `hostname` vào claim "sans" NẾU không có `--san`
    nào được truyền — hễ truyền `--san` thì PHẢI tự liệt kê lại chính
    `hostname` vào đó nếu còn muốn nó có mặt (đã verify qua `step ca token
    --help`, không suy đoán). `step ca certificate ... --token` sau đó tự
    lấy đúng danh sách SAN từ token, KHÔNG nhận `--san` riêng (2 cờ đó loại
    trừ nhau) — nên toàn bộ SAN phải quyết định ngay từ bước tạo token này.
    """
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            pw_file = os.path.join(tmpdir, "pw")
            with open(pw_file, "w", encoding="utf-8") as f:
                f.write(settings.stepca_provisioner_password)

            san_args = []
            if extra_sans:
                for san in [hostname, *extra_sans]:
                    san_args += ["--san", san]

            result = subprocess.run(
                [
                    "step", "ca", "token", hostname,
                    "--provisioner", settings.stepca_agent_provisioner_name,
                    "--provisioner-password-file", pw_file,
                    "--not-after", ttl,
                    "--ca-url", settings.stepca_url,
                    "--root", settings.stepca_root_cert_path,
                    *san_args,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                raise RuntimeError(f"tạo enrollment token thất bại: {result.stderr.strip()}")
            return result.stdout.strip()
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"tạo enrollment token timeout sau {exc.timeout}s") from exc
    except OSError as exc:
        raise RuntimeError(f"lỗi hệ thống khi tạo enrollment token: {exc}") from exc


def mint_agent_client_cert(hostname: str, token: str) -> tuple[str, str]:
    """Đổi 1 bootstrap token (từ create_agent_enrollment_token) lấy cert
    mTLS x509 thật cho agent trên `hostname`. Trả về (cert_pem, key_pem).

    Raises RuntimeError cho mọi lỗi (cùng hợp đồng với mint_ssh_certificate).
    """
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            crt_file = os.path.join(tmpdir, "agent.crt")
            key_file = os.path.join(tmpdir, "agent.key")

            result = subprocess.run(
                [
                    "step", "ca", "certificate", hostname, crt_file, key_file,
                    "--token", token,
                    "--ca-url", settings.stepca_url,
                    "--root", settings.stepca_root_cert_path,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                raise RuntimeError(f"cấp agent cert thất bại: {result.stderr.strip()}")

            with open(crt_file, encoding="utf-8") as f:
                cert_pem = f.read()
            with open(key_file, encoding="utf-8") as f:
                key_pem = f.read()
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"cấp agent cert timeout sau {exc.timeout}s") from exc
    except OSError as exc:
        raise RuntimeError(f"lỗi hệ thống khi cấp agent cert: {exc}") from exc

    return cert_pem, key_pem


def mint_agent_manager_server_cert(
    subject: str = "agent-manager", extra_sans: list[str] | None = None,
) -> tuple[str, str]:
    """Cấp cert x509 server cho 1 service nội bộ tự renew định kỳ (Agent
    Manager, job-dispatcher, và giờ cả Keycloak/Web/chính Orchestrator cho
    TLS — mục "Dựng TLS thật") — KHÁC với mint_agent_client_cert (cert máy
    fleet, dùng-1-lần qua token): đây là định danh dịch vụ dài hạn, mỗi
    service tự gọi lại định kỳ để renew trước khi hết hạn (TTL do
    provisioner quyết định, hiện 8h mặc định — xem
    infra/step-ca/setup-provisioners.sh). Không cần bảng theo dõi dùng-1-lần
    vì mọi lần gọi đều từ 1 service đáng tin (đã qua shared secret) xin lại
    danh tính của chính nó, không phải cấp quyền mới cho một bên thứ ba.

    `extra_sans`: cần cho Keycloak/Web (browser verify theo IP LAN, service
    nội bộ khác verify theo DNS name docker network — 1 cert không đủ nếu
    chỉ có `subject` làm SAN duy nhất, xem create_agent_enrollment_token).
    Agent Manager/job-dispatcher không cần (không có client browser nào
    verify theo IP) nên giữ mặc định None, không đổi hành vi cũ.

    Vẫn đi qua đúng 1 cửa "chỉ Orchestrator được gọi CA": tạo OTT nội bộ
    rồi đổi lấy cert ngay trong cùng lệnh gọi, không lộ OTT ra ngoài.

    Raises RuntimeError cho mọi lỗi (cùng hợp đồng với mint_ssh_certificate).
    """
    token = create_agent_enrollment_token(subject, ttl="5m", extra_sans=extra_sans)
    return mint_agent_client_cert(subject, token)


def get_ssh_user_ca_pubkey() -> str:
    """Trả về public key (1 dòng, format OpenSSH) của SSH User CA — dùng để
    đẩy vào `/etc/ssh/user_ca.pub` + `TrustedUserCAKeys` trên host lúc
    bootstrap CA trust (mục "Zero-to-CA Migration", xem app/jobs.py:
    trigger_ca_bootstrap và ansible/playbooks/zero-to-ca-migration.yml —
    thủ công trước đây phải `docker compose exec step-ca step ssh config
    --roots`, giờ Orchestrator tự lấy qua đúng `--ca-url`/`--root` đã dùng
    cho mint_ssh_certificate, KHÔNG cần exec vào container step-ca).

    Public key KHÔNG bí mật (chỉ private key của CA mới bí mật) — an toàn để
    trả qua API/nhúng vào script mà không cần xác thực đặc biệt.

    Raises RuntimeError cho mọi lỗi (cùng hợp đồng với mint_ssh_certificate).
    """
    try:
        result = subprocess.run(
            [
                "step", "ssh", "config", "--roots",
                "--ca-url", settings.stepca_url,
                "--root", settings.stepca_root_cert_path,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"lấy SSH User CA public key thất bại: {result.stderr.strip()}")
        return result.stdout.strip()
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"lấy SSH User CA public key timeout sau {exc.timeout}s") from exc
    except OSError as exc:
        raise RuntimeError(f"lỗi hệ thống khi lấy SSH User CA public key: {exc}") from exc
