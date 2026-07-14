"""Test cho app/tls_identity.py (Giai đoạn 2 — mTLS Orchestrator/job-dispatcher).

Chạy qua container python:3.12-slim tạm, cài thêm `cryptography` (chỉ để TỰ
SINH cert test — KHÔNG có trong requirements.txt production, cùng lý do
pytest/httpx không bake vào image production, xem docstring test_main.py):

    docker run --rm -v <path-repo>/apps/job-dispatcher:/src -w /src \\
      python:3.12-slim sh -c \\
      "pip install -q -r requirements.txt pytest cryptography && python -m pytest tests/ -v"
"""
import datetime
import os

os.environ.setdefault("JOB_DISPATCHER_SHARED_SECRET", "test-secret")
os.environ.setdefault("ALLOWED_EXECUTION_IMAGE", "test-image:latest")
os.environ.setdefault("CONTENT_SIGNING_SIGNED_HOST_PATH", "/host/signed")

import ssl

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import tls_identity as tls_identity_module
from app.tls_identity import TLSIdentity


def _generate_self_signed_pem(cn: str = "job-dispatcher") -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


@pytest.fixture(autouse=True)
def _isolate_tls_paths(tmp_path, monkeypatch):
    # Mỗi test dùng đường dẫn file RIÊNG (không phải /tmp/job-dispatcher-tls/
    # cố định) — tránh test này ảnh hưởng lẫn nhau hoặc để lại rác thật trên
    # máy chạy test.
    monkeypatch.setattr(tls_identity_module, "CERT_PATH", str(tmp_path / "server.crt"))
    monkeypatch.setattr(tls_identity_module, "KEY_PATH", str(tmp_path / "server.key"))
    monkeypatch.setattr(tls_identity_module, "CA_ROOT_PATH", str(tmp_path / "ca-root.crt"))


def _fake_post_success(cert_pem, key_pem, ca_root_pem):
    def _fake(*args, **kwargs):
        class _Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return {"cert_pem": cert_pem, "key_pem": key_pem, "ca_root_pem": ca_root_pem}

        return _Resp()

    return _fake


def test_bootstrap_blocking_writes_files_on_success(monkeypatch):
    cert_pem, key_pem = _generate_self_signed_pem()
    monkeypatch.setattr(httpx, "post", _fake_post_success(cert_pem, key_pem, cert_pem))

    identity = TLSIdentity("http://unused", "secret")
    identity.bootstrap_blocking()

    with open(tls_identity_module.CERT_PATH, encoding="utf-8") as f:
        assert f.read() == cert_pem
    with open(tls_identity_module.KEY_PATH, encoding="utf-8") as f:
        assert f.read() == key_pem


def test_bootstrap_blocking_succeeds_after_transient_failures(monkeypatch):
    cert_pem, key_pem = _generate_self_signed_pem()
    attempts = {"n": 0}

    def _fake(*args, **kwargs):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise httpx.ConnectError("Orchestrator chưa sẵn sàng")
        return _fake_post_success(cert_pem, key_pem, cert_pem)()

    monkeypatch.setattr(httpx, "post", _fake)
    monkeypatch.setattr(tls_identity_module.time, "sleep", lambda _: None)

    identity = TLSIdentity("http://unused", "secret")
    identity.bootstrap_blocking(interval=0.01, deadline=1.0)
    assert attempts["n"] == 3


def test_bootstrap_blocking_gives_up_after_deadline(monkeypatch):
    def _always_fail(*args, **kwargs):
        raise httpx.ConnectError("Orchestrator không phản hồi")

    monkeypatch.setattr(httpx, "post", _always_fail)
    monkeypatch.setattr(tls_identity_module.time, "sleep", lambda _: None)

    identity = TLSIdentity("http://unused", "secret")
    with pytest.raises(RuntimeError):
        identity.bootstrap_blocking(interval=0.01, deadline=0.03)


def test_refresh_and_reload_hot_swaps_real_ssl_context(monkeypatch):
    old_cert, old_key = _generate_self_signed_pem(cn="old")
    new_cert, new_key = _generate_self_signed_pem(cn="new")

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Nạp cert CŨ trước — mô phỏng context server ĐANG chạy với cert cũ.
    old_cert_path = tls_identity_module.CERT_PATH + ".old"
    old_key_path = tls_identity_module.KEY_PATH + ".old"
    with open(old_cert_path, "w", encoding="utf-8") as f:
        f.write(old_cert)
    with open(old_key_path, "w", encoding="utf-8") as f:
        f.write(old_key)
    ssl_context.load_cert_chain(old_cert_path, old_key_path)

    monkeypatch.setattr(httpx, "post", _fake_post_success(new_cert, new_key, new_cert))

    identity = TLSIdentity("http://unused", "secret")
    identity.refresh_and_reload(ssl_context)  # KHÔNG được raise

    with open(tls_identity_module.CERT_PATH, encoding="utf-8") as f:
        assert f.read() == new_cert


def test_refresh_and_reload_rejects_invalid_cert_without_touching_old_files(monkeypatch):
    old_cert, old_key = _generate_self_signed_pem(cn="old")
    with open(tls_identity_module.CERT_PATH, "w", encoding="utf-8") as f:
        f.write(old_cert)
    with open(tls_identity_module.KEY_PATH, "w", encoding="utf-8") as f:
        f.write(old_key)

    monkeypatch.setattr(httpx, "post", _fake_post_success("khong-phai-pem-hop-le", "cung-khong-hop-le", "x"))

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    identity = TLSIdentity("http://unused", "secret")
    with pytest.raises(ssl.SSLError):
        identity.refresh_and_reload(ssl_context)

    # File cũ KHÔNG bị ghi đè bởi cert hỏng — server thật (nếu đang chạy)
    # vẫn tiếp tục dùng cert cũ an toàn.
    with open(tls_identity_module.CERT_PATH, encoding="utf-8") as f:
        assert f.read() == old_cert


def test_renewal_loop_survives_refresh_failure(monkeypatch):
    call_count = {"n": 0}

    def _fail_once_then_stop(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise httpx.ConnectError("renew thất bại tạm thời")
        raise SystemExit  # dừng vòng lặp vô hạn sau lần thử thứ 2

    identity = TLSIdentity("http://unused", "secret")
    monkeypatch.setattr(identity, "refresh_and_reload", _fail_once_then_stop)
    monkeypatch.setattr(tls_identity_module.time, "sleep", lambda _: None)

    with pytest.raises(SystemExit):
        identity.renewal_loop(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), interval=0.01)

    # Lần lỗi ĐẦU TIÊN không làm loop dừng (except Exception nuốt lỗi) — nếu
    # nó dừng ngay, call_count sẽ dừng ở 1 thay vì tới được lần gọi thứ 2.
    assert call_count["n"] == 2
