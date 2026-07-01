"""Test cho cơ chế audit log hash-chain (Giai đoạn 0).

- test_compute_hash_* : unit test thuần, không cần DB.
- test_write_and_verify_chain_integration : cần Postgres thật đang chạy
  (docker compose up postgres) và biến môi trường DATABASE_URL/AUDIT_DATABASE_URL
  đã trỏ đúng — bị skip tự động nếu không có.
"""
import os

import pytest

from app.audit import _compute_hash


def test_compute_hash_is_deterministic():
    h1 = _compute_hash("0" * 64, "2026-01-01T00:00:00+00:00", "alice", "login", None, {})
    h2 = _compute_hash("0" * 64, "2026-01-01T00:00:00+00:00", "alice", "login", None, {})
    assert h1 == h2
    assert len(h1) == 64


def test_compute_hash_changes_if_any_field_changes():
    base = _compute_hash("0" * 64, "2026-01-01T00:00:00+00:00", "alice", "login", None, {})
    changed_actor = _compute_hash("0" * 64, "2026-01-01T00:00:00+00:00", "bob", "login", None, {})
    changed_prev = _compute_hash("1" * 64, "2026-01-01T00:00:00+00:00", "alice", "login", None, {})
    assert base != changed_actor
    assert base != changed_prev


@pytest.mark.skipif(
    "AUDIT_DATABASE_URL" not in os.environ,
    reason="cần Postgres thật đang chạy (docker compose up postgres)",
)
def test_write_and_verify_chain_integration():
    from app.audit import verify_chain, write_audit_event

    e1 = write_audit_event("tester", "unit-test", "audit_log", {"seq": 1})
    e2 = write_audit_event("tester", "unit-test", "audit_log", {"seq": 2})

    assert e2.prev_hash == e1.record_hash
    assert verify_chain() is True
