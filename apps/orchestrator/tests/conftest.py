"""Fixture CHUNG cho toàn bộ test suite — riêng cho RBAC tuỳ biến (app/rbac.py).

`app_roles`/`role_permissions`/`user_role_assignments` là dữ liệu KHÔNG
thuộc riêng 1 test file nào (khác domain tables Host/Job/Control... mỗi file
tự có engine riêng) — xem tests/_rbac_test_engine.py để biết lý do dùng 1
engine SQLite RIÊNG, DÙNG CHUNG bởi `app.rbac._get_db` (ở đây) VÀ
`app.roles._get_db`/`app.users._get_db` (override riêng trong test_roles.py/
test_users.py, cùng module _rbac_test_engine, để 3 dependency khác nhau vẫn
nhìn thấy cùng 1 dữ liệu — đúng thực tế production, cả 3 module cùng dùng
app/db.py:SessionLocal).

`app.rbac._get_db` được MỌI router gọi tới qua `require_permission` (không
thuộc riêng file nào, khác `hosts_module._get_db`/`jobs_module._get_db`...)
— PHẢI override đúng 1 LẦN Ở ĐÂY. Override key này ở nhiều file khác nhau sẽ
dẫm lên nhau (`app.dependency_overrides` là dict global, xem gotcha trong
CLAUDE.md), key cuối cùng thắng áp dụng cho TOÀN BỘ session pytest.

`app.auth._get_db` (dependency nội bộ của `get_current_user` thật) KHÔNG cần
override ở đây — mọi test file hiện có override THẲNG `get_current_user`
(qua `_as()`), nên thân hàm thật (và `_get_db` bên trong nó) không bao giờ
chạy trong các test đó.
"""
import pytest

from app import rbac as rbac_module
from app.db import Base
from app.main import app

from _rbac_test_engine import RbacSessionLocal, override_rbac_db, rbac_engine

app.dependency_overrides[rbac_module._get_db] = override_rbac_db


@pytest.fixture(autouse=True)
def _rbac_schema():
    Base.metadata.create_all(
        bind=rbac_engine,
        tables=[
            Base.metadata.tables["app_roles"],
            Base.metadata.tables["role_permissions"],
            Base.metadata.tables["user_role_assignments"],
        ],
    )
    db = RbacSessionLocal()
    try:
        rbac_module.seed_builtin_roles(db)
    finally:
        db.close()
    yield
    Base.metadata.drop_all(bind=rbac_engine)
