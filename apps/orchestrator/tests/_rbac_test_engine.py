"""Engine SQLite RIÊNG, DÙNG CHUNG cho 3 bảng RBAC (app_roles/role_permissions/
user_role_assignments) trong toàn bộ test suite — xem conftest.py để biết lý
do: 3 bảng này KHÔNG thuộc riêng 1 test file nào (khác domain tables Host/Job/
Control... mỗi file tự có engine riêng), vì `require_permission` (app/rbac.py)
được MỌI router gọi tới, và app/roles.py + app/users.py cũng tự đọc/ghi 3
bảng này qua `_get_db` riêng của CHÍNH CHÚNG — 3 dependency khác nhau nhưng
phải cùng nhìn thấy 1 dữ liệu, đúng thực tế production (cả 3 module cùng
dùng app/db.py:SessionLocal, cùng 1 Postgres).

Import module này (KHÔNG phải conftest.py trực tiếp) từ test_roles.py/
test_users.py để override đúng `_get_db` của CHÍNH router đó vào cùng engine.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

rbac_engine = create_engine(
    "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
)
RbacSessionLocal = sessionmaker(bind=rbac_engine, autoflush=False, autocommit=False)


def override_rbac_db():
    db = RbacSessionLocal()
    try:
        yield db
    finally:
        db.close()
