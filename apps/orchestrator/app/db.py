from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from app.config import settings

# Engine "app" — dùng cho các bảng nghiệp vụ thông thường (Control Registry,
# Host, Job... sẽ thêm ở Giai đoạn 1).
engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Engine "audit" — kết nối bằng role Postgres bị giới hạn quyền (chỉ
# INSERT/SELECT trên audit_log, không có UPDATE/DELETE). Đây là cơ chế thực
# thi ở tầng DB cho nguyên tắc audit log append-only, không chỉ dựa vào kỷ
# luật ở tầng application code.
audit_engine = create_engine(settings.audit_database_url, pool_pre_ping=True)
AuditSessionLocal = sessionmaker(bind=audit_engine, autoflush=False, autocommit=False)

Base = declarative_base()
