"""Unit test thuần cho logic role-check trong app/auth.py (không gọi Keycloak
thật — get_current_user bị bypass bằng cách truyền thẳng CurrentUser)."""
import pytest
from fastapi import HTTPException

from app.auth import CurrentUser, require_roles


def _user(*roles: str) -> CurrentUser:
    return CurrentUser(subject="u-1", username="tester", roles=frozenset(roles))


def test_require_roles_allows_when_role_matches():
    checker = require_roles("admin", "operator")
    result = checker(user=_user("operator"))
    assert result.username == "tester"


def test_require_roles_allows_when_user_has_extra_roles():
    checker = require_roles("admin")
    result = checker(user=_user("viewer", "admin"))
    assert "admin" in result.roles


def test_require_roles_blocks_when_role_missing():
    checker = require_roles("admin")
    with pytest.raises(HTTPException) as exc_info:
        checker(user=_user("viewer"))
    assert exc_info.value.status_code == 403


def test_require_roles_blocks_when_user_has_no_roles():
    checker = require_roles("viewer", "admin")
    with pytest.raises(HTTPException) as exc_info:
        checker(user=_user())
    assert exc_info.value.status_code == 403
