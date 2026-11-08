"""Authentication primitives: password hashing, sessions, RBAC roles.

- Passwords are hashed with stdlib ``hashlib.scrypt`` (no third-party
  dependency) and verified in constant time.
- Session tokens are random, returned to the client once, and stored
  only as a SHA-256 hash with an expiry — a database read never yields a
  usable token.
- Roles form an ordered hierarchy; endpoints require a minimum role.
"""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from enum import StrEnum

_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_SESSION_TTL_HOURS = 12


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    RESEARCHER = "researcher"
    ADMIN = "admin"


# Higher number = more privilege. An endpoint requires a minimum level.
_ROLE_LEVEL: dict[Role, int] = {
    Role.VIEWER: 0,
    Role.ANALYST: 1,
    Role.RESEARCHER: 2,
    Role.ADMIN: 3,
}


def role_at_least(role: Role, minimum: Role) -> bool:
    return _ROLE_LEVEL[role] >= _ROLE_LEVEL[minimum]


def parse_role(value: str) -> Role:
    try:
        return Role(value)
    except ValueError as exc:
        valid = ", ".join(r.value for r in Role)
        raise ValueError(f"Invalid role '{value}'. Valid roles: {valid}.") from exc


def hash_password(password: str) -> str:
    """Return a ``scrypt$<salt_hex>$<hash_hex>`` string."""

    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=32,
    )
    return f"scrypt${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time password verification against a stored hash."""

    try:
        scheme, salt_hex, hash_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, TypeError):
        return False

    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=len(expected),
    )
    return hmac.compare_digest(derived, expected)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_expiry(hours: int = _SESSION_TTL_HOURS) -> str:
    return (datetime.now(UTC) + timedelta(hours=hours)).isoformat()


def is_expired(expiry_iso: str) -> bool:
    try:
        expiry = datetime.fromisoformat(expiry_iso)
    except ValueError:
        return True
    return datetime.now(UTC) >= expiry
